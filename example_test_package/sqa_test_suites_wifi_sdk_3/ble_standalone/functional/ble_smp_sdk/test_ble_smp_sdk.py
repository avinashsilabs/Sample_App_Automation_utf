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
from utf.interfaces.bluetooth.nrf_blatann import (NRFBLEIoCapabilities, NRFBLEPeerDevAddrTypes)
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
                 reconnection_from_remote=False, powersave=True, random_addr_on_dut=False, local_oob_flag=False, nrf_dongle_as_master=False, testcase_no=None, connect_from_raspi_passkey_entry=None, iter=1, passkey_entry=False):
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
        self.connect_from_raspi_passkey_entry = connect_from_raspi_passkey_entry
        self.iter = iter
        self.passkey_entry = passkey_entry


    def run(self):
        if self.sniffer_check or self.encrypted_file:
            self.ble_sniffer.interfaces.sniffer.init_sniffer()
            self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        logger().info("Initiate ble service in DUT")
        logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability}")
        ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.smp_sc, capability=self.smp_io_capability)
        assert ble_dut_address, "failed to initiate ble in dut"
        if self.random_addr_on_dut:
            self.wifi_dut.interfaces.wifi.ble_set_bd_addr(remote_dev_addr=1)
            self.wifi_dut.interfaces.wifi.ble_set_random_addr()

        if self.nrf_connect_to_dut:

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
            self.nrf_ble_client.interfaces.bluetooth.register_dynamic_passkey_entry()
            if self.testcase_no == 557287 or  self.testcase_no == 557289 or  self.testcase_no == 557290 or self.testcase_no == 557293:
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
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=0, smp_io_cap=self.smp_io_capability,
                                                           smp_auth_req_bonding=self.smp_auth_bond,
                                                           smp_auth_req_mitm=self.smp_mtim,
                                                           smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                           smp_local_oob_data_flag_not_present=0,
                                                           smp_enc_key=1, smp_id_key=0,
                                                           smp_sign_key=0)
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
            assert str(ble_dut_address) in found_devices
            self.nrf_ble_client.interfaces.bluetooth.stop_scanning()
            self.nrf_ble_client.interfaces.bluetooth.set_connection_parameters(100, 120, 6000)
            connection_status = False
            logger().info("\n\n======= start nRF dongle ========")
            ble_client_address = self.nrf_ble_client.interfaces.bluetooth.get_ble_address()
            assert ble_client_address is not None
            logger().info(f"**********Initiating connection from dongle****************")
            self.nrf_ble_client.interfaces.bluetooth.connect(ble_dut_address)
            time.sleep(2)
            connection_status = self.nrf_ble_client.interfaces.bluetooth.get_peer_connection_status(ble_dut_address)
            logger().info(f"\n\nConnection status: {connection_status}")
            assert connection_status
            self.nrf_ble_client.interfaces.bluetooth.set_peer_security_params(ble_dut_address, passcode_pairing=True,
                                                                              io_capabilities=self.cap_on_dongle,
                                                                              lesc_pairing=True,
                                                                              long_term_bonding=True)
            self.nrf_ble_client.interfaces.bluetooth.pair(ble_dut_address)
            security_level = self.nrf_ble_client.interfaces.bluetooth.get_peer_connection_security_status(
                ble_dut_address)
            assert security_level.value == 2
            logger().info("Checking connection status of BLE")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"**********{state_int}****************")
            assert state_int == 8, f"Device disconnected"
        if self.ble_connect_from_raspi:
            if self.random_addr_on_dut:
                  logger().info("Set DUT in advertise mode with random")
                  self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_addr_type=1)
            else:
                logger().info("Set DUT in advertise mode")
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info("Start smp scan from the remote device")
            logger().info(f"Capability on remote: {self.capability_on_remote}")
            self.ble_client.interfaces.bluetooth.close()
            time.sleep(2)
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
        if self.reconnection_from_remote:
            logger().info("Set DUT in advertise mode")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info("Start smp scan from the remote device")
            logger().info(f"Capability on remote: {self.capability_on_remote}")
            self.ble_client.interfaces.bluetooth.close()
            time.sleep(2)
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address,
                                                                                     capability=self.capability_on_remote)
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
            assert state_int==8, f"Device disconnected"
            for i in range(0, 10):
                logger().info("Disconnecting the bt host....")
                self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
                time.sleep(5)
                self.ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address)
                time.sleep(10)
                logger().info("Checking connection status of BLE")
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == 8, f"Device disconnected"



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

        if self.connect_from_raspi_passkey_entry:
            if self.random_addr_on_dut:
                logger().info("Set DUT in advertise mode with random")
                self.wifi_dut.interfaces.wifi.ble_start_advertising(own_addr_type=1, ble_addr_type=1)
            else:
                logger().info("Set DUT in advertise mode")
                self.wifi_dut.interfaces.wifi.ble_start_advertising()

            # Start ble client scan
            logger().info("Start smp scan from the remote device")
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address,
                                                                                capability=self.client_capability,
                                                                                pin_code=self.pin_code, remove_device=False)
            assert ble_client_address, "failed to initiate ble in remote device"

            if self.powersave:
                logger().info("enabling the power save modes ")
                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)


            time.sleep(5)

            logger().info("stop scanning ....")
            self.ble_client.interfaces.bluetooth.stop_scanning()

            logger().info("Check the dut is listed...")
            self.ble_client.interfaces.bluetooth.get_devices()

            def connect():
                logger().info("Connecting to the DUT with MAC address...")
                self.ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address, timeout=10)

            time.sleep(3)  # Give it time to connect

            # Create and start the connect thread
            connect_thread = threading.Thread(target=connect)
            connect_thread.start()
            time.sleep(10)
            tw = Stopwatch()

            pass_key_found = False
            while tw.elapsed_sec < 30:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    logger().info(f"********{event.event_data}*************")
                    if "passkey" in event.event_data:
                        passkey = re.findall(r"(?<=passkey: )\d*", event.event_data)
                        if passkey[0] is not None:
                            pass_key_value = str(passkey[0])
                            logger().info(f"passkey : {pass_key_value}")
                            self.ble_client.interfaces.bluetooth.set_pin(pass_key_value)
                            pass_key_found = True
                            break
                        time.sleep(1)
                if pass_key_found:
                    break

            time.sleep(60)
            logger().info(f"********************************")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            logger().info(f"********************************")
            logger().info("Disconnecting the bt host....")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
            time.sleep(10)

        if self.encrypted_file:
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            if state_int == 8:
                self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
                time.sleep(10)
            self.ble_sniffer.interfaces.sniffer.stop_capture()


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



def test_ble_smp_anthencation_verify_passkey_not_entered_C557281(wifi_dut, nrf_ble_client, sl_collections, ble_client):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods timeout occure if passkey is not entered (Initiator:KeyboardOnly Responder: Displayonly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, error_code_expected="0x4b04", smp_io_capability=2, passkey_state=2,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


def test_ble_smp_anthencation_verify_passkey_not_enterred_C557282(wifi_dut, nrf_ble_client, sl_collections, ble_client):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods timeout occure if passkey is not entered (Initiator:KeyboardDisplay Responder: DisplayYes No"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, error_code_expected="0x4b04", smp_io_capability=4, passkey_state=2,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

def test_ble_smp_anthencation_verify_passkey_entered_incorrectly_C557283(wifi_dut, nrf_ble_client, sl_collections, ble_client):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods fail with "confirm value failed" if passkey is not entered correctly (Initiator:KeyboardOnly Responder: DisplayOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client,  ble_client=ble_client, error_code_expected="0x4b04",  smp_io_capability=2, passkey_state=1,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


def test_ble_smp_anthencation_verify_passkey_entered_incorrectly_C557284(wifi_dut, nrf_ble_client, sl_collections, ble_client):
    """SMP Anthentication: Verify Passkey Display/Passkey Entry Auth methods fail with "confirm value failed" if passkey is not entered correctly (Initiator:KeyboardOnly Responder: KeyboardOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,  error_code_expected="0x4b01", smp_io_capability=2, passkey_state=1,  cap_on_dongle = NRFBLEIoCapabilities.KEYBOARD_ONLY,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


def test_ble_smp_anthencation_verify_passkey_not_entered_C557292(wifi_dut, nrf_ble_client, sl_collections, ble_sniffer, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: No action][Action Order: Peripheral][Expected Behaviour: SMP Timeout]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, error_code_expected="0x4b04", check_error=True, smp_io_capability=1, passkey_state=1,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

def test_ble_smp_anthencation_verify_passkey_entered_incorrectly_C557288(wifi_dut, nrf_ble_client, sl_collections, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: No action][Action Order: Peripheral][Expected Behaviour: SMP Timeout]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, error_code_expected="0x4b0c", smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_passkey_entered_C557285(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify combo: [Numeric Comparison][Peripheral Action: Accept][Central Action: Accept][Action Order: Central, Peripheral][Expected Behaviour: Bonding Completes]"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557285",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)



@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_passkey_entered_C557256(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the NumericCompairision Pairing Method for DUT as Peripheral"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557256",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_verify_dh_key_check_exchange_C557257(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify DH key check exchanges for DUT as Peripheral"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557257", smp_io_capability=0, nrf_connect_to_dut=False, ble_connect_from_raspi=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
def test_ble_smp_anthencation_verify_fields_of_pairing_request_C557253(wifi_dut, nrf_ble_client, ble_sniffer, dut_capability, client_capability, pin_code, sl_collections, ble_client):
    """Verify the fields of Pairing_Request LL initiated by Initiator in OTA log"""
    t = ""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client,  ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code, capture_filename="frontline_capture_C557253", smp_io_capability=0, pair_connect_from_dut=True, nrf_connect_to_dut=False)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),
    ],
)
def test_ble_smp_anthencation_passkey_verify_pairing_response_C557254(wifi_dut, nrf_ble_client, ble_sniffer, dut_capability, client_capability, pin_code, sl_collections, ble_client):
    """Verify the Responder key distribution fields in Pairing_Request in OTA log"""
    t = ""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client,  ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code, capture_filename="frontline_capture_C557254", smp_io_capability=0, pair_connect_from_dut=True, nrf_connect_to_dut=False)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
def test_ble_smp_anthencation_verify_responder_key_fields_C557255(wifi_dut, nrf_ble_client, ble_sniffer, dut_capability, client_capability, pin_code, sl_collections, ble_client):
    """Verify the fields of Pairing_Response LL in OTA log"""
    t = ""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client,  ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code, capture_filename="frontline_capture_C557255", smp_io_capability=0, pair_connect_from_dut=True, nrf_connect_to_dut=False)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_pairing_with_dut_entered_C557258(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify SMP Pairing of DUT with nrf Dongle with IO Capability as Display YES/NO(0X01) on both sides"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client,  ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557258",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO,  nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability,  pin_code",
    [
        (0,  "-1"),
    ],
)
def test_ble_smp_disconnection_failure_C557265(wifi_dut, nrf_ble_client, ble_sniffer, dut_capability, pin_code, sl_collections, ble_client):
    """Verify BLE disconnect on authentication failure """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client,  ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=True, sniffer_check=False, layer_name="SMP", dut_capability=dut_capability, pin_code=pin_code, capture_filename="frontline_capture_C557265", capability_on_remote="KeyboardOnly",smp_io_capability=0, ble_connect_from_raspi=True, nrf_connect_to_dut=False, error_code_expected="0x4b04")
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_passkey_entered_C557256(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the NumericCompairision Pairing Method for DUT as Peripheral"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557256",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_lesc_non_lesc_C557263(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the pairing between LESC supported DUT(Central ) and Non-LESC supported nRF Dongle"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557263",  smp_io_capability=1, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True,  lesc_disabled=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
def test_ble_smp_anthencation_encryption_initiation_C557277(wifi_dut, nrf_ble_client, ble_sniffer, dut_capability, client_capability, pin_code, sl_collections, ble_client):
    """verify Encryption initiation by DUT as Central"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client,  ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code, capture_filename="frontline_capture_C557277", smp_io_capability=0, pair_connect_from_dut=True, nrf_connect_to_dut=False)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_mitm_bit_disabled_C557259(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the auth flag is proper when the MITM flaf is set to FALSE"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, smp_mtim=0, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557259",  smp_io_capability=1, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True,  mtim_disabled=True, local_oob_flag=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_justworks_pairing_method_C557261(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the JustWorks pairing method for DUT as Central"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557261",  smp_io_capability=0, passkey_state=0, cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True,  mtim_disabled=True, smp_mtim=0)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)



#-------------------------------------------------------------------------------#
#Public Address for DUT
#---------------------------------------------------------------------------------#
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_just_works_displayonly_on_both_sides_pairing_method_C663304(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """VVerify JustWorks Pairing method for IOCap , Initiator : DisplayOnly and Responder : DisplayOnly with public addr"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663304",  smp_io_capability=0, passkey_state=0,cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_just_works_pairing_method_Initiator_displayonly_responsder_displayyesno_C663309(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator: DisplayOnly and Responder: DisplayYesNo  with public addr"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663309",  smp_io_capability=1, passkey_state=0,cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_just_works_pairing_Initiator_displayonly_responder_NoInput_NoOutput_C663319(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : DisplayOnly and Responder : No Input No Output with public addr"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663319",  smp_io_capability=3, passkey_state=0,cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_ONLY,nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_just_works_pairing_Initiator_displayyesorno_responder_displayonly_C663305(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : Display yes/no and Responder : DisplayOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663305",  smp_io_capability=0, passkey_state=0,cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_YESNO,nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.skip()
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_just_works_pairing_Initiator_displayyesorno_responder_displayyesno_C663310(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : Display yes/no and Responder : Display yes/no"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663310",  smp_io_capability=1, passkey_state=0,cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_YESNO,nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_just_works_pairing_Initiator_displayyesorno_responder_no_input_no_output_C663320(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : DisplayyesorNo and Responder : No Input No Output"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663320",  smp_io_capability=3, passkey_state=0,cap_on_dongle="DisplayYesOrNo",nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_just_works_pairing_Initiator_no_input_no_output_responder_no_input_no_output_C663322(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : No Input No Output and Responder : No Input No Output"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663322",  smp_io_capability=3, passkey_state=0,cap_on_dongle=NRFBLEIoCapabilities.NONE,nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_just_works_pairing_Initiator_noInputNoOutput_responder_displayyesno_C663312(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify JustWorks Pairing method for IOCap, Initiator : No Input No Output and Responder : Display yes/no"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663312",  smp_io_capability=1, passkey_state=0,cap_on_dongle=NRFBLEIoCapabilities.NONE,nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_just_works_pairing_initiator_No_Input_No_Output_responder_displayonly_C663307(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify PasskeyEntry Pairing method for IOCap, Initiator : No Input No Output ,and Responder : DisplayOnly"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663307",  smp_io_capability=0, passkey_state=0,cap_on_dongle=NRFBLEIoCapabilities.NONE, nrf_dongle_as_master=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_passkey_declined_C557287(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the connect, disconnect and reconnect(with bond info) for DUT as Central with paring method Just works"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=True, error_code_expected="0x4b0c", sniffer_check=False, layer_name="SMP", capture_filename="frontline_capture_C557287",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, testcase_no=557287)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_passkey_decline_C557289(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the connect, disconnect and reconnect(with bond info) for DUT as Central with paring method Just works"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=True, error_code_expected="0x4b0c", sniffer_check=False, layer_name="SMP", capture_filename="frontline_capture_C557289",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, testcase_no=557287)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_passkey_decline_C557290(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the connect, disconnect and reconnect(with bond info) for DUT as Central with paring method Just works"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=True, error_code_expected="0x4b0c", sniffer_check=False, layer_name="SMP", capture_filename="frontline_capture_C557290",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, delay=25,testcase_no=557287)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_ble_smp_anthencation_verify_passkey_declined_C557291(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify the connect, disconnect and reconnect(with bond info) for DUT as Central with paring method Just works"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=True, error_code_expected="0x4b08", sniffer_check=False, layer_name="SMP", capture_filename="frontline_capture_C557291",  smp_io_capability=1, passkey_state=0,  cap_on_dongle = NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_just_works_pairing_DUT_master_with_random_address_C557267(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify just works pairing method for DUT as master with random address"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", smp_io_capability=0, passkey_state=0, cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_ONLY, nrf_connect_to_dut=True, random_addr_on_dut=True, capture_filename="frontline_capture_C557267")
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_just_works_pairing_method_DUT_as_peripheral_C663376(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client, dut_capability, client_capability, pin_code):
    """VVerify JustWorks Pairing method for IOCap , Initiator : DisplayOnly and Responder : DisplayOnly with public addr"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C663376",  dut_capability=dut_capability, smp_io_capability=0, pin_code=pin_code, client_capability=client_capability, passkey_state=0, connect_from_raspi_passkey_entry=True, capability_on_remote="KeyboardOnly")
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_Encryption_initiation_DUT_as_central_with_random_addr_C557278(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client, dut_capability, client_capability, pin_code):
    """Verify Encryption pause resume for DUT as central """
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557278", dut_capability=dut_capability, smp_io_capability=0, smp_sc=1, passkey_state=0, pin_code=pin_code, client_capability=client_capability, pair_connect_from_dut=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_numeric_comparision_SMP_timeout_C557293(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client):
    """Verify just works pairing method for DUT as master with random address"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=True, error_code_expected="0x4b0c", sniffer_check=False, layer_name="SMP", smp_io_capability=1, passkey_state=0, cap_on_dongle=NRFBLEIoCapabilities.DISPLAY_YESNO, nrf_connect_to_dut=True, capture_filename="frontline_capture_C557293")
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_passkey_entry_pairing_method_for_DUT_as_peripheral_C557266(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client, dut_capability, client_capability, pin_code):
    """Verify Encryption initiated by DUT as peripheral"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557266", dut_capability=dut_capability, smp_io_capability=0, smp_sc=1, passkey_state=0, pin_code=pin_code, client_capability=client_capability, connect_from_raspi_passkey_entry=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_Encryption_initiated_by_DUT_as_peripheral_C557274(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client, dut_capability, client_capability, pin_code):
    """Verify Encryption initiated by DUT as peripheral"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557274", dut_capability=dut_capability, smp_io_capability=0, smp_sc=1, passkey_state=0, pin_code=pin_code, client_capability=client_capability, connect_from_raspi_passkey_entry=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
def test_ble_smp_anthencation_encryption_initiation_C557277(wifi_dut, nrf_ble_client, ble_sniffer, dut_capability, client_capability, pin_code, sl_collections, ble_client):
    """verify Encryption initiation by DUT as Central"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, nrf_ble_client=nrf_ble_client,  ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code, capture_filename="frontline_capture_C557277", smp_io_capability=0, pair_connect_from_dut=True, nrf_connect_to_dut=False)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_passkey_entry_pairing_method_by_DUT_as_peripheral_with_random_addr_C557269(wifi_dut, nrf_ble_client, ble_sniffer, sl_collections, ble_client, dut_capability, client_capability, pin_code):
    """Verify Encryption initiated by DUT as peripheral"""
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client, ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, layer_name="SMP", capture_filename="frontline_capture_C557269", dut_capability=dut_capability, smp_io_capability=0, smp_sc=1, passkey_state=0, pin_code=pin_code, client_capability=client_capability, connect_from_raspi_passkey_entry=True, random_addr_on_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)