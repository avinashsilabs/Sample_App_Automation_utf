import re
import pytest
import time
import os
from utf.interfaces.bluetooth.nrf_blatann import (
    NRFBLEIoCapabilities, NRFBLEPeerDevAddrTypes
)
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
    def __init__(self, wifi_dut=None, ble_client=None, ble_sniffer=None, error_code_expected=None, check_error=True, sniffer_check=False, layer_name=None,
                 capture_filename=None, smp_io_capability=None, encrypted_file=False, smp_auth_bond=1, smp_mtim=1, smp_enc_key=1, passkey_state=None, smp_sc=1, cap_on_dongle=None, delay=0, nrf_connect_to_dut=False,
                 ble_connect_from_raspi=False, pair_connect_from_dut=False, pin_code=None, client_capability=None, dut_capability=None, capability_on_remote=None, mtim_disabled=False, lesc_disabled=False,
                 reconnection_from_remote=False, powersave=True, random_addr_on_dut=False, local_oob_flag=False, nrf_dongle_as_master=False, testcase_no=None, passkey_entry=False, ble_dut_address=None, ble_client_address=None, connect_from_raspi_passkey_entry=False, linkkey_not_required=True, iteration_count=10, max_retries=3):
        super().__init__()
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
        self.passkey_entry = passkey_entry
        self.ble_dut_address = ble_dut_address
        self.connect_from_raspi_passkey_entry = connect_from_raspi_passkey_entry
        self.ble_client_address = ble_client_address
        self.linkkey_not_required = linkkey_not_required
        self.max_retries = max_retries
        self.iteration_count=iteration_count


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

        if self.smp_io_capability == 0x00:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> DisplayOnly")
        elif self.smp_io_capability == 0x01:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> Display yes or no")
        elif self.smp_io_capability == 0x02:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> keyboardOnly")
        elif self.smp_io_capability == 0x03:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> No Input No output")
        else:
            logger().info(f"Setting IO capability on dut: 0x0{self.smp_io_capability} --> Keyboarddisplay")

        if self.connect_from_raspi_passkey_entry:
            for i in range(10):
                max_retries = 3  # Maximum number of retries for the process
                for retry in range(max_retries):
                    try:
                        logger().info(f"Attempt {retry + 1} for BLE pairing process, Iteration {i + 1}...")

                        if self.random_addr_on_dut:
                            logger().info("Set DUT in advertise mode with random")
                            self.wifi_dut.interfaces.wifi.ble_start_advertising(own_addr_type=1, ble_addr_type=1)
                        else:
                            logger().info("Set DUT in advertise mode")
                            self.wifi_dut.interfaces.wifi.ble_start_advertising()

                        # Start BLE client scan
                        self.ble_client.interfaces.bluetooth.close()
                        logger().info("Start SMP scan from the remote device")
                        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                            bt_dut_address=self.ble_dut_address,
                            capability=self.client_capability,
                            pin_code=self.pin_code
                        )
                        assert self.ble_client_address, "Failed to initiate BLE in remote device"

                        if self.powersave:
                            logger().info("Enabling the power save modes")
                            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

                        time.sleep(5)

                        logger().info("Stop scanning...")
                        self.ble_client.interfaces.bluetooth.stop_scanning()

                        logger().info("Check if the DUT is listed...")
                        self.ble_client.interfaces.bluetooth.get_devices()

                        def connect():
                            logger().info("Connecting to the DUT with MAC address...")
                            self.ble_client.interfaces.bluetooth.pair_and_connect(self.ble_dut_address, timeout=10)

                        time.sleep(3)  # Give it time to connect

                        # Create and start the connect thread
                        connect_thread = threading.Thread(target=connect)
                        connect_thread.start()
                        time.sleep(10)
                        tw = Stopwatch()

                        pass_key_found = False
                        while tw.elapsed_sec < 120:
                            events = self.wifi_dut.interfaces.wifi.get_async_events()
                            for event in events:
                                logger().info(f"********{event.event_data}*************")
                                if "passkey" in event.event_data:
                                    passkey = re.findall(r"(?<=passkey: )\d*", event.event_data)
                                    if passkey[0] is not None:
                                        pass_key_value = str(passkey[0])
                                        logger().info(f"Passkey: {pass_key_value}")
                                        self.ble_client.interfaces.bluetooth.set_pin(pass_key_value)
                                        pass_key_found = True
                                        break
                                    time.sleep(1)
                            if pass_key_found:
                                break

                        time.sleep(60)
                        try:
                            logger().info(f"********************************")
                            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                            state_int = int(state) if state.isdigit() else -1
                            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
                            logger().info(f"BLE device is in connected state.")
                            logger().info(f"********************************")

                        except Exception as error:
                            logger().error(f"An unexpected error occurred: {error}")
                            # Handle unexpected exceptions
                            raise
                        finally:
                            logger().info("Performing cleanup ")
                            if state_int == 1:
                                self.wifi_dut.interfaces.wifi.ble_stop_advertising()

                        logger().info("Disconnecting the BT host....")
                        self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
                        time.sleep(10)

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
                            link_key_data = link_key
                            link_key_value = re.split("--", link_key_data)
                            link_key_re = re.split("$", link_key_value[0])
                            link_key = ""
                            for value in link_key_re[0]:
                                if value.isalnum():
                                    link_key = link_key + value
                            logger().info(f"Link Key Extracted: {link_key}")
                            logger().info(f"Link Key Length: {len(link_key)}")
                            assert len(link_key) > 0, "Link key is not extracted"

                        ble_dut_address_hex = re.split(":", self.ble_dut_address)
                        ble_client_address_hex = re.split(":", self.ble_client_address)
                        master_address = "0x"
                        for hex_data_part in ble_dut_address_hex:
                            master_address = master_address + hex_data_part
                        slave_address = "0x"
                        for hex_data_part in ble_client_address_hex:
                            slave_address = slave_address + hex_data_part
                        self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
                        time.sleep(30)
                        if link_key != "":
                            self.ble_sniffer.interfaces.sniffer.add_link_key(link_key.upper(), master_address,
                                                                             slave_address)
                        logger().info(f"*********Iteration :{i + 1}")
                        break  # Exit retry loop if successful

                    except AssertionError as e:
                        logger().warning(f"Attempt {retry + 1} failed: {e}. Retrying...")
                        if retry == max_retries - 1:
                            logger().error("Maximum retries reached. BLE pairing process failed.")
                            raise e
                        time.sleep(5)  # Wait before retrying # Wait before retrying
        if self.ble_connect_from_raspi:
            if self.random_addr_on_dut:
                  logger().info("Set DUT in advertise mode with random")
                  self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_addr_type=1)
            else:
                logger().info("Set DUT in advertise mode")
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info("Start smp scan from the remote device")
            logger().info(f"Capability on remote: {self.capability_on_remote}")
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.ble_dut_address, capability=self.capability_on_remote)
            assert ble_client_address, "failed to initiate ble in remote device"

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

        if self.pair_connect_from_dut:
            link_key_list = []
            self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=0, smp_io_cap=self.smp_io_capability,
                                                           smp_auth_req_bonding=self.smp_auth_bond,
                                                           smp_auth_req_mitm=self.smp_mtim,
                                                           smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
                                                           smp_local_oob_data_flag_not_present=0,
                                                           smp_enc_key=1, smp_id_key=0,
                                                           smp_sign_key=0)
            self.ble_client_address = ""
            self.wifi_dut.interfaces.wifi.bt_set_local_name("BLE_UNIFIED_DEMO")
            for i in range(self.iteration_count):
                for retry in range(self.max_retries):
                    try:
                        logger().info(f"Attempt {retry + 1} for pairing and extracting link key...")
                        # Start BLE client
                        self.ble_client.interfaces.bluetooth.close()
                        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                            pin_code=self.pin_code, capability=self.client_capability, bt_dut_address=self.ble_dut_address
                        )
                        assert self.ble_client_address is not None
                        time.sleep(1)
                        # Start scanning and connect to BLE client
                        self.wifi_dut.interfaces.wifi.ble_start_scanning(
                            ble_client_address=self.ble_client_address, timeout=60
                        )
                        if self.powersave:
                            logger().info("Enabling the power save modes")
                            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
                        time.sleep(5)
                        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
                        def connect():
                            self.wifi_dut.interfaces.wifi.ble_connect(
                                ble_remote_dev_address=self.ble_client_address, timeout=120
                            )

                        t = threading.Thread(target=connect)
                        t.start()
                        time.sleep(2)
                        tw = Stopwatch()
                        pass_key_found = False
                        while tw.elapsed_sec < 300:
                            events = self.wifi_dut.interfaces.wifi.get_async_events()
                            for event in events:
                                if "passkey" in event.event_data:
                                    logger().info(f"*********************{event.event_data}*")
                                    passkey = re.findall(r"passkey: ([\d]*)", event.event_data)
                                    if passkey[0] is not None:
                                        pass_key_value = str(passkey[0])
                                        logger().info(f"passkey : {pass_key_value}")
                                        self.ble_client.interfaces.bluetooth.set_pin(pass_key_value)
                                        pass_key_found = True
                                        break
                            if pass_key_found:
                                break
                            time.sleep(2)
                        time.sleep(60)
                        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                        state_int = int(state) if state.isdigit() else -1
                        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
                        if t is not None:
                            t.join()
                        if state_int == 8:
                            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)

                        # Extract Link Key
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
                        if len(link_key) > 34:
                            link_key_data = link_key
                            link_key_value = re.split("--", link_key_data)
                            link_key_re = re.split("$", link_key_value[0])
                            link_key = ""
                            for value in link_key_re[0]:
                                if value.isalnum():
                                    link_key = link_key + value
                            logger().info(f"Link Key Extracted:{link_key}")
                            logger().info(f"Link Key Length:{len(link_key)}")
                            assert len(link_key) > 0, "Link key is not extracted"
                            break  # Exit retry loop if link key is successfully extracted
                        elif len(link_key)==34:
                            break
                        else:
                            logger().warning(f"Link Key Extraction Failed on Attempt {retry + 1}. Retrying...")
                            if retry == self.max_retries - 1:
                                assert False, "Failed to extract link key after maximum retries."

                    except Exception as e:
                        logger().error(f"Error during pairing attempt {retry + 1}: {e}")
                        if retry == max_retries - 1:
                            raise  # Re-raise the exception if maximum retries are reached
                ble_dut_address_hex = re.split(":", self.ble_dut_address)
                ble_client_address_hex = re.split(":", self.ble_client_address)
                master_address = "0x"
                for hex_data_part in ble_dut_address_hex:
                    master_address = master_address + hex_data_part
                slave_address = "0x"
                for hex_data_part in ble_client_address_hex:
                    slave_address = slave_address + hex_data_part
                self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
                time.sleep(30)
                if link_key != "":
                    self.ble_sniffer.interfaces.sniffer.add_link_key(link_key.upper(), master_address,
                                                                     slave_address)
                logger().info(f"*********Iteration :{i + 1}")

        # if self.pair_connect_from_dut:
        #     link_key_list = []
        #     self.wifi_dut.interfaces.wifi.ble_set_cap_data(remote_addr_type=0, smp_io_cap=self.smp_io_capability,
        #                                                    smp_auth_req_bonding=self.smp_auth_bond,
        #                                                    smp_auth_req_mitm=self.smp_mtim,
        #                                                    smp_auth_req_sc=self.smp_sc, smp_max_enc_key_size=16,
        #                                                    smp_local_oob_data_flag_not_present=0,
        #                                                    smp_enc_key=1, smp_id_key=0,
        #                                                    smp_sign_key=0)
        #     self.ble_client_address = ""
        #     self.wifi_dut.interfaces.wifi.bt_set_local_name("BLE_UNIFIED_DEMO")
        #     for i in range(10):
        #         # self.ble_sniffer.interfaces.sniffer.init_sniffer()
        #         # self.ble_sniffer.interfaces.sniffer.start_capture(capture_file=self.capture_filename)
        #         # Start ble client
        #         self.ble_client.interfaces.bluetooth.close()
        #         self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
        #             pin_code=self.pin_code, capability=self.client_capability, bt_dut_address=self.ble_dut_address
        #         )
        #         assert self.ble_client_address is not None
        #         time.sleep(1)
        #         # Start scanning and connect to ble client
        #         self.wifi_dut.interfaces.wifi.ble_start_scanning(
        #             ble_client_address=self.ble_client_address, timeout=60
        #         )
        #         self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        #
        #         def connect():
        #             self.wifi_dut.interfaces.wifi.ble_connect(
        #                 ble_remote_dev_address=self.ble_client_address, timeout=120
        #             )
        #
        #         t = threading.Thread(target=connect)
        #         t.start()
        #         time.sleep(2)
        #         tw = Stopwatch()
        #         pass_key_found = False
        #         while tw.elapsed_sec < 120:
        #             events = self.wifi_dut.interfaces.wifi.get_async_events()
        #             for event in events:
        #                 # if event.event_type == AsyncEventIdentifiers.BLE_SC_PASSKEY:
        #                 #     logger().info(f"**********************")
        #                 if "passkey" in event.event_data:
        #                     logger().info(f"*********************{event.event_data}*")
        #                     passkey = re.findall(r"passkey: ([\d]*)", event.event_data)
        #                     if passkey[0] is not None:
        #                         pass_key_value = str(passkey[0])
        #                         logger().info(f"passkey : {pass_key_value}")
        #                         self.ble_client.interfaces.bluetooth.set_pin(pass_key_value)
        #                         pass_key_found = True
        #                         break
        #             if pass_key_found:
        #                 break
        #             time.sleep(1)
        #
        #         time.sleep(60)
        #
        #         state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        #         state_int = int(state) if state.isdigit() else -1
        #         assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        #         if t is not None:
        #             t.join()
        #         if state_int == 8:
        #             self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        #         tw = Stopwatch()
        #         link_key = ""
        #         while tw.elapsed_sec < 120:
        #             events = self.wifi_dut.interfaces.wifi.get_async_events()
        #             for event in events:
        #                 if "link_key" in event.event_data:
        #                     event_data = event.event_data
        #                     link_key_data = re.findall("link_key::.*", event_data)
        #                     link_key_data_str = re.split(":<", link_key_data[0])
        #                     link_key_data_hex = re.split(":", link_key_data_str[0])
        #                     link_key = "0x"
        #                     for hex_data_part in link_key_data_hex:
        #                         hex_data_part = hex_data_part.replace(" ", "")
        #                         if len(hex_data_part) == 1:
        #                             hex_data_part = '0' + hex_data_part
        #                         link_key = link_key + hex_data_part
        #                 else:
        #                     continue
        #             if link_key:
        #                 break
        #         link_key = link_key.replace(" ", "")
        #         link_key = link_key.replace("link_key", "")
        #         if self.ble_connect_from_raspi or self.pair_connect_from_dut or len(link_key) > 34:
        #             link_key_data = link_key
        #             link_key_value = re.split("--", link_key_data)
        #             link_key_re = re.split("$", link_key_value[0])
        #             link_key = ""
        #             for value in link_key_re[0]:
        #                 if value.isalnum():
        #                     link_key = link_key + value
        #             logger().info(f"Link Key Extracted:{link_key}")
        #             logger().info(f"Link Key Extracted:{len(link_key)}")
        #             assert len(link_key) > 0, "Link key is not extracted"
        #             # link_key_list = link_key_list.append(link_key)
        #             # logger().info(f"Link Key list:{link_key_list}")
        #         ble_dut_address_hex = re.split(":", self.ble_dut_address)
        #         ble_client_address_hex = re.split(":", self.ble_client_address)
        #         master_address = "0x"
        #         for hex_data_part in ble_dut_address_hex:
        #             master_address = master_address + hex_data_part
        #         slave_address = "0x"
        #         for hex_data_part in ble_client_address_hex:
        #             slave_address = slave_address + hex_data_part
        #         self.ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address])
        #         time.sleep(30)
        #         if link_key != "":
        #             self.ble_sniffer.interfaces.sniffer.add_link_key(link_key.upper(), master_address,
        #                                                              slave_address)
        #         logger().info(f"*********Iteration :{i + 1}")

        if self.encrypted_file:
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            if state_int == 8:
                self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
                time.sleep(10)
            self.ble_sniffer.interfaces.sniffer.stop_capture()


        if self.sniffer_check  and self.linkkey_not_required:
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
                if self.random_addr_on_dut:
                    self.ble_sniffer.interfaces.sniffer.select_bt_devices(
                        [slave_address + f" type=random"])
                else:
                    self.ble_sniffer.interfaces.sniffer.select_bt_devices(
                        [master_address, slave_address + f" type=random"])
                    time.sleep(30)
                if link_key != "":
                    self.ble_sniffer.interfaces.sniffer.add_link_key(link_key.upper(), master_address,
                                                                     slave_address + f" type=random")
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
        time.sleep(180)
        logger().info("Checking connection status of BLE after 180 secs(3minutes")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(10)
        # self.sniffer_file_export()
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
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_master_C667600(wifi_dut, ble_sniffer, sl_collections, ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667600", smp_io_capability=dut_capability,  dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code, pair_connect_from_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"*****{ble_obj.sniffer_data_df_2['Role'].astype(str).fillna('Nan')}******")
        logger().info(f"**********{ble_obj.sniffer_data_df_2['Signature Key'].astype(str).fillna('Nan')}***********")
        data = ble_obj.sniffer_data_df_2['Signature Key'].astype(str).fillna('Nan')
        sign_keys = []
        for i in data:
            if i != "nan":
                sign_keys.append(i)
        logger().info(f"************sign keys: {sign_keys}*************")
        logger().info(f"************Number of sign keys in the capture: {len(sign_keys)}*************")
        # assert len(sign_keys) == 20, f"sign keys missed in the capture"
        unique_elements = set()
        for element in sign_keys:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        logger().info(f"*********different sign keys exists in csv file**********")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)




@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_master_C667601(wifi_dut, ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667601", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          pair_connect_from_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"***********{ble_obj.sniffer_data_df_2['DHKey'].astype(str).fillna('Nan')}*********************")
        data = ble_obj.sniffer_data_df_2['DHKey'].astype(str).fillna(' ')
        dh_packets = []
        for i in data:
            if i != "nan":
                dh_packets.append(i)
        logger().info(f"************dh keys: {dh_packets} ********************")
        logger().info(f"************Number of dh keys in the capture : {len(dh_packets)} ********************")
        # assert len(dh_packets) == 20, f"dh keys missed in the capture"
        unique_elements = set()
        for element in dh_packets:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        logger().info(f"*********different dh keys exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_master_C667602(wifi_dut, ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True,linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667602", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          pair_connect_from_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"***********{ble_obj.sniffer_data_df_2['Confirm Value'].astype(str).fillna('Nan')}*********************")
        data = ble_obj.sniffer_data_df_2['Confirm Value'].astype(str).fillna(' ')
        pairing_confirm_pkts = []
        for i in data:
            if i != "nan":
                pairing_confirm_pkts.append(i)
        logger().info(f"************pairing_confirm_pkt keys: {pairing_confirm_pkts} ********************")
        logger().info(f"************Number of pairing confirm packets in the capture : {len(pairing_confirm_pkts)} ********************")
        # assert len(pairing_confirm_pkts) == 400, f"pairing confirm packets missed in the capture"
        unique_elements = set()
        for element in pairing_confirm_pkts:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        logger().info(f"*********different pairing confirm packets exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_master_C667603(wifi_dut,  ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True,linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667603", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          pair_connect_from_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"***********{ble_obj.sniffer_data_df_2['Random Value'].astype(str).fillna('Nan')}*********************")
        data = ble_obj.sniffer_data_df_2['Random Value'].astype(str).fillna(' ')
        pairing_random_pkts = []
        for i in data:
            if i != "nan":
                pairing_random_pkts.append(i)
        logger().info(f"************pairing_random_pkt keys: {pairing_random_pkts} ********************")
        logger().info(f"************Number of pairing random packets in the capture : {len(pairing_random_pkts)} ********************")
        # assert len(pairing_random_pkts) == 400, f"pairing random packets keys missed in the capture"
        unique_elements = set()
        for element in pairing_random_pkts:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        logger().info(f"*********different pairing random packets exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_master_C667604(wifi_dut, ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,  ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667604", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          pair_connect_from_dut=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"***********{ble_obj.sniffer_data_df_1['Session Key Identifier - Peripheral (SKD_P)'].astype(str).fillna('Nan')}*********************")
        logger().info(f"***********{ble_obj.sniffer_data_df_1['Initialization Vector - Peripheral (IV_P)'].astype(str).fillna('Nan')}*********************")
        session_key_data = ble_obj.sniffer_data_df_1['Session Key Identifier - Peripheral (SKD_P)'].astype(str).fillna(' ')
        vector_data = ble_obj.sniffer_data_df_1['Initialization Vector - Peripheral (IV_P)'].astype(str).fillna(' ')
        session_key_identifier_data = []
        Initialization_vector = []
        for i in session_key_data:
            if i != "nan":
                session_key_identifier_data.append(i)
        for j in vector_data:
            if j != "nan":
                Initialization_vector.append(j)
        logger().info(f"************session key identifer in encryption response: {session_key_identifier_data} ********************")
        logger().info(f"************Initialization Vector in encryption response: {Initialization_vector} ********************")
        logger().info(f"************Number of session key identifer in encryption response packets in the capture : {len(session_key_identifier_data)} ********************")
        logger().info(f"************Number of Initialization Vector id in encryption response packets in the capture : {len(Initialization_vector)} ********************")
        # assert len(session_key_identifier_data) == 10, f"session key identifer in encryption response packets keys missed in the capture"
        # assert len(Initialization_vector) == 10, f"Initialization Vector id in encryption response packets keys missed in the capture"
        unique_elements = set()
        unique_elements1 = set()
        for element in session_key_identifier_data:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        for element in Initialization_vector:
            if element in unique_elements1:
                assert False, f"same number exists"
            unique_elements1.add(element)
            assert True
        logger().info(f"*********different session key identifer in encryption response packets exists in csv file**********")
        logger().info(f"*********different Initialization_vector in encryption response packets exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_slave_C667595(wifi_dut,  ble_sniffer, sl_collections, ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,  ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True,linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667595", smp_io_capability=dut_capability,  dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,  connect_from_raspi_passkey_entry=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"*****{ble_obj.sniffer_data_df_2['Role'].astype(str).fillna('Nan')}******")
        logger().info(f"**********{ble_obj.sniffer_data_df_2['Signature Key'].astype(str).fillna('Nan')}***********")
        data = ble_obj.sniffer_data_df_2['Signature Key'].astype(str).fillna('Nan')
        sign_keys = []
        for i in data:
            if i != "nan":
                sign_keys.append(i)
        logger().info(f"************sign keys: {sign_keys}*************")
        logger().info(f"************Number of sign keys in the capture: {len(sign_keys)}*************")
        # assert len(sign_keys) == 20, f"sign keys missed in the capture"
        unique_elements = set()
        for element in sign_keys:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        logger().info(f"*********different sign keys exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)




@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_slave_C667596(wifi_dut, ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut,  ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True,linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667596", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          connect_from_raspi_passkey_entry=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"***********{ble_obj.sniffer_data_df_2['DHKey'].astype(str).fillna('Nan')}*********************")
        data = ble_obj.sniffer_data_df_2['DHKey'].astype(str).fillna(' ')
        dh_packets = []
        for i in data:
            if i != "nan":
                dh_packets.append(i)
        logger().info(f"************dh keys: {dh_packets} ********************")
        logger().info(f"************Number of dh keys in the capture : {len(dh_packets)} ********************")
        # assert len(dh_packets) == 20, f"dh keys missed in the capture"
        unique_elements = set()
        for element in dh_packets:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        logger().info(f"*********different dh keys exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_slave_C667597(wifi_dut, ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, linkkey_not_required=False,layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667597", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          connect_from_raspi_passkey_entry=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"***********{ble_obj.sniffer_data_df_2['Confirm Value'].astype(str).fillna('Nan')}*********************")
        data = ble_obj.sniffer_data_df_2['Confirm Value'].astype(str).fillna(' ')
        pairing_confirm_pkts = []
        for i in data:
            if i != "nan":
                pairing_confirm_pkts.append(i)
        logger().info(f"************pairing_confirm_pkt keys: {pairing_confirm_pkts} ********************")
        logger().info(f"************Number of pairing confirm packets in the capture : {len(pairing_confirm_pkts)} ********************")
        # assert len(pairing_confirm_pkts) == 400, f"pairing confirm packets missed in the capture"
        unique_elements = set()
        for element in pairing_confirm_pkts:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        logger().info(f"*********different pairing confirm packets exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_slave_C667598(wifi_dut, ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True, linkkey_not_required=False,layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667598", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          connect_from_raspi_passkey_entry=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"***********{ble_obj.sniffer_data_df_2['Random Value'].astype(str).fillna('Nan')}*********************")
        data = ble_obj.sniffer_data_df_2['Random Value'].astype(str).fillna(' ')
        pairing_random_pkts = []
        for i in data:
            if i != "nan":
                pairing_random_pkts.append(i)
        logger().info(f"************pairing_random_pkt keys: {pairing_random_pkts} ********************")
        logger().info(f"************Number of pairing random packets in the capture : {len(pairing_random_pkts)} ********************")
        # assert len(pairing_random_pkts) == 400, f"pairing random packets keys missed in the capture"
        unique_elements = set()
        for element in pairing_random_pkts:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        logger().info(f"*********different pairing random packets exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pairing_reconnection_dut_as_slave_C667599(wifi_dut,  ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True,linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C667599", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          connect_from_raspi_passkey_entry=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(
            f"***********{ble_obj.sniffer_data_df_1['Session Key Identifier - Peripheral (SKD_P)'].astype(str).fillna('Nan')}*********************")
        logger().info(
            f"***********{ble_obj.sniffer_data_df_1['Initialization Vector - Peripheral (IV_P)'].astype(str).fillna('Nan')}*********************")
        session_key_data = ble_obj.sniffer_data_df_1['Session Key Identifier - Peripheral (SKD_P)'].astype(str).fillna(
            ' ')
        vector_data = ble_obj.sniffer_data_df_1['Initialization Vector - Peripheral (IV_P)'].astype(str).fillna(' ')
        session_key_identifier_data = []
        Initialization_vector = []
        for i in session_key_data:
            if i != "nan":
                session_key_identifier_data.append(i)
        for j in vector_data:
            if j != "nan":
                Initialization_vector.append(j)
        logger().info(
            f"************session key identifer in encryption response: {session_key_identifier_data} ********************")
        logger().info(
            f"************Initialization Vector in encryption response: {Initialization_vector} ********************")
        logger().info(
            f"************Number of session key identifer in encryption response packets in the capture : {len(session_key_identifier_data)} ********************")
        logger().info(
            f"************Number of Initialization Vector id in encryption response packets in the capture : {len(Initialization_vector)} ********************")
        # assert len(
        #     session_key_identifier_data) == 10, f"session key identifer in encryption response packets keys missed in the capture"
        # assert len(
        #     Initialization_vector) == 10, f"Initialization Vector id in encryption response packets keys missed in the capture"
        unique_elements = set()
        unique_elements1 = set()
        for element in session_key_identifier_data:
            if element in unique_elements:
                assert False, f"same number exists"
            unique_elements.add(element)
            assert True
        for element in Initialization_vector:
            if element in unique_elements1:
                assert False, f"same number exists"
            unique_elements1.add(element)
            assert True
        logger().info(
            f"*********different session key identifer in encryption response packets exists in csv file**********")
        logger().info(
            f"*********different Initialization_vector in encryption response packets exists in csv file**********")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (1, "KeyboardOnly", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_passkey_entry_pairing_Initiator_display_yes_no_responder_keyboard_only_C557260(wifi_dut,  ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    ble_obj = None
    try:
        ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                          ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True,linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                          capture_filename="frontline_capture_C557260", smp_io_capability=dut_capability,
                          dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                          pair_connect_from_dut=True, powersave=True, iteration_count=10, max_retries=1)
        ble_obj.start()
        ble_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.parametrize(
    "dut_capability, client_capability, pin_code",
    [
        (0, "KeyboardDisplay", "-8"),  # -8 to wait for pass_key
    ],
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_ble_smp_pair_unpair_C557252(wifi_dut,  ble_sniffer, sl_collections,
                                                        ble_client, dut_capability, client_capability, pin_code):
    bt_mon_log_file_name = (f"reports/test_ble_smp_pair_unpair_C557252"
                            f"{int(time.time())}.log")
    ble_obj = None
    try:
        with (BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name)):
            ble_obj = BLEFunc(wifi_dut=wifi_dut, ble_client=ble_client,
                              ble_sniffer=ble_sniffer, check_error=False, sniffer_check=True,linkkey_not_required=False, layer_name=["LE LL", "SMP"],
                              capture_filename="frontline_capture_C557252", smp_io_capability=dut_capability,
                              dut_capability=dut_capability, client_capability=client_capability, pin_code=pin_code,
                              pair_connect_from_dut=True, powersave=True, iteration_count=100, max_retries=1)
            ble_obj.start()
            ble_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        time.sleep(3)

    finally:
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
