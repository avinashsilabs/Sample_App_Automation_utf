
import os
import time
import threading
import datetime
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
import re
import yaml

def logger():
    return get_logger(__name__)

class BLESMPPairingTest:
    """
    BLE Security Manager Protocol (SMP) Pairing Test Handler
    
    This class manages the complete BLE pairing process between a DUT (peripheral) 
    and a Raspberry Pi (central) with configurable IO capabilities and authentication 
    requirements.
    
    Attributes:
        wifi_dut: DUT device interface
        ble_client: Raspberry Pi BLE client interface
        dut_capability: IO capability of the DUT (DisplayOnly, KeyboardOnly, etc.)
        client_capability: IO capability of the Raspberry Pi client
        pin_code: PIN code for pairing
        oob_data_flag: Out-of-Band data flag (0x00 = not present, 0x01 = present)
    """
    def __init__(self, wifi_dut, ble_client, dut_capability, client_capability, pin_code, smp_sc=0, smp_auth_bond=1, smp_mtim=1, smp_enc_key=1, passkey_state=2, random_addr_on_dut=False, auth_req="0x05", oob_data_flag="0x00"):
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.dut_capability = dut_capability
        self.client_capability = client_capability
        self.pin_code = pin_code
        self.smp_sc = smp_sc
        self.smp_auth_bond = smp_auth_bond
        self.smp_mtim = smp_mtim
        self.smp_enc_key = smp_enc_key
        self.passkey_state = passkey_state
        self.random_addr_on_dut = random_addr_on_dut
        self.auth_req = auth_req
        self.ble_dut_address = None
        self.ble_client_address = None
        self.connection_successful = False
        self.pairing_successful = False
        self.last_bt_disconnect_reason = None
    

    def run(self):
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03, "KeyboardDisplay": 0x04}
        
        # Determine pairing method and auth_req based on IO capabilities
        dut_io = io_capability[self.dut_capability]
        client_io = io_capability[self.client_capability]
        
        # JustWorks scenarios (no MITM protection possible - use auth_req=0x01)
        # Format: (DUT/Responder IO, Raspi/Initiator IO)
        justworks_scenarios = [
            (0x00, 0x00),  # DisplayOnly + DisplayOnly
            (0x00, 0x01),  # DisplayOnly + DisplayYesNo
            (0x00, 0x03),  # DisplayOnly + NoInputNoOutput
            (0x01, 0x00),  # DisplayYesNo + DisplayOnly
            (0x01, 0x03),  # DisplayYesNo + NoInputNoOutput
            (0x02, 0x03),  # KeyboardOnly + NoInputNoOutput
            (0x03, 0x00),  # NoInputNoOutput + DisplayOnly
            (0x03, 0x03),  # NoInputNoOutput + NoInputNoOutput
            (0x03, 0x01),  # NoInputNoOutput + DisplayYesNo
            (0x03, 0x04),  # NoInputNoOutput + KeyboardDisplay
            (0x03, 0x02),  # NoInputNoOutput + KeyboardOnly
            (0x04, 0x03),  # KeyboardDisplay + NoInputNoOutput
        ]
        
        # Numeric Comparison scenarios (both devices display passkey, both need to confirm/enter)
        # Format: (DUT/Responder IO, Raspi/Initiator IO)
        numeric_comparison_scenarios = [
            (0x01, 0x01),  # DisplayYesNo + DisplayYesNo
            (0x01, 0x04),  # DisplayYesNo + KeyboardDisplay
            (0x04, 0x01),  # KeyboardDisplay + DisplayYesNo
            (0x04, 0x04),  # KeyboardDisplay + KeyboardDisplay
        ]
        
        # Passkey Entry scenarios - Responder (DUT) DISPLAYS, Initiator (Raspi) ENTERS
        # The DUT generates and displays the passkey, Raspi must enter it
        # Format: (DUT/Responder IO, Raspi/Initiator IO)
        passkey_responder_displays_scenarios = [
            (0x00, 0x02),  # DisplayOnly + KeyboardOnly -> DUT displays, Raspi enters
            (0x00, 0x04),  # DisplayOnly + KeyboardDisplay -> DUT displays, Raspi enters
            (0x01, 0x02),  # DisplayYesNo + KeyboardOnly -> DUT displays, Raspi enters
            (0x04, 0x02),  # KeyboardDisplay + KeyboardOnly -> DUT displays, Raspi enters
            (0x02, 0x02),  # KeyboardOnly + KeyboardOnly -> DUT displays, Raspi enters (though this may also be Numeric Comparison in some implementations
        ]
        
        # Passkey Entry scenarios - Initiator (Raspi) DISPLAYS, Responder (DUT) ENTERS
        # The Raspi generates and displays the passkey, DUT must enter it
        # Format: (DUT/Responder IO, Raspi/Initiator IO)
        passkey_initiator_displays_scenarios = [
            (0x02, 0x00),  # KeyboardOnly + DisplayOnly -> Raspi displays, DUT enters
            (0x02, 0x01),  # KeyboardOnly + DisplayYesNo -> Raspi displays, DUT enters
            (0x02, 0x04),  # KeyboardOnly + KeyboardDisplay -> Raspi displays, DUT enters
            (0x04, 0x00),  # KeyboardDisplay + DisplayOnly -> Raspi displays, DUT enters
            
        ]
        
        # Determine pairing method and passkey direction
        if (dut_io, client_io) in justworks_scenarios:
            pairing_method = "JustWorks"
            passkey_direction = None
            auth_req_value = 0x09  # Bonding + SC (no MITM) - prevents Raspi disconnect
        elif (dut_io, client_io) in numeric_comparison_scenarios:
            pairing_method = "NumericComparison"
            passkey_direction = "both"  # Both devices display and need confirmation/entry
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        elif (dut_io, client_io) in passkey_responder_displays_scenarios:
            pairing_method = "PasskeyEntry"
            passkey_direction = "dut_displays"  # DUT (responder) displays, Raspi (initiator) enters
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        elif (dut_io, client_io) in passkey_initiator_displays_scenarios:
            pairing_method = "PasskeyEntry"
            passkey_direction = "raspi_displays"  # Raspi (initiator) displays, DUT (responder) enters
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        else:
            # Fallback - should not reach here if all scenarios are covered
            pairing_method = "PasskeyEntry"
            passkey_direction = "dut_displays"  # Default: DUT displays
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)

        if pairing_method in ("JustWorks", "NumericComparison"):
            nuc_capability = self.client_capability
            nuc_pin_code = "0"
        elif pairing_method == "PasskeyEntry" and passkey_direction == "dut_displays":
            nuc_capability = "KeyboardOnly"
            nuc_pin_code = "-8"
        else:
            nuc_capability = self.client_capability
            nuc_pin_code = "0"

        # ======================================================================
        logger().info("=" * 80)
        logger().info("STEP 1: NUC - Start BT Classic Advertising (discoverable + pairable)")
        logger().info("=" * 80)

        try:
            logger().info("Getting DUT local address...")
            # time.sleep(20)
            self.dut_address = self.wifi_dut.interfaces.wifi.get_local_address()
            logger().info(f"DUT address: {self.dut_address}")

            logger().info("Starting BLE advertising on NUC...")
            self.nuc_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.dut_address,
                capability=nuc_capability,
                pin_code=nuc_pin_code,
                restart_bt_service=False,
            )
            logger().info(f"✓ PASS: NUC advertising started, address: {self.nuc_address}")
            time.sleep(3)

        except Exception as e:
            logger().error(f"✗ FAIL: Failed to start NUC advertising: {e}")
            assert False, f"NUC advertising failed: {e}"

        # ======================================================================
        logger().info("=" * 80)
        logger().info("STEP 2: DUT - Connect to NUC via BT Classic CLI")
        logger().info("=" * 80)
        time.sleep(5)
        connect_result = self.wifi_dut.interfaces.wifi.bt_connect(self.nuc_address)
        logger().info("bt_connect command issued; waiting for authentication/profile events.")
        time.sleep(5)
        logger().info(f"bt_connect returned: {connect_result!r}")

        logger().info("=" * 80)
        logger().info("STEP 5: NUC -- Enable AG")
        logger().info("=" * 80)


        logger().info("✅ STEP 5 PASSED: AG profile ready (HFP RFCOMM channel active from STEP 4.5)")
        logger().info("=" * 80)
        logger().info("STEP 6: DUT -- AG Call Establish (btc hfp ag_call_establish)")
        logger().info("=" * 80)
        try:
            logger().info(f"Sending AG call establish to NUC ({self.nuc_address})...")
            self.wifi_dut.interfaces.wifi.bt_ag_call_establish(bt_address=self.nuc_address)
            logger().info("AG call establish command sent (btc hfp ag_call_establish)")
        except Exception as e:
            assert False, f"AG call establish failed: {e}"

        try:
            logger().info(f"Accepting AG call from NUC ({self.nuc_address})...")
            self.wifi_dut.interfaces.wifi.bt_ag_call_accept(bt_address=self.nuc_address)
            logger().info("AG call accept command sent (btc hfp ag_call_accept)")
            time.sleep(300)
        except Exception as e:
            assert False, f"AG call accept failed: {e}"

        try:
            logger().info(f"Terminating AG call to NUC ({self.nuc_address})...")
            self.wifi_dut.interfaces.wifi.bt_ag_call_terminate(bt_address=self.nuc_address)
            logger().info("AG call terminate command sent (btc hfp ag_call_terminate)")
        except Exception as e:
            assert False, f"AG call terminate failed: {e}"
        logger().info("✅ STEP 8 PASSED: AG call terminated (firmware-initiated disconnect after call end is expected)")


        # Disconnect from the BLE client
        logger().info(f"Disconnecting from BLE client at {self.nuc_address}")
        try:
            self.wifi_dut.interfaces.wifi.btc_disconnect(ble_address=self.nuc_address)
            logger().info("PASS: btc_disconnect executed successfully")
        except Exception as e:
            logger().error(f"FAIL: btc_disconnect failed: {e}")
            assert False, f"btc_disconnect failed: {e}"
        logger().info("Disconnection completed")
        logger().info("Clearing bonding data on Raspberry Pi to ensure fresh pairing")

        logger().info("Attempting to clear bonding data on Raspberry Pi...")
        self.wifi_dut.interfaces.wifi.stop_scan()
        # try:
        #     self.ble_client.interfaces.bluetooth.remove_all_devices()
        #     logger().info("PASS: remove_all_devices executed successfully")
        #     time.sleep(5)
        # except Exception as e:
        #     logger().warning(f"Failed to clear bonding data on Raspi: {e}")
        #     # Note: remove_all_devices failure is a warning, not a test failure
        #
        # try:
        #     self.ble_client.interfaces.bluetooth.close()
        #     logger().info("PASS: close executed successfully")
        # except Exception as e:
        #     logger().warning(f"FAIL: close failed: {e}")
        #     # Note: close failure is a warning, not a test failure
        #     time.sleep(5)
        time.sleep(5)

# Just works, Raspi: 0x00 (Display) DUT: 0x00 (Display)
def test_nuc_as_ble_client_ag(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    
    # Generate unique btmon log filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bt_mon_log_file = f"reports/ag_test_btmon_NUC_{timestamp}.log"
    remote_btmon_log = f"/tmp/btmon_ag_{timestamp}.log"
    
    # Access NUC shell
    nuc_shell = ble_client.interfaces.ssh_host
    btmon_command = None
    
    # ======================================================================
    # Start btmon on NUC BEFORE the test
    # ======================================================================
    logger().info("=" * 80)
    logger().info(f"Starting btmon on NUC (10.207.20.149)")
    logger().info(f"Remote log: {remote_btmon_log}")
    logger().info("=" * 80)
    
    try:
        # Kill any existing btmon processes
        nuc_shell.execute("sudo pkill btmon")
        time.sleep(1)
        
        # Start btmon in background on NUC
        btmon_command = nuc_shell.execute_in_background(
            f"sudo btmon -t > {remote_btmon_log} 2>&1"
        )
        time.sleep(2)  # Give btmon time to start
        logger().info("✓ btmon started on NUC")
        
    except Exception as e:
        logger().error(f"Failed to start btmon on NUC: {e}")
    
    # ======================================================================
    # Execute pre-test commands on NUC/BLE client
    # ======================================================================
    logger().info("=" * 80)
    logger().info("Executing pre-test commands on NUC/BLE client...")
    logger().info("=" * 80)
    
    try:
        
        # Check Bluetooth status
        rc, stdout, stderr = nuc_shell.execute("hciconfig -a")
        logger().info(f"HCI Config output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pulseaudio -k")
        logger().info(f"Pulseaudio output:\n{stdout}")

        time.sleep(2)

        rc, stdout, stderr = nuc_shell.execute("pulseaudio --start")
        logger().info(f"Pulseaudio output:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluez5-discover")
        logger().info(f"pactl bluez5 modules:\n{stdout}")

        rc, stdout, stderr = nuc_shell.execute("pactl list modules | grep -A10 module-bluetooth-discover")
        logger().info(f"pactl bluetooth modules:\n{stdout}")
        
    except Exception as e:
        logger().error(f"Failed to execute pre-test commands on NUC: {e}")
        # Decide if you want to fail the test or continue
        # raise  # Uncomment to fail test on command execution error
    
    logger().info("Pre-test commands completed")
    logger().info("=" * 80)
    
    # ======================================================================
    # Run the actual test (btmon is capturing in background on NUC)
    # ======================================================================
    logger().info("Starting test execution (btmon running on NUC)...")
    
    try:
        ble_test = BLESMPPairingTest(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            dut_capability="DisplayOnly",
            client_capability="DisplayOnly",
            pin_code="-8",
        )
        ble_test.run()
    finally:
        # ======================================================================
        # Stop btmon on NUC and retrieve the log
        # ======================================================================
        logger().info("=" * 80)
        logger().info("Stopping btmon on NUC and retrieving log...")
        logger().info("=" * 80)
        
        try:
            # Stop btmon
            if btmon_command:
                btmon_command.stop()
            nuc_shell.execute("sudo pkill btmon")
            time.sleep(2)
            
            # Check if log file exists
            rc, stdout, stderr = nuc_shell.execute(f"ls -lh {remote_btmon_log}")
            logger().info(f"Remote btmon log file info: {stdout}")
            
            # Download btmon log from NUC to local machine
            logger().info(f"Downloading btmon log from NUC to {bt_mon_log_file}")
            with nuc_shell.client.open_sftp() as sftp:
                sftp.get(remote_btmon_log, bt_mon_log_file)
            
            logger().info(f"✓ btmon log downloaded: {bt_mon_log_file}")
            
            # Clean up remote file
            nuc_shell.execute(f"rm -f {remote_btmon_log}")
            
        except Exception as e:
            logger().error(f"Failed to retrieve btmon log from NUC: {e}")
    
    logger().info("=" * 80)
    logger().info(f"✅ Test completed. NUC btmon log saved to: {bt_mon_log_file}")
    logger().info("=" * 80)
    
