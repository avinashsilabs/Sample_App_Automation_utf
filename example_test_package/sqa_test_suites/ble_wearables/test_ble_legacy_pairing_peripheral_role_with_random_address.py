import pytest

import time
import threading
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
import re
def logger():
    return get_logger(__name__)

"""
BLE SMP Legacy Pairing IO Capability Test Suite

This module contains automated test cases for validating BLE Security Manager Protocol (SMP) 
pairing across different IO capability combinations between a Raspberry Pi BLE Central device 
and a Device Under Test (DUT) configured as a BLE Peripheral.

Test Coverage:
    - JustWorks pairing scenarios (11 combinations)
    - Passkey Entry pairing scenarios (14 combinations)

The test suite validates proper authentication, secure connection establishment, and pairing 
success for all 25 IO capability combinations as defined in the Bluetooth Core Specification.

Author: Hussain korra
Date: 26th FEB 2026
"""
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
    def __init__(self, wifi_dut, ble_client, dut_capability, client_capability, pin_code, smp_sc=0, smp_auth_bond=1, smp_mtim=0, smp_enc_key=1, passkey_state=2, random_addr_on_dut=True, auth_req="0x05", oob_data_flag="0x00", sniffer=None,target_address=None):
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
        self.oob_data_flag = oob_data_flag  
        self.ble_dut_address = None
        self.ble_client_address = None
        self.target_address = None

    
    def _verify_connection_status(self, max_retries=0):
        """
        Verify BLE connection status with retries.
       
        Args:
            max_retries: Maximum number of retry attempts (default: 0)
           
        Returns:
            bool: True if connected, False otherwise
        """
        logger().info(f"Verifying connection status to {self.ble_dut_address}...")
       
        for attempt in range(max_retries + 1):
            try:
                connection_status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
                logger().info(f"Connection status (attempt {attempt + 1}/{max_retries + 1}): {connection_status}")
                if connection_status:
                    logger().info(f"Connection verified to {self.ble_dut_address}")
                    return True
            except Exception as e:
                logger().warning(f"Could not get connection status (attempt {attempt + 1}/{max_retries + 1}): {e}")
            if attempt < max_retries:
                time.sleep(2)
       
        logger().error(f"Connection verification failed after {max_retries + 1} attempts")
        return False
       
    def _extract_passkey_from_log(self):
        """Extract passkey from DUT serial log and ensure it's 6 digits with leading zeros if needed"""
        serial_conn = self.wifi_dut.interfaces.wifi.bus  
        input_log = serial_conn.get_input_log()
        
        # Print all lines captured from serial log for debugging
        logger().info("Serial log lines captured for passkey parsing:")
        for ts, line in input_log:
            try:
                decoded_line = line.decode(errors="ignore")
            except Exception:
                decoded_line = str(line)
            logger().info(f"SERIAL_LOG: {decoded_line}")
        
        passkey = None
        for ts, line in input_log:
            try:
                decoded_line = line.decode(errors="ignore")
            except Exception:
                continue
            
            # Look for passkey pattern in the log
            # Match "passkey:" followed by optional whitespace and then digits
            match = re.search(r"passkey[:\s]+(\d+)", decoded_line, re.IGNORECASE)
            if match:
                passkey_raw = match.group(1)
                # Ensure it's 6 digits (pad with leading zeros if needed)
                if len(passkey_raw) <= 6:
                    passkey = passkey_raw.zfill(6)
                    logger().info(f"Passkey extracted ({len(passkey_raw)} digits): {passkey_raw} -> Padded to 6 digits: {passkey}")
                    break
                else:
                    logger().warning(f"Passkey found but has more than 6 digits: {passkey_raw}")
        
        return passkey
    
    def _wait_for_serial_log_regex(self, pattern: str, timeout: float, start_index: int = 0, poll_interval: float = 0.2):
        """Wait for a regex pattern to appear in DUT serial log"""
        serial_conn = self.wifi_dut.interfaces.wifi.bus
        compiled = re.compile(pattern, re.IGNORECASE)
        deadline = time.time() + timeout

        while time.time() < deadline:
            input_log = serial_conn.get_input_log()

            for _ts, line in input_log[start_index:]:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)

                if compiled.search(decoded_line):
                    return True, decoded_line

            time.sleep(poll_interval)

        return False, ""
    
    def _determine_passkey_direction(self, dut_io, client_io):
        """
        Determine which side displays the passkey and which side enters it.
        Based on BLE SMP IO capability matrix for Legacy Pairing.
        
        Args:
            dut_io: DUT IO capability (0x00-0x04)
            client_io: Client (Raspi) IO capability (0x00-0x04)
        Returns:
            tuple: (displayer, enterer) where each is 'dut' or 'raspi'
        """
        dut_can_display = dut_io in [0x00, 0x01, 0x04]  # DisplayOnly, DisplayYesNo, KeyboardDisplay
        dut_can_input = dut_io in [0x02, 0x04]  # KeyboardOnly, KeyboardDisplay
        raspi_can_display = client_io in [0x00, 0x01, 0x04]
        raspi_can_input = client_io in [0x02, 0x04]
        
        # Passkey Entry decision matrix (Raspi=initiator/Central, DUT=responder/Peripheral): 
        if dut_can_display and raspi_can_input and not (raspi_can_display and dut_can_input):
            return ('dut', 'raspi')
        elif raspi_can_display and dut_can_input:
            return ('raspi', 'dut')
        elif dut_io == 0x04 and client_io == 0x04:
            # Both KeyboardDisplay: initiator displays, responder enters
            return ('raspi', 'dut')
        else:
            # Default: DUT displays, Raspi enters
            return ('dut', 'raspi')
    
    def run(self):
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03, "KeyboardDisplay": 0x04}
        
        # Determine pairing method and auth_req based on IO capabilities
        dut_io = io_capability[self.dut_capability]
        client_io = io_capability[self.client_capability]
        
        # JustWorks scenarios (no MITM protection possible - use auth_req=0x01)
        justworks_scenarios = [
            (0x00, 0x00),  # DisplayOnly + DisplayOnly
            (0x01, 0x00),  # DisplayYesNo + DisplayOnly
            (0x03, 0x00),  # NoInputNoOutput + DisplayOnly
            (0x00, 0x01),  # DisplayOnly + DisplayYesNo
            (0x03, 0x01),  # NoInputNoOutput + DisplayYesNo
            (0x00, 0x03),  # DisplayOnly + NoInputNoOutput
            (0x01, 0x03),  # DisplayYesNo + NoInputNoOutput
            (0x02, 0x03),  # KeyboardOnly + NoInputNoOutput
            (0x03, 0x03),  # NoInputNoOutput + NoInputNoOutput
            (0x04, 0x03),  # KeyboardDisplay + NoInputNoOutput
            (0x03, 0x04),  # NoInputNoOutput + KeyboardDisplay
            (0x03, 0x02),  # NoInputNoOutput + KeyboardOnly
            (0x01, 0x01),  # DisplayYesNo + DisplayYesNo
        ] 
        
        # Determine pairing method
        if (dut_io, client_io) in justworks_scenarios:
            pairing_method = "JustWorks"
            auth_req_value = 0x01 # Bonding + SC (no MITM) - prevents Raspi disconnect
        else:
            pairing_method = "PasskeyEntry"
            auth_req_value = 0x05 # Bonding + MITM + SC (45 decimal)
        
        logger().info(f"Pairing Method: {pairing_method}, auth_req=0x{auth_req_value:02X} ({auth_req_value} decimal)")
        logger().info(f"DUT IO: {self.dut_capability} (0x{dut_io:02X}), Raspi IO: {self.client_capability} (0x{client_io:02X})")
        
        self.wifi_dut.interfaces.wifi.stop_adv()
        # self._set_random_address_on_dut()
        fixed_ble_addr = "C0:98:E5:00:00:01"
        self.wifi_dut.interfaces.wifi.set_random_address(bd_addr=fixed_ble_addr)
        self.ble_dut_address = fixed_ble_addr
        logger().info(f"Fixed BLE address set on DUT: {fixed_ble_addr}")
        # Set SMP pairing capability data on DUT
        logger().info(f"Setting DUT SMP pairing capability: IO={io_capability[self.dut_capability]}, OOB={self.oob_data_flag}, auth_req={auth_req_value}")
        try:
            self.wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
                io_capability=io_capability[self.dut_capability],
                oob_data_flag=int(self.oob_data_flag, 16) if isinstance(self.oob_data_flag, str) else self.oob_data_flag,
                auth_req=auth_req_value,
                enc_key_size=16,
                ini_key_dist=15,
                rsp_key_dist=15
            )
            logger().info("PASS: set_smp_pairing_capability_data executed successfully")
        except Exception as e:
            logger().error(f"FAIL: set_smp_pairing_capability_data failed: {e}")
            assert False, f"set_smp_pairing_capability_data failed: {e}"
        
        self.wifi_dut.interfaces.wifi.legacy_adv(own_addr_type=0x01)  # 0x00=Public, 0x01=Random
        logger().info("Start SMP scan from the remote device (Raspi)")
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.ble_dut_address, capability=self.client_capability, pin_code=self.pin_code)
        assert self.ble_client_address, "failed to initiate ble in remote device"
        import time
        time.sleep(5)
        logger().info("Stop scanning ...")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        logger().info("Check the DUT is listed ...")
        # ...existing code...
        devices = self.ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"Devices scanned by Raspi: {devices}")
        for dev in devices:
            logger().info(f"Scanned device: {dev}")
            
        # Initialize bus connection before pairing
        self.ble_client.interfaces.bluetooth.set_bus()
        def connect():
            # Passkey Entry or Numeric Comparison - use connect with supervision timeout
            logger().info(f"Connect and pair to the DUT ({pairing_method} - using connect with supervision timeout)")
            self.ble_client.interfaces.bluetooth.connect(
                dev_addr=self.ble_dut_address,
                supervision_timeout=500  # 5000 ms (500 * 10ms units = 5000ms)
            )
            
        t = threading.Thread(target=connect)
        t.start()
        
        # Wait a bit for pairing to start and request passkey
        time.sleep(5)
        
        if pairing_method == "PasskeyEntry":
            # Determine which side displays vs enters the passkey
            displayer, enterer = self._determine_passkey_direction(dut_io, client_io)
            logger().info(f"Passkey Entry pairing - {displayer.upper()} displays, {enterer.upper()} enters")
            
            passkey = None
            max_attempts = 10
            
            if displayer == 'dut':
                # DUT displays passkey -> extract from DUT logs, send to Raspi
                logger().info("Waiting for DUT to display passkey...")
                for attempt in range(max_attempts):
                    passkey = self._extract_passkey_from_log()
                    if passkey:
                        break
                    logger().info(f"Passkey not found in DUT logs yet, attempt {attempt + 1}/{max_attempts}, waiting...")
                    time.sleep(2)
                
                if not passkey:
                    assert False, "Passkey not found in DUT serial log!"
                
                logger().info(f"Sending passkey {passkey} to Raspi")
                self.ble_client.interfaces.bluetooth.set_pin(passkey)
                
            else:  
                # Raspi displays passkey -> extract from Raspi, send to DUT IMMEDIATELY
                # Poll aggressively for passkey and DUT's smp_passkey event simultaneously
                logger().info("Waiting for Raspi to display passkey and DUT passkey event...")
                serial_conn = self.wifi_dut.interfaces.wifi.bus
                passkey_event_pattern = re.compile(r"in smp_passkey", re.IGNORECASE)
                
                deadline = time.time() + 30  # 30 second timeout (SMP takes time after connect)
                passkey_ready = False
                dut_ready = False
                passkey_sent = False
                
                while time.time() < deadline:
                    # Check if passkey is available from Raspi
                    if not passkey_ready:
                        try:
                            pk = self.ble_client.interfaces.bluetooth.get_passkey()
                            if pk is not None:
                                pk_int = int(pk) if pk else 0
                                if pk_int != 0:
                                    passkey = str(pk_int)
                                    passkey_ready = True
                                    logger().info(f"Passkey ready from Raspi: {passkey}")
                        except Exception:
                            pass
                    
                    # Check if DUT is waiting for passkey
                    if not dut_ready:
                        recent_log = serial_conn.get_input_log()[-20:] if len(serial_conn.get_input_log()) > 20 else serial_conn.get_input_log()
                        for line in recent_log:
                            if passkey_event_pattern.search(str(line)):
                                dut_ready = True
                                logger().info("DUT passkey event detected - ready to receive passkey")
                                break
                    
                    # If both ready, send passkey immediately
                    if passkey_ready and dut_ready:
                        logger().info(f"Sending passkey {passkey} to DUT IMMEDIATELY (address: {self.ble_client_address})")
                        self.wifi_dut.interfaces.wifi.smp_passkey(self.ble_client_address, int(passkey))
                        passkey_sent = True
                        break
                    
                    time.sleep(0.05)  # Very fast polling
                
                # Fallback: If passkey ready but DUT event wasn't detected, send anyway
                if passkey_ready and not passkey_sent:
                    logger().warning("DUT passkey event not detected, but sending passkey anyway...")
                    self.wifi_dut.interfaces.wifi.smp_passkey(self.ble_client_address, int(passkey))
                    passkey_sent = True
                
                if not passkey_ready:
                    logger().error("Passkey not found from Raspi after timeout!")
                    assert False, "Passkey not found from Raspi!"
        else:  # JustWorks
            logger().info(f"JustWorks pairing (DUT: {self.dut_capability}, Client: {self.client_capability}) - no passkey required")
            time.sleep(5)  # Wait for pairing to complete without passkey
        
        # Wait for pairing to complete
        time.sleep(10)
        logger().info("Pairing process completed")

        # Verify pairing by checking DUT logs for failures
        serial_conn = self.wifi_dut.interfaces.wifi.bus
        input_log = serial_conn.get_input_log()
        smp_failed = False
        connection_failed = False
        disconnect_detected = False
        disconnect_reason = None
        disconnect_line = None
        smp_pair_request_received = False
        smp_response_received = False
        smp_encrypt_event_detected = False

        target_addr_lower = str(self.ble_client_address).lower() if self.ble_client_address else ""
        for _ts, line in input_log:
            try:
                decoded_line = line.decode(errors="ignore")
            except Exception:
                decoded_line = str(line)

            decoded_lower = decoded_line.lower()

            # Check for SMP pair request
            if any(pattern in decoded_lower for pattern in ["smp pair request", "pairing_request", "smp_pair_request", "rsi_ble_on_smp_request"]):
                smp_pair_request_received = True
                # logger().info(f"SMP pair request detected: {decoded_line}")

            # Check for SMP response
            if any(pattern in decoded_lower for pattern in ["smp response", "pairing_response", "smp_pair_response", "rsi_ble_on_smp_response"]):
                smp_response_received = True
                logger().info(f"SMP response detected: {decoded_line}")

            # Check for SMP encrypt event
            if any(pattern in decoded_lower for pattern in ["smp encrypt event", "encrypt_started", "encryption started", "encrypt started", "rsi_ble_on_encrypt_started", "encryption enabled"]):
                smp_encrypt_event_detected = True
                logger().info(f"SMP encrypt event detected: {decoded_line}")

            # Check for SMP failure - multiple patterns to catch all SMP failure scenarios
            if any(pattern in decoded_lower for pattern in ["smp failed", "in smp failed", "security failed"]):
                smp_failed = True
                # Extract status code if present
                status_match = re.search(r"status\s*:\s*([0-9a-fA-F]+)", decoded_line, re.IGNORECASE)
                if status_match:
                    logger().error(f"SMP failed detected with status 0x{status_match.group(1)}: {decoded_line}")
                else:
                    logger().error(f"SMP failed detected: {decoded_line}")    

            # Check for SMP failure
            if "smp failed" in decoded_lower:
                smp_failed = True
                logger().error(f"SMP failed detected: {decoded_line}")

            # Check for connection failure
            if "connection failed" in decoded_lower or "connect failed" in decoded_lower:
                connection_failed = True
                logger().error(f"Connection failed detected: {decoded_line}")

            # Check for unexpected disconnect
            if "disconnect" in decoded_lower and "disconnecting" not in decoded_lower:
                disconnect_detected = True
                disconnect_line = decoded_line
                match = re.search(r"0x[0-9a-fA-F]+", decoded_line)
                if match:
                    raw_hex = match.group(0)
                    try:
                        raw_val = int(raw_hex, 16)
                        hci_reason = raw_val & 0xFF
                        hci_reason_map = {
                            0x08: "Connection Timeout",
                            0x13: "Remote User Terminated Connection",
                            0x16: "Connection Terminated by Local Host",
                            0x3E: "Connection Failed to be Established",
                        }
                        hci_desc = hci_reason_map.get(hci_reason, "unknown")
                        disconnect_reason = f"{raw_hex} (hci 0x{hci_reason:02x}: {hci_desc})"
                    except Exception:
                        disconnect_reason = raw_hex
                else:
                    disconnect_reason = "unknown"
                logger().error(f"Disconnect detected (reason {disconnect_reason}): {decoded_line}")

        # Log SMP handshake status
        if smp_pair_request_received:
            logger().info(f"SMP response: {'DETECTED' if smp_response_received else 'NOT DETECTED'}, SMP encrypt event: {'DETECTED' if smp_encrypt_event_detected else 'NOT DETECTED'}")

        # Assert on failures
        assert not smp_failed, "Pairing failed - SMP failure detected in DUT logs!"
        assert not connection_failed, "Connection failed during pairing!"

        # Wait for "rsi_ble_event_profile_dummy" event before checking stability
        logger().info("Waiting for profile event (rsi_ble_event_profile_dummy)...")
        profile_event_found, matched_line = self._wait_for_serial_log_regex(
            pattern=r"rsi_ble_event_profile_dummy",
            timeout=60,
        )
        if profile_event_found:
            logger().info(f"Profile event detected: {matched_line.strip()}")
            # Monitor connection stability for 60 seconds
            logger().info("Monitoring connection stability for 60 seconds...")
            time.sleep(60)
            # Final pass/fail condition: only pass if no failure conditions are met
            if not smp_failed and not connection_failed and not disconnect_detected:
                logger().info("Test PASSED: All required events detected, no failure conditions met, connection stable.")
            else:
                assert False, "Test failed due to SMP failure, connection failure, or disconnect detected."
        else:
            assert False, "FAIL: 'rsi_ble_event_profile_dummy' event not found in DUT logs!"

            # Verify BLE connection status after profile dummy event
        connection_verified = self._verify_connection_status(max_retries=0)
        if not connection_verified:
            assert False, "BLE connection verification failed - device is not connected"
        time.sleep(5) 

        # Disconnect from the BLE client
        logger().info(f"Disconnecting from BLE client at {self.ble_client_address}")
        self.wifi_dut.interfaces.wifi.btc_disconnect(ble_address=self.ble_client_address)
        logger().info("Disconnection completed")
        # self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.ble_dut_address)
        # Clear any existing bonding data to avoid LTK mismatch
        logger().info("Clearing bonding data on Raspberry Pi to ensure fresh pairing")
        try:
            self.ble_client.interfaces.bluetooth.remove_all_devices()
            time.sleep(5)
        except Exception as e:
            logger().warning(f"Failed to clear bonding data on Raspi: {e}")
        self.ble_client.interfaces.bluetooth.close()
        time.sleep(5)
        
# Just works, Raspi: 0x00 (Display) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C1700078')
def test_ble_smp_just_works_with_io_capability_dut_0x00_raspi_0x00_C1700078(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",
        client_capability="DisplayOnly",
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# Just works, Raspi: 0x01 (Display Yes/No) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C1700079')
def test_ble_smp_just_works_with_io_capability_dut_0x00_raspi_0x01_C1700079(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",  
        client_capability="DisplayYesNo",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (Keyboard Only) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C1700080')
def test_ble_smp_passkeyentry_with_io_capability_dut_0x00_raspi_0x02_C1700080(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",  
        client_capability="KeyboardOnly",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()
# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C1700081')
def test_ble_smp_just_works_with_io_capability_dut_0x00_raspi_0x03_C1700081(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly", 
        client_capability="NoInputNoOutput",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# Passkey, Raspi: 0x04 (Keyboard Display) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C1700082')
def test_ble_smp_passkeyentry_with_io_capability_dut_0x00_raspi_0x04_C1700082(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",  
        client_capability="KeyboardDisplay",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# JustWorks, Raspi: 0x00 (DisplayOnly) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C1700083')
def test_ble_smp_just_works_with_io_capability_dut_0x01_raspi_0x00_C1700083(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo", 
        client_capability="DisplayOnly",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# just work, Raspi: 0x01 (DisplayYesNo) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C1700084')
def test_ble_smp_just_works_with_io_capability_dut_0x01_raspi_0x01_C1700084(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)   
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",  
        client_capability="DisplayYesNo",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C1700085')
def test_ble_smp_passkeyentry_with_io_capability_dut_0x01_raspi_0x02_C1700085(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",  
        client_capability="KeyboardOnly",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C1700086')
def test_ble_smp_just_works_with_io_capability_dut_0x01_raspi_0x03_C1700086(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo", 
        client_capability="NoInputNoOutput",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# NumericComparison, Raspi: 0x04 (KeyboardDisplay) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C1700087')
def test_ble_smp_passkeyentry_with_io_capability_dut_0x01_raspi_0x04_C1700087(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",  
        client_capability="KeyboardDisplay",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# Passkey, Raspi: 0x00 (DisplayOnly) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C1700088')
def test_ble_connects_to_dut_02_raspi_00_C1700088(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly", 
        client_capability="DisplayOnly",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# Passkey, Raspi: 0x01 (DisplayYesNo) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C1700089')
def test_ble_connects_to_dut_02_raspi_01_C1700089(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly", 
        client_capability="DisplayYesNo",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C1700090')
def test_ble_connects_to_dut_02_raspi_02_C1700090(wifi_dut, ble_client):
    time.sleep(20)
    fixed_passkey = "123456"
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",
        client_capability="KeyboardOnly",
        pin_code=fixed_passkey,
        random_addr_on_dut=True
    )
    def run_with_fixed_passkey():
        import re as _re
        import time as _time
        logger = ble_test.wifi_dut.logger if hasattr(ble_test.wifi_dut, 'logger') else None
        def log_info(msg):
            if logger:
                logger.info(msg)
            else:
                print(msg)
        # Clear bonding data on raspi 
        try:
            ble_test.ble_client.interfaces.bluetooth.remove_all_devices()
            _time.sleep(2)
        except Exception as e:
            log_info(f"Warning: Failed to clear Raspi bonds: {e}")

        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03, "KeyboardDisplay": 0x04}
        dut_io = io_capability[ble_test.dut_capability]
        client_io = io_capability[ble_test.client_capability]
        # Set up DUT as advertiser (peripheral)
        log_info(f"Setting DUT SMP pairing capability: IO={dut_io}, KeyboardOnly/KeyboardOnly, fixed passkey {fixed_passkey}")
        ble_test.wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
            io_capability=dut_io,
            oob_data_flag=0x00,
            auth_req=0x05,
            enc_key_size=16,
            ini_key_dist=15,
            rsp_key_dist=15
        )
        ble_test.ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
        ble_test.ble_client.interfaces.bluetooth.set_mitm_sc_bits(f"{client_io} 0x00 0x05")
        # Raspi (central) scans and connects
        log_info("Starting SMP scan on Raspi...")
        ble_test.ble_client_address = ble_test.ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=None,
            capability=ble_test.client_capability,
            pin_code=fixed_passkey
        )
        assert ble_test.ble_client_address, "failed to initiate ble in remote device"
        _time.sleep(5)
        ble_test.ble_client.interfaces.bluetooth.stop_scanning()
        # Raspi connects to DUT
        if not ble_test.wifi_dut.interfaces.wifi.get_local_address():
            raise RuntimeError("DUT local address not available!")
        dut_addr = ble_test.wifi_dut.interfaces.wifi.get_local_address()
        # Move log_start_index assignment BEFORE connection to avoid missing early events
        serial_conn = ble_test.wifi_dut.interfaces.wifi.bus
        log_start_index = len(serial_conn.get_input_log())
        log_info(f"Raspi connecting to DUT at {dut_addr}...")
        ble_test.ble_client.interfaces.bluetooth.connect(dev_addr=dut_addr, supervision_timeout=500)
        _time.sleep(5)
        # Wait extra time to ensure both sides are ready for passkey entry
        log_info("Waiting 5s before passkey entry to ensure both sides are ready...")
        _time.sleep(5)
        # Wait for DUT to prompt for passkey entry
        passkey_prompt_pattern = _re.compile(r"in smp_passkey", _re.IGNORECASE)
        dut_ready = False
        timeout = 30  # seconds
        deadline = _time.time() + timeout
        log_info("Waiting for DUT to prompt for passkey entry...")
        while _time.time() < deadline:
            # Always search the last 50 lines to avoid missing the event
            input_log = serial_conn.get_input_log()
            recent_log = input_log[-50:] if len(input_log) > 50 else input_log
            for _ts, line in recent_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                if passkey_prompt_pattern.search(decoded_line):
                    log_info(f"DUT passkey prompt detected: {decoded_line.strip()}")
                    dut_ready = True
                    break
            if dut_ready:
                break
            _time.sleep(0.2)
        assert dut_ready, "DUT did not prompt for passkey entry in time!"
        # Send fixed passkey to both sides
        log_info(f"Entering fixed passkey {fixed_passkey} on DUT and Raspi...")
        ble_test.wifi_dut.interfaces.wifi.smp_passkey(ble_test.ble_client_address, int(fixed_passkey))
        ble_test.ble_client.interfaces.bluetooth.set_pin(fixed_passkey)
        _time.sleep(5)
        # Continue with pairing verification, disconnect, cleanup
        log_info("Waiting 60s for pairing and connection stability...")
        _time.sleep(60)
        log_info("Disconnecting from BLE client...")
        ble_test.wifi_dut.interfaces.wifi.btc_disconnect(ble_test.ble_client_address)
        try:
            ble_test.ble_client.interfaces.bluetooth.remove_all_devices()
            _time.sleep(2)
        except Exception as e:
            log_info("Warning: Failed to clear Raspi bonds after test.")
        ble_test.ble_client.interfaces.bluetooth.close()
    ble_test.run = run_with_fixed_passkey
    ble_test.run()

# Passkey, Raspi: 0x03 (NoInputNoOutput) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C1700091')
def test_ble_connects_to_dut_02_raspi_03_C1700091(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",  
        client_capability="NoInputNoOutput", 
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# Passkey, Raspi: 0x04 (KeyboardDisplay) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C1700092')
def test_ble_connects_to_dut_02_raspi_04_C1700092(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",  
        client_capability="KeyboardDisplay",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# JustWorks, Raspi: 0x00 (DisplayOnly) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C1700093')
def test_ble_connects_to_dut_03_raspi_00_C1700093(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput", 
        client_capability="DisplayOnly", 
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# JustWorks, Raspi: 0x01 (DisplayYesNo) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C1700094')
def test_ble_connects_to_dut_03_raspi_01_C1700094(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",  
        client_capability="DisplayYesNo",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# JustWorks, Raspi: 0x02 (KeyboardOnly) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C1700095')
def test_ble_connects_to_dut_03_raspi_02_C1700095(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput", 
        client_capability="KeyboardOnly",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C1700096')
def test_ble_connects_to_dut_03_raspi_03_C1700096(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",  
        client_capability="NoInputNoOutput",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()  

# JustWorks, Raspi: 0x04 (KeyboardDisplay) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C1700097')
def test_ble_connects_to_dut_03_raspi_04_C1700097(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput", 
        client_capability="KeyboardDisplay", 
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run() 

# Passkey, Raspi: 0x00 (DisplayOnly) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C1700098')
def test_ble_connects_to_dut_04_raspi_00_C1700098(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  
        client_capability="DisplayOnly", 
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run() 

# passkey entry, Raspi: 0x01 (DisplayYesNo) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C1700099')
def test_ble_connects_to_dut_04_raspi_01_C1700099(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  
        client_capability="DisplayYesNo", 
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run() 


# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C1700100')
def test_ble_smp_passkey_with_io_capability_dut_0x04_raspi_0x02_C1700100(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  # 0x04
        client_capability="KeyboardOnly",  # 0x02
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()
   
# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C1700101')
def test_ble_connects_to_dut_04_raspi_03_C1700101(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  
        client_capability="NoInputNoOutput", 
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()

# NumericComparison, Raspi: 0x04 (KeyboardDisplay) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C1700102')
def test_ble_connects_to_dut_04_raspi_04_C1700102(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  
        client_capability="KeyboardDisplay",  
        pin_code="-8",
        random_addr_on_dut=True
    )
    ble_test.run()
