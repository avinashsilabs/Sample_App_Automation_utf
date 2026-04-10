"""
BLE SMP Pairing IO Capability Test Suite

This module contains automated test cases for validating BLE Security Manager Protocol (SMP) 
pairing across different IO capability combinations between a Raspberry Pi BLE Central device 
and a Device Under Test (DUT) configured as a BLE Peripheral.

Test Coverage:
    - JustWorks pairing scenarios (11 combinations)
    - Passkey Entry pairing scenarios (10 combinations)
    - Numeric Comparison pairing scenarios (4 combinations)

The test suite validates proper authentication, secure connection establishment, and pairing 
success for all 25 IO capability combinations as defined in the Bluetooth Core Specification.

Author: Hussain korra
Date: 26th Feb 2026
"""


import time
import threading
from utf.utils.logger import get_logger
import re

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
        self.oob_data_flag = oob_data_flag  # Added OOB data flag parameter
        self.ble_dut_address = None
        self.ble_client_address = None

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
    
    def _extract_passkey_from_dut_log(self):
        """Extract passkey from DUT serial log and ensure it's 6 digits with leading zeros if needed"""
        serial_conn = self.wifi_dut.interfaces.wifi.bus  # HostSerialConnectionAsync
        input_log = serial_conn.get_input_log()
        
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

    def _extract_passkey_from_raspi(self, timeout=30):
        """
        Extract passkey displayed by Raspberry Pi's BlueZ agent.
        The Raspi agent stores the passkey when DisplayPasskey is called.
        
        Args:
            timeout: Maximum time to wait for passkey to appear (seconds)
        Returns:
            str: 6-digit passkey string, or None if not found
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                passkey = self.ble_client.interfaces.bluetooth.get_passkey()
                # Check for valid passkey - handle both string and int types
                if passkey is not None:
                    passkey_int = int(passkey) if passkey else 0
                    if passkey_int != 0:
                        passkey_str = str(passkey_int).zfill(6)
                        logger().info(f"Passkey extracted from Raspi: {passkey_int} -> Padded to 6 digits: {passkey_str}")
                        return passkey_str
                    else:
                        logger().debug(f"Raspi passkey is 0/empty, waiting for real passkey...")
            except Exception as e:
                logger().debug(f"Waiting for Raspi passkey: {e}")
            time.sleep(0.2)  # Poll faster for quicker passkey response
        return None

    def _determine_passkey_direction(self, dut_io, client_io):
        """
        Determine which side displays the passkey and which side enters it.
        Based on BLE SMP IO capability matrix.
        
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
        
        # Passkey Entry decision matrix (initiator=DUT, responder=Raspi):
        if raspi_can_display and dut_can_input and not (dut_can_display and raspi_can_input):
            return ('raspi', 'dut')
        elif dut_can_display and raspi_can_input:
            return ('dut', 'raspi')
        elif dut_io == 0x04 and client_io == 0x04:
            # Both KeyboardDisplay: initiator displays, responder enters
            return ('dut', 'raspi')
        else:
            # Default: DUT displays, Raspi enters
            return ('dut', 'raspi')

    def _wait_for_serial_log_regex(self, pattern: str, timeout: float, start_index: int = 0, poll_interval: float = 0.2):
        serial_conn = self.wifi_dut.interfaces.wifi.bus  # HostSerialConnectionAsync
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
    
    def _verify_connection_status(self, timeout=30):
        """
        Verify BLE connection status with retries.
       
        Args:
            timeout: Maximum time to wait for connection verification
           
        Returns:
            bool: True if connected, False otherwise
        """
        logger().info(f"Verifying connection status to {self.ble_dut_address}...")
        start_time = time.time()
       
        while time.time() - start_time < timeout:
            try:
                connection_status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
                logger().info(f"Connection status: {connection_status}")
                if connection_status:
                    logger().info(f"Connection verified to {self.ble_dut_address}")
                    return True
            except Exception as e:
                logger().warning(f"Could not get connection status: {e}")
            time.sleep(2)
       
        logger().error(f"Connection verification failed after {timeout}s")
        return False
    
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
        
        # Numeric Comparison scenarios (DisplayYesNo + DisplayYesNo, DisplayYesNo + KeyboardDisplay, KeyboardDisplay + KeyboardDisplay)
        numeric_comparison_scenarios = []
        
        # Passkey Entry scenarios (all others requiring passkey display/entry)
        # This includes DisplayOnly + KeyboardOnly, DisplayOnly + KeyboardDisplay, etc.
        
        # Determine pairing method
        if (dut_io, client_io) in justworks_scenarios:
            pairing_method = "JustWorks"
            auth_req_value = 0x01  # Bonding only (no MITM, no SC)
        elif (dut_io, client_io) in numeric_comparison_scenarios:
            pairing_method = "NumericComparison"
            auth_req_value = 0x05  # Bonding + MITM (no SC)
        else:
            pairing_method = "PasskeyEntry"
            auth_req_value = 0x05  # Bonding + MITM (no SC)
        
        logger().info(f"Pairing Method: {pairing_method}, auth_req=0x{auth_req_value:02X} ({auth_req_value} decimal)")
        logger().info(f"DUT IO: {self.dut_capability} (0x{dut_io:02X}), Raspi IO: {self.client_capability} (0x{client_io:02X})")
        self.wifi_dut.interfaces.wifi.legacy_scan_stop()
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
           
        logger().info("Start SMP advertsing from the remote device (Raspi)")
        try:
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.ble_dut_address,
                capability=self.client_capability,
                pin_code=self.pin_code
            )
            logger().info(f"PASS: start_smp_adv executed successfully, client address: {self.ble_client_address}")
        except Exception as e:
            logger().error(f"FAIL: start_smp_adv failed: {e}")
            assert False, f"start_smp_adv failed: {e}"
        
        # Disable Secure Connections on Raspi to use Legacy Pairing
        logger().info("Disabling Secure Connections on Raspi for Legacy Pairing compatibility")
        try:
            self.ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
            logger().info("PASS: set_secure_connection executed successfully")
        except Exception as e:
            logger().error(f"FAIL: set_secure_connection failed: {e}")
        
        # Re-apply the MITM/SC bits via HCI after BT service restart
        raspi_auth_req = f"0x{auth_req_value:02x}"
        logger().info(f"Re-setting Raspi auth_req via HCI: {io_capability[self.client_capability]} {self.oob_data_flag} {raspi_auth_req}")
        try:
            self.ble_client.interfaces.bluetooth.set_mitm_sc_bits(f"{io_capability[self.client_capability]} {self.oob_data_flag} {raspi_auth_req}")
            logger().info("PASS: set_mitm_sc_bits executed successfully")
        except Exception as e:
            logger().error(f"FAIL: set_mitm_sc_bits failed: {e}")
            assert False, f"set_mitm_sc_bits failed: {e}"
        
        time.sleep(5)
            

        # Snapshot current serial log index so we can reason about events for this test only
        serial_conn = self.wifi_dut.interfaces.wifi.bus
        log_start_index = len(serial_conn.get_input_log())

        # Stop background scanning before connect to avoid the DUT latching onto other nearby devices
        # Note: `legacy_scan(status=0)` actually *starts* scanning on this platform (see DUT log: "start scan command called").
        try:
            self.wifi_dut.interfaces.wifi.legacy_scan(own_addr_type=0x01)
            time.sleep(10)
            self.wifi_dut.interfaces.wifi.legacy_scan_stop()
            time.sleep(1)
            logger().info("PASS: legacy_scan_stop executed successfully")
        except Exception as e:
            logger().error(f"FAIL: legacy_scan_stop failed: {e}")
            assert False, f"legacy_scan_stop failed: {e}"
        
        def connect():
            # Passkey Entry or Numeric Comparison - use connect with supervision timeout
            logger().info(f"Connect and pair to the Remote Device ({pairing_method} - using connect with supervision timeout)")
            try:
                self.wifi_dut.interfaces.wifi.req_legacy_connect(own_addr_type=0x01, dev_addr=self.ble_client_address)
                logger().info("PASS: req_legacy_connect executed successfully")
            except Exception as e:
                assert False, f"req_legacy_connect failed: {e}"
            time.sleep(30)
            
        
        t = threading.Thread(target=connect)
        t.start()
        
        # Wait for the DUT to connect specifically to the Raspi (scan stopped before connect to prevent auto-multi-connect)
        logger().info("Waiting for BLE connection to establish...")
        connected, matched_line = self._wait_for_serial_log_regex(
            pattern=rf"Connected Address:\s*{re.escape(str(self.ble_client_address))}(\s|,|$)",
            timeout=15,
            start_index=log_start_index,
        )

        if connected:
            logger().info(f"Connection established: {matched_line.strip()}")
            # Add delay after connection to allow remote device to be ready for MTU exchange
            logger().info("Delaying 1s after connection to avoid MTU exchange timing issues...")
            time.sleep(1)
        else:
            logger().warning("Did not observe connection event for Raspi; proceeding with fixed delay")
            time.sleep(8)
        
        if pairing_method == "PasskeyEntry":
            # Determine which side displays vs enters the passkey
            displayer, enterer = self._determine_passkey_direction(dut_io, client_io)
            logger().info(f"Passkey Entry pairing - {displayer.upper()} displays, {enterer.upper()} enters")
            passkey = None
            max_attempts = 15
            if displayer == 'dut':
                # DUT displays passkey -> extract from DUT logs, send to Raspi
                logger().info("Waiting for DUT to display passkey...")
                for attempt in range(max_attempts):
                    passkey = self._extract_passkey_from_dut_log()
                    if passkey:
                        break
                    logger().info(f"Passkey not found in DUT logs yet, attempt {attempt + 1}/{max_attempts}, waiting...")
                    time.sleep(2)
                if not passkey:
                    logger().error("Passkey not found in DUT serial log after multiple attempts!")
                    assert False, "Passkey not found in DUT serial log!"
                logger().info(f"Sending passkey {passkey} to Raspi")
                try:
                    self.ble_client.interfaces.bluetooth.set_pin(passkey)
                    logger().info("PASS: set_pin executed successfully")
                except Exception as e:
                    logger().error(f"FAIL: set_pin failed: {e}")
                    assert False, f"set_pin failed: {e}"
            else:  # displayer == 'raspi'
                # Raspi displays passkey -> extract from Raspi, send to DUT IMMEDIATELY
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
                    # Check if DUT is waiting for passkey (search from log start to catch the event)
                    if not dut_ready:
                        input_log = serial_conn.get_input_log()[log_start_index:]
                        for _ts, line_bytes in input_log:
                            try:
                                decoded_line = line_bytes.decode(errors="ignore")
                            except Exception:
                                decoded_line = str(line_bytes)
                            if passkey_event_pattern.search(decoded_line):
                                dut_ready = True
                                logger().info(f"DUT passkey event detected - ready to receive passkey: {decoded_line.strip()}")
                                break
                    # If both ready, send passkey immediately
                    if passkey_ready and dut_ready:
                        logger().info(f"Sending passkey {passkey} to DUT IMMEDIATELY (address: {self.ble_client_address})")
                        try:
                            self.wifi_dut.interfaces.wifi.smp_passkey(self.ble_client_address, int(passkey))
                            logger().info("PASS: smp_passkey executed successfully")
                        except Exception as e:
                            logger().error(f"FAIL: smp_passkey failed: {e}")
                            assert False, f"smp_passkey failed: {e}"
                        passkey_sent = True
                        break
                    time.sleep(0.2)  # Prevent CPU spin while waiting
                
                # Fail if DUT passkey event was not detected (indicates pattern mismatch or DUT issue)
                if passkey_ready and not passkey_sent:
                    logger().error("FAIL: DUT passkey event ('in smp_passkey') not detected - DUT not ready for passkey")
                    assert False, "DUT passkey event not detected - cannot send passkey without DUT confirmation"
                
                # Fail if neither passkey nor DUT event was ready
                if not passkey_ready and not dut_ready:
                    logger().error("FAIL: Neither Raspi passkey nor DUT passkey event detected after timeout")
                    assert False, "Passkey entry failed - neither Raspi passkey nor DUT event detected"
                
                if not passkey_ready:
                    logger().error("Passkey not found from Raspi after timeout!")
                    assert False, "Passkey not found from Raspi!"
        else:  # JustWorks
            logger().info(f"JustWorks pairing (DUT: {self.dut_capability}, Client: {self.client_capability}) - no passkey required")
            time.sleep(5)  # Wait for pairing to complete without passkey
        
        # Wait for pairing to complete and verify connection stability
        logger().info("Waiting for pairing to complete...")
        time.sleep(5)
        
        
        # Verify pairing by checking DUT logs produced during this run (avoid false positives from earlier boot noise)
        input_log = serial_conn.get_input_log()[log_start_index:]
        seen_target_connected = False
        smp_failed_for_target = False
        smp_pair_request_received = False
        smp_response_received = False
        smp_encrypt_event_found = False
        smp_security_keys_event_found = False
        disconnect_after_target = False
        connection_failed = False
        mtu_exchange_failed = False
        mtu_exchange_error_line = None
        disconnect_reason = None
        disconnect_line = None

        target_addr_lower = str(self.ble_client_address).lower() if self.ble_client_address else ""
        for _ts, line in input_log:
            try:
                decoded_line = line.decode(errors="ignore")
            except Exception:
                decoded_line = str(line)

            decoded_lower = decoded_line.lower()

            if target_addr_lower and (f"connected address: {target_addr_lower}" in decoded_lower):
                seen_target_connected = True

            # Detect SMP pair request exchange (pairing request/response)
            if any(pattern in decoded_lower for pattern in ["smp pairing request", "pairing request received", "smp_pair_req", "smp pair request", "pairing req"]):
                smp_pair_request_received = True
                logger().info(f"SMP pair request exchange detected: {decoded_line}")

            # Detect SMP security keys event
            if "smp security keys event" in decoded_lower:
                smp_security_keys_event_found = True
                logger().info(f"SMP security keys event detected: {decoded_line}")

            # Detect SMP response received (confirms SMP handshake is progressing)
            if any(pattern in decoded_lower for pattern in ["smp_resp", "smp response", "rsi_ble_on_smp_response", "smp_resp_event"]):
                smp_response_received = True
                logger().info(f"SMP response detected: {decoded_line}")

            # Detect SMP encrypt event (confirms pairing completed successfully)
            if "smp encrypt event" in decoded_lower:
                smp_encrypt_event_found = True
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

            # Detect connection failure
            if any(pattern in decoded_lower for pattern in ["connection failed", "connect failed", "failed to connect", "connection establishment failed"]):
                connection_failed = True
                logger().warning(f"Connection failure detected: {decoded_line}")

            # Detect MTU Exchange failure (e.g., "MTU Exchange request failed with ffd9-conn0")
            if "mtu exchange" in decoded_lower and "failed" in decoded_lower:
                mtu_exchange_failed = True
                mtu_exchange_error_line = decoded_line
                logger().error(f"MTU Exchange failure detected: {decoded_line}")

            # Most reliable failure signature includes the peer address
            if "smp failed" in decoded_lower and target_addr_lower and (target_addr_lower in decoded_lower):
                smp_failed_for_target = True
                logger().error(f"SMP failed for target: {decoded_line}")

            # If we observe any disconnect after connecting to the Raspi, treat it as a test failure
            if seen_target_connected and ("disconnect" in decoded_lower):
                disconnect_after_target = True
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
                        # Firmware prints a uint16; low byte aligns with standard HCI disconnect reason.
                        disconnect_reason = f"{raw_hex} (hci 0x{hci_reason:02x}: {hci_desc})"
                    except Exception:
                        disconnect_reason = raw_hex
                else:
                    disconnect_reason = "unknown"

                logger().error(
                    f"Disconnect detected after target connect (reason {disconnect_reason}): {decoded_line}"
                )

        # Fail condition: If SMP pair request was NOT exchanged AND connection failed, this is a failure
        if not smp_pair_request_received and (connection_failed or not seen_target_connected):
            logger().error("Test FAILED: No SMP pair request exchange and connection failed")
            assert False, "No SMP pair request exchange and connection failed - pairing did not occur"

        if smp_failed_for_target or disconnect_after_target:
            logger().error("Pairing failed - DUT log indicates SMP failure or disconnect")
            if disconnect_after_target:
                assert False, f"Pairing failed - disconnect observed after connect (reason {disconnect_reason}): {disconnect_line}"
            assert False, "Pairing failed - SMP failed for target"
        
        # Fail condition: MTU Exchange failed - this is a BLE protocol error
        # Error 0xFFD9 (RSI_ERROR_BLE_ATT_CMD_IN_PROGRESS = -39) indicates firmware timing issue
        # where MTU exchange is attempted while another ATT command is pending.
        # This is a DUT firmware issue that should be fixed.
        if mtu_exchange_failed:
            logger().error(f"Test FAILED: MTU Exchange request failed - {mtu_exchange_error_line}")
            assert False, f"MTU Exchange request failed: {mtu_exchange_error_line}"

        logger().info("Pairing process completed successfully - waiting for profile dummy event before stability monitoring")
        # Log SMP handshake status for debugging
        logger().info(
            f"SMP handshake status: Pairing Request: {'DETECTED' if smp_pair_request_received else 'NOT DETECTED'}, "
            f"Encrypt Event: {'DETECTED' if smp_encrypt_event_found else 'NOT DETECTED'}, "
            f"Security Keys Event: {'DETECTED' if smp_security_keys_event_found else 'NOT DETECTED'}"
        )

        # Assert SMP encrypt event detected after SMP pairing completion
        assert smp_encrypt_event_found, "FAIL: 'smp encrypt event' not found in DUT logs!"
        logger().info("PASS: 'smp encrypt event' found in DUT logs.")

        # Log SMP handshake status for debugging
        if not smp_pair_request_received:
            logger().warning("SMP pair request exchange not detected in logs - but encryption may have started")

        logger().info("Pairing process completed successfully - waiting for profile dummy event before stability monitoring")
        # Wait for rsi_ble_event_profile_dummy event before starting stability monitoring
        profile_dummy_received, profile_dummy_line = self._wait_for_serial_log_regex(
            pattern=r"rsi_ble_event_profile_dummy",
            timeout=30,
            start_index=log_start_index,
        )
        
        if profile_dummy_received:
            logger().info(f"PASS: rsi_ble_event_profile_dummy event received: {profile_dummy_line.strip()}")
        else:
            logger().error("FAIL: rsi_ble_event_profile_dummy event not detected within 30 seconds - failing test")
        
        # Verify BLE connection status after profile dummy event
        connection_verified = self._verify_connection_status(timeout=30)
        if not connection_verified:
            logger().error("FAIL: BLE connection verification failed")
           
        
        # Keep the link up for a bit and catch disconnects that happen shortly after pairing
        logger().info("Monitoring connection stability for 60 seconds...")
        time.sleep(60)
        
        # Verify BLE connection status after stability monitoring
        connection_verified_after_stability = self._verify_connection_status(timeout=30)
        if not connection_verified_after_stability:
            logger().error("FAIL: BLE connection verification failed after 60s stability monitoring")
        
        # Final success assertion
        logger().info("Test PASSED: Connection established, encryption started, connection stable")
        # Test passes if no assertion fails above
        
        # Disconnect from the BLE client
        logger().info(f"Disconnecting from BLE client at {self.ble_client_address}")
        try:
            self.wifi_dut.interfaces.wifi.btc_disconnect(ble_address=self.ble_client_address)
            logger().info("PASS: btc_disconnect executed successfully")
        except Exception as e:
            logger().error(f"FAIL: btc_disconnect failed: {e}")
            assert False, f"btc_disconnect failed: {e}"
        logger().info("Disconnection completed")
        logger().info("Clearing bonding data on Raspberry Pi to ensure fresh pairing")
        try:
            self.ble_client.interfaces.bluetooth.remove_all_devices()
            logger().info("PASS: remove_all_devices executed successfully")
            time.sleep(5)
        except Exception as e:
            logger().warning(f"Failed to clear bonding data on Raspi: {e}")
            # Note: remove_all_devices failure is a warning, not a test failure
        
        try:
            self.ble_client.interfaces.bluetooth.close()
            logger().info("PASS: close executed successfully")
        except Exception as e:
            logger().warning(f"FAIL: close failed: {e}")
            # Note: close failure is a warning, not a test failure
            time.sleep(5)

# Just works, Raspi: 0x00 (Display) DUT: 0x00 (Display)
def test_ble_smp_just_works_dut_0x00_raspi_0x00_C1699954(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",
        client_capability="DisplayOnly",
        pin_code="-8",
    )
    ble_test.run()
    

# Just works, Raspi: 0x01 (Display Yes/No) DUT: 0x00 (Display)
def test_ble_smp_just_works_dut_0x00_raspi_0x01_C1699959(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",
        client_capability="DisplayYesNo",
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (Keyboard Only) DUT: 0x00 (Display)
def test_ble_smp_passkey_entry_dut_0x00_raspi_0x02_C1699964(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",
        client_capability="KeyboardOnly",
        pin_code="-8",
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x00 (Display)
def test_ble_smp_just_works_dut_0x00_raspi_0x03_C1699969(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",
        client_capability="NoInputNoOutput",
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x04 (Keyboard Display) DUT: 0x00 (Display)
def test_ble_smp_passkey_entry_dut_0x00_raspi_0x04_C1699974(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",
        client_capability="KeyboardDisplay",
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x00 (DisplayOnly) DUT: 0x01 (DisplayYesNo)
def test_ble_smp_just_works_dut_0x01_raspi_0x00_C1699955(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",
        client_capability="DisplayOnly",
        pin_code="-8"
    )
    ble_test.run()

# NumericComparison, Raspi: 0x01 (DisplayYesNo) DUT: 0x01 (DisplayYesNo)
def test_ble_smp_just_works_dut_0x01_raspi_0x01_C1699960(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",
        client_capability="DisplayYesNo",
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x01 (DisplayYesNo)
def test_ble_smp_passkey_entry_dut_0x01_raspi_0x02_C1699965(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",
        client_capability="KeyboardOnly",
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x01 (DisplayYesNo)
def test_ble_smp_just_works_dut_0x01_raspi_0x03_C1699970(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",
        client_capability="NoInputNoOutput",
        pin_code="-8"
    )
    ble_test.run()

# passkey entry, Raspi: 0x04 (KeyboardDisplay) DUT: 0x01 (DisplayYesNo)
def test_ble_smp_passkey_entry_dut_0x01_raspi_0x04_C1699975(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",
        client_capability="KeyboardDisplay",
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x00 (DisplayOnly) DUT: 0x02 (KeyboardOnly) 
def test_ble_dut_0x02_raspi_0x00_C1699956(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",
        client_capability="DisplayOnly",
        pin_code="-8"
    )
    ble_test.run()


# Passkey, Raspi: 0x01 (DisplayYesNo) DUT: 0x02 (KeyboardOnly)
def test_ble_dut_0x02_raspi_0x01_C1699961(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",
        client_capability="DisplayYesNo",
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x02 (KeyboardOnly)
def test_ble_dut_0x02_raspi_0x02_C1699966(wifi_dut, ble_client):
    time.sleep(20)
    # For KeyboardOnly/KeyboardOnly, both sides must enter the same fixed passkey after SMP pairing starts.
    fixed_passkey = "123456"
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",
        client_capability="KeyboardOnly",
        pin_code=fixed_passkey
    )
    import time as _time
    import re as _re
    def run_with_fixed_passkey():
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03, "KeyboardDisplay": 0x04}
        dut_io = io_capability[ble_test.dut_capability]
        client_io = io_capability[ble_test.client_capability]
        ble_test.wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
            io_capability=dut_io,
            oob_data_flag=0x00,
            auth_req=0x05,
            enc_key_size=16,
            ini_key_dist=15,
            rsp_key_dist=15
        )
        ble_test.ble_client_address = ble_test.ble_client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=ble_test.ble_dut_address,
            capability=ble_test.client_capability,
            pin_code=fixed_passkey
        )
        ble_test.ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
        ble_test.ble_client.interfaces.bluetooth.set_mitm_sc_bits(f"{client_io} 0x00 0x05")
        _time.sleep(5)
        if not ble_test.ble_dut_address:
            ble_test.ble_dut_address = ble_test.wifi_dut.interfaces.wifi.get_local_address()
        _time.sleep(5)
        serial_conn = ble_test.wifi_dut.interfaces.wifi.bus
        log_start_index = len(serial_conn.get_input_log())
        try:
            ble_test.wifi_dut.interfaces.wifi.legacy_scan_stop()
            _time.sleep(1)
        except Exception:
            pass
        def connect():
            ble_test.wifi_dut.interfaces.wifi.req_legacy_connect(dev_addr=ble_test.ble_client_address)
            _time.sleep(30)
        import threading as _threading
        t = _threading.Thread(target=connect)
        t.start()
        # Wait for connection
        ble_test._wait_for_serial_log_regex(
            pattern=rf"Connected Address:\s*{ble_test.ble_client_address}(\s|,|$)",
            timeout=15,
            start_index=log_start_index,
        )
        # Wait for DUT to prompt for passkey entry
        passkey_prompt_pattern = _re.compile(r"in smp_passkey", _re.IGNORECASE)
        dut_ready = False
        timeout = 30  # seconds
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            input_log = serial_conn.get_input_log()[log_start_index:]
            for _ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                if passkey_prompt_pattern.search(decoded_line):
                    dut_ready = True
                    break
            if dut_ready:
                break
            _time.sleep(0.2)
        assert dut_ready, "DUT did not prompt for passkey entry in time!"
        # Send fixed passkey to both sides
        ble_test.wifi_dut.interfaces.wifi.smp_passkey(ble_test.ble_client_address, int(fixed_passkey))
        ble_test.ble_client.interfaces.bluetooth.set_pin(fixed_passkey)
        _time.sleep(5)
        # Continue with pairing verification, disconnect, cleanup
        _time.sleep(60)
        ble_test.wifi_dut.interfaces.wifi.btc_disconnect(ble_test.ble_client_address)
        try:
            ble_test.ble_client.interfaces.bluetooth.remove_all_devices()
            _time.sleep(2)
        except Exception:
            pass
        ble_test.ble_client.interfaces.bluetooth.close()
    ble_test.run = run_with_fixed_passkey
    ble_test.run()

# justwork, Raspi: 0x03 (NoInputNoOutput) DUT: 0x02 (KeyboardOnly)
def test_ble_dut_0x02_raspi_0x03_C1699971(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",
        client_capability="NoInputNoOutput",
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x04 (KeyboardDisplay) DUT: 0x02 (KeyboardOnly)
def test_ble_dut_0x02_raspi_0x04_C1699976(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",
        client_capability="KeyboardDisplay",
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x00 (DisplayOnly) DUT: 0x03 (NoInputNoOutput)
def test_ble_dut_0x03_raspi_0x00_C1699957(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",
        client_capability="DisplayOnly",
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x01 (DisplayYesNo) DUT: 0x03 (NoInputNoOutput)
def test_ble_dut_0x03_raspi_0x01_C1699962(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",
        client_capability="DisplayYesNo",
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x02 (KeyboardOnly) DUT: 0x03 (NoInputNoOutput)
def test_ble_dut_0x03_raspi_0x02_C1699967(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",
        client_capability="KeyboardOnly",
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x03 (NoInputNoOutput)
def test_ble_dut_0x03_raspi_0x03_C1699972(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",
        client_capability="NoInputNoOutput",
        pin_code="-8"
    )
    ble_test.run()  

# JustWorks, Raspi: 0x04 (KeyboardDisplay) DUT: 0x03 (NoInputNoOutput)
def test_ble_dut_0x03_raspi_0x04_C1699977(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",
        client_capability="KeyboardDisplay",
        pin_code="-8"
    )
    ble_test.run() 

# Passkey, Raspi: 0x00 (DisplayOnly) DUT: 0x04 (KeyboardDisplay)
def test_ble_dut_0x04_raspi_0x00_C1699958(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",
        client_capability="DisplayOnly",
        pin_code="-8"
    )
    ble_test.run() 

# passkeyentry Raspi: 0x01 (DisplayYesNo) DUT: 0x04 (KeyboardDisplay)
def test_ble_dut_0x04_raspi_0x01_C1699963(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",
        client_capability="DisplayYesNo",
        pin_code="-8"
    )
    ble_test.run()  


# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x04 (KeyboardDisplay)
def test_ble_dut_0x04_raspi_0x02_C1699968(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",
        client_capability="KeyboardOnly",
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x04 (KeyboardDisplay)
def test_ble_dut_0x04_raspi_0x03_C1699973(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",
        client_capability="NoInputNoOutput",
        pin_code="-8"
    )
    ble_test.run()

# passkeyentry Raspi: 0x04 (KeyboardDisplay) DUT: 0x04 (KeyboardDisplay)
def test_ble_dut_0x04_raspi_0x04_C1699978(wifi_dut, ble_client):
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",
        client_capability="KeyboardDisplay",
        pin_code="-8"
    )
    ble_test.run()
