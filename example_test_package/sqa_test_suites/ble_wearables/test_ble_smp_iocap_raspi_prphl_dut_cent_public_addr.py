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

Hardware Setup:
    - DUT: Si91x-based BLE Central configured with specific IO capabilities for each test case.
    - Raspberry Pi: BLE Peripheral device running the UTF BLE client interface.

Author: Ashish Chittimilla
Date: 7th November 2025
"""


import os
import time
import threading
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
import re
import yaml
import pytest

def logger():
    return get_logger(__name__)

# --- Load BLE/BT error codes from YAML for human-readable error reporting ---
_ERROR_CODE_MAP = {}

def _load_error_codes():
    """Load error codes from config/error_codes.yaml into a flat lookup dict.
    Keys are normalised hex strings (uppercase, e.g. '0x4E13').
    Called once at module import time."""
    global _ERROR_CODE_MAP
    yaml_path = os.path.join(
        os.path.dirname(__file__), '..', '..', '..', '..', '..', 'config', 'error_codes.yaml'
    )
    alt_yaml_path = os.path.join(
        os.path.dirname(__file__), '..', '..', '..', '..', 'config', 'error_codes.yaml'
    )
    for path in [yaml_path, alt_yaml_path]:
        path = os.path.normpath(path)
        if os.path.isfile(path):
            try:
                with open(path, 'r') as f:
                    data = yaml.safe_load(f)
                for section_name, entries in data.items():
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        code = entry.get('code')
                        hex_val = entry.get('hex', '')
                        desc = entry.get('description', 'Unknown error')
                        if isinstance(code, str) and code.startswith('0x'):
                            _ERROR_CODE_MAP[code.upper()] = desc
                        elif hex_val and isinstance(hex_val, str):
                            _ERROR_CODE_MAP[hex_val.upper()] = desc
                        # Note: PyYAML parses '0x4E16' as int 20006, so most
                        # codes come through this path.  .upper() ensures the
                        # key format ('0X4E16') matches lookup normalisation.
                        if isinstance(code, int) and code > 0:
                            _ERROR_CODE_MAP[f'0x{code:04X}'.upper()] = desc
                        elif isinstance(code, int) and code < 0:
                            _ERROR_CODE_MAP[f'{code}'] = desc
                logger().info(f"Loaded {len(_ERROR_CODE_MAP)} error codes from {path}")
                return
            except Exception as e:
                logger().warning(f"Failed to load error_codes.yaml from {path}: {e}")
    logger().warning("error_codes.yaml not found — error code lookup will be unavailable")

_load_error_codes()


def lookup_error_code(code_str):
    """Look up a hex error code string (e.g. '0x4E13') and return its description.
    Returns None if not found."""
    normalised = code_str.strip().upper()
    if not normalised.startswith('0X'):
        normalised = '0X' + normalised
    normalised = normalised.replace('0X', '0x').upper()
    desc = _ERROR_CODE_MAP.get(normalised)
    if desc:
        return desc
    stripped = '0x' + normalised[2:].lstrip('0')
    if not stripped[2:]:
        stripped = '0x0'
    return _ERROR_CODE_MAP.get(stripped.upper())

# --- Module-level cached DUT BD address ---
_cached_dut_address = None
_BD_ADDR_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

def get_dut_address(wifi_dut):
    """
    Retrieve the DUT BD address dynamically via CLI and cache it for all
    subsequent test cases.  No hardcoded fallback — the address is always
    queried from the DUT so the script works on any setup without edits.

    Returns:
        str: BD address in XX:XX:XX:XX:XX:XX format.

    Raises:
        RuntimeError: If the address cannot be retrieved.
    """
    global _cached_dut_address
    if _cached_dut_address is not None:
        logger().info(f"DUT BD Address (cached): {_cached_dut_address}")
        return _cached_dut_address

    try:
        dynamic_address = wifi_dut.interfaces.wifi.get_local_address()
        if dynamic_address and _BD_ADDR_PATTERN.match(dynamic_address.strip()):
            _cached_dut_address = dynamic_address.strip()
            logger().info(f"DUT BD Address (retrieved dynamically): {_cached_dut_address}")
            return _cached_dut_address
        else:
            raise RuntimeError(
                f"get_local_address() returned invalid/empty value: '{dynamic_address}'. "
                f"Ensure the DUT is powered on and the 'btc gap get_local_address' CLI command is available."
            )
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(
            f"Failed to retrieve DUT BD address: {e}. "
            f"Ensure the DUT is powered on and the 'btc gap get_local_address' CLI command is available."
        )


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
        #OOB (Out-of-Band) Data Flag
        #0x00 = OOB authentication data not present
        #0x01 = OOB authentication data from remote device present
        self.oob_data_flag = oob_data_flag  # Added OOB data flag parameter
        self.ble_dut_address = None
        self.ble_client_address = None
        self.connection_successful = False
        self.pairing_successful = False
    
    def _check_dut_serial_log_for_errors(self):
        """Scan DUT serial log for BLE/BT error codes and log their human-readable descriptions.
        Looks for hex patterns like 0x4E13, 0x4BFC, etc. in the DUT serial output and
        cross-references them against config/error_codes.yaml.
        Returns a list of (error_code, description) tuples found."""
        errors_found = []
        try:
            serial_conn = self.wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            error_pattern = re.compile(r'(?:reason|error|status|err_code|failed)[\s:]*?(0x[0-9A-Fa-f]{3,8})', re.IGNORECASE)
            seen_codes = set()
            for _ts, line in input_log:
                try:
                    decoded = line.decode(errors="ignore")
                except Exception:
                    decoded = str(line)
                for match in error_pattern.finditer(decoded):
                    code_str = match.group(1).upper()
                    if code_str in seen_codes:
                        continue
                    seen_codes.add(code_str)
                    description = lookup_error_code(code_str)
                    if description:
                        logger().error(f"DUT Error Code {code_str}: {description}")
                        errors_found.append((code_str, description))
                    else:
                        logger().warning(f"DUT Error Code {code_str}: (not found in error_codes.yaml)")
                        errors_found.append((code_str, "Unknown error code"))
        except Exception as e:
            logger().warning(f"Could not scan DUT serial log for error codes: {e}")
        return errors_found

    def _get_log_snapshot(self):
        """Return the current DUT serial log length as a snapshot index.
        Used to isolate log entries for a specific command — only lines
        after the snapshot belong to that command's response."""
        try:
            serial_conn = self.wifi_dut.interfaces.wifi.bus
            return len(serial_conn.get_input_log())
        except Exception:
            return 0

    def _assert_dut_command_success(self, command_name, log_start_index, timeout=5):
        """Proactively check DUT serial log for errors after a command.

        Reads only NEW serial log entries (after log_start_index) to check
        whether the command succeeded or returned an error code.

        If an error code is found, it is looked up in error_codes.yaml and
        the test is failed immediately with a descriptive assertion message
        so the framework can move on to the next test case.

        Args:
            command_name: Human-readable name of the command (for logging).
            log_start_index: Snapshot index from _get_log_snapshot() taken
                             before the command was sent.
            timeout: Seconds to wait for the command response to appear in
                     the serial log before checking.
        """
        time.sleep(timeout)  # Give firmware time to print response
        try:
            serial_conn = self.wifi_dut.interfaces.wifi.bus
            input_log = serial_conn.get_input_log()
            new_entries = input_log[log_start_index:]

            error_pattern = re.compile(
                r'(?:reason|error|status|err_code|failed)[\s:]*?(0x[0-9A-Fa-f]{3,8})',
                re.IGNORECASE
            )

            for _ts, line in new_entries:
                try:
                    decoded = line.decode(errors="ignore")
                except Exception:
                    decoded = str(line)

                for match in error_pattern.finditer(decoded):
                    code_str = match.group(1).upper()
                    description = lookup_error_code(code_str) or "Unknown error code"
                    logger().error(
                        f"\u274c Command '{command_name}' returned error {code_str}: {description}"
                    )
                    assert False, (
                        f"DUT command '{command_name}' failed with error {code_str}: {description}. "
                        f"Skipping remaining steps for this test case."
                    )

            logger().info(f"\u2705 Command '{command_name}' — no error codes detected in DUT response.")
        except AssertionError:
            raise  # Re-raise so pytest catches it
        except Exception as e:
            logger().warning(f"Could not verify command '{command_name}' response: {e}")

    def _wait_for_smp_passkey_event(self, timeout=30, log_start_index=0):
        """Wait for the 'smp sc passkey event' to appear in DUT serial logs.

        The DUT firmware prints 'in smp sc passkey event' when it is ready to
        accept a passkey via the smp_passkey CLI command.  Sending the passkey
        before this event causes an SMP timeout (error 0x4BFC).

        Args:
            timeout: Maximum seconds to wait for the event.
            log_start_index: Snapshot index from _get_log_snapshot() taken
                             before the connect command was issued.

        Returns:
            True if the event was found, False on timeout.
        """
        serial_conn = self.wifi_dut.interfaces.wifi.bus
        SMP_PASSKEY_EVENT_PATTERN = re.compile(r'in smp sc passkey event', re.IGNORECASE)

        for elapsed in range(timeout):
            input_log = serial_conn.get_input_log()
            new_entries = input_log[log_start_index:]
            for _ts, line in new_entries:
                try:
                    decoded = line.decode(errors="ignore")
                except Exception:
                    decoded = str(line)
                if SMP_PASSKEY_EVENT_PATTERN.search(decoded):
                    logger().info(f"\u2705 SMP SC passkey event detected after ~{elapsed}s")
                    return True
            time.sleep(1)

        logger().warning(f"\u274c Timeout ({timeout}s) waiting for 'smp sc passkey event' in DUT logs.")
        return False

    def _wait_for_ltk_in_logs(self, device_label, timeout=30, log_start_index=0):
        """Wait for LE LTK generation in DUT serial logs.

        The LE LTK banner is the authoritative proof that SMP pairing completed
        successfully — it is printed by the Si91x firmware only when the Long
        Term Key has been generated and stored.

        Uses a strict regex requiring the asterisk-bordered banner pattern
        (e.g. '****  LE LTK  ****') to avoid false positives from random data
        content that may contain 'LTK' as a substring.

        Only NEW serial log entries (after log_start_index) are checked so that
        LTK banners from previous connections do not create false positives.

        Args:
            device_label: Human-readable label for logging (e.g. 'DUT-Central').
            timeout: Maximum seconds to wait for LTK to appear.
            log_start_index: Snapshot index from _get_log_snapshot() taken
                             before the connect command was issued.

        Returns:
            True if LTK banner was found, False otherwise.
        """
        serial_conn = self.wifi_dut.interfaces.wifi.bus
        # The actual LTK banner in serial log looks like:
        #   **************************
        #    LE LTK
        #   d0 46 73 03 85 eb 2c fa 9f 33 56 5c 9f dc 64 2d
        #   **************************
        LTK_BANNER_PATTERN = re.compile(r'\*{5,}.*?LE\s+LTK', re.DOTALL)

        for _ in range(timeout):
            input_log = serial_conn.get_input_log()
            new_entries = input_log[log_start_index:]
            # Combine all new entries into a single string for multi-line pattern matching
            combined = ""
            for _ts, line in new_entries:
                try:
                    decoded = line.decode(errors="ignore")
                except Exception:
                    decoded = str(line)
                combined += decoded + "\n"

            if LTK_BANNER_PATTERN.search(combined):
                # Try to extract the actual LTK hex bytes for logging
                ltk_hex = re.search(
                    r'LE\s+LTK\s*\n\s*([0-9a-f]{2}[\s][0-9a-f]{2}.*)', combined
                )
                if ltk_hex:
                    logger().info(f"\u2705 LTK confirmed for {device_label}: {ltk_hex.group(1).strip()[:80]}")
                else:
                    logger().info(f"\u2705 LTK confirmed for {device_label} (banner pattern matched)")
                return True

            # Early exit on disconnect/restart indicators
            if "device disconnected" in combined.lower() or "restarted advertising" in combined.lower():
                logger().warning(f"Disconnect/restart detected while waiting for LTK ({device_label}).")
                return False

            time.sleep(1)

        logger().warning(f"\u274c Timeout waiting for LTK generation for {device_label}.")
        return False

    def _verify_connection_status(self, timeout=30):
        """
        Verify BLE connection status with retries.
        
        Args:
            timeout: Maximum time to wait for connection verification
            
        Returns:
            bool: True if connected, False otherwise
        """
        logger().info(f"Verifying connection status to {self.ble_client_address}...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                connection_status = self.ble_client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
                logger().info(f"Connection status: {connection_status}")
                if connection_status:
                    logger().info(f"✅ Connection verified to {self.ble_client_address}")
                    return True
            except Exception as e:
                logger().warning(f"Could not get connection status: {e}")
            time.sleep(2)
        
        logger().error(f"❌ Connection verification failed after {timeout}s")
        return False
    
    def _verify_pairing_status(self, timeout=30):
        """
        Verify BLE pairing/bonding status.
        
        Args:
            timeout: Maximum time to wait for pairing verification
            
        Returns:
            bool: True if paired, False otherwise
        """
        logger().info(f"Verifying pairing status with {self.ble_client_address}...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Check if device is paired using the Paired property
                paired_status = self.ble_client.interfaces.bluetooth.get_remote_device_property(
                    self.ble_dut_address, prop="Paired"
                )
                logger().info(f"Paired status: {paired_status}")
                if paired_status:
                    logger().info(f"✅ Pairing verified with {self.ble_client_address}")
                    return True
            except Exception as e:
                logger().warning(f"Could not get pairing status: {e}")
            time.sleep(2)
        
        logger().error(f"❌ Pairing verification failed after {timeout}s")
        return False

    def _extract_passkey_from_log(self):
        """Extract passkey from DUT serial log and ensure it's 6 digits with leading zeros if needed"""
        serial_conn = self.wifi_dut.interfaces.wifi.bus  # HostSerialConnectionAsync
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
    
    def run(self):
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03, "KeyboardDisplay": 0x04}
        
        # Determine pairing method and auth_req based on IO capabilities
        dut_io = io_capability[self.dut_capability]
        client_io = io_capability[self.client_capability]
        
        # JustWorks scenarios (no MITM protection possible - use auth_req=0x01)
        # Format: (DUT/Initiator IO, Raspi/Responder IO)
        # DUT is Central (Initiator), Raspi is Peripheral (Responder)
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
        # Format: (DUT/Initiator IO, Raspi/Responder IO)
        numeric_comparison_scenarios = [
            (0x01, 0x01),  # DisplayYesNo + DisplayYesNo
            (0x01, 0x04),  # DisplayYesNo + KeyboardDisplay
            (0x04, 0x01),  # KeyboardDisplay + DisplayYesNo
            (0x04, 0x04),  # KeyboardDisplay + KeyboardDisplay
        ]
        
        # Passkey Entry scenarios - Initiator (DUT) DISPLAYS, Responder (Raspi) ENTERS
        # The DUT generates and displays the passkey, Raspi must enter it
        # Format: (DUT/Initiator IO, Raspi/Responder IO)
        passkey_initiator_displays_scenarios = [
            (0x00, 0x02),  # DisplayOnly + KeyboardOnly -> DUT displays, Raspi enters
            (0x00, 0x04),  # DisplayOnly + KeyboardDisplay -> DUT displays, Raspi enters
            (0x01, 0x02),  # DisplayYesNo + KeyboardOnly -> DUT displays, Raspi enters
            (0x04, 0x02),  # KeyboardDisplay + KeyboardOnly -> DUT displays, Raspi enters
            (0x02, 0x02),  # KeyboardOnly + KeyboardOnly -> DUT displays, Raspi enters
        ]
        
        # Passkey Entry scenarios - Responder (Raspi) DISPLAYS, Initiator (DUT) ENTERS
        # The Raspi generates and displays the passkey, DUT must enter it
        # Format: (DUT/Initiator IO, Raspi/Responder IO)
        passkey_responder_displays_scenarios = [
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
        elif (dut_io, client_io) in passkey_initiator_displays_scenarios:
            pairing_method = "PasskeyEntry"
            passkey_direction = "dut_displays"  # DUT (initiator) displays, Raspi (responder) enters
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        elif (dut_io, client_io) in passkey_responder_displays_scenarios:
            pairing_method = "PasskeyEntry"
            passkey_direction = "raspi_displays"  # Raspi (responder) displays, DUT (initiator) enters
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        else:
            # Fallback - should not reach here if all scenarios are covered
            pairing_method = "PasskeyEntry"
            passkey_direction = "dut_displays"  # Default: DUT displays
            auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
        
        # Use the module-level cached DUT address (retrieved once, reused by all tests)
        self.ble_dut_address = get_dut_address(self.wifi_dut)
        time.sleep(5)

        logger().info(f"Pairing Method: {pairing_method}, Passkey Direction: {passkey_direction}, auth_req=0x{auth_req_value:02X} ({auth_req_value} decimal)")
        logger().info(f"DUT IO: {self.dut_capability} (0x{dut_io:02X}), Raspi IO: {self.client_capability} (0x{client_io:02X})")
        
        # Set MITM and security requirements in BLE client (Raspi)
        # Format IO capability and auth_req as hex strings for the HCI command
        raspi_io_cap = f"0x{io_capability[self.client_capability]:02x}"
        raspi_auth_req = f"0x{auth_req_value:02x}"
        logger().info(f"Setting Raspi SMP params: IO={raspi_io_cap}, OOB={self.oob_data_flag}, auth_req={raspi_auth_req}")
        self.ble_client.interfaces.bluetooth.set_mitm_sc_bits(f"{raspi_io_cap} {self.oob_data_flag} {raspi_auth_req}")
        
        test_failure = None  # Track any test failure to re-raise after cleanup
        try:
            self._run_test_logic(io_capability, pairing_method, passkey_direction, auth_req_value)
        except Exception as e:
            test_failure = e
            logger().error(f"Test failed with error: {e}")
        finally:
            self._cleanup()
        
        if test_failure:
            raise test_failure

    def _cleanup(self):
        """Perform cleanup actions to ensure proper state for subsequent tests."""
        logger().info("=" * 60)
        logger().info("CLEANUP: Ensuring proper teardown for next test case...")
        logger().info("=" * 60)
        try:
            if self.ble_client_address:
                logger().info(f"Disconnecting DUT from BLE client at {self.ble_client_address}")
                self.wifi_dut.interfaces.wifi.btc_disconnect(ble_address=self.ble_client_address)
                logger().info("Disconnection command sent")
                time.sleep(2)
        except Exception as e:
            logger().warning(f"Cleanup: disconnect failed (may already be disconnected): {e}")
        
        try:
            if self.ble_dut_address:
                logger().info(f"Removing device {self.ble_dut_address} from Raspi")
                self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.ble_dut_address)
        except Exception as e:
            logger().warning(f"Cleanup: remove_device failed: {e}")
        
        try:
            logger().info("Closing Raspi BLE client bus")
            self.ble_client.interfaces.bluetooth.close()
        except Exception as e:
            logger().warning(f"Cleanup: close failed: {e}")
        
        logger().info("Cleanup completed.")

    def _run_test_logic(self, io_capability, pairing_method, passkey_direction, auth_req_value):
        """Main test logic separated from cleanup to allow try/finally pattern."""
        # Set SMP pairing capability data on DUT
        logger().info(f"Setting DUT SMP pairing capability: IO={io_capability[self.dut_capability]}, OOB={self.oob_data_flag}, auth_req={auth_req_value}")
        log_snap = self._get_log_snapshot()
        self.wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
            io_capability=io_capability[self.dut_capability],
            oob_data_flag=int(self.oob_data_flag, 16) if isinstance(self.oob_data_flag, str) else self.oob_data_flag,
            auth_req=auth_req_value,
            enc_key_size=16,
            ini_key_dist=15,
            rsp_key_dist=15
        )
        self._assert_dut_command_success("set_smp_pairing_capability_data", log_snap, timeout=3)
        
        logger().info(f"Start SMP advertising from the remote device (Raspi) with capability={self.client_capability}")
        # IMPORTANT: Pass the capability to start_smp_adv so BlueZ agent registers with correct IO capability
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.ble_dut_address,
            capability=self.client_capability,
            pin_code=self.pin_code
        )
        assert self.ble_client_address, "failed to initiate ble in remote device"
        time.sleep(5)

        
        
        def connect():
            """Initiate BLE connection from DUT (Central) to Raspi (Peripheral) in a thread.
            Runs in a separate thread because the connect call blocks until pairing completes."""
            logger().info(f"Connect and pair to the Remote Device ({pairing_method} - using req_legacy_connect)")
            self.wifi_dut.interfaces.wifi.req_legacy_connect(dev_addr=self.ble_client_address 
                                                            #  dev_name = "rt595"
                                                             )

        # Snapshot log before connection so we can check for connection-phase errors
        connect_log_snap = self._get_log_snapshot()
        t = threading.Thread(target=connect)
        t.start()
        
        # For PasskeyEntry and NumericComparison, we need to handle passkeys IMMEDIATELY
        # The SMP passkey timeout is very short (~1-2 seconds), so we can't wait
        if pairing_method in ["PasskeyEntry", "NumericComparison"]:
            # Short initial delay to let connection start
            logger().info("Waiting briefly for connection to initiate before passkey handling...")
            time.sleep(2)
            # Quick check for immediate connection errors (e.g. connection rejected)
            self._assert_dut_command_success("req_legacy_connect (initial)", connect_log_snap, timeout=0)
        else:
            # JustWorks doesn't need passkey, so we can wait longer
            logger().info("Waiting for BLE connection to establish...")
            time.sleep(5)
            # Check for connection errors after the wait
            self._assert_dut_command_success("req_legacy_connect (JustWorks)", connect_log_snap, timeout=0)
        
        if pairing_method == "PasskeyEntry":
            if passkey_direction == "dut_displays":
                # DUT (initiator) displays passkey, Raspi (responder) enters
                logger().info("Passkey Entry: DUT (Initiator) displays passkey, Raspi (Responder) enters")
                logger().info("Monitoring DUT serial logs for displayed passkey...")
                passkey = None
                max_attempts = 20  # More attempts with shorter delay
                for attempt in range(max_attempts):
                    passkey = self._extract_passkey_from_log()
                    if passkey:
                        break
                    logger().info(f"Passkey not found yet, attempt {attempt + 1}/{max_attempts}, waiting...")
                    time.sleep(0.5)  # Fast polling - SMP has short timeout
                
                if not passkey:
                    logger().error("Passkey not found in DUT serial log after multiple attempts!")
                    assert False, "Passkey not found in DUT serial log!"
                    
                # Raspi enters the passkey displayed by DUT
                logger().info(f"Raspi entering passkey from DUT: {passkey}")
                self.ble_client.interfaces.bluetooth.set_pin(passkey)
                
            elif passkey_direction == "raspi_displays":
                # Passkey Entry: Raspi (responder) generates and displays the passkey
                # DUT (initiator) must enter the passkey displayed by Raspi
                # DUT does NOT generate a passkey in this scenario
                logger().info("Passkey Entry: Raspi displays passkey, DUT enters it")
                logger().info("Only Raspi generates a passkey — DUT must enter it")
                
                raspi_passkey = None
                max_attempts = 20  # Fast polling due to SMP timeout
                
                # Get passkey from Raspi (the only side that generates one)
                for attempt in range(max_attempts):
                    if not raspi_passkey:
                        try:
                            raspi_pk = self.ble_client.interfaces.bluetooth.get_passkey()
                            if raspi_pk and str(raspi_pk) != "0":
                                raspi_passkey = str(raspi_pk).zfill(6)
                                logger().info(f"Raspi displayed passkey: {raspi_passkey}")
                        except Exception as e:
                            logger().debug(f"Could not get Raspi passkey yet: {e}")
                    
                    if raspi_passkey:
                        break
                    
                    logger().info(f"Waiting for Raspi passkey, attempt {attempt + 1}/{max_attempts}")
                    time.sleep(0.5)  # Fast polling - SMP has short timeout
                
                if raspi_passkey:
                    # Wait for DUT to be ready to accept passkey (smp sc passkey event)
                    logger().info("Waiting for DUT 'smp sc passkey event' before entering passkey...")
                    smp_event_ok = self._wait_for_smp_passkey_event(
                        timeout=30,
                        log_start_index=connect_log_snap
                    )
                    if not smp_event_ok:
                        logger().error("❌ SMP SC passkey event not received — DUT not ready for passkey entry!")
                        self._check_dut_serial_log_for_errors()
                        assert False, "DUT did not emit 'smp sc passkey event' — cannot enter passkey safely."

                    # DUT enters the passkey displayed by Raspi
                    logger().info(f"DUT entering Raspi's displayed passkey: {raspi_passkey}")
                    pk_snap = self._get_log_snapshot()
                    self.wifi_dut.interfaces.wifi.smp_passkey(
                        bd_addr=self.ble_client_address,
                        passkey=raspi_passkey
                    )
                    self._assert_dut_command_success("smp_passkey (DUT enters Raspi displayed key)", pk_snap, timeout=2)
                else:
                    logger().error("No passkey received from Raspi!")
                    assert False, "Raspi did not generate/display a passkey for DUT to enter!"
                
                
        elif pairing_method == "NumericComparison":
            # Numeric Comparison: Both devices display the same passkey
            # DUT (Initiator) and Raspi (Responder) both display - both need confirmation/entry
            logger().info(f"Numeric Comparison pairing (DUT/Initiator: {self.dut_capability}, Raspi/Responder: {self.client_capability})")
            logger().info("Both devices display passkey - extracting passkeys from both sides...")
            
            # Get passkeys from both sides quickly - SMP has short timeout
            dut_passkey = None
            raspi_passkey = None
            max_attempts = 20  # More attempts with shorter delay
            
            for attempt in range(max_attempts):
                # Get DUT passkey from serial log
                if not dut_passkey:
                    dut_passkey = self._extract_passkey_from_log()
                    if dut_passkey:
                        logger().info(f"DUT (Initiator) displayed passkey: {dut_passkey}")
                
                # Get Raspi passkey from BlueZ agent
                if not raspi_passkey:
                    try:
                        raspi_pk = self.ble_client.interfaces.bluetooth.get_passkey()
                        if raspi_pk and str(raspi_pk) != "0":
                            raspi_passkey = str(raspi_pk).zfill(6)
                            logger().info(f"Raspi (Responder) displayed passkey: {raspi_passkey}")
                    except Exception as e:
                        logger().debug(f"Could not get Raspi passkey yet: {e}")
                
                if dut_passkey and raspi_passkey:
                    break
                    
                logger().info(f"Waiting for passkeys, attempt {attempt + 1}/{max_attempts} (DUT: {dut_passkey}, Raspi: {raspi_passkey})")
                time.sleep(0.5)  # Fast polling - SMP has short timeout
            
            # Enter passkeys - cross-entry for Secure Connections
            if dut_passkey:
                # Raspi (Responder) enters the passkey displayed by DUT
                logger().info(f"Raspi (Responder) entering DUT's passkey: {dut_passkey}")
                self.ble_client.interfaces.bluetooth.set_pin(dut_passkey)
            
            if raspi_passkey:
                # DUT (Initiator) enters the passkey displayed by Raspi
                logger().info(f"DUT (Initiator) entering Raspi's passkey: {raspi_passkey}")
                pk_snap = self._get_log_snapshot()
                self.wifi_dut.interfaces.wifi.smp_passkey(
                    bd_addr=self.ble_client_address,
                    passkey=raspi_passkey
                )
                self._assert_dut_command_success("smp_passkey (numeric comparison)", pk_snap, timeout=2)
            
            time.sleep(5)  # Wait for pairing to complete with numeric comparison
        else:  # JustWorks
            logger().info(f"JustWorks pairing (DUT: {self.dut_capability}, Client: {self.client_capability}) - no passkey required")
            time.sleep(5)  # Wait for pairing to complete without passkey
        
        # Wait for pairing to complete
        time.sleep(10)
        logger().info("Pairing process initiated, verifying connection and pairing status...")

        # ── LTK verification (authoritative connection proof) ──────────
        # The LE LTK banner in DUT serial log is the definitive proof that
        # SMP pairing completed successfully.  We use the connect_log_snap
        # taken before the connect thread started so only NEW log entries
        # are checked (avoids false positives from earlier connections).
        logger().info("Waiting for LE LTK generation in DUT serial log (authoritative connection proof)...")
        ltk_ok = self._wait_for_ltk_in_logs(
            device_label=f"DUT-Central ({pairing_method})",
            timeout=30,
            log_start_index=connect_log_snap
        )
        if not ltk_ok:
            logger().error("❌ FAILED: LE LTK was NOT generated — SMP pairing did not complete!")
            self._check_dut_serial_log_for_errors()
            assert False, (
                f"LE LTK not generated for connection to {self.ble_client_address} — "
                f"SMP pairing ({pairing_method}) did not complete successfully."
            )
        logger().info("✅ LE LTK generated — SMP pairing completed successfully!")

        # Verify Raspi-side connection status (secondary confirmation)
        logger().info("Verifying Raspi-side BLE connection status...")
        self.connection_successful = self._verify_connection_status(timeout=30)
        if not self.connection_successful:
            logger().error(f"❌ FAILED: Raspi reports NOT connected to {self.ble_client_address} (despite LTK success)!")
            self._check_dut_serial_log_for_errors()
            assert False, f"BLE connection to {self.ble_client_address} failed — Raspi-side not connected"
        logger().info(f"✅ BLE connection to {self.ble_client_address} verified successfully!")

        # Verify Raspi-side pairing/bonding status (secondary confirmation)
        self.pairing_successful = self._verify_pairing_status(timeout=30)
        if not self.pairing_successful:
            logger().error(f"❌ FAILED: SMP pairing with {self.ble_client_address} — Raspi reports NOT paired!")
            connection_still_active = self._verify_connection_status(timeout=5)
            if not connection_still_active:
                logger().error("❌ Connection was lost during pairing!")
            self._check_dut_serial_log_for_errors()
            assert False, f"SMP pairing with {self.ble_client_address} failed — device not paired"
        logger().info(f"✅ SMP pairing with {self.ble_client_address} verified successfully!")
        
        # Final verification - ensure both connection and pairing are successful
        logger().info("=" * 60)
        logger().info("FINAL TEST RESULTS:")
        logger().info(f"  Connection Status: {'✅ CONNECTED' if self.connection_successful else '❌ NOT CONNECTED'}")
        logger().info(f"  Pairing Status:    {'✅ PAIRED' if self.pairing_successful else '❌ NOT PAIRED'}")
        logger().info("=" * 60)

        # Wait for observation period
        logger().info("Connection established, waiting 60s observation period...")
        time.sleep(60)
        
        # Verify connection is still active after observation period
        connection_after_observation = self._verify_connection_status(timeout=5)
        if not connection_after_observation:
            logger().error("❌ Connection dropped during observation period!")
            # Scan DUT serial log for disconnect reason codes
            self._check_dut_serial_log_for_errors()
        logger().info(f"Connection after observation period: {'✅ STILL CONNECTED' if connection_after_observation else '❌ DISCONNECTED'}")
        
        # Assert connection survived the observation period
        assert connection_after_observation, "Test failed: Connection dropped during 60s observation period"
        logger().info("🎉 TEST PASSED: Connection, pairing, and stability verified!")


# Just works, Raspi: 0x00 (Display) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C664756')
def test_raspi_connects_to_dut_disp_disp_C664756(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
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
@pytest.mark.test_src_map_id('C664761')
def test_raspi_connects_to_dut_dispyn_disp_C664761(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",  # Update as needed
        client_capability="DisplayYesNo",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (Keyboard Only) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C664766')
def test_raspi_connects_to_dut_keybonly_disp_C664766(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",  # Update as needed
        client_capability="KeyboardOnly",  # Update as needed
        pin_code="-8",
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C664771')
def test_raspi_connects_to_dut_noinputnooutput_disp_C664771(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",  # Update as needed
        client_capability="NoInputNoOutput",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x04 (Keyboard Display) DUT: 0x00 (Display)
@pytest.mark.test_src_map_id('C664776')
def test_raspi_connects_to_dut_keybdisp_disp_C664776(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayOnly",  # Update as needed
        client_capability="KeyboardDisplay",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x00 (DisplayOnly) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C664756')
def test_raspi_connects_to_dut_disponly_dispyn_C664757(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",  # Update as needed
        client_capability="DisplayOnly",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# NumericComparison, Raspi: 0x01 (DisplayYesNo) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C664762')
def test_raspi_connects_to_dut_dispyn_dispyn_C664762(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",  # Update as needed
        client_capability="DisplayYesNo",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C664767')
def test_raspi_connects_to_dut_keyboardonly_dispyn_C664767(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",  # Update as needed
        client_capability="KeyboardOnly",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C664772')
def test_raspi_connects_to_dut_noinputnooutput_dispyn_C664772(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",  # Update as needed
        client_capability="NoInputNoOutput",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# NumericComparison, Raspi: 0x04 (KeyboardDisplay) DUT: 0x01 (DisplayYesNo)
@pytest.mark.test_src_map_id('C664777')
def test_raspi_connects_to_dut_keyboarddisplay_dispyn_C664777(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="DisplayYesNo",  # Update as needed
        client_capability="KeyboardDisplay",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x00 (DisplayOnly) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C664758')
def test_raspi_connects_to_dut_disponly_keybonly_C664758(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",  # Update as needed
        client_capability="DisplayOnly",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()


# Passkey, Raspi: 0x01 (DisplayYesNo) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C664763')
def test_raspi_connects_to_dut_dispyesno_keybonly_C664763(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",  # Update as needed
        client_capability="DisplayYesNo",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C664768')
def test_raspi_connects_to_dut_keybonly_keybonly_C664768(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",  # Update as needed
        client_capability="KeyboardOnly",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x03 (NoInputNoOutput) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C664773')
def test_raspi_connects_to_dut_noinputnooutput_keybonly_C664773(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",  # Update as needed
        client_capability="NoInputNoOutput",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# Passkey, Raspi: 0x04 (KeyboardDisplay) DUT: 0x02 (KeyboardOnly)
@pytest.mark.test_src_map_id('C664778')
def test_raspi_connects_to_dut_keybdisp_keybonly_C664778(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardOnly",  # Update as needed
        client_capability="KeyboardDisplay",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x00 (DisplayOnly) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C664759')
def test_raspi_connects_to_dut_disponly_noinputnooutput_C664759(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",  # Update as needed
        client_capability="DisplayOnly",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x01 (DisplayYesNo) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C664764')
def test_raspi_connects_to_dut_dispyn_noinputnooutput_C664764(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",  # Update as needed
        client_capability="DisplayYesNo",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x02 (KeyboardOnly) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C664769')
def test_raspi_connects_to_dut_keybonly_noinputnooutput_C664769(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",  # Update as needed
        client_capability="KeyboardOnly",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C664774')
def test_raspi_connects_to_dut_noinputnooutput_noinputnooutput_C664774(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",  # Update as needed
        client_capability="NoInputNoOutput",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()  

# JustWorks, Raspi: 0x04 (KeyboardDisplay) DUT: 0x03 (NoInputNoOutput)
@pytest.mark.test_src_map_id('C664779')
def test_raspi_connects_to_dut_keybdisp_noinputnooutput_C664779(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="NoInputNoOutput",  # Update as needed
        client_capability="KeyboardDisplay",  # Update as needed
        pin_code="-8"
    )
    ble_test.run() 

# Passkey, Raspi: 0x00 (DisplayOnly) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C664760')
def test_raspi_connects_to_dut_disponly_keybdisp_C664760(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  # Update as needed
        client_capability="DisplayOnly",  # Update as needed
        pin_code="-8"
    )
    ble_test.run() 

# NumericComparison, Raspi: 0x01 (DisplayYesNo) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C664765')
def test_raspi_connects_to_dut_dispyn_keybdisp_C664765(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  # Update as needed
        client_capability="DisplayYesNo",  # Update as needed
        pin_code="-8"
    )
    ble_test.run() 


# Passkey, Raspi: 0x02 (KeyboardOnly) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C664770')
def test_raspi_connects_to_dut_keybonly_keybdisp_C664770(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  # Update as needed
        client_capability="KeyboardOnly",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# JustWorks, Raspi: 0x03 (NoInputNoOutput) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C664775')
def test_raspi_connects_to_dut_noinputnooutput_keybdisp_C664775(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  # Update as needed
        client_capability="NoInputNoOutput",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()

# NumericComparison, Raspi: 0x04 (KeyboardDisplay) DUT: 0x04 (KeyboardDisplay)
@pytest.mark.test_src_map_id('C664780')
def test_raspi_connects_to_dut_keybdisp_keybdisp_C664780(wifi_dut, ble_client):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)
    # Instantiate BLESMPPairingTest handler and execute pairing test
    ble_test = BLESMPPairingTest(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        dut_capability="KeyboardDisplay",  # Update as needed
        client_capability="KeyboardDisplay",  # Update as needed
        pin_code="-8"
    )
    ble_test.run()
