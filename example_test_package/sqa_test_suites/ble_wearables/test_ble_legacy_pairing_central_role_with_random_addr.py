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

    def _verify_connection_status(self, address=None, max_retries=0):
        """
        Verify BLE connection status with retries.
       
        Args:
            address: BLE address to check connection status for (defaults to ble_dut_address)
            max_retries: Maximum number of retry attempts (default: 0)
           
        Returns:
            bool: True if connected, False otherwise
        """
        check_address = address if address is not None else self.ble_dut_address
        logger().info(f"Verifying connection status to {check_address}...")
       
        for attempt in range(max_retries + 1):
            try:
                connection_status = self.ble_client.interfaces.bluetooth.get_connection_status(check_address)
                logger().info(f"Connection status (attempt {attempt + 1}/{max_retries + 1}): {connection_status}")
                if connection_status:
                    logger().info(f"Connection verified to {check_address}")
                    return True
            except Exception as e:
                error_str = str(e)
                # Handle case where device is no longer tracked by BlueZ (D-Bus object removed after idle/disconnect)
                if "UnknownObject" in error_str or "doesn't exist" in error_str:
                    logger().warning(f"Device {check_address} no longer tracked by BlueZ (may have disconnected after idle)")
                    return False
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

    def _format_disconnect_reason(self, decoded_line: str):
        """Parse disconnect reason from a DUT serial log line."""
        match = re.search(r"0x[0-9a-fA-F]+", decoded_line)
        if not match:
            return "unknown"
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
            return f"{raw_hex} (hci 0x{hci_reason:02x}: {hci_desc})"
        except Exception:
            return raw_hex

    def _check_early_disconnect(self, log_start_index: int, settle_timeout: float = 5.0):
        """
        Watch DUT logs after connect for any disconnect before pairing starts.
        Prefer lines that include a reason code (e.g. 0x4e3e); bare
        "On Event Disconnect" alone is not enough to return immediately.
        Returns: (disconnected: bool, reason: str|None, line: str|None)
        """
        serial_conn = self.wifi_dut.interfaces.wifi.bus
        deadline = time.time() + settle_timeout
        target_addr_lower = str(self.ble_client_address).lower() if self.ble_client_address else ""
        seen_target_connected = False
        pending_disconnect_line = None

        while time.time() < deadline:
            input_log = serial_conn.get_input_log()[log_start_index:]
            for _ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                decoded_lower = decoded_line.lower()

                if target_addr_lower and f"connected address: {target_addr_lower}" in decoded_lower:
                    seen_target_connected = True

                if not seen_target_connected:
                    continue

                if "0x4e3e" in decoded_lower or (
                    "reason" in decoded_lower and "disconnect" in decoded_lower
                ):
                    reason = self._format_disconnect_reason(decoded_line)
                    return True, reason, decoded_line

                if "disconnect" in decoded_lower:
                    pending_disconnect_line = decoded_line
            time.sleep(0.2)

        if pending_disconnect_line:
            reason = self._format_disconnect_reason(pending_disconnect_line)
            return True, reason, pending_disconnect_line

        # Final pass
        input_log = serial_conn.get_input_log()[log_start_index:]
        for _ts, line in input_log:
            try:
                decoded_line = line.decode(errors="ignore")
            except Exception:
                decoded_line = str(line)
            decoded_lower = decoded_line.lower()
            if target_addr_lower and f"connected address: {target_addr_lower}" in decoded_lower:
                seen_target_connected = True
            if seen_target_connected and (
                "0x4e3e" in decoded_lower
                or ("disconnect" in decoded_lower)
            ):
                reason = self._format_disconnect_reason(decoded_line)
                return True, reason, decoded_line

        return False, None, None

    def _partial_cleanup_before_retry(self, already_disconnected=False):
        """
        Settle between connect retries (keep Raspi adv/agent alive).
        If already_disconnected=True, skip disconnect APIs — link is already down.
        Prefer DUT-initiated disconnect when a disconnect is needed.
        """
        if already_disconnected:
            logger().info("Skipping disconnect APIs - early disconnect already observed")
        elif self.ble_client_address:
            try:
                self.wifi_dut.interfaces.wifi.btc_disconnect(ble_address=self.ble_client_address)
                logger().info("PASS: DUT btc_disconnect (retry cleanup) executed successfully")
            except Exception as e:
                logger().warning(f"Retry cleanup DUT disconnect failed (may already be down): {e}")
        time.sleep(2)

    def _ensure_raspi_advertising(self):
        """
        Re-enable Raspi discoverable + LE advertising between connect retries.
        After a failed/early-drop connect, BlueZ often stops advertising; without
        this, DUT retries cannot find the Raspi.
        Also re-applies legacy SC-off / MITM HCI bits stored from setup.
        """
        try:
            self.ble_client.interfaces.bluetooth.set_discoverable()
            self.ble_client.interfaces.bluetooth.set_discoverable_timeout()
        except Exception as e:
            logger().warning(f"set_discoverable before retry adv failed: {e}")
        try:
            self.ble_client.interfaces.bluetooth.stop_advertising()
        except Exception:
            pass
        try:
            self.ble_client.interfaces.bluetooth.start_advertising()
            logger().info("PASS: Restarted Raspi LE advertising for connect retry")
        except Exception as e:
            logger().warning(f"start_advertising for retry failed: {e}")
        # Re-apply after any BT/HCI churn (start_smp_adv restarts bluetoothd)
        try:
            self.ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
        except Exception as e:
            logger().warning(f"set_secure_connection on retry failed: {e}")
        hci_bits = getattr(self, "_raspi_hci_auth_bits", None)
        if hci_bits:
            try:
                self.ble_client.interfaces.bluetooth.set_mitm_sc_bits(hci_bits)
                logger().info(f"PASS: Re-applied Raspi HCI auth bits on retry: {hci_bits}")
            except Exception as e:
                logger().warning(f"set_mitm_sc_bits on retry failed: {e}")
        time.sleep(1)

    def _cleanup(self):
        """Full cleanup: DUT disconnect first, then clear Raspi bonds / close BlueZ."""
        logger().info("Running cleanup: DUT disconnect, clear Raspi bonds, close BlueZ")
        # Prefer DUT-initiated disconnect. Do not disconnect from Raspi first —
        # that leaves the DUT already down and btc_disconnect returns 0x4d05.
        if self.ble_client_address:
            try:
                self.wifi_dut.interfaces.wifi.btc_disconnect(ble_address=self.ble_client_address)
                logger().info("PASS: DUT btc_disconnect executed successfully")
            except Exception as e:
                logger().warning(f"DUT disconnect failed (may already be disconnected): {e}")
        try:
            self.ble_client.interfaces.bluetooth.remove_all_devices()
            logger().info("PASS: remove_all_devices executed successfully")
        except Exception as e:
            logger().warning(f"Failed to clear bonding data on Raspi: {e}")
        try:
            self.ble_client.interfaces.bluetooth.close()
            logger().info("PASS: close executed successfully")
        except Exception as e:
            logger().warning(f"close failed: {e}")
        time.sleep(3)

    def _connect_with_retry(self, pairing_method: str, max_attempts: int = 3, settle_timeout: float = 5.0):
        """
        Connect from DUT to Raspi and verify the link stays up before pairing.
        Retries on any early disconnect (including 0x4e3e). Does not proceed to
        pairing if the link dropped after connect.
        Uses own_addr_type=0x01 for random address on DUT.
        Restarts Raspi advertising between attempts.
        Returns log_start_index of the successful attempt.
        """
        last_disconnect_reason = None
        last_disconnect_line = None
        addr = str(self.ble_client_address)

        for attempt in range(1, max_attempts + 1):
            # Refresh Raspi adv before every attempt (esp. after early disconnect)
            if attempt > 1:
                self._ensure_raspi_advertising()

            serial_conn = self.wifi_dut.interfaces.wifi.bus
            log_start_index = len(serial_conn.get_input_log())

            try:
                self.wifi_dut.interfaces.wifi.legacy_scan_stop()
                time.sleep(1)
                logger().info("PASS: legacy_scan_stop executed successfully")
            except Exception as e:
                logger().warning(f"legacy_scan_stop failed (attempt {attempt}): {e}")

            connect_error = []

            def connect():
                logger().info(
                    f"Connect attempt {attempt}/{max_attempts} "
                    f"({pairing_method}) to {addr} (own_addr_type=0x01)"
                )
                try:
                    self.wifi_dut.interfaces.wifi.req_legacy_connect(
                        own_addr_type=0x01,
                        dev_addr=self.ble_client_address,
                    )
                    logger().info("PASS: req_legacy_connect executed successfully")
                except Exception as e:
                    logger().error(f"FAIL: req_legacy_connect failed: {e}")
                    connect_error.append(str(e))

            t = threading.Thread(target=connect, daemon=True)
            t.start()

            logger().info("Waiting for BLE connection to establish...")
            connected, matched_line = self._wait_for_serial_log_regex(
                pattern=rf"Connected Address:\s*{re.escape(addr)}(\s|,|$)",
                timeout=20,
                start_index=log_start_index,
            )
            # Case-insensitive fallback
            if not connected:
                connected, matched_line = self._wait_for_serial_log_regex(
                    pattern=rf"connected address:\s*{re.escape(addr)}",
                    timeout=5,
                    start_index=log_start_index,
                )
            t.join(timeout=10)

            if not connected:
                logger().warning(
                    f"Connect attempt {attempt}/{max_attempts}: no Connected Address for {addr}"
                    + (f" (connect error: {connect_error[0]})" if connect_error else "")
                )
                self._partial_cleanup_before_retry()
                continue

            logger().info(f"Connection established: {matched_line.strip()}")
            logger().info(
                f"Checking link stability for {settle_timeout}s before pairing "
                "(will retry on any disconnect, including 0x4e3e)..."
            )
            disconnected, reason, disc_line = self._check_early_disconnect(
                log_start_index=log_start_index,
                settle_timeout=settle_timeout,
            )
            if disconnected:
                last_disconnect_reason = reason
                last_disconnect_line = disc_line
                logger().error(
                    f"Early disconnect on attempt {attempt}/{max_attempts} "
                    f"(reason {reason}): {disc_line}"
                )
                if reason and "0x4e3e" in str(reason).lower():
                    logger().error(
                        "Disconnect reason 0x4e3e (Connection Failed to be Established) "
                        "- settling and retrying (no disconnect API; link already down)"
                    )
                self._partial_cleanup_before_retry(already_disconnected=True)
                continue

            logger().info("Link stable after connect - proceeding to pairing")
            return log_start_index

        # All attempts exhausted - fail with a clear message, do not enter pairing
        if last_disconnect_reason and "0x4e3e" in str(last_disconnect_reason).lower():
            assert False, (
                f"Connection dropped with 0x4e3e (Connection Failed to be Established) "
                f"after connect to {addr}; retries exhausted ({max_attempts}). "
                f"Last disconnect: {last_disconnect_line}"
            )
        if last_disconnect_reason:
            assert False, (
                f"Connection dropped after connect to {addr} "
                f"(reason {last_disconnect_reason}); retries exhausted ({max_attempts}). "
                f"Last disconnect: {last_disconnect_line}"
            )
        assert False, (
            f"Failed to establish stable BLE connection to {addr} "
            f"after {max_attempts} attempts - not proceeding to pairing"
        )

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

        try:
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
                assert False, f"set_smp_pairing_capability_data failed: {e}"
               
            logger().info("Start SMP advertsing from the remote device (Raspi)")
            try:
                # start_smp_adv restarts bluetoothd — SC/MITM HCI must be applied AFTER this
                self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=self.ble_dut_address,
                    capability=self.client_capability,
                    pin_code=self.pin_code
                )
                logger().info(f"PASS: start_smp_adv executed successfully, client address: {self.ble_client_address}")
            except Exception as e:
                logger().error(f"FAIL: start_smp_adv failed: {e}")
                assert False, f"start_smp_adv failed: {e}"
            
            # Disable Secure Connections on Raspi to use Legacy Pairing (must be after BT restart)
            logger().info("Disabling Secure Connections on Raspi for Legacy Pairing compatibility")
            try:
                self.ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
                logger().info("PASS: set_secure_connection executed successfully")
            except Exception as e:
                logger().error(f"FAIL: set_secure_connection failed: {e}")
                assert False, f"set_secure_connection failed: {e}"
            
            # Apply MITM/SC bits via HCI after BT service restart; store for connect retries
            raspi_auth_req = f"0x{auth_req_value:02x}"
            self._raspi_hci_auth_bits = (
                f"{io_capability[self.client_capability]} {self.oob_data_flag} {raspi_auth_req}"
            )
            logger().info(f"Setting Raspi auth_req via HCI: {self._raspi_hci_auth_bits}")
            try:
                self.ble_client.interfaces.bluetooth.set_mitm_sc_bits(self._raspi_hci_auth_bits)
                logger().info("PASS: set_mitm_sc_bits executed successfully")
            except Exception as e:
                logger().error(f"FAIL: set_mitm_sc_bits failed: {e}")
                assert False, f"set_mitm_sc_bits failed: {e}"
            
            time.sleep(5)

            # Connect with retry on any early disconnect; do not enter pairing until link is stable
            serial_conn = self.wifi_dut.interfaces.wifi.bus
            log_start_index = self._connect_with_retry(
                pairing_method=pairing_method,
                max_attempts=3,
                settle_timeout=5.0,
            )
        
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
                    disconnect_reason = self._format_disconnect_reason(decoded_line)
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
                    if disconnect_reason and "0x4e3e" in str(disconnect_reason).lower():
                        assert False, (
                            f"Pairing failed - disconnect with 0x4e3e "
                            f"(Connection Failed to be Established): {disconnect_line}"
                        )
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
            
            # Keep the link up for a bit and catch disconnects that happen shortly after pairing
            logger().info("Monitoring connection stability for 60 seconds...")
            time.sleep(60)
            # Verify connection from Raspi's perspective - Raspi (Peripheral) checks connection to DUT (Central)
            connection_verified = self._verify_connection_status(address=self.ble_dut_address, max_retries=0)
            if not connection_verified:
                logger().error("BLE connection no longer active after stability monitoring - DUT disconnected")
                assert False, "Test FAILED: DUT is not connected after stability monitoring"
            time.sleep(5)
            # Final success assertion
            logger().info("Test PASSED: Connection established, encryption started, connection stable")
        finally:
            self._cleanup()

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

    def run_with_fixed_passkey():
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03, "KeyboardDisplay": 0x04}
        dut_io = io_capability[ble_test.dut_capability]
        client_io = io_capability[ble_test.client_capability]
        try:
            # Random-addr DUT setup (same as main run path)
            ble_test.wifi_dut.interfaces.wifi.legacy_scan_stop()
            fixed_ble_addr = "C0:98:E5:00:00:01"
            ble_test.wifi_dut.interfaces.wifi.set_random_address(bd_addr=fixed_ble_addr)
            ble_test.ble_dut_address = fixed_ble_addr
            logger().info(f"Fixed BLE address set on DUT: {fixed_ble_addr}")

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
            time.sleep(5)

            # Use shared connect-retry path (retries on 0x4e3e / early disconnect)
            serial_conn = ble_test.wifi_dut.interfaces.wifi.bus
            log_start_index = ble_test._connect_with_retry(
                pairing_method="PasskeyEntry",
                max_attempts=3,
                settle_timeout=5.0,
            )

            # Wait for DUT to prompt for passkey entry
            passkey_prompt_pattern = re.compile(r"in smp_passkey", re.IGNORECASE)
            dut_ready = False
            deadline = time.time() + 30
            while time.time() < deadline:
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
                # Abort early if link dropped after connect (retry already exhausted in connect path)
                disconnected, reason, disc_line = ble_test._check_early_disconnect(
                    log_start_index=log_start_index,
                    settle_timeout=0.2,
                )
                if disconnected:
                    assert False, (
                        f"Connection dropped while waiting for passkey prompt "
                        f"(reason {reason}): {disc_line}"
                    )
                time.sleep(0.2)
            assert dut_ready, "DUT did not prompt for passkey entry in time!"

            # Send fixed passkey to both sides
            ble_test.wifi_dut.interfaces.wifi.smp_passkey(ble_test.ble_client_address, int(fixed_passkey))
            ble_test.ble_client.interfaces.bluetooth.set_pin(fixed_passkey)
            time.sleep(5)

            # Basic encrypt/stability checks
            encrypt_found, _ = ble_test._wait_for_serial_log_regex(
                pattern=r"smp encrypt event",
                timeout=30,
                start_index=log_start_index,
            )
            assert encrypt_found, "FAIL: 'smp encrypt event' not found in DUT logs!"
            logger().info("Monitoring connection stability for 60 seconds...")
            time.sleep(60)
            connection_verified = ble_test._verify_connection_status(
                address=ble_test.ble_dut_address,
                max_retries=0,
            )
            assert connection_verified, "Test FAILED: DUT is not connected after stability monitoring"
            logger().info("Test PASSED: Fixed-passkey KeyboardOnly/KeyboardOnly pairing stable")
        finally:
            ble_test._cleanup()

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
