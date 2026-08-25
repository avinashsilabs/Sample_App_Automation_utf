
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
       
    def _extract_passkey_from_log(self):
        """Extract passkey from DUT serial log and ensure it's 6 digits with leading zeros if needed"""
        serial_conn = self.wifi_dut.interfaces.wifi.bus  
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
        Returns: (disconnected: bool, reason: str|None, line: str|None)
        """
        serial_conn = self.wifi_dut.interfaces.wifi.bus
        deadline = time.time() + settle_timeout
        seen_connected = False
        peer_addrs = []
        if self.ble_client_address:
            peer_addrs.append(str(self.ble_client_address).lower())
        if self.ble_dut_address:
            peer_addrs.append(str(self.ble_dut_address).lower())

        while time.time() < deadline:
            input_log = serial_conn.get_input_log()[log_start_index:]
            for _ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)
                decoded_lower = decoded_line.lower()

                if "connected address:" in decoded_lower:
                    if not peer_addrs or any(addr in decoded_lower for addr in peer_addrs):
                        seen_connected = True

                if seen_connected and ("disconnect" in decoded_lower or "0x4e3e" in decoded_lower):
                    if "disconnecting" in decoded_lower:
                        continue
                    reason = self._format_disconnect_reason(decoded_line)
                    return True, reason, decoded_line
            time.sleep(0.2)

        # Final pass
        input_log = serial_conn.get_input_log()[log_start_index:]
        for _ts, line in input_log:
            try:
                decoded_line = line.decode(errors="ignore")
            except Exception:
                decoded_line = str(line)
            decoded_lower = decoded_line.lower()
            if "connected address:" in decoded_lower:
                if not peer_addrs or any(addr in decoded_lower for addr in peer_addrs):
                    seen_connected = True
            if seen_connected and ("disconnect" in decoded_lower or "0x4e3e" in decoded_lower):
                if "disconnecting" in decoded_lower:
                    continue
                reason = self._format_disconnect_reason(decoded_line)
                return True, reason, decoded_line

        return False, None, None

    def _partial_cleanup_before_retry(self, already_disconnected=False):
        """
        Settle between connect retries (keep Raspi agent/scan setup usable).
        If already_disconnected=True, skip disconnect APIs — link is already down.
        Prefer DUT-initiated disconnect when a disconnect is needed.
        """
        try:
            self.ble_client.interfaces.bluetooth.stop_scanning()
        except Exception:
            pass
        if already_disconnected:
            logger().info("Skipping disconnect APIs - early disconnect already observed")
        elif self.ble_client_address:
            try:
                self.wifi_dut.interfaces.wifi.btc_disconnect(ble_address=self.ble_client_address)
                logger().info("PASS: DUT btc_disconnect (retry cleanup) executed successfully")
            except Exception as e:
                logger().warning(f"Retry cleanup DUT disconnect failed (may already be down): {e}")
        time.sleep(2)

    def _restart_dut_advertising(self):
        """Restart random-address legacy advertising so Raspi can rediscover the DUT."""
        try:
            self.wifi_dut.interfaces.wifi.stop_adv()
            time.sleep(0.3)
        except Exception as e:
            logger().warning(f"stop_adv before retry adv restart failed: {e}")
        try:
            self.wifi_dut.interfaces.wifi.legacy_adv(own_addr_type=0x01)
            logger().info("PASS: Restarted DUT legacy_adv (own_addr_type=0x01)")
            time.sleep(0.5)
        except Exception as e:
            logger().warning(f"legacy_adv restart failed: {e}")

    def _clear_stale_dut_cache(self):
        """Drop UTF's local BlueZ device_dict entry for DUT (cache has no InterfacesRemoved)."""
        addr_key = str(self.ble_dut_address).upper().replace(":", "_")
        try:
            device_dict = self.ble_client.interfaces.bluetooth.adapter.device_dict
            for path in list(device_dict.keys()):
                if addr_key in str(path).upper():
                    del device_dict[path]
                    logger().info(f"Cleared stale BlueZ cache entry: {path}")
        except Exception as e:
            logger().warning(f"Failed clearing stale device cache: {e}")

    def _dut_live_on_dbus(self):
        """
        Return True only if BlueZ currently exposes org.bluez.Device1 for the DUT.
        get_devices() alone is unreliable (stale local cache).
        """
        try:
            import dbus
            from utf.interfaces.bluetooth.bluez.bluez_interfaces import BTDBusInterfaces

            bt = self.ble_client.interfaces.bluetooth
            addr_key = f"dev_{str(self.ble_dut_address).upper().replace(':', '_')}"
            manager = dbus.Interface(
                bt.bus.get_object(BTDBusInterfaces.ORG_BLUEZ, "/"),
                BTDBusInterfaces.ORG_DBUS_OBJECT_MANAGER,
            )
            for path, ifaces in manager.GetManagedObjects().items():
                if addr_key in str(path) and BTDBusInterfaces.ORG_BLUEZ_DEVICE in ifaces:
                    return True
            return False
        except Exception as e:
            logger().warning(f"DBus Device1 liveness check failed: {e}")
            return False

    def _ensure_dut_discovered(self, scan_seconds: float = 8.0):
        """
        Re-create a live BlueZ Device1 object for the DUT before connect.

        After StopDiscovery, BlueZ often removes temporary devices. UTF's
        get_devices() can still list them (stale local cache, no InterfacesRemoved
        handler), so connect then fails with UnknownObject on Properties.Set(Trusted).
        Connect while discovery is still active to keep the object alive.
        """
        addr = str(self.ble_dut_address).upper()
        self._restart_dut_advertising()
        self._clear_stale_dut_cache()

        # Best-effort remove so BlueZ must recreate Device1 on next advertisement
        try:
            self.ble_client.interfaces.bluetooth.remove_device(bt_dut_address=self.ble_dut_address)
            self._clear_stale_dut_cache()
            time.sleep(0.3)
        except Exception as e:
            logger().warning(f"remove_device before rediscovery (ok if absent): {e}")

        try:
            self.ble_client.interfaces.bluetooth.start_scanning()
        except Exception as e:
            logger().warning(f"start_scanning before connect failed: {e}")

        deadline = time.time() + scan_seconds
        found = False
        while time.time() < deadline:
            if self._dut_live_on_dbus():
                found = True
                break
            time.sleep(0.5)

        if found:
            logger().info(
                f"DUT {addr} has live BlueZ Device1; connecting while discovery is active"
            )
        else:
            logger().warning(
                f"DUT {addr} Device1 not live after {scan_seconds}s scan; "
                "connect will likely hit UnknownObject"
            )
        return found

    def _cleanup(self):
        """Full cleanup: DUT disconnect first, then clear Raspi bonds / close BlueZ."""
        logger().info("Running cleanup: DUT disconnect, clear Raspi bonds, close BlueZ")
        try:
            self.ble_client.interfaces.bluetooth.stop_scanning()
        except Exception:
            pass
        # Prefer DUT-initiated disconnect (same as central suites). Calling Raspi
        # disconnect first leaves the DUT already down, so btc_disconnect returns 0x4d05.
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
        Connect from Raspi (Central) to DUT (Peripheral, random addr) and verify the link
        stays up before pairing. Re-discovers DUT before each attempt (fixes BlueZ
        UnknownObject / stale device). Retries on any early disconnect (including 0x4e3e).
        Does not proceed to pairing if the link dropped after connect.
        Returns log_start_index of the successful attempt.
        """
        last_disconnect_reason = None
        last_disconnect_line = None
        last_connect_error = None
        addr = str(self.ble_dut_address)

        for attempt in range(1, max_attempts + 1):
            # Always rediscover before connect so BlueZ has a live Device1 object
            if not self._ensure_dut_discovered(scan_seconds=8.0):
                logger().warning(
                    f"Connect attempt {attempt}/{max_attempts}: DUT Device1 not live on DBus; "
                    "skipping connect and retrying rediscovery"
                )
                self._partial_cleanup_before_retry()
                continue

            serial_conn = self.wifi_dut.interfaces.wifi.bus
            log_start_index = len(serial_conn.get_input_log())
            connect_error = []

            def connect():
                logger().info(
                    f"Connect attempt {attempt}/{max_attempts} "
                    f"({pairing_method}) Raspi->DUT {addr} (random addr)"
                )
                try:
                    self.ble_client.interfaces.bluetooth.connect(
                        dev_addr=self.ble_dut_address,
                        supervision_timeout=500,
                    )
                    logger().info("PASS: Raspi connect executed successfully")
                except Exception as e:
                    logger().error(f"FAIL: Raspi connect failed: {e}")
                    connect_error.append(str(e))

            t = threading.Thread(target=connect, daemon=True)
            t.start()

            logger().info("Waiting for BLE connection to establish on DUT...")
            connected = False
            matched_line = ""
            if self.ble_client_address:
                connected, matched_line = self._wait_for_serial_log_regex(
                    pattern=rf"Connected Address:\s*{re.escape(str(self.ble_client_address))}(\s|,|$)",
                    timeout=20,
                    start_index=log_start_index,
                )
            if not connected:
                connected, matched_line = self._wait_for_serial_log_regex(
                    pattern=r"Connected Address:\s*([0-9A-Fa-f:]{17})",
                    timeout=5,
                    start_index=log_start_index,
                )
            if not connected:
                try:
                    if self._verify_connection_status(address=self.ble_dut_address, max_retries=2):
                        connected = True
                        matched_line = f"Raspi reports connected to {addr}"
                except Exception:
                    pass
            t.join(timeout=15)

            # Stop discovery after connect attempt (success or fail)
            try:
                self.ble_client.interfaces.bluetooth.stop_scanning()
            except Exception:
                pass

            if not connected:
                last_connect_error = connect_error[0] if connect_error else None
                logger().warning(
                    f"Connect attempt {attempt}/{max_attempts}: no connection confirmed to {addr}"
                    + (f" (connect error: {connect_error[0]})" if connect_error else "")
                )
                self._partial_cleanup_before_retry()
                continue

            logger().info(f"Connection established: {matched_line.strip() if matched_line else addr}")
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

            if not self._verify_connection_status(address=self.ble_dut_address, max_retries=1):
                logger().warning(
                    f"Connect attempt {attempt}/{max_attempts}: Raspi lost connection during settle"
                )
                self._partial_cleanup_before_retry(already_disconnected=True)
                continue

            logger().info("Link stable after connect - proceeding to pairing")
            return log_start_index

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
        err_hint = f" Last connect error: {last_connect_error}" if last_connect_error else ""
        assert False, (
            f"Failed to establish stable BLE connection to {addr} "
            f"after {max_attempts} attempts - not proceeding to pairing.{err_hint}"
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
        
        # Determine pairing method
        if (dut_io, client_io) in justworks_scenarios:
            pairing_method = "JustWorks"
            auth_req_value = 0x01 # Bonding only (no MITM, no SC) for legacy
        else:
            pairing_method = "PasskeyEntry"
            auth_req_value = 0x05 # Bonding + MITM (no SC) for legacy
        
        logger().info(f"Pairing Method: {pairing_method}, auth_req=0x{auth_req_value:02X} ({auth_req_value} decimal)")
        logger().info(f"DUT IO: {self.dut_capability} (0x{dut_io:02X}), Raspi IO: {self.client_capability} (0x{client_io:02X})")

        try:
            self.wifi_dut.interfaces.wifi.stop_adv()
            time.sleep(0.5)  # Allow firmware to process stop_adv
            fixed_ble_addr = "C0:98:E5:00:00:01"
            self.wifi_dut.interfaces.wifi.set_random_address(bd_addr=fixed_ble_addr)
            time.sleep(0.5)  # Allow firmware to process random address setting
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
            
            time.sleep(0.5)  # Allow serial buffer to clear before starting advertising
            self.wifi_dut.interfaces.wifi.legacy_adv(own_addr_type=0x01)  # 0x00=Public, 0x01=Random
            logger().info("Start SMP scan from the remote device (Raspi)")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=self.ble_dut_address,
                capability=self.client_capability,
                pin_code=self.pin_code,
            )
            assert self.ble_client_address, "failed to initiate ble in remote device"
            # Do NOT call set_bus() here — it replaces the DBus connection and
            # orphans signal receivers registered by start_smp_scan.
            # _connect_with_retry rediscovers and connects while scan is active.
            time.sleep(1)

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
                        
                        # Check if DUT is waiting for passkey (from this attempt's log only)
                        if not dut_ready:
                            input_log = serial_conn.get_input_log()[log_start_index:]
                            for _ts, line_bytes in input_log:
                                try:
                                    decoded_line = line_bytes.decode(errors="ignore")
                                except Exception:
                                    decoded_line = str(line_bytes)
                                if passkey_event_pattern.search(decoded_line):
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
                    
                    if passkey_ready and not passkey_sent:
                        logger().error("FAIL: DUT passkey event ('in smp_passkey') not detected - DUT not ready for passkey")
                        assert False, "DUT passkey event not detected - cannot send passkey without DUT confirmation"
                    
                    if not passkey_ready:
                        logger().error("Passkey not found from Raspi after timeout!")
                        assert False, "Passkey not found from Raspi!"
            else:  # JustWorks
                logger().info(f"JustWorks pairing (DUT: {self.dut_capability}, Client: {self.client_capability}) - no passkey required")
                time.sleep(5)  # Wait for pairing to complete without passkey
            
            # Wait for pairing to complete
            time.sleep(10)
            logger().info("Pairing process completed")

            # Verify pairing by checking DUT logs for this attempt only
            input_log = serial_conn.get_input_log()[log_start_index:]
            smp_failed = False
            connection_failed = False
            disconnect_detected = False
            disconnect_reason = None
            disconnect_line = None
            smp_pair_request_received = False
            smp_response_received = False
            smp_encrypt_event_detected = False

            for _ts, line in input_log:
                try:
                    decoded_line = line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(line)

                decoded_lower = decoded_line.lower()

                # Check for SMP pair request
                if any(pattern in decoded_lower for pattern in ["smp pair request", "pairing_request", "smp_pair_request", "rsi_ble_on_smp_request"]):
                    smp_pair_request_received = True

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
                    status_match = re.search(r"status\s*:\s*([0-9a-fA-F]+)", decoded_line, re.IGNORECASE)
                    if status_match:
                        logger().error(f"SMP failed detected with status 0x{status_match.group(1)}: {decoded_line}")
                    else:
                        logger().error(f"SMP failed detected: {decoded_line}")    

                # Check for connection failure
                if "connection failed" in decoded_lower or "connect failed" in decoded_lower:
                    connection_failed = True
                    logger().error(f"Connection failed detected: {decoded_line}")

                # Check for unexpected disconnect
                if "disconnect" in decoded_lower and "disconnecting" not in decoded_lower:
                    disconnect_detected = True
                    disconnect_line = decoded_line
                    disconnect_reason = self._format_disconnect_reason(decoded_line)
                    logger().error(f"Disconnect detected (reason {disconnect_reason}): {decoded_line}")

            # Log SMP handshake status
            if smp_pair_request_received:
                logger().info(f"SMP response: {'DETECTED' if smp_response_received else 'NOT DETECTED'}, SMP encrypt event: {'DETECTED' if smp_encrypt_event_detected else 'NOT DETECTED'}")

            # Assert on failures
            assert not smp_failed, "Pairing failed - SMP failure detected in DUT logs!"
            assert not connection_failed, "Connection failed during pairing!"
            if disconnect_detected:
                if disconnect_reason and "0x4e3e" in str(disconnect_reason).lower():
                    assert False, (
                        f"Pairing failed - disconnect with 0x4e3e "
                        f"(Connection Failed to be Established): {disconnect_line}"
                    )
                assert False, f"Pairing failed - disconnect observed (reason {disconnect_reason}): {disconnect_line}"

            # Wait for "rsi_ble_event_profile_dummy" event before checking stability
            logger().info("Waiting for profile event (rsi_ble_event_profile_dummy)...")
            profile_event_found, matched_line = self._wait_for_serial_log_regex(
                pattern=r"rsi_ble_event_profile_dummy",
                timeout=60,
                start_index=log_start_index,
            )
            if profile_event_found:
                logger().info(f"Profile event detected: {matched_line.strip()}")
                # Monitor connection stability for 60 seconds
                logger().info("Monitoring connection stability for 60 seconds...")
                time.sleep(60)
                logger().info("Test PASSED: All required events detected, no failure conditions met, connection stable.")
            else:
                assert False, "FAIL: 'rsi_ble_event_profile_dummy' event not found in DUT logs!"

            # Verify connection from Raspi's perspective - Raspi (Central) checks connection to DUT (Peripheral)
            connection_verified = self._verify_connection_status(address=self.ble_dut_address, max_retries=0)
            if not connection_verified:
                logger().error("BLE connection no longer active after stability monitoring - DUT disconnected")
                assert False, "Test FAILED: DUT is not connected after stability monitoring"
            time.sleep(5)
        finally:
            self._cleanup()
        
# Just works, Raspi: 0x00 (Display) DUT: 0x00 (Display)
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
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03, "KeyboardDisplay": 0x04}
        dut_io = io_capability[ble_test.dut_capability]
        client_io = io_capability[ble_test.client_capability]
        try:
            # Clear bonding data on raspi
            try:
                ble_test.ble_client.interfaces.bluetooth.remove_all_devices()
                time.sleep(2)
            except Exception as e:
                logger().warning(f"Failed to clear Raspi bonds: {e}")

            # Random-address DUT: set address + advertise before scan
            fixed_ble_addr = "C0:98:E5:00:00:01"
            try:
                ble_test.wifi_dut.interfaces.wifi.stop_adv()
                time.sleep(0.5)
            except Exception as e:
                logger().warning(f"stop_adv before fixed-passkey setup failed: {e}")
            try:
                ble_test.wifi_dut.interfaces.wifi.set_random_address(bd_addr=fixed_ble_addr)
                time.sleep(0.5)
                logger().info(f"Fixed BLE address set on DUT: {fixed_ble_addr}")
            except Exception as e:
                logger().warning(f"set_random_address failed: {e}")
            ble_test.ble_dut_address = fixed_ble_addr
            try:
                ble_test.wifi_dut.interfaces.wifi.legacy_adv(own_addr_type=0x01)
                logger().info("PASS: Started DUT legacy_adv (own_addr_type=0x01 random)")
                time.sleep(0.5)
            except Exception as e:
                logger().warning(f"legacy_adv (random) at start failed: {e}")

            assert ble_test.ble_dut_address, "DUT local address not available!"
            logger().info(f"DUT BD Address: {ble_test.ble_dut_address}")

            logger().info(
                f"Setting DUT SMP pairing capability: IO={dut_io}, "
                f"KeyboardOnly/KeyboardOnly, fixed passkey {fixed_passkey}"
            )
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

            logger().info("Starting SMP scan on Raspi...")
            ble_test.ble_client_address = ble_test.ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=ble_test.ble_dut_address,
                capability=ble_test.client_capability,
                pin_code=fixed_passkey
            )
            assert ble_test.ble_client_address, "failed to initiate ble in remote device"
            # Do NOT stop_scanning here — BlueZ removes temporary Device1 after
            # StopDiscovery; _connect_with_retry rediscovers and connects while scanning.
            time.sleep(1)

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
            logger().info("Waiting for DUT to prompt for passkey entry...")
            while time.time() < deadline:
                input_log = serial_conn.get_input_log()[log_start_index:]
                for _ts, line in input_log:
                    try:
                        decoded_line = line.decode(errors="ignore")
                    except Exception:
                        decoded_line = str(line)
                    if passkey_prompt_pattern.search(decoded_line):
                        logger().info(f"DUT passkey prompt detected: {decoded_line.strip()}")
                        dut_ready = True
                        break
                if dut_ready:
                    break
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

            logger().info(f"Entering fixed passkey {fixed_passkey} on DUT and Raspi...")
            ble_test.wifi_dut.interfaces.wifi.smp_passkey(
                ble_test.ble_client_address, int(fixed_passkey)
            )
            ble_test.ble_client.interfaces.bluetooth.set_pin(fixed_passkey)
            time.sleep(5)

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

# Passkey, Raspi: 0x03 (NoInputNoOutput) DUT: 0x02 (KeyboardOnly)
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
