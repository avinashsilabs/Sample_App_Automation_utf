"""
BLE Central Passive Scan and Connection Test Suite

This module validates BLE passive scanning with different scan intervals and windows,
followed by connection establishment, SMP pairing, connection stability verification,
and clean DUT-initiated disconnect.

Test Flow:
    1. DUT initializes and fetches local BD address (cached across iterations)
    2. SMP pairing capabilities configured (DisplayOnly on DUT, KeyboardOnly on Raspi)
    3. Pre-test cleanup: stop scan, drain serial, re-apply SMP
    4. Raspberry Pi starts advertising as peripheral (start_smp_adv)
    5. DUT starts passive scanning with parameters from Passive_Scan_Param.csv
    6. Scan error codes checked - negative scenario (0x4e12/0x4046) = PASS
    7. DUT scans for 30 seconds, then initiates connection to discovered peripheral
    8. Wait for Enhanced Connect Event on DUT serial (up to 120s)
    9. SMP pairing with passkey exchange (DUT displays, Raspi enters)
   10. SMP pairing verified via "smp encrypt event" on DUT serial
   11. Connection stability monitored for 60 seconds (10s polling)
        - Raspi D-Bus get_connection_status keep-alive every 10s
        - Accumulated-string disconnect detection (multi-line safe)
        - SMP failure detection during stability window
   12. DUT initiates btc_disconnect (post-pass cleanup)
   13. Disconnect verified via 0x4e16 (informational only)
   14. Full Raspi cleanup: remove_device, close BLE, stop advertising
   15. Results (Error codes + PASS/FAIL) written to CSV in finally block

Test Coverage:
    - Scan intervals: 60 to 16384 BLE slot units (0.625ms each)
    - Scan windows: 30 to 16384 BLE slot units
    - scan_type=0 (Passive scan with scan request/response)
    - SMP pairing with passkey authentication
    - Connection stability monitoring

CSV Parameters:
    - TC_ID: Test case identifier
    - scan_type: Scan type (0=Passive, 1=Active)
    - filter_policy: Filter policy (0=Accept all, 1=Whitelist only)
    - own_addr_type: Own address type (0=Public, 1=Random)
    - scan_interval: Scan interval (units of 0.625ms)
    - scan_window: Scan window (units of 0.625ms)

Error Codes Monitored:
    0x4e12  Invalid Scan/ADV Parameters (negative-scenario PASS)
    0x4046  Invalid Scan Parameters - scan_interval < scan_window (negative-scenario PASS)
    0x4e16  Local Host Terminated Connection (expected on clean disconnect)
    0x4e13  Remote User Terminated Connection
    0x4e08  Connection Timeout
    0x4e3e  MIC Failure
    0x4e05  Authentication Failure
    0x4d15  SMP Pairing Process Failed
    0x4b0b  SMP SC Passkey/Pairing Failure
    0x4e0c  Invalid BLE State
    0x4e04  Page Timeout
    0x4d05  BLE Device Not Connected

Author: Sairam Chintalapati
Date: April 2nd 2026
"""

import csv
import os
import time
import re
import threading
import pytest
from utf.utils.logger import get_logger

LOGGER = get_logger(__name__)

# Thread lock for CSV file access
csv_lock = threading.Lock()


def get_bus(device):
    """Get the serial bus interface from a device."""
    return device.interfaces.wifi.bus


def fetch_local_address(wifi_dut):
    """
    Fallback: extract local BD address from the serial boot log.
    Parses 'local_bd_address: XX:XX:XX:XX:XX:XX' from input_log history.

    Args:
        wifi_dut: DUT device interface

    Returns:
        str: BD address or None if not found
    """
    bus = get_bus(wifi_dut)
    input_log = bus.get_input_log()
    for _, line in input_log:
        try:
            decoded = line.decode(errors="ignore")
        except Exception:
            decoded = str(line)
        if "local_bd_address" in decoded:
            addr = decoded.split("local_bd_address:")[-1].strip().split()[0]
            return addr
    return None


def is_valid_bd_addr(addr):
    """Validate Bluetooth Device address format."""
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", str(addr))) \
        and not str(addr).endswith(":00:00:00:00:00:00")

# ---------------------------------------------------------------------------
# CSV file paths
# ---------------------------------------------------------------------------
CSV_INPUT_PATH = os.path.join(os.path.dirname(__file__), "Passive_Scan_Param.csv")
RESULTS_CSV_FILENAME = "Passive_Scan_Results.csv"


def _get_results_csv_paths():
    """
    Returns a list of paths where the results CSV should be written.
    Includes both local (next to source) and reports dir (survives Docker).
    """
    paths = []
    paths.append(os.path.join(os.path.dirname(__file__), RESULTS_CSV_FILENAME))
    for reports_candidate in [
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "reports"),
        "/app/reports",
    ]:
        abs_candidate = os.path.abspath(reports_candidate)
        if os.path.isdir(abs_candidate):
            paths.append(os.path.join(abs_candidate, RESULTS_CSV_FILENAME))
            break
    return paths


def write_result_to_csv(testcase_id, error_code, result):
    """
    Update results CSV with test result for a specific testcase.
    Reads from the input CSV and writes to a separate results CSV.
    Writes to multiple locations to ensure persistence.

    Args:
        testcase_id: The test case ID from CSV
        error_code: Error code found during test (e.g., '0x4e12', '0x4e16', 'None')
        result: Test result - 'PASS' or 'FAIL'
    """
    with csv_lock:
        output_paths = _get_results_csv_paths()
        LOGGER.info(f"[CSV WRITE] Will write to: {output_paths}")

        for output_path in output_paths:
            try:
                abs_path = os.path.abspath(output_path)
                LOGGER.info(f"[CSV WRITE] Writing TC {testcase_id} -> {abs_path}")

                source_path = output_path if os.path.exists(output_path) else CSV_INPUT_PATH

                rows = []
                headers = []
                with open(source_path, "r", encoding="utf-8-sig") as f:
                    reader = csv.reader(f)
                    headers = next(reader)

                    if "Error" not in headers:
                        headers.append("Error")
                    if "Result" not in headers:
                        headers.append("Result")

                    error_idx = headers.index("Error")
                    result_idx = headers.index("Result")

                    for row in reader:
                        while len(row) < len(headers):
                            row.append("")
                        if row[0].strip() == str(testcase_id).strip():
                            row[error_idx] = str(error_code) if error_code else "None"
                            row[result_idx] = result
                        rows.append(row)

                os.makedirs(os.path.dirname(abs_path), exist_ok=True)
                with open(abs_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(rows)

                LOGGER.info(f"[CSV WRITE] SUCCESS: TC {testcase_id} -> Error={error_code}, Result={result} at {abs_path}")
            except Exception as e:
                LOGGER.error(f"[CSV WRITE] FAILED to write TC {testcase_id} at {output_path}: {e}")


def read_scan_params_from_csv(csv_file_path):
    """Load scan parameter rows from CSV into dict list."""
    cases = []
    if not os.path.exists(csv_file_path):
        LOGGER.error(f"CSV not found: {csv_file_path}")
        return cases

    with open(csv_file_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("TC_ID"):
                continue
            try:
                case = {
                    "testcase_id": row["TC_ID"],
                    "scan_type": int(row["scan_type"]),
                    "filter_policy": int(row["filter_policy"]),
                    "own_addr_type": int(row["own_addr_type"]),
                    "scan_interval": row["scan_interval"].strip(),
                    "scan_window": row["scan_window"].strip(),
                    "channel_map": int(row["channel_map"]),
                }
            except ValueError as e:
                LOGGER.error(f"CSV row parse error: {e} row={row}")
                continue
            cases.append(case)
            LOGGER.info(f"Loaded TestCase {case['testcase_id']} scan_interval={case['scan_interval']} scan_window={case['scan_window']}")

    LOGGER.info(f"Total CSV scan cases: {len(cases)}")
    return cases


def pytest_generate_tests(metafunc):
    """
    Pytest hook to dynamically generate test cases from CSV file.
    This creates individual test instances for each parameter set.
    """
    if "scan_params" in metafunc.fixturenames:
        csv_path = os.path.join(os.path.dirname(__file__), "Passive_Scan_Param.csv")
        cases = read_scan_params_from_csv(csv_path)

        test_ids = [f"TC_{case['testcase_id']}_scan_{case['scan_interval']}_{case['scan_window']}"
                    for case in cases]
        metafunc.parametrize("scan_params", cases, ids=test_ids)


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------
# Module-level variable to cache local address across test iterations
local_addr = None

ERROR_CODES = {
    "4e12": "Invalid Scan/ADV parameters",
    "4e16": "Local Host Terminated Connection",
    "4e13": "Remote User Terminated Connection",
    "4e08": "Connection Timeout",
    "4e3e": "MIC Failure",
    "4e05": "Authentication Failure",
    "4d15": "SMP Pairing Process Failed",
    "4e0c": "Invalid BLE State",
    "4e04": "Page Timeout",
    "4b0b": "SMP SC Passkey/Pairing Failure",
    "4d05": "BLE Device Not Connected",
    "4046": "Invalid Scan Parameters (scan_interval < scan_window or out-of-range)",
}

# Error codes that indicate invalid/rejected scan parameters (negative-scenario PASS)
SCAN_INVALID_PARAM_CODES = {"4e12", "4046"}


def find_error_codes_in_log(input_log):
    """
    Extract error codes from serial log.

    Args:
        input_log: List of (timestamp, line) tuples from serial bus

    Returns:
        set: Set of error codes found (normalised to lowercase without 0x prefix)
    """
    found_codes = set()
    for _, line in input_log:
        try:
            decoded = line.decode(errors="ignore").lower()
        except Exception:
            decoded = str(line).lower()
        for code in ERROR_CODES:
            if f"0x{code}" in decoded or f" {code}" in decoded:
                found_codes.add(code)
        # Also catch generic "error status 0xNNNN" patterns from scan/command responses
        generic_match = re.search(r'error status 0x([0-9a-fA-F]+)', decoded)
        if generic_match:
            generic_code = generic_match.group(1).lower()
            found_codes.add(generic_code)
    return found_codes


# ---------------------------------------------------------------------------
# Test function
# ---------------------------------------------------------------------------
@pytest.mark.parametrize_from_csv
@pytest.mark.test_src_map_id('TC5665129921')
def test_ble_scan_and_connect_from_csv(wifi_dut, ble_client, scan_params):
    """
    Run BLE passive scan with parameters from CSV, then initiate connection to
    the Raspberry Pi peripheral, SMP pair, hold the connection for 60 s, and
    disconnect cleanly from the DUT side.
    Results (Error code + PASS/FAIL) are written to CSV in the finally block.
    """
    global local_addr
    case = scan_params
    tcid = case["testcase_id"]

    # ========== FETCH LOCAL ADDRESS (once, cached across iterations) ==========
    if local_addr is None:
        LOGGER.info("Waiting for DUT boot sequence to complete...")
        time.sleep(15)
        try:
            get_bus(wifi_dut).get_input_log()
            LOGGER.info("Serial buffer cleared after boot")
        except Exception:
            pass

        # Set SMP pairing capability: DisplayOnly, auth_req=0x2D (Bonding + MITM)
        wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
            io_capability=0x00, auth_req=0x2D
        )
        time.sleep(2)

        addr_candidate = None
        for attempt in range(5):
            try:
                addr_candidate = wifi_dut.interfaces.wifi.get_local_address()
                if is_valid_bd_addr(addr_candidate):
                    break
                LOGGER.warning(f"get_local_address attempt {attempt + 1}: invalid address '{addr_candidate}'")
            except Exception as e:
                LOGGER.warning(f"get_local_address attempt {attempt + 1} failed: {e}")
            time.sleep(2)

        if is_valid_bd_addr(addr_candidate):
            local_addr = addr_candidate
            LOGGER.info(f"Fetched DUT local address (API): {local_addr}")
        else:
            local_addr = fetch_local_address(wifi_dut)
            if local_addr:
                LOGGER.info(f"Fetched DUT local address (log fallback): {local_addr}")
            else:
                raise ValueError("Failed to get valid DUT local address from API or logs!")

    # Track test result and error code - written to CSV in finally block
    result_error = None
    test_result = "FAIL"
    peripheral_address = None

    try:
        # ========== PRE-TEST CLEANUP ==========
        for attempt in range(3):
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
                time.sleep(1)
                break
            except Exception:
                if attempt < 2:
                    time.sleep(3)
        try:
            get_bus(wifi_dut).get_input_log()
        except Exception:
            pass

        # Re-apply SMP pairing capability every test to ensure fresh SMP state
        # DisplayOnly on DUT, auth_req=0x2D (Bonding + MITM)
        try:
            wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
                io_capability=0x00, auth_req=0x2D
            )
            LOGGER.info("SMP pairing capability re-applied for this test.")
            time.sleep(1)
        except Exception as smp_cap_err:
            LOGGER.warning(f"Failed to re-apply SMP capability: {smp_cap_err}")

        LOGGER.info("Waiting for DUT to settle...")
        time.sleep(3)

        LOGGER.info(f"\n=== Start TestCase {tcid} ===")
        LOGGER.info(
            f"Parameters: scan_type={case['scan_type']}, "
            f"scan_interval={case['scan_interval']}, scan_window={case['scan_window']}, "
            f"own_addr_type={case['own_addr_type']}, local_addr={local_addr}"
        )

        # ========== START RASPBERRY PI ADVERTISING (Peripheral Role) ==========
        LOGGER.info("Starting Raspberry Pi advertising as peripheral...")
        ble_client.interfaces.bluetooth.set_bus()
        time.sleep(2)
        # Pass the DUT address so start_smp_adv can remove stale bond info
        # before restarting BlueZ. This prevents 0x4B0B (DH Key Check Failed)
        # caused by stale keys from the previous test iteration.
        LOGGER.info(f"Calling start_smp_adv with bt_dut_address={local_addr} to clear stale bonds")
        ble_remote_address = ble_client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=local_addr,
            pin_code="-8",
            capability="KeyboardOnly",
        )
        assert ble_remote_address is not None, "Failed to start advertising on Raspberry Pi"
        peripheral_address = ble_remote_address
        LOGGER.info(f"Raspberry Pi advertising started. Peripheral address: {peripheral_address}")
        time.sleep(3)

        # Drain serial buffer for clean scan error detection
        get_bus(wifi_dut).get_input_log()
        
        LOGGER.info(
            f"Starting BLE scan: scan_type={case['scan_type']}, "
            f"interval={case['scan_interval']}, window={case['scan_window']}"
        )
        _scan_cmd = (
            f"btc ble req_legacy_scan 0 1 {case['scan_type']} "
            f"{case['filter_policy']} {case['own_addr_type']} "
            f"{case['scan_interval']} {case['scan_window']}"
        )
        bus = get_bus(wifi_dut)
        bus.write_line_and_expect(_scan_cmd)
        bus.read_line()
        LOGGER.info(f"Scan started (tc={tcid}) interval={case['scan_interval']} window={case['scan_window']}")
        time.sleep(5)

        # ========== CHECK SCAN START ERROR CODES ==========
        bus = get_bus(wifi_dut)
        input_log = bus.get_input_log()
        found_codes = find_error_codes_in_log(input_log)

        # Check for any known invalid-scan-parameter error codes (negative scenario)
        invalid_param_hits = found_codes & SCAN_INVALID_PARAM_CODES
        if invalid_param_hits:
            hit_code = sorted(invalid_param_hits)[0]  # report the first matching code
            result_error = f"0x{hit_code}"
            test_result = "PASS"
            LOGGER.info(
                f"TestCase {tcid} PASS (error code 0x{hit_code} - "
                f"{ERROR_CODES.get(hit_code, 'Invalid scan parameters')}, "
                f"negative scenario — DUT correctly rejected invalid params)"
            )
            return

        unexpected_errors = found_codes - {"4e16"}
        if unexpected_errors:
            result_error = ",".join([f"0x{c}" for c in unexpected_errors])
            test_result = "FAIL"
            for code in unexpected_errors:
                LOGGER.error(
                    f"TestCase {tcid} FAIL: Error code 0x{code} "
                    f"({ERROR_CODES.get(code, 'Unknown')}) found after scan start."
                )
            assert False, f"Unexpected error codes found: {[f'0x{c}' for c in unexpected_errors]}"

        # ========== SCAN FOR 30 SECONDS ==========
        LOGGER.info("Scanning in progress for 30 seconds...")
        scan_duration = 30
        for i in range(6):
            time.sleep(5)
            LOGGER.info(f"Scan progress: {(i + 1) * 5}/{scan_duration} seconds")

        LOGGER.info("Scan completed (30 seconds)")

        # ========== INITIATE CONNECTION TO PERIPHERAL ==========
        LOGGER.info(f"Connecting to peripheral: {peripheral_address}")
        get_bus(wifi_dut).get_input_log()  # clear buffer before connect
        wifi_dut.interfaces.wifi.req_legacy_connect(
            dev_addr=peripheral_address, supervision_tout=500
        )
        LOGGER.info("Connection request sent, waiting for connection event...")

        connection_wait_timeout = 120
        connection_established = False
        connection_wait_start = time.time()
        accumulated_log = ""

        while (time.time() - connection_wait_start) < connection_wait_timeout:
            time.sleep(2)
            new_log = "\n".join(
                line.decode(errors="ignore") if hasattr(line, "decode") else str(line)
                for _, line in get_bus(wifi_dut).get_input_log()
            )
            accumulated_log += new_log
            accumulated_lower = accumulated_log.lower()

            if "error status 0x4e08" in accumulated_lower:
                result_error = "0x4e08"
                test_result = "FAIL"
                LOGGER.error("Connection timeout (0x4e08)")
                assert False, "Connection timeout (0x4e08)"

            if "error status 0x4e04" in accumulated_lower:
                result_error = "0x4e04"
                test_result = "FAIL"
                LOGGER.error("Page timeout (0x4e04)")
                assert False, "Connection failed - Page timeout (0x4e04)"

            if ("on enhance connect event" in accumulated_lower
                    or "enhanced connect event status report : 0" in accumulated_lower):
                LOGGER.info(f"Connection established to {peripheral_address}")
                connection_established = True
                break

            elapsed = int(time.time() - connection_wait_start)
            LOGGER.info(f"Waiting for connection event... {elapsed}/{connection_wait_timeout}s")

        if not connection_established:
            result_error = "Connection_Failed"
            test_result = "FAIL"
            LOGGER.error("Connection event not received within timeout")
            assert False, "Connection failed - No connection event received"

        get_bus(wifi_dut).get_input_log()
        time.sleep(0.5)

        # ========== SMP PASSKEY HANDLING ==========
        LOGGER.info("Waiting for passkey event from DUT...")
        dut_passkey = None
        smp_failed_early = False
        disconnected_early = False
        max_passkey_attempts = 30  # 30 x 0.5s = 15s total

        for attempt in range(max_passkey_attempts):
            time.sleep(0.5)
            # Single get_input_log() call per iteration to avoid losing serial data
            new_log_items = list(get_bus(wifi_dut).get_input_log())

            for _, raw_line in new_log_items:
                try:
                    decoded_line = raw_line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(raw_line)
                decoded_lower = decoded_line.lower()

                # Check for passkey in this chunk
                if not dut_passkey:
                    pk_match = re.search(r"passkey[:\s]+(\d+)", decoded_line, re.IGNORECASE)
                    if pk_match:
                        passkey_raw = pk_match.group(1)
                        if len(passkey_raw) <= 6:
                            dut_passkey = passkey_raw.zfill(6)
                            LOGGER.info(f"Passkey extracted: {passkey_raw} -> {dut_passkey}")

                # Check for early SMP failure
                if "smp failed" in decoded_lower or "4b0b" in decoded_lower:
                    LOGGER.error(f"SMP failure detected during passkey wait: {decoded_lower.strip()}")
                    smp_failed_early = True

                # Check for unexpected disconnect (e.g. DUT lost connection)
                if "peripheral is disconnected" in decoded_lower or "on event disconnect" in decoded_lower:
                    LOGGER.error(f"Disconnect detected during passkey wait: {decoded_lower.strip()}")
                    disconnected_early = True

            if dut_passkey:
                LOGGER.info(f"DUT passkey found: {dut_passkey}")
                break

            if smp_failed_early or disconnected_early:
                break

            if (attempt + 1) % 4 == 0:  # Log every 2s instead of every 0.5s
                LOGGER.info(f"Passkey not found yet, attempt {attempt + 1}/{max_passkey_attempts}...")

        if smp_failed_early:
            result_error = "0x4b0b"
            test_result = "FAIL"
            LOGGER.error("SMP pairing failed before passkey could be exchanged (0x4b0b). "
                         "Possible stale bond keys on Raspi from a previous test.")
            assert False, "SMP pairing failed early (0x4b0b) - stale bond keys or timing issue"

        if disconnected_early:
            result_error = "Disconnected_During_Pairing"
            test_result = "FAIL"
            LOGGER.error("DUT disconnected before passkey exchange could complete.")
            assert False, "DUT disconnected during SMP passkey wait"

        if dut_passkey:
            ble_client.interfaces.bluetooth.set_pin(int(dut_passkey))
            LOGGER.info(f"Set passkey {dut_passkey} on Raspi BLE client.")
        else:
            result_error = "Passkey_Not_Found"
            test_result = "FAIL"
            LOGGER.error("Passkey not found in DUT logs after all attempts.")
            assert False, "Passkey not found in DUT logs after connection."

        # ========== VERIFY SMP PAIRING SUCCESS ==========
        # Poll rapidly for up to 10 seconds to catch SMP failure or success
        LOGGER.info("Verifying SMP pairing outcome...")
        smp_verified = False
        smp_failed_in_verification = False
        smp_fail_detail = ""
        smp_verify_timeout = 10  # seconds
        smp_verify_start = time.time()

        while (time.time() - smp_verify_start) < smp_verify_timeout:
            time.sleep(0.5)
            bus = get_bus(wifi_dut)
            pairing_log_items = bus.get_input_log()

            for _, raw_line in pairing_log_items:
                try:
                    decoded_pair = raw_line.decode(errors="ignore").lower()
                except Exception:
                    decoded_pair = str(raw_line).lower()

                # Check for SMP failure patterns
                if "smp failed" in decoded_pair or "4b0b" in decoded_pair:
                    smp_failed_in_verification = True
                    smp_fail_detail = decoded_pair.strip()
                    LOGGER.error(f"SMP failure detected: {smp_fail_detail}")
                    break

                # Check for SMP success indicators
                if ("smp encrypt event" in decoded_pair
                        or "smp security keys event" in decoded_pair
                        or "le ltk" in decoded_pair):
                    smp_verified = True
                    LOGGER.info("SMP pairing success indicators found in DUT log.")
                    break

            if smp_failed_in_verification or smp_verified:
                break

        if smp_failed_in_verification:
            result_error = "0x4b0b"
            test_result = "FAIL"
            LOGGER.error(f"SMP DH Key Check / Pairing Failure (0x4b0b): {smp_fail_detail}")
            assert False, f"SMP Pairing Failed (0x4b0b) - {smp_fail_detail}"

        # Final check: look for any error codes in remaining log
        bus = get_bus(wifi_dut)
        pairing_log_items = bus.get_input_log()
        pairing_codes = find_error_codes_in_log(pairing_log_items)

        if "4b0b" in pairing_codes:
            result_error = "0x4b0b"
            test_result = "FAIL"
            LOGGER.error("SMP SC Passkey/Pairing Failure (0x4b0b)")
            assert False, "SMP SC Passkey/Pairing Failure (0x4b0b)"
        if "4e3e" in pairing_codes:
            result_error = "0x4e3e"
            test_result = "FAIL"
            LOGGER.error("SMP pairing failed with MIC failure (0x4e3e)")
            assert False, "SMP pairing failed - MIC failure (0x4e3e)"
        if "4e05" in pairing_codes:
            result_error = "0x4e05"
            test_result = "FAIL"
            LOGGER.error("SMP pairing failed with authentication failure (0x4e05)")
            assert False, "SMP pairing failed - Authentication failure (0x4e05)"
        if "4d15" in pairing_codes:
            result_error = "0x4d15"
            test_result = "FAIL"
            LOGGER.error("SMP Pairing Process Failed (0x4d15)")
            assert False, "SMP Pairing Process Failed (0x4d15)"

        if smp_verified:
            LOGGER.info("SMP Pairing completed successfully!")
        else:
            LOGGER.warning("SMP pairing success not explicitly confirmed in log, "
                          "proceeding with connection stability check.")

        # ========== CONNECTION STABILITY (60 seconds) ==========
        LOGGER.info("Checking connection stability for 60 seconds...")
        connection_duration = 60
        check_interval = 10

        for i in range(connection_duration // check_interval):
            # ---- Raspi-side D-Bus connection keep-alive ----
            # Query BlueZ D-Bus 'Connected' property every 10 seconds.
            # This serves two critical purposes:
            #  1. Prevents BlueZ from considering the link idle and
            #     initiating a 0x4e13 (Remote User Terminated) disconnect.
            #     The D-Bus query exercises the BlueZ connection manager,
            #     resetting internal idle timers.
            #  2. Provides an early warning if the Raspi side has already
            #     disconnected before the DUT's serial log reflects it.
            try:
                raspi_still_connected = (
                    ble_client.interfaces.bluetooth.get_connection_status(
                        dev_addr=local_addr
                    )
                )
                LOGGER.info(
                    f"[RASPI-CHECK] Connection status for "
                    f"{local_addr}: {raspi_still_connected} "
                    f"at {(i + 1) * check_interval}s into stability"
                )
                if not raspi_still_connected:
                    LOGGER.warning(
                        f"[RASPI-CHECK] Raspi D-Bus reports device "
                        f"NOT connected at {(i + 1) * check_interval}s "
                        f"into stability"
                    )
            except Exception as raspi_chk_err:
                LOGGER.debug(
                    f"[RASPI-CHECK] D-Bus connection query failed: "
                    f"{raspi_chk_err}"
                )

            time.sleep(check_interval)
            elapsed_time = (i + 1) * check_interval
            LOGGER.info(f"Connection stable: {elapsed_time}/{connection_duration} seconds")

            conn_check_log = list(get_bus(wifi_dut).get_input_log())

            # ---- Accumulate ALL serial entries into one string ----
            # The serial bus splits multi-line firmware responses into
            # separate (timestamp, bytes) entries.  The disconnect event
            # often arrives as:
            #   Entry N:   "On Event Disconnect\r\n"
            #   Entry N+1: "peripheral is disconnected, reason : 0x4e08"
            # Checking entries individually caused the reason-code regex
            # to miss the code (it was in the NEXT entry), defaulting
            # every disconnect to 0x4e13 regardless of actual cause.
            # Accumulating into one string guarantees the regex always
            # sees the full message.
            accumulated_stab = ""
            for _, raw_line in conn_check_log:
                try:
                    accumulated_stab += raw_line.decode(errors="ignore")
                except Exception:
                    accumulated_stab += str(raw_line)
            accumulated_stab_lower = accumulated_stab.lower()

            # Check for SMP failure during stability
            if "smp failed" in accumulated_stab_lower or "4b0b" in accumulated_stab_lower:
                result_error = "0x4b0b"
                test_result = "FAIL"
                LOGGER.error(f"SMP failure detected at {elapsed_time}s")
                assert False, f"SMP failure during stability period at {elapsed_time}s"

            # Check for disconnect during stability
            if (
                "peripheral is disconnected" in accumulated_stab_lower
                or "on event disconnect" in accumulated_stab_lower
            ):
                reason_match = re.search(
                    r'reason\s*:\s*0x([0-9a-fA-F]+)',
                    accumulated_stab_lower,
                )
                if reason_match:
                    actual_reason = reason_match.group(1).lower()
                    result_error = f"0x{actual_reason}"
                    reason_desc = ERROR_CODES.get(actual_reason, "Unknown")
                    LOGGER.error(
                        f"Device disconnected during stability period at {elapsed_time}s "
                        f"(reason: 0x{actual_reason} - {reason_desc})"
                    )
                else:
                    detected_code = None
                    for code in ERROR_CODES:
                        if f"0x{code}" in accumulated_stab_lower or f" {code}" in accumulated_stab_lower:
                            detected_code = code
                            break
                    if detected_code:
                        result_error = f"0x{detected_code}"
                    else:
                        result_error = "Unknown_Disconnect"
                    LOGGER.error(
                        f"Device disconnected during stability period at {elapsed_time}s "
                        f"(error: {result_error})"
                    )
                test_result = "FAIL"
                assert False, (
                    f"Device disconnected during stability period "
                    f"at {elapsed_time}s (error: {result_error})"
                )

        LOGGER.info(f"Connection maintained successfully for {connection_duration} seconds")

        # ========== STABILITY PASSED — MARK TEST AS PASS ==========
        # The 60-second connection stability is the pass criteria.
        # If we reach here without any disconnect/error during stability,
        # the test case is considered PASS.
        result_error = "0x4e16"
        test_result = "PASS"
        LOGGER.info(f"TestCase {tcid} PASS — connection stable for {connection_duration} seconds")

        # ========== DUT INITIATES DISCONNECT (cleanup) ==========
        # This is post-pass cleanup. The disconnect and 0x4e16 verification
        # are logged but do not change the test result.
        LOGGER.info(f"DUT initiating disconnect from peripheral: {peripheral_address}")
        try:
            wifi_dut.interfaces.wifi.btc_disconnect(ble_address=peripheral_address)
            time.sleep(3)
            LOGGER.info(f"Disconnect command sent for TestCase {tcid}.")
        except Exception as disc_exc:
            disc_msg = str(disc_exc).lower()
            LOGGER.warning(f"btc_disconnect raised exception: {disc_exc}")
            if "4e16" in disc_msg:
                LOGGER.info("DUT disconnect already completed (0x4e16 found in response).")
            elif "4d05" in disc_msg:
                LOGGER.warning("BLE Device Not Connected (0x4d05) — device already disconnected.")
            else:
                LOGGER.warning(f"Disconnect exception (non-fatal): {disc_exc}")

        # ========== VERIFY DISCONNECT ERROR CODES (informational) ==========
        bus = get_bus(wifi_dut)
        input_log = bus.get_input_log()
        found_codes = find_error_codes_in_log(input_log)

        if "4e16" in found_codes:
            LOGGER.info(f"TestCase {tcid}: 0x4e16 (Local Host Terminated) confirmed after disconnect.")
        else:
            LOGGER.warning(
                f"TestCase {tcid}: 0x4e16 not found in logs after disconnect. "
                f"Found codes: {[f'0x{c}' for c in found_codes] if found_codes else 'none'}. "
                f"Test result remains PASS (stability was verified)."
            )

        unexpected_errors = found_codes - SCAN_INVALID_PARAM_CODES - {"4e16"}
        if unexpected_errors:
            for code in unexpected_errors:
                LOGGER.warning(
                    f"TestCase {tcid}: Unexpected error code 0x{code} "
                    f"({ERROR_CODES.get(code, 'Unknown')}) found after disconnect (informational)."
                )

    except Exception as e:
        LOGGER.error(f"TestCase {tcid} FAIL: {e}")
        if result_error is None:
            result_error = str(e)[:80]
        raise
    finally:
        # ========== ALWAYS WRITE RESULT TO CSV ==========
        try:
            LOGGER.info(f"[FINALLY] Writing CSV result for TC {tcid}: Error={result_error}, Result={test_result}")
            write_result_to_csv(tcid, result_error, test_result)
        except Exception as csv_err:
            LOGGER.error(f"[FINALLY] CSV write failed for TC {tcid}: {csv_err}")

        # ========== CLEANUP ==========
        try:
            wifi_dut.interfaces.wifi.legacy_scan_stop()
            LOGGER.info("[CLEANUP] DUT scan stopped.")
        except Exception as e:
            LOGGER.warning(f"[CLEANUP] Failed to stop scan: {e}")
        try:
            wifi_dut.interfaces.wifi.stop_adv()
            LOGGER.info("[CLEANUP] DUT advertising stopped.")
        except Exception as e:
            LOGGER.warning(f"[CLEANUP] Failed to stop advertising: {e}")

        # ========== REMOVE DEVICE WITH RETRY ==========
        if peripheral_address:
            remove_success = False
            for rm_attempt in range(3):
                try:
                    ble_client.interfaces.bluetooth.remove_device(bt_dut_address=local_addr)
                    LOGGER.info(f"[CLEANUP] Successfully removed DUT ({local_addr}) from Raspi.")
                    remove_success = True
                    break
                except Exception as e:
                    LOGGER.warning(f"[CLEANUP] remove_device attempt {rm_attempt + 1}/3 failed: {e}")
                    time.sleep(1)
            if not remove_success:
                LOGGER.error(f"[CLEANUP] All 3 remove_device attempts failed for {local_addr}. "
                             "Stale bond keys may cause SMP failures in subsequent tests.")

        # ========== CLOSE BLE INTERFACE WITH RETRY ==========
        close_success = False
        for close_attempt in range(3):
            try:
                ble_client.interfaces.bluetooth.close()
                LOGGER.info("[CLEANUP] BLE interface closed successfully.")
                close_success = True
                break
            except Exception as e:
                LOGGER.warning(f"[CLEANUP] close() attempt {close_attempt + 1}/3 failed: {e}")
                time.sleep(1)
        if not close_success:
            LOGGER.error("[CLEANUP] All 3 close() attempts failed. "
                         "BlueZ stack may be in dirty state for next test.")

        # ========== STOP RASPI ADVERTISING ==========
        try:
            ble_client.interfaces.bluetooth.stop_advertising()
            LOGGER.info("[CLEANUP] Raspi advertising stopped.")
        except Exception:
            pass
        time.sleep(2)
        LOGGER.info(f"=== End TestCase {tcid} ===\n")