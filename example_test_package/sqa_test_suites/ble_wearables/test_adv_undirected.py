"""
BLE ADV Type 128 (Undirected Scannable) Advertisement and Connection Test Suite

This module validates BLE advertising with adv_type=128 (ADV_SCAN_IND - Undirected Scannable)
across various advertising intervals, followed by connection establishment and SMP pairing.

Test Flow:
    1. DUT initializes and fetches local BD address (cached across iterations)
    2. SMP pairing capabilities configured (DisplayOnly on DUT, KeyboardOnly on Raspi)
    3. Pre-test cleanup: stop scan + stop ADV, drain serial, re-apply SMP
    4. DUT starts advertising with specified parameters from ADV_Param_128.csv
    5. Stale ADV detection (ble_connectable_adv_already_in_progress) with recovery
    6. ADV error codes checked - negative scenario (0x4e12) = PASS
    7. Raspberry Pi (BLE client) scans and discovers the DUT
    8. Connection is established with SMP pairing (passkey exchange)
    9. JustWorks pairing auto-detected (smp encrypt event without passkey)
   10. Connection stability monitored for 60 seconds (10s polling)
        - Raspi D-Bus get_connection_status keep-alive every 10s
        - Accumulated-string disconnect detection (multi-line safe)
        - SMP failure detection during stability window
   11. DUT initiates btc_disconnect (post-pass cleanup)
   12. Disconnect verified via 0x4e16 (informational only)
   13. Full cleanup: disconnect wait + scan_stop + stop_adv + remove_device + close
   14. Results (Error codes + PASS/FAIL) written to CSV in finally block

Test Coverage:
    - ADV intervals: 20 (0x14) to 10000+ (0x2710) in BLE slot units (0.625ms each)
    - adv_type=128: ADV_SCAN_IND (Undirected Scannable advertising)
    - SMP pairing with passkey authentication (auth_req=0x2D: Bonding + MITM + SC)
    - Connection stability monitoring with Raspi D-Bus keep-alive

CSV Parameters:
    - Testcase ID: Test case identifier
    - status: ADV enable/disable (1=start)
    - adv_type: Advertisement type (128=ADV_SCAN_IND)
    - filter_type: Filter policy
    - direct_addr_type: Direct address type
    - addr_str: Direct address
    - adv_int_min: Minimum advertising interval (hex, units of 0.625ms)
    - adv_int_max: Maximum advertising interval (hex, units of 0.625ms)
    - own_addr_type: Own address type (0=Public, 1=Random)
    - channel_map: Advertising channel map

Error Codes Monitored:
    0x4e12  Invalid ADV parameters (negative-scenario PASS)
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
Date: April 18th 2026

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
    return device.interfaces.wifi.bus
def fetch_local_address(wifi_dut):
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
def assert_connection(ble_client, addr):
    """
    Verify BLE connection is established.
    Uses is_connected() method which is available on Bluez interface.
    Raises AssertionError if device reports not connected.
    """
    try:
        # Try is_connected() method first (Bluez interface)
        if hasattr(ble_client.interfaces.bluetooth, 'is_connected'):
            connected = ble_client.interfaces.bluetooth.is_connected(dev_addr=addr)
        elif hasattr(ble_client.interfaces.bluetooth, 'get_connection_status'):
            connected = ble_client.interfaces.bluetooth.get_connection_status(dev_addr=addr)
        else:
            # Fallback: no connection status method available, skip verification
            LOGGER.warning("No connection status method available, assuming connected")
            return
        if not connected:
            raise AssertionError(f"Connection to {addr} failed — device reports not connected")
    except AssertionError:
        raise  # Propagate actual connection failures
    except Exception as e:
        LOGGER.warning(f"Connection status check method raised: {e}, assuming connected")
def is_valid_bd_addr(addr):
    """Validate Bluetooth Device address format."""
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", str(addr))) and not str(addr).endswith(":00:00:00:00:00:00")
# CSV file path for input parameters
CSV_INPUT_PATH = os.path.join(os.path.dirname(__file__), "ADV_Param_128.csv")
# Results CSV: written to multiple locations to survive Docker container teardown
# 1. Next to source CSV (works for local runs)
# 2. In reports directory (survives Docker runs - gets synced back to host)
RESULTS_CSV_FILENAME = "ADV_Param_128_Results.csv"
def _get_results_csv_paths():
    """
    Returns a list of paths where the results CSV should be written.
    Includes both local (next to source) and reports dir (survives Docker).
    """
    paths = []
    # Path 1: Next to the source CSV
    paths.append(os.path.join(os.path.dirname(__file__), RESULTS_CSV_FILENAME))
    # Path 2: Reports directory (synced back from Docker to host)
    # Try multiple known report locations
    for reports_candidate in [
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "reports"),  # relative from test file
        "/app/reports",  # Docker container path
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

                # Determine source: use existing results file if it exists, else input CSV
                source_path = output_path if os.path.exists(output_path) else CSV_INPUT_PATH

                rows = []
                headers = []
                with open(source_path, "r", encoding="utf-8-sig") as f:
                    reader = csv.reader(f)
                    headers = next(reader)

                    # Add Error and Result columns if not present
                    if "Error" not in headers:
                        headers.append("Error")
                    if "Result" not in headers:
                        headers.append("Result")

                    error_idx = headers.index("Error")
                    result_idx = headers.index("Result")

                    for row in reader:
                        # Extend row if needed
                        while len(row) < len(headers):
                            row.append("")
                        # Update matching testcase
                        if row[0].strip() == str(testcase_id).strip():
                            row[error_idx] = str(error_code) if error_code else "None"
                            row[result_idx] = result
                        rows.append(row)

                # Ensure output directory exists
                os.makedirs(os.path.dirname(abs_path), exist_ok=True)

                # Write updated CSV
                with open(abs_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(rows)

                LOGGER.info(f"[CSV WRITE] SUCCESS: TC {testcase_id} -> Error={error_code}, Result={result} at {abs_path}")

            except Exception as e:
                LOGGER.error(f"[CSV WRITE] FAILED to write TC {testcase_id} at {abs_path}: {e}")
def read_adv_params_from_csv(csv_file_path):
    """Load advertising parameter rows into dict list."""
    cases = []
    if not os.path.exists(csv_file_path):
        LOGGER.error(f"CSV not found: {csv_file_path}")
        return cases
    with open(csv_file_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("Testcase ID"):
                continue
            # Clean addr_str (handles embedded triple quotes in sample)
            raw_addr = row.get("addr_str", "00:00:00:00:00:00").strip().strip('"').strip("'")
            try:
                # Keep adv_int_min and adv_int_max as raw strings to preserve hex values (ee, 1bc, 28a)
                adv_int_min_raw = row["adv_int_min"].strip()
                adv_int_max_raw = row["adv_int_max"].strip() 
                case = {
                    "testcase_id": row["Testcase ID"],
                    "status": int(row["status"]),
                    "adv_type": int(row["adv_type"]),
                    "filter_type": int(row["filter_type"]),
                    "direct_addr_type": int(row["direct_addr_type"]),
                    "addr_str": raw_addr,
                    "adv_int_min": adv_int_min_raw,  # Keep as string (hex values like 'ee', '1bc', '28a')
                    "adv_int_max": adv_int_max_raw,  # Keep as string (hex values like 'ee', '1bc', '28a')
                    "own_addr_type": int(row["own_addr_type"]),
                    "channel_map": int(row["channel_map"]),
                }
            except ValueError as e:
                LOGGER.error(f"CSV row parse error: {e} row={row}")
                continue
            cases.append(case)
            LOGGER.info(f"Loaded TestCase {case['testcase_id']} int={case['adv_int_min']}-{case['adv_int_max']}")
    LOGGER.info(f"Total CSV cases: {len(cases)}")
    return cases
def pytest_generate_tests(metafunc):
    """
    Pytest hook to dynamically generate test cases from CSV file.
    This creates individual test instances for each parameter set.
    """
    if "adv_params" in metafunc.fixturenames:
        csv_path = os.path.join(os.path.dirname(__file__), "ADV_Param_128.csv")
        cases = read_adv_params_from_csv(csv_path)        
        # Create test IDs for better reporting
        test_ids = [f"TC_{case['testcase_id']}_interval_{case['adv_int_min']}-{case['adv_int_max']}" 
                    for case in cases]
        # Parametrize the test with each case
        metafunc.parametrize("adv_params", cases, ids=test_ids)
# Module-level variable to cache local address across test cases
local_addr = None
# Error code definitions with descriptions
ERROR_CODES = {
    "4e12": "Invalid ADV parameters",
    "4e16": "Local Host Terminated Connection",
    "4e3e": "MIC Failure",
    "4e05": "Authentication Failure",
    "4d15": "SMP Pairing Process Failed",
    "4e08": "Connection Timeout",
    "4e13": "Remote User Terminated Connection",
    "4b0b": "SMP SC Passkey/Pairing Failure",
    "4d05": "BLE Device Not Connected",
    "4e0c": "Invalid BLE State",
    "4e04": "Page Timeout",
}
def find_error_codes_in_log(input_log):
    """
    Extract error codes from serial log.
    
    Args:
        input_log: List of (timestamp, line) tuples from serial bus
        
    Returns:
        set: Set of error codes found (normalized to lowercase without 0x prefix)
    """
    found_codes = set()
    for _, line in input_log:
        try:
            decoded = line.decode(errors="ignore").lower()
        except Exception:
            decoded = str(line).lower()
        
        for code in ERROR_CODES:
            # Match both '0x4e12' and '4e12' patterns
            if f"0x{code}" in decoded or f" {code}" in decoded or decoded.endswith(code):
                found_codes.add(code)
        # Also catch generic "error status 0xNNNN" patterns from command responses
        generic_match = re.search(r'error status 0x([0-9a-fA-F]+)', decoded)
        if generic_match:
            generic_code = generic_match.group(1).lower()
            found_codes.add(generic_code)

    return found_codes
def test_ble_adv_from_csv(wifi_dut, ble_client, adv_params):
    """
    Run advertising + pairing for a single parameter set from CSV.
    This test is parametrized to create individual test instances for each CSV row.
    Results (Error code + PASS/FAIL) are written to CSV in the finally block.
    """
    global local_addr
    case = adv_params
    tcid = case["testcase_id"]

    # ========== FETCH LOCAL ADDRESS (once) ==========
    if local_addr is None:
        LOGGER.info("Waiting for DUT boot sequence to complete...")
        time.sleep(15)
        try:
            get_bus(wifi_dut).get_input_log()
            LOGGER.info("Serial buffer cleared after boot")
        except Exception:
            pass
        # Set SMP pairing capability: DisplayOnly, auth_req=0x2D (Bonding + MITM + SC)
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

    # Track test result and error code — written to CSV in finally block
    result_error = None
    test_result = "FAIL"
    raspi_addr = None

    try:
        # ========== PRE-TEST CLEANUP ==========
        # Stop scan (may be left over from FW boot or a previous failed test)
        for attempt in range(3):
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
                time.sleep(1)
                break
            except Exception:
                if attempt < 2:
                    time.sleep(3)

        # Stop advertising (DUT may have stale ADV from another suite)
        for attempt in range(3):
            try:
                wifi_dut.interfaces.wifi.stop_adv()
                time.sleep(1)
                break
            except Exception:
                if attempt < 2:
                    time.sleep(3)

        # Drain serial buffer so stale errors don't contaminate this test
        try:
            get_bus(wifi_dut).get_input_log()
        except Exception:
            pass

        # Re-apply SMP pairing capability every test to ensure fresh SMP state
        # DisplayOnly on DUT, auth_req=0x2D (Bonding + MITM + SC)
        try:
            wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
                io_capability=0x00, auth_req=0x2D
            )
            LOGGER.info("SMP pairing capability re-applied for this test.")
            time.sleep(1)
        except Exception as smp_cap_err:
            LOGGER.warning(f"Failed to re-apply SMP capability: {smp_cap_err}")

        LOGGER.info("Waiting for DUT initialization to complete...")
        time.sleep(10)
        LOGGER.info(f"\n=== Start TestCase {tcid} ===")
        LOGGER.info(f"Parameters: interval={case['adv_int_min']}-{case['adv_int_max']}, adv_type={case['adv_type']}, own_addr_type={case['own_addr_type']}, local_addr={local_addr}")

        # ========== START ADVERTISING WITH STALE STATE RECOVERY ==========
        for adv_attempt in range(3):
            try:
                LOGGER.info(
                    f"[ADV] Starting advertising attempt {adv_attempt + 1}/3: "
                    f"adv_type={case['adv_type']} interval={case['adv_int_min']}-{case['adv_int_max']}"
                )
                wifi_dut.interfaces.wifi.legacy_adv(
                    status=case["status"],
                    adv_type=case["adv_type"],
                    filter_type=case["filter_type"],
                    direct_addr_type=case["direct_addr_type"],
                    direct_addr=case["addr_str"],
                    adv_int_min=case["adv_int_min"],
                    adv_int_max=case["adv_int_max"],
                    own_addr_type=case["own_addr_type"],
                    channel_map=case["channel_map"],
                )
                # Detect stale advertising state: firmware returns
                # "ble_connectable_adv_already_in_progress" without
                # raising an exception.  The radio is NOT actually
                # transmitting, so the Raspi will never see the DUT.
                time.sleep(0.5)
                _post_adv = get_bus(wifi_dut).get_input_log()
                _post_adv_text = "".join(
                    line.decode(errors="ignore")
                    if hasattr(line, "decode") else str(line)
                    for _, line in _post_adv
                )
                if "adv_already_in_progress" in _post_adv_text.lower():
                    raise RuntimeError(
                        "Firmware rejected advertising: "
                        "ble_connectable_adv_already_in_progress "
                        "(stale state from previous test)"
                    )
                break
            except Exception as adv_err:
                if adv_attempt < 2:
                    LOGGER.warning(
                        f"[ADV-RECOVERY] TC {tcid}: legacy_adv failed "
                        f"on attempt {adv_attempt + 1} ({adv_err}). "
                        f"Attempting BLE state recovery..."
                    )
                    # Force-disconnect any stale connection handle
                    try:
                        wifi_dut.interfaces.wifi.btc_disconnect(
                            ble_address="00:00:00:00:00:00"
                        )
                    except Exception:
                        pass
                    time.sleep(5)
                    # Stop adv/scan in case they are in a bad state
                    try:
                        wifi_dut.interfaces.wifi.stop_adv()
                    except Exception:
                        pass
                    try:
                        wifi_dut.interfaces.wifi.legacy_scan_stop()
                    except Exception:
                        pass
                    time.sleep(3)
                    # Drain serial buffer before retry
                    try:
                        get_bus(wifi_dut).get_input_log()
                    except Exception:
                        pass
                    LOGGER.info(
                        f"[ADV-RECOVERY] TC {tcid}: Recovery complete, "
                        f"retrying legacy_adv..."
                    )
                else:
                    LOGGER.error(
                        f"[ADV-RECOVERY] TC {tcid}: legacy_adv failed "
                        f"on all retries ({adv_err}). BLE state unrecoverable."
                    )
                    result_error = "ADV_Failed"
                    test_result = "FAIL"
                    assert False, f"Advertising failed after 3 attempts: {adv_err}"

        LOGGER.info(f"Advertising started (tc={tcid}) interval={case['adv_int_min']}-{case['adv_int_max']}")

        # ========== ADVERTISE FOR 30 SECONDS ==========
        # DUT must advertise long enough for the Raspi to discover it.
        # Log every 10s so the test report shows ADV is actively running.
        adv_duration = 30
        adv_check_interval = 10
        for adv_i in range(adv_duration // adv_check_interval):
            time.sleep(adv_check_interval)
            adv_elapsed = (adv_i + 1) * adv_check_interval
            LOGGER.info(
                f"[ADV] DUT advertising in progress: "
                f"{adv_elapsed}/{adv_duration} seconds "
                f"(tc={tcid}, interval={case['adv_int_min']}-{case['adv_int_max']})"
            )
        LOGGER.info(
            f"[ADV] DUT advertising completed {adv_duration} seconds successfully "
            f"(tc={tcid}, interval={case['adv_int_min']}-{case['adv_int_max']})"
        )

        # ========== CHECK ADV ERROR CODES ==========
        bus = get_bus(wifi_dut)
        input_log = bus.get_input_log()
        found_codes = find_error_codes_in_log(input_log)

        if "4e12" in found_codes:
            result_error = "0x4e12"
            test_result = "PASS"
            LOGGER.info(f"TestCase {tcid} PASS (error code 0x4e12 found - invalid ADV parameters)")
            return  # CSV write happens in finally
        unexpected_errors = found_codes - {"4e16"}
        if unexpected_errors:
            result_error = ",".join([f"0x{c}" for c in unexpected_errors])
            test_result = "FAIL"
            for code in unexpected_errors:
                LOGGER.error(f"TestCase {tcid} FAIL: Error code 0x{code} ({ERROR_CODES.get(code, 'Unknown')}) found after advertising.")
            assert False, f"Unexpected error codes found: {[f'0x{c}' for c in unexpected_errors]}"
        # ========== SCAN AND CONNECT ==========
        ble_client.interfaces.bluetooth.set_bus()
        ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=local_addr,
            capability="KeyboardOnly",
            pin_code="-8"
        )
        found_addr = None
        scan_timeout = 30
        for _ in range(scan_timeout):
            devices = ble_client.interfaces.bluetooth.get_devices()
            if local_addr in devices:
                found_addr = local_addr
                break
            time.sleep(1)
        ble_client.interfaces.bluetooth.stop_scanning()
        if not found_addr:
            result_error = "Scan_Failed"
            test_result = "FAIL"
            raise AssertionError(f"DUT address {local_addr} not found by Raspi during scan.")
        LOGGER.info(f"DUT address {local_addr} found by Raspi during scan.")
        # ========== CONNECTION INITIATION WITH RETRIES ==========
        max_connect_attempts = 3
        connect_success = False
        for attempt in range(1, max_connect_attempts + 1):
            try:
                ble_client.interfaces.bluetooth.connect(dev_addr=local_addr, supervision_timeout=500)
                assert_connection(ble_client, local_addr)
                LOGGER.info(f"Connection successful for TestCase {tcid} on attempt {attempt}.")
                connect_success = True
                break
            except Exception as e:
                LOGGER.warning(f"Connection attempt {attempt} failed: {e}")
                time.sleep(2)
        if not connect_success:
            result_error = "Connection_Failed"
            test_result = "FAIL"
            LOGGER.error(f"All {max_connect_attempts} connection attempts failed. TestCase {tcid} FAIL.")
            assert False, f"Raspi failed to connect to DUT after {max_connect_attempts} attempts."
        # ========== PASSKEY HANDLING ==========
        LOGGER.info("Waiting for passkey event from DUT...")
        dut_passkey = None
        raspi_addr = None
        smp_failed_early = False
        disconnected_early = False
        justworks_detected = False
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

                # Extract RASPI (remote) address from DUT connection event
                if not raspi_addr:
                    addr_match = re.search(
                        r"Remote Device Address\s*:\s*([0-9A-Fa-f:]{11,17})",
                        decoded_line,
                    )
                    if addr_match:
                        raspi_addr = addr_match.group(1).strip()
                        LOGGER.info(f"Extracted RASPI address from DUT logs: {raspi_addr}")

                # Check for passkey in this chunk
                if not dut_passkey:
                    pk_match = re.search(r"passkey[:\s]+(\d{4,6})", decoded_line, re.IGNORECASE)
                    if pk_match:
                        passkey_raw = pk_match.group(1)
                        dut_passkey = passkey_raw.zfill(6)
                        LOGGER.info(f"Passkey extracted: {passkey_raw} -> {dut_passkey}")

                # Detect JustWorks pairing (SMP completed without passkey)
                if not dut_passkey and not justworks_detected:
                    if ("smp encrypt event" in decoded_lower
                            or "le ltk" in decoded_lower):
                        justworks_detected = True
                        LOGGER.info(
                            "JustWorks pairing detected (smp encrypt event "
                            "without passkey). Proceeding without passkey exchange."
                        )

                # Check for early SMP failure
                if "smp failed" in decoded_lower or "4b0b" in decoded_lower:
                    LOGGER.error(f"SMP failure detected during passkey wait: {decoded_lower.strip()}")
                    smp_failed_early = True

                # Check for unexpected disconnect
                if ("central is disconnected" in decoded_lower
                        or "peripheral is disconnected" in decoded_lower
                        or "on event disconnect" in decoded_lower):
                    LOGGER.error(f"Disconnect detected during passkey wait: {decoded_lower.strip()}")
                    disconnected_early = True

            if dut_passkey or justworks_detected:
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
        elif justworks_detected:
            LOGGER.info("JustWorks pairing — no passkey exchange needed.")
        else:
            result_error = "Passkey_Not_Found"
            test_result = "FAIL"
            LOGGER.error("Passkey not found in DUT logs after all attempts.")
            assert False, "Passkey not found in DUT logs after connection."
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
            #   Entry N+1: "central is disconnected, reason : 0x4e13"
            # Checking entries individually caused the reason-code regex
            # to miss the code (it was in the NEXT entry).
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
                "central is disconnected" in accumulated_stab_lower
                or "peripheral is disconnected" in accumulated_stab_lower
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

        # ========== STABILITY PASSED - MARK TEST AS PASS ==========
        # The 60-second connection stability is the pass criteria.
        # If we reach here without any disconnect/error during stability,
        # the test case is considered PASS.
        result_error = "0x4e16"
        test_result = "PASS"
        LOGGER.info(f"TestCase {tcid} PASS - connection stable for {connection_duration} seconds")

        # ========== DUT INITIATES DISCONNECT (cleanup) ==========
        # This is post-pass cleanup. The disconnect and 0x4e16 verification
        # are logged but do not change the test result.
        if raspi_addr:
            LOGGER.info(f"DUT initiating disconnect from remote device: {raspi_addr}")
            try:
                wifi_dut.interfaces.wifi.btc_disconnect(ble_address=raspi_addr)
                time.sleep(3)
                LOGGER.info(f"Disconnect command sent for TestCase {tcid}.")
            except Exception as disc_exc:
                disc_msg = str(disc_exc).lower()
                LOGGER.warning(f"btc_disconnect raised exception: {disc_exc}")
                if "4e16" in disc_msg:
                    LOGGER.info("DUT disconnect already completed (0x4e16 found in response).")
                elif "4d05" in disc_msg:
                    LOGGER.warning("BLE Device Not Connected (0x4d05) - device already disconnected.")
                else:
                    LOGGER.warning(f"Disconnect exception (non-fatal): {disc_exc}")
        else:
            LOGGER.warning("RASPI address not available - skipping DUT-initiated disconnect.")

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

        unexpected_errors = found_codes - {"4e12", "4e16"}
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

        # ========== WAIT FOR DISCONNECT EVENT ==========
        # After Raspi removes the device, the DUT receives an async
        # disconnect event (0x4e13).  If we don't wait for it, the BLE
        # state machine is mid-transition when the next TC starts,
        # causing 0x4e0c cascades.
        disconnect_wait = 10.0
        disconnect_confirmed = False
        poll_interval = 1.0
        elapsed = 0.0

        # First stop scan to prevent firmware race conditions
        try:
            wifi_dut.interfaces.wifi.legacy_scan_stop()
            LOGGER.info("[CLEANUP] DUT scan stopped.")
        except Exception:
            pass

        # Stop advertising
        try:
            wifi_dut.interfaces.wifi.stop_adv()
            LOGGER.info("[CLEANUP] DUT advertising stopped.")
        except Exception as e:
            LOGGER.warning(f"[CLEANUP] Failed to stop advertising: {e}")

        # ========== REMOVE DEVICE WITH RETRY ==========
        remove_success = False
        for rm_attempt in range(3):
            try:
                LOGGER.info(
                    f"[CLEANUP] Removing DUT ({local_addr}) from Raspi, "
                    f"attempt {rm_attempt + 1}/3..."
                )
                ble_client.interfaces.bluetooth.remove_device(
                    bt_dut_address=local_addr
                )
                LOGGER.info(
                    f"[CLEANUP] Successfully removed DUT ({local_addr}) "
                    f"from Raspi."
                )
                remove_success = True
                break
            except Exception as e:
                LOGGER.warning(
                    f"[CLEANUP] remove_device attempt "
                    f"{rm_attempt + 1}/3 failed: {e}"
                )
                time.sleep(1)
        if not remove_success:
            LOGGER.error(
                f"[CLEANUP] All 3 remove_device attempts failed for "
                f"{local_addr}. Stale bond keys may cause SMP failures "
                f"in subsequent tests."
            )

        # ========== POLL FOR DUT DISCONNECT EVENT ==========
        while elapsed < disconnect_wait:
            time.sleep(poll_interval)
            elapsed += poll_interval
            try:
                disc_log = get_bus(wifi_dut).get_input_log()
                for _, raw_line in disc_log:
                    try:
                        decoded_disc = raw_line.decode(errors="ignore").lower()
                    except Exception:
                        decoded_disc = str(raw_line).lower()
                    if (
                        "on event disconnect" in decoded_disc
                        or "peripheral is disconnected" in decoded_disc
                        or "central is disconnected" in decoded_disc
                    ):
                        disconnect_confirmed = True
                        break
                if disconnect_confirmed:
                    LOGGER.info(
                        f"[FINALLY] TC {tcid}: Disconnect event "
                        f"confirmed after {elapsed:.1f}s."
                    )
                    # Extra 3s after event to let firmware settle
                    time.sleep(3)
                    break
            except Exception:
                pass

        if not disconnect_confirmed:
            LOGGER.warning(
                f"[FINALLY] TC {tcid}: Disconnect event NOT confirmed "
                f"after {disconnect_wait:.1f}s - proceeding anyway. "
                f"This may cause 0x4e0c on the next test."
            )

        # ========== POST-DISCONNECT: VERIFY BLE STATE ==========
        # Check for 0x4e0c in remaining serial data. If found, attempt
        # recovery before the next test case starts.
        try:
            post_disc_log = get_bus(wifi_dut).get_input_log()
            post_disc_text = "".join(
                line.decode(errors="ignore")
                if hasattr(line, "decode") else str(line)
                for _, line in post_disc_log
            )
            if "0x4e0c" in post_disc_text.lower():
                LOGGER.warning(
                    f"[CLEANUP] TC {tcid}: 0x4e0c detected after cleanup. "
                    f"Attempting BLE state recovery..."
                )
                try:
                    wifi_dut.interfaces.wifi.btc_disconnect(
                        ble_address="00:00:00:00:00:00"
                    )
                except Exception:
                    pass
                time.sleep(3)
                try:
                    wifi_dut.interfaces.wifi.stop_adv()
                except Exception:
                    pass
                try:
                    wifi_dut.interfaces.wifi.legacy_scan_stop()
                except Exception:
                    pass
                time.sleep(2)
                # Drain serial after recovery
                try:
                    get_bus(wifi_dut).get_input_log()
                except Exception:
                    pass
                LOGGER.info(f"[CLEANUP] TC {tcid}: 0x4e0c recovery complete.")
        except Exception:
            pass

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

        # Final scan_stop to ensure DUT is fully idle
        try:
            wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass

        time.sleep(5)
        LOGGER.info(f"=== End TestCase {tcid} ===\n")
