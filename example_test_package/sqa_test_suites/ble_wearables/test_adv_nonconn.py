import csv
import os
import time
import re
import threading
import pytest
from utf.utils.logger import get_logger
 
"""
BLE Non-Connectable ADV Test Suite
 
This module validates BLE non-connectable advertising across various advertising
intervals and parameters.  The DUT advertises with parameters from ADV_Non_Conn_Scan_Param.csv
and the Raspberry Pi scans for 45 seconds to verify discoverability.
 
Test Flow:
    1. DUT initializes and fetches local BD address (cached across iterations)
    2. Pre-test cleanup: stop scan + stop ADV, drain serial
    3. DUT starts non-connectable advertising with parameters from CSV
    4. Stale ADV detection (ble_connectable_adv_already_in_progress) with recovery
    5. ADV error codes checked - negative scenario (0x4e12) = PASS
    6. DUT advertises for 30 seconds with 10-second progress logging
    7. Raspberry Pi scans for 45 seconds to discover the DUT
    8. DUT found in scan results = PASS, not found = FAIL
    9. Full cleanup: stop scan + stop ADV + 0x4e0c recovery
   10. Results (Error codes + PASS/FAIL) written to CSV in finally block
 
Test Coverage:
    - Various ADV intervals in BLE slot units (0.625ms each)
    - Non-connectable advertising types (no connection/SMP phase)
    - Positive TCs: DUT found in Raspi scan = PASS
    - Negative TCs: Invalid ADV parameters -> error code 0x4e12 = PASS
 
CSV Parameters:
    - Testcase ID: Test case identifier
    - status: ADV enable/disable (1=start)
    - adv_type: Advertisement type
    - filter_type: Filter policy
    - direct_addr_type: Direct address type
    - addr_str: Direct address
    - adv_int_min: Minimum advertising interval (hex, units of 0.625ms)
    - adv_int_max: Maximum advertising interval (hex, units of 0.625ms)
    - own_addr_type: Own address type (0=Public, 1=Random)
    - channel_map: Advertising channel map
 
Error Codes Monitored:
    0x4e12  Invalid ADV parameters (negative-scenario PASS)
    0x4e0c  Invalid BLE State
    0x4e04  Page Timeout
 
Author: Sairam Chintalapati
Date: 14th November 2025
Updated: April 5, 2026 - Full rewrite: local address fetching with retry,
                          stale ADV detection, 30s ADV with 10s logging,
                          45s Raspi scan, error code detection, CSV result
                          writing, 0x4e0c recovery in cleanup
"""
def logger():
    return get_logger(__name__)
 
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
 
 
def is_valid_bd_addr(addr):
    """Validate Bluetooth Device address format."""
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", str(addr))) and not str(addr).endswith(":00:00:00:00:00:00")
 
 
# CSV file path for input parameters
CSV_INPUT_PATH = os.path.join(os.path.dirname(__file__), "ADV_Non_Conn_Scan_Param.csv")
 
# Results CSV: written to multiple locations to survive Docker container teardown
RESULTS_CSV_FILENAME = "ADV_Non_Conn_Scan_Param_Results.csv"
 
 
def _get_results_csv_paths():
    """
    Returns a list of paths where the results CSV should be written.
    Includes both local (next to source) and reports dir (survives Docker).
    """
    paths = []
    # Path 1: Next to the source CSV
    paths.append(os.path.join(os.path.dirname(__file__), RESULTS_CSV_FILENAME))
    # Path 2: Reports directory (synced back from Docker to host)
    for reports_candidate in [
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "reports"),
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
    """
    with csv_lock:
        output_paths = _get_results_csv_paths()
        logger().info(f"[CSV WRITE] Will write to: {output_paths}")
 
        for output_path in output_paths:
            try:
                abs_path = os.path.abspath(output_path)
                logger().info(f"[CSV WRITE] Writing TC {testcase_id} -> {abs_path}")
 
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
 
            except Exception as e:
                logger().error(f"[CSV WRITE] FAILED to write TC {testcase_id} at {abs_path}: {e}")
 
 
def read_adv_params_from_csv(csv_file_path):
    """Load advertising parameter rows into dict list."""
    cases = []
    if not os.path.exists(csv_file_path):
        logger().error(f"CSV not found: {csv_file_path}")
        return cases
    with open(csv_file_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("Testcase ID"):
                continue
            raw_addr = row.get("addr_str", "00:00:00:00:00:00").strip().strip('"').strip("'")
            try:
                adv_int_min_raw = row["adv_int_min"].strip()
                adv_int_max_raw = row["adv_int_max"].strip()
                case = {
                    "testcase_id": row["Testcase ID"],
                    "status": int(row["status"]),
                    "adv_type": int(row["adv_type"]),
                    "filter_type": int(row["filter_type"]),
                    "direct_addr_type": int(row["direct_addr_type"]),
                    "addr_str": raw_addr,
                    "adv_int_min": adv_int_min_raw,
                    "adv_int_max": adv_int_max_raw,
                    "own_addr_type": int(row["own_addr_type"]),
                    "channel_map": int(row["channel_map"]),
                }
            except ValueError as e:
                logger().error(f"CSV row parse error: {e} row={row}")
                continue
            cases.append(case)
            logger().info(f"Loaded TestCase {case['testcase_id']} int={case['adv_int_min']}-{case['adv_int_max']}")
    logger().info(f"Total CSV cases: {len(cases)}")
    return cases
 
 
def pytest_generate_tests(metafunc):
    """
    Pytest hook to dynamically generate test cases from CSV file.
    This creates individual test instances for each parameter set.
    """
    if "adv_params" in metafunc.fixturenames:
        csv_path = CSV_INPUT_PATH
        cases = read_adv_params_from_csv(csv_path)
        test_ids = [f"TC_{case['testcase_id']}_interval_{case['adv_int_min']}-{case['adv_int_max']}"
                    for case in cases]
        metafunc.parametrize("adv_params", cases, ids=test_ids)
 
 
# Module-level variable to cache local address across test cases
local_addr = None
 
# Error code definitions with descriptions
ERROR_CODES = {
    "4e12": "Invalid ADV parameters",
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
            if f"0x{code}" in decoded or f" {code}" in decoded or decoded.endswith(code):
                found_codes.add(code)
        generic_match = re.search(r'error status 0x([0-9a-fA-F]+)', decoded)
        if generic_match:
            generic_code = generic_match.group(1).lower()
            found_codes.add(generic_code)
 
    return found_codes
 
 
def test_ble_adv_from_csv(wifi_dut, ble_client, adv_params):
    """
    Run non-connectable advertising for a single parameter set from CSV.
    DUT advertises with specified parameters, Raspi scans for 45 seconds.
    Positive TC: DUT found in scan results = PASS.
    Negative TC: Error code 0x4e12 (invalid params) = PASS.
    Results (Error code + PASS/FAIL) are written to CSV in the finally block.
    """
    global local_addr
    case = adv_params
    tcid = case["testcase_id"]
 
    # ========== FETCH LOCAL ADDRESS (once) ==========
    if local_addr is None:
        logger().info("Waiting for DUT boot sequence to complete...")
        time.sleep(15)
        try:
            get_bus(wifi_dut).get_input_log()
            logger().info("Serial buffer cleared after boot")
        except Exception:
            pass
 
        addr_candidate = None
        for attempt in range(5):
            try:
                addr_candidate = wifi_dut.interfaces.wifi.get_local_address()
                if is_valid_bd_addr(addr_candidate):
                    break
                logger().warning(f"get_local_address attempt {attempt + 1}: invalid address '{addr_candidate}'")
            except Exception as e:
                logger().warning(f"get_local_address attempt {attempt + 1} failed: {e}")
            time.sleep(2)
        if is_valid_bd_addr(addr_candidate):
            local_addr = addr_candidate
            logger().info(f"Fetched DUT local address (API): {local_addr}")
        else:
            local_addr = fetch_local_address(wifi_dut)
            if local_addr:
                logger().info(f"Fetched DUT local address (log fallback): {local_addr}")
            else:
                raise ValueError("Failed to get valid DUT local address from API or logs!")
 
    # Track test result and error code — written to CSV in finally block
    result_error = None
    test_result = "FAIL"
 
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
 
        logger().info("Waiting for DUT initialization to complete...")
        time.sleep(10)
        logger().info(f"\n=== Start TestCase ===")
        logger().info(f"Parameters: interval={case['adv_int_min']}-{case['adv_int_max']}, "
                     f"adv_type={case['adv_type']}, own_addr_type={case['own_addr_type']}, "
                     f"local_addr={local_addr}")
 
        # ========== START ADVERTISING WITH STALE STATE RECOVERY ==========
        for adv_attempt in range(3):
            try:
                logger().info(
                    f" Starting advertising attempt {adv_attempt + 1}/3: "
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
                    logger().warning(
                        f"[ADV-RECOVERY] TC: legacy_adv failed "
                        f"on attempt {adv_attempt + 1} ({adv_err}). "
                        f"Attempting BLE state recovery..."
                    )
                    try:
                        wifi_dut.interfaces.wifi.btc_disconnect(
                            ble_address="00:00:00:00:00:00"
                        )
                    except Exception:
                        pass
                    time.sleep(5)
                    try:
                        wifi_dut.interfaces.wifi.stop_adv()
                    except Exception:
                        pass
                    try:
                        wifi_dut.interfaces.wifi.legacy_scan_stop()
                    except Exception:
                        pass
                    time.sleep(3)
                    try:
                        get_bus(wifi_dut).get_input_log()
                    except Exception:
                        pass
                    logger().info(
                        f"[ADV-RECOVERY] TC: Recovery complete, "
                        f"retrying legacy_adv..."
                    )
                else:
                    logger().error(
                        f"[ADV-RECOVERY] TC: legacy_adv failed "
                        f"on all retries ({adv_err}). BLE state unrecoverable."
                    )
                    result_error = "ADV_Failed"
                    test_result = "FAIL"
                    assert False, f"Advertising failed after 3 attempts: {adv_err}"
 
        logger().info(f"Advertising started interval={case['adv_int_min']}-{case['adv_int_max']}")
 
        # ========== ADVERTISE FOR 30 SECONDS ==========
        adv_duration = 30
        adv_check_interval = 10
        for adv_i in range(adv_duration // adv_check_interval):
            time.sleep(adv_check_interval)
            adv_elapsed = (adv_i + 1) * adv_check_interval
            logger().info(
                f"DUT advertising in progress: "
                f"{adv_elapsed}/{adv_duration} seconds "
                f"interval={case['adv_int_min']}-{case['adv_int_max']})"
            )
        logger().info(
            f"DUT advertising completed {adv_duration} seconds successfully "
            f"interval={case['adv_int_min']}-{case['adv_int_max']})"
        )
 
        # ========== CHECK ADV ERROR CODES ==========
        bus = get_bus(wifi_dut)
        input_log = bus.get_input_log()
        found_codes = find_error_codes_in_log(input_log)
 
        if "4e12" in found_codes:
            result_error = "0x4e12"
            test_result = "PASS"
            logger().info(f"PASS (error code 0x4e12 found - invalid ADV parameters)")
            return  # CSV write happens in finally
 
        unexpected_errors = found_codes - set()
        if unexpected_errors:
            result_error = ",".join([f"0x{c}" for c in unexpected_errors])
            test_result = "FAIL"
            for code in unexpected_errors:
                logger().error(f"FAIL: Error code 0x{code} ({ERROR_CODES.get(code, 'Unknown')}) found after advertising.")
            assert False, f"Unexpected error codes found: {[f'0x{c}' for c in unexpected_errors]}"
 
        # ========== RASPI SCAN FOR 45 SECONDS ==========
        logger().info(f"Starting Raspi scan for DUT address {local_addr} (45 seconds)...")
        ble_client.interfaces.bluetooth.set_bus()
        ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=local_addr,
            capability="KeyboardOnly",
            pin_code="-8"
        )
 
        found_addr = None
        scan_timeout = 45
        for scan_sec in range(scan_timeout):
            devices = ble_client.interfaces.bluetooth.get_devices()
            if local_addr in devices:
                found_addr = local_addr
                break
            time.sleep(1)
            if (scan_sec + 1) % 10 == 0:
                logger().info(
                    f"[SCAN] Raspi scanning: {scan_sec + 1}/{scan_timeout} seconds "
                    f"looking for {local_addr})"
                )
 
        ble_client.interfaces.bluetooth.stop_scanning()
 
        if not found_addr:
            result_error = "Scan_Failed"
            test_result = "FAIL"
            logger().error(f"DUT address {local_addr} NOT found by Raspi during {scan_timeout}s scan.")
            assert False, f"DUT address {local_addr} not found by Raspi during {scan_timeout}s scan."
 
        # ========== DUT FOUND = PASS ==========
        result_error = "None"
        test_result = "PASS"
        logger().info(f"PASS - DUT {local_addr} found in Raspi scan results.")
 
    except Exception as e:
        logger().error(f"FAIL: {e}")
        if result_error is None:
            result_error = str(e)[:80]
        raise
    finally:
        # ========== ALWAYS WRITE RESULT TO CSV ==========
        try:
            logger().info(f"[FINALLY] Writing CSV result: Error={result_error}, Result={test_result}")
            write_result_to_csv(tcid, result_error, test_result)
        except Exception as csv_err:
            logger().error(f"[FINALLY] CSV write failed: {csv_err}")
 
        # ========== STOP RASPI SCANNING ==========
        try:
            ble_client.interfaces.bluetooth.stop_scanning()
        except Exception:
            pass
 
        # ========== STOP DUT SCAN ==========
        try:
            wifi_dut.interfaces.wifi.legacy_scan_stop()
            logger().info("[CLEANUP] DUT scan stopped.")
        except Exception:
            pass
 
        # ========== STOP DUT ADVERTISING ==========
        try:
            wifi_dut.interfaces.wifi.stop_adv()
            logger().info("[CLEANUP] DUT advertising stopped.")
        except Exception as e:
            logger().warning(f"[CLEANUP] Failed to stop advertising: {e}")
 
        # ========== POST-CLEANUP: VERIFY BLE STATE ==========
        try:
            post_disc_log = get_bus(wifi_dut).get_input_log()
            post_disc_text = "".join(
                line.decode(errors="ignore")
                if hasattr(line, "decode") else str(line)
                for _, line in post_disc_log
            )
            if "0x4e0c" in post_disc_text.lower():
                logger().warning(
                    f"[CLEANUP] 0x4e0c detected after cleanup. "
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
                try:
                    get_bus(wifi_dut).get_input_log()
                except Exception:
                    pass
                logger().info(f"[CLEANUP] 0x4e0c recovery complete.")
        except Exception:
            pass
 
        # ========== CLOSE BLE INTERFACE WITH RETRY ==========
        close_success = False
        for close_attempt in range(3):
            try:
                ble_client.interfaces.bluetooth.close()
                logger().info("[CLEANUP] BLE interface closed successfully.")
                close_success = True
                break
            except Exception as e:
                logger().warning(f"[CLEANUP] close() attempt {close_attempt + 1}/3 failed: {e}")
                time.sleep(1)
        if not close_success:
            logger().error("[CLEANUP] All 3 close() attempts failed. "
                         "BlueZ stack may be in dirty state for next test.")
 
        # Final scan_stop to ensure DUT is fully idle
        try:
            wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass
 
        time.sleep(5)
        logger().info(f"=== End TestCase ===\n")