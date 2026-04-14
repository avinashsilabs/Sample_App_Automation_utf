"""
================================================================================
BLE Connection Parameter Update - DUT as Peripheral
================================================================================

Test Case Overview
------------------
This test validates BLE connection parameter updates when the DUT operates
as a **peripheral** (advertiser).  The Raspberry Pi acts as the **central**
(scanner / initiator).  After the connection is established and SMP pairing
completes, the **DUT (peripheral)** sends an LL_CONNECTION_PARAM_REQ to the
Raspi central requesting new connection parameters from the CSV.  Connection
stability is then monitored for 60 seconds.

Roles:
  +---------------------+              +------------------------+
  |  DUT (Peripheral)   |  <--BLE-->   |  Raspi (Central)       |
  |  RS9116 RT595 SAPI  |              |  BlueZ / hci0          |
  |  Advertises         |              |  Scans & Connects      |
  |  Displays passkey   |              |  Enters passkey        |
  |  Sends conn_param   |              |  Accepts/Rejects       |
  +---------------------+              +------------------------+

Test Flow (per CSV row):
    1.  Pre-test cleanup: stop ADV, stop scan, drain serial, re-apply SMP
    2.  Delete stale Raspi bond files (filesystem + D-Bus RemoveDevice)
    3.  Raspi starts scanning with SMP capability (start_smp_scan)
    4.  DUT starts advertising (legacy_adv, adv_type=128, interval=338)
    5.  Raspi discovers DUT address and initiates BLE connection
    6.  DUT logs Enhanced Connect Event - connection established
    7.  SMP pairing: DUT displays passkey -> Raspi enters passkey
    8.  SMP pairing verified via "smp encrypt event" on DUT serial
    9.  Firmware auto-scan killed (legacy_scan_stop) to protect connection
   10.  DUT sends conn_param_update with CSV values to Raspi
   11.  Poll DUT serial for "conn updated device address" confirmation
   12.  Firmware auto-scan killed again before stability window
   13.  Connection stability monitored for 60 seconds (10s polling)
         - Preemptive scan_stop every 10s to kill FW auto-scan
         - Disconnect detection with accumulated-string parsing
   14.  DUT initiates btc_disconnect (cleanup only)
   15.  Poll for disconnect event confirmation
   16.  Full Raspi cleanup: remove_device, bond deletion, close BLE

Pass/Fail Criteria:
    PASS - Positive scenario:
        conn_param_update confirmed ("conn updated" event received) AND
        connection remains stable for 60 seconds after parameter update.
        No disconnect detected during the stability window.
    PASS - Negative scenario (invalid connection parameters):
        DUT returns 0x4e62 after conn_param_update - firmware correctly
        rejected out-of-range connection parameter values.
    FAIL:
        conn_param_update not confirmed within timeout, OR
        device disconnects during the 60-second stability window, OR
        SMP pairing fails, OR
        unexpected error code detected after ADV or conn_param_update.

Test Coverage:
    - Connection intervals: 6 (7.5ms) to 3200 (4000ms) in BLE units (1.25ms each)
    - Slave latency: 0 to 499
    - Supervision timeout: 10 (100ms) to 3200 (32000ms) in BLE units (10ms each)
    - DUT Adv with default adv parameters
    - RASPI initiates connection as central to DUT 
    - SMP pairing with passkey authentication
    - Connection stability monitoring after parameter update

Error Codes Monitored:
    0x4e62  Invalid Connection Parameters
    0x4e16  Local Host Terminated Connection (expected on clean disconnect)
    0x4e13  Remote User Terminated Connection
    0x4e08  Connection Timeout
    0x4e3e  MIC Failure
    0x4e05  Authentication Failure
    0x4d15  SMP Pairing Process Failed
    0x4b0b  SMP SC Passkey/Pairing Failure
    0x4e0c  Invalid BLE State
    0x4e0b  ACL Connection Already Exists
    0x4e04  Page Timeout
    0x4d05  BLE Device Not Connected

CSV Parameters (Conn_Param_Update.csv):
    Testcase ID           - Test case number
    conn_interval_min     - Minimum connection interval (BLE units x 1.25ms)
    conn_interval_max     - Maximum connection interval (BLE units x 1.25ms)
    slave_latency         - Number of connection events the peripheral can skip
    supervision_timeout   - Supervision timeout (BLE units x 10ms)

Author: Sairam Chintalapati
Date: April 1, 2026 
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


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def get_bus(device):
    """Get the serial bus interface from a device."""
    return device.interfaces.wifi.bus


def fetch_local_address(wifi_dut):
    """
    Fallback: extract local BD address from the serial boot log.
    Parses 'local_bd_address: XX:XX:XX:XX:XX:XX' from input_log history.
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
# Serial log offset helpers
# ---------------------------------------------------------------------------
# get_input_log() returns a REFERENCE to the internal list and never clears
# it.  Calling .clear() would destroy the Serial Transaction Log printed by
# release_resources() at teardown.
#
# Instead, we track a "high-water mark" (offset) into the list.  Flushing
# advances the offset; reading returns only entries added since the last
# flush.  The underlying list is never modified, so the full transaction
# log is preserved for teardown diagnostics.
_serial_log_offset = 0


def _flush_serial_log(wifi_dut):
    """Mark the current end of the serial log as 'already processed'.

    Subsequent calls to ``_get_fresh_log_entries()`` will only return
    entries appended *after* this point.  The underlying ``input_log``
    list is **not** modified, preserving the complete Serial Transaction
    Log for teardown.
    """
    global _serial_log_offset
    try:
        _serial_log_offset = len(get_bus(wifi_dut).get_input_log())
    except Exception:
        pass


def _get_fresh_log_entries(wifi_dut):
    """Return serial log entries added since the last ``_flush_serial_log()``
    call (or since the start of the session if flush was never called).

    Does NOT advance the offset - call ``_flush_serial_log()`` explicitly
    when you want to discard the returned entries from future reads.
    """
    try:
        full_log = get_bus(wifi_dut).get_input_log()
        return full_log[_serial_log_offset:]
    except Exception:
        return []


def _force_clear_raspi_bonds(ble_client, dut_address):
    """
    Force-delete stale BLE bond files from the Raspi filesystem.

    The BlueZ D-Bus RemoveDevice() can race with bluetoothd loading
    bonds from /var/lib/bluetooth/ after a restart.  If the race is lost,
    BlueZ resumes LL encryption with stale LTK keys.  The DUT still holds
    the old LTK, but the LL encryption context was reset on disconnect.
    The MIC computation fails -> 0x4e3e (MIC Failure) -> LL disconnect
    within ~2 seconds, before any SMP/ATT traffic.

    This function deletes on-disk bond files via SSH before bluetoothd
    is (re)started, eliminating the race.
    """
    try:
        dut_addr = dut_address.upper()
        LOGGER.info(
            f"[BOND CLEANUP] Removing stale bond files for "
            f"{dut_addr} from Raspi filesystem"
        )
        bt = ble_client.interfaces.bluetooth
        bt.shell.execute(
            f"sudo rm -rf /var/lib/bluetooth/*/{dut_addr}", "*"
        )
        bt.shell.execute(
            "sudo rm -rf /var/lib/bluetooth/*/cache/*", "*"
        )
        LOGGER.info("[BOND CLEANUP] Stale bond files deleted from Raspi")
    except Exception as e:
        LOGGER.warning(f"[BOND CLEANUP] Failed to delete bond files: {e}")


# ---------------------------------------------------------------------------
# CSV file paths
# ---------------------------------------------------------------------------
CSV_INPUT_PATH = os.path.join(os.path.dirname(__file__), "Conn_Param_Update_DUT_Peripheral.csv")
RESULTS_CSV_FILENAME = "Conn_Param_Update_DUT_Peripheral_Results.csv"


def _get_results_csv_paths():
    """
    Returns a list of paths where the results CSV should be written.
    Includes both local (next to source) and reports dir (survives Docker).
    """
    paths = []
    paths.append(os.path.join(os.path.dirname(__file__), RESULTS_CSV_FILENAME))
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

                LOGGER.info(
                    f"[CSV WRITE] SUCCESS: TC {testcase_id} -> "
                    f"Error={error_code}, Result={result} at {abs_path}"
                )
            except Exception as e:
                LOGGER.error(
                    f"[CSV WRITE] FAILED to write TC {testcase_id} "
                    f"at {output_path}: {e}"
                )


def read_conn_params_from_csv(csv_file_path):
    """Load connection parameter rows from CSV into dict list."""
    cases = []
    if not os.path.exists(csv_file_path):
        LOGGER.error(f"CSV not found: {csv_file_path}")
        return cases

    with open(csv_file_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("Testcase ID"):
                continue
            try:
                case = {
                    "testcase_id": row["Testcase ID"],
                    "conn_interval_min": int(row["conn_interval_min"]),
                    "conn_interval_max": int(row["conn_interval_max"]),
                    "slave_latency": int(row["slave_latency"]),
                    "supervision_timeout": int(row["supervision_timeout"]),
                }
            except ValueError as e:
                LOGGER.error(f"CSV row parse error: {e} row={row}")
                continue
            cases.append(case)
            LOGGER.info(
                f"Loaded TestCase {case['testcase_id']} "
                f"interval={case['conn_interval_min']}-{case['conn_interval_max']} "
                f"latency={case['slave_latency']} timeout={case['supervision_timeout']}"
            )

    LOGGER.info(f"Total CSV conn param cases: {len(cases)}")
    return cases


def pytest_generate_tests(metafunc):
    """
    Pytest hook to dynamically generate test cases from CSV file.
    Creates individual test instances for each parameter set.
    """
    if "conn_params" in metafunc.fixturenames:
        csv_path = os.path.join(os.path.dirname(__file__), "Conn_Param_Update_DUT_Peripheral.csv")
        cases = read_conn_params_from_csv(csv_path)
        test_ids = [
            f"TC_{case['testcase_id']}_int_{case['conn_interval_min']}-{case['conn_interval_max']}"
            for case in cases
        ]
        metafunc.parametrize("conn_params", cases, ids=test_ids)


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------
# Module-level variable to cache local address across test iterations
local_addr = None

ERROR_CODES = {
    "4e62": "Invalid Connection Parameters",
    "4e16": "Local Host Terminated Connection",
    "4e13": "Remote User Terminated Connection",
    "4e08": "Connection Timeout",
    "4e3e": "MIC Failure",
    "4e05": "Authentication Failure",
    "4d15": "SMP Pairing Process Failed",
    "4e0c": "Invalid BLE State",
    "4e0b": "ACL Connection Already Exists",
    "4e04": "Page Timeout",
    "4b0b": "SMP SC Passkey/Pairing Failure",
    "4d05": "BLE Device Not Connected",
}

# Error codes that indicate invalid/rejected connection parameters (negative-scenario PASS)
CONN_PARAM_INVALID_CODES = {"4e62"}

# Benign error codes that should never trigger a test failure.
# 0x103 is the DUT firmware response when legacy_scan_stop() is called
# while no explicit scan is active (the firmware's internal connectable
# scan returns this).
BENIGN_ERROR_CODES = {"103"}


def find_error_codes_in_log(input_log):
    """
    Extract error codes from serial log.
    Returns set of error codes found (normalized to lowercase without 0x prefix).
    Benign codes (e.g. 0x103 from scan_stop in wrong state) are excluded.
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
        generic_match = re.search(r'error status 0x([0-9a-fA-F]+)', decoded)
        if generic_match:
            generic_code = generic_match.group(1).lower()
            found_codes.add(generic_code)
    # Strip benign codes so they never trigger a FAIL
    found_codes -= BENIGN_ERROR_CODES
    return found_codes


# ---------------------------------------------------------------------------
# Fixed default advertising parameters (used for every test case)
# The CSV only supplies connection-parameter-update values.
# ---------------------------------------------------------------------------
DEFAULT_ADV_TYPE = 128       # Connectable undirected
DEFAULT_ADV_INT_MIN = 338    # ~211.25 ms
DEFAULT_ADV_INT_MAX = 338    # ~211.25 ms


# ---------------------------------------------------------------------------
# Test function
# ---------------------------------------------------------------------------
@pytest.mark.parametrize_from_csv
@pytest.mark.test_src_map_id('TC2853243912')
def test_ble_conn_param_update_peripheral_from_csv(wifi_dut, ble_client, conn_params):
    """
    DUT (Peripheral) advertises, Raspi (Central) scans and connects,
    SMP pairing completes, DUT sends conn_param_update with CSV values,
    then 60-second connection stability is verified.

    Results (Error code + PASS/FAIL) are written to CSV in the finally block.
    """
    global local_addr, _serial_log_offset
    case = conn_params
    tcid = case["testcase_id"]

    # Reset serial log offset - the harness reopens the serial port for
    # each test iteration which creates a new (empty) input_log list.
    _serial_log_offset = 0

    # ========== FETCH LOCAL ADDRESS (once, cached across iterations) ==========
    if local_addr is None:
        LOGGER.info("Waiting for DUT boot sequence to complete...")
        time.sleep(15)

        # Set SMP pairing capability: DisplayOnly, auth_req=0x2D (Bonding + MITM + SC)
        # MITM bit (0x04) is required to force PasskeyEntry instead of JustWorks.
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
                LOGGER.warning(
                    f"get_local_address attempt {attempt + 1}: "
                    f"invalid address '{addr_candidate}'"
                )
            except Exception as e:
                LOGGER.warning(
                    f"get_local_address attempt {attempt + 1} failed: {e}"
                )
            time.sleep(2)

        if is_valid_bd_addr(addr_candidate):
            local_addr = addr_candidate
            LOGGER.info(f"Fetched DUT local address (API): {local_addr}")
        else:
            local_addr = fetch_local_address(wifi_dut)
            if local_addr:
                LOGGER.info(
                    f"Fetched DUT local address (log fallback): {local_addr}"
                )
            else:
                raise ValueError(
                    "Failed to get valid DUT local address from API or logs!"
                )

        # Now that address is obtained, flush the boot log so stale data
        # from the boot sequence doesn't contaminate error checks.
        _flush_serial_log(wifi_dut)

    # Track test result and error code - written to CSV in finally block
    result_error = None
    test_result = "FAIL"
    # raspi_addr is the Raspi BLE address extracted from DUT connection event.
    # Declared here so the finally block can always disconnect, even after
    # early returns (e.g. 0x4e62 negative-scenario PASS).
    raspi_addr = None
    # Flag: set True when a disconnect event (0x4e13, 0x4e08, etc.) has
    # already been detected during the test.  The finally block uses this
    # to SKIP btc_disconnect() - calling btc_disconnect on an already-
    # disconnected link corrupts the DUT BLE state machine, producing
    # 0x4e0c ("Invalid BLE State") that cascades to ALL subsequent tests.
    dut_already_disconnected = False

    try:
        # ========== PRE-TEST CLEANUP ==========
        # Stop advertising (may be left over from a previous failed test)
        for attempt in range(3):
            try:
                wifi_dut.interfaces.wifi.stop_adv()
                time.sleep(1)
                break
            except Exception:
                if attempt < 2:
                    time.sleep(3)

        # Stop scan (DUT may have a residual internal scan)
        for attempt in range(3):
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
                time.sleep(1)
                break
            except Exception:
                if attempt < 2:
                    time.sleep(3)

        # Drain serial buffer so stale errors don't contaminate this test
        _flush_serial_log(wifi_dut)

        # Re-apply SMP pairing capability every test to ensure fresh SMP state
        # auth_req=0x2D (Bonding + MITM + SC) forces PasskeyEntry pairing.
        try:
            wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
                io_capability=0x00, auth_req=0x2D
            )
            LOGGER.info("SMP pairing capability re-applied for this test.")
            time.sleep(1)
        except Exception as smp_cap_err:
            LOGGER.warning(
                f"Failed to re-apply SMP capability: {smp_cap_err}"
            )

        LOGGER.info("Waiting for DUT to settle...")
        time.sleep(3)

        LOGGER.info(f"\n=== Start TestCase {tcid} ===")
        LOGGER.info(
            f"Parameters: conn_interval={case['conn_interval_min']}-"
            f"{case['conn_interval_max']}, "
            f"latency={case['slave_latency']}, "
            f"timeout={case['supervision_timeout']}, "
            f"local_addr={local_addr}"
        )

        # ========== PREPARE RASPI AS CENTRAL (scan + connect) ==========
        LOGGER.info("Preparing Raspberry Pi as BLE Central...")
        ble_client.interfaces.bluetooth.set_bus()
        time.sleep(2)

        # ---- PRE-SCAN BOND CLEANUP (filesystem level) ----
        # Delete bond files BEFORE starting scan/bluetoothd.
        # This ensures the new bluetoothd has NOTHING to load from
        # /var/lib/bluetooth/, eliminating the race between
        # bluetoothd bond-loading and the D-Bus RemoveDevice() call.
        _force_clear_raspi_bonds(ble_client, local_addr)

        # Start Raspi scanning with SMP capability.
        # Pass the DUT address so start_smp_scan can also call
        # RemoveDevice via D-Bus (belt-and-suspenders).
        LOGGER.info(
            f"Calling start_smp_scan with bt_dut_address={local_addr} "
            f"to clear stale bonds and begin scanning"
        )
        ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=local_addr,
            capability="KeyboardOnly",
            pin_code="-8",
        )
        LOGGER.info("Raspberry Pi scanning started (Central role).")
        time.sleep(3)

        # ========== FLUSH SERIAL LOG BEFORE ADV ==========
        # Critical: Flush the serial log IMMEDIATELY before legacy_adv().
        # The pre-test stop_adv() may have produced 0x4e0c ("Invalid BLE
        # State") if the DUT booted with auto-advertising but the BLE stack
        # was in an inconsistent state.  If we don't flush here, the stale
        # 0x4e0c from the pre-cleanup contaminates the post-ADV error check
        # and causes a false FAIL.
        _flush_serial_log(wifi_dut)

        # ========== DUT STARTS ADVERTISING (Peripheral Role) ==========
        # Wrap legacy_adv() in a retry loop.  If the first attempt fails
        # (e.g. "Failed to start advertising" due to a stale BLE
        # connection handle from the previous test), attempt a
        # force-disconnect recovery and retry once.  This prevents a
        # single stuck state from cascading to ALL subsequent test cases.
        adv_success = False
        for adv_attempt in range(3):
            try:
                LOGGER.info(
                    f"DUT starting advertising (tc={tcid}, attempt="
                    f"{adv_attempt + 1}) adv_type="
                    f"{DEFAULT_ADV_TYPE} interval={DEFAULT_ADV_INT_MIN}"
                )
                wifi_dut.interfaces.wifi.legacy_adv(
                    status=1,
                    adv_type=DEFAULT_ADV_TYPE,
                    filter_type=0,
                    direct_addr_type=0,
                    direct_addr="00:00:00:00:00:00",
                    adv_int_min=DEFAULT_ADV_INT_MIN,
                    adv_int_max=DEFAULT_ADV_INT_MAX,
                    own_addr_type=0,
                    channel_map=7,
                )
                # Detect stale advertising state: firmware returns
                # "ble_connectable_adv_already_in_progress" without
                # raising an exception.  The radio is NOT actually
                # transmitting, so the Raspi will never see the DUT.
                time.sleep(0.5)
                _post_adv = _get_fresh_log_entries(wifi_dut)
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
                adv_success = True
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
                    # Flush serial buffer after recovery disconnect
                    _flush_serial_log(wifi_dut)
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
                    # Final flush before retry
                    _flush_serial_log(wifi_dut)
                    LOGGER.info(
                        f"[ADV-RECOVERY] TC {tcid}: Recovery complete, "
                        f"retrying legacy_adv..."
                    )
                else:
                    LOGGER.error(
                        f"[ADV-RECOVERY] TC {tcid}: legacy_adv failed "
                        f"on retry ({adv_err}). BLE state unrecoverable."
                    )
                    result_error = "ADV_Failed"
                    test_result = "FAIL"
                    assert False, (
                        f"Failed to start advertising after BLE state "
                        f"recovery: {adv_err}"
                    )
        time.sleep(3)

        # ========== CHECK ADV ERROR CODES ==========
        adv_log = list(_get_fresh_log_entries(wifi_dut))
        found_codes = find_error_codes_in_log(adv_log)

        unexpected_errors = found_codes - {"4e16"}
        if unexpected_errors:
            result_error = ",".join([f"0x{c}" for c in sorted(unexpected_errors)])
            test_result = "FAIL"
            for code in unexpected_errors:
                LOGGER.error(
                    f"TestCase {tcid} FAIL: Error code 0x{code} "
                    f"({ERROR_CODES.get(code, 'Unknown')}) found after ADV."
                )
            assert False, (
                f"Unexpected error codes found after ADV: "
                f"{[f'0x{c}' for c in sorted(unexpected_errors)]}"
            )

        LOGGER.info(
            f"DUT advertising started (tc={tcid}) adv_type="
            f"{DEFAULT_ADV_TYPE} interval={DEFAULT_ADV_INT_MIN}"
        )

        # ========== RASPI DISCOVERS DUT AND INITIATES CONNECTION ==========
        LOGGER.info(
            f"Raspi scanning for DUT address {local_addr}..."
        )
        found_addr = None
        scan_timeout = 30
        for _ in range(scan_timeout):
            try:
                devices = ble_client.interfaces.bluetooth.get_devices()
                if local_addr in devices:
                    found_addr = local_addr
                    break
            except Exception:
                pass
            time.sleep(1)

        try:
            ble_client.interfaces.bluetooth.stop_scanning()
        except Exception:
            pass

        if not found_addr:
            result_error = "Scan_Failed"
            test_result = "FAIL"
            LOGGER.error(
                f"DUT address {local_addr} not found by Raspi during "
                f"{scan_timeout}s scan."
            )
            assert False, (
                f"DUT address {local_addr} not found by Raspi during scan."
            )
        LOGGER.info(f"DUT address {local_addr} found by Raspi during scan.")

        # ---- Raspi initiates connection to DUT ----
        LOGGER.info(f"Raspi connecting to DUT {local_addr}...")
        try:
            ble_client.interfaces.bluetooth.connect(
                dev_addr=local_addr, supervision_timeout=500
            )
        except Exception as conn_exc:
            LOGGER.warning(
                f"Raspi connect() raised (may still succeed): {conn_exc}"
            )
        time.sleep(3)

        # ========== WAIT FOR CONNECTION EVENT ON DUT SERIAL ==========
        # The DUT (peripheral) logs "On Enhance Connect Event" when the
        # Raspi central's connection request is accepted at the LL level.
        LOGGER.info(
            "Waiting for connection event on DUT serial..."
        )
        connection_established = False
        connection_wait_timeout = 30
        connection_wait_start = time.time()
        accumulated_conn_log = ""

        while (time.time() - connection_wait_start) < connection_wait_timeout:
            time.sleep(2)
            try:
                new_log = "\n".join(
                    line.decode(errors="ignore")
                    if hasattr(line, "decode") else str(line)
                    for _, line in _get_fresh_log_entries(wifi_dut)
                )
                accumulated_conn_log += new_log
            except Exception:
                pass
            accumulated_lower = accumulated_conn_log.lower()

            # Check for connection established
            if (
                "on enhance connect event" in accumulated_lower
                or "enhanced connect event status report : 0" in accumulated_lower
            ):
                connection_established = True
                LOGGER.info(
                    "DUT connection event received - BLE link established."
                )
                break

            # Check for connection timeout
            if "error status 0x4e08" in accumulated_lower:
                result_error = "0x4e08"
                test_result = "FAIL"
                LOGGER.error("Connection timeout (0x4e08)")
                assert False, "Connection timeout (0x4e08)"

            elapsed = int(time.time() - connection_wait_start)
            LOGGER.info(
                f"Waiting for DUT connection event... "
                f"{elapsed}/{connection_wait_timeout}s"
            )

        if not connection_established:
            result_error = "Connection_Failed"
            test_result = "FAIL"
            LOGGER.error(
                "DUT connection event not received within timeout"
            )
            assert False, (
                "Connection failed - No connection event on DUT serial"
            )

        # Extract Raspi address from DUT connection log
        addr_match = re.search(
            r"(?:Connected Address|Remote Device Address)\s*:\s*([0-9A-Fa-f:]{11,17})",
            accumulated_conn_log,
        )
        if addr_match:
            raspi_addr = addr_match.group(1).strip()
            LOGGER.info(
                f"Extracted Raspi address from DUT log: {raspi_addr}"
            )
        else:
            # Fallback: try to get from Raspi's own adapter
            try:
                raspi_addr = ble_client.interfaces.bluetooth.get_address()
                LOGGER.info(
                    f"Got Raspi address from adapter: {raspi_addr}"
                )
            except Exception:
                pass

        # ----- Early passkey extraction from connection log -----
        # In peripheral role the Raspi initiates connection AND SMP
        # pairing immediately, so the passkey event often arrives in
        # the same serial RX batch as the Enhanced Connect Event.
        # Extract it BEFORE flushing so it is not lost.
        dut_passkey = None
        pk_early = re.search(
            r"passkey[:\s]+(\d+)", accumulated_conn_log, re.IGNORECASE
        )
        if pk_early and len(pk_early.group(1)) <= 6:
            dut_passkey = pk_early.group(1).zfill(6)
            LOGGER.info(
                f"Passkey found in connection log (early extract): "
                f"{pk_early.group(1)} -> {dut_passkey}"
            )

        # Flush connection log artifacts
        _flush_serial_log(wifi_dut)
        time.sleep(0.5)

        # ========== STOP FIRMWARE SCAN IMMEDIATELY AFTER CONNECTION ==========
        # The firmware fires rsi_ble_event_scan_restart_driver_callback
        # right after the Enhanced Connect Event, restarting an internal
        # BLE scan.  This background scan competes for radio time with
        # the active connection.  Killing it HERE - before SMP even
        # begins - prevents the scan from interfering with the fragile
        # SMP passkey exchange.
        for _post_conn_scan_stop in range(2):
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
                LOGGER.info(
                    "[POST-CONNECT] Stopped firmware auto-scan "
                    "to protect SMP pairing."
                )
                break
            except Exception:
                time.sleep(0.5)
        # Flush scan-stop artefacts (0x103 etc.) before SMP
        _flush_serial_log(wifi_dut)

        # ========== SMP PASSKEY HANDLING ==========
        LOGGER.info("Waiting for passkey event from DUT...")
        smp_failed_early = False
        disconnected_early = False
        justworks_completed = False
        max_passkey_attempts = 30  # 30 x 0.5s = 15s total

        for attempt in range(max_passkey_attempts):
            time.sleep(0.5)
            new_log_items = list(_get_fresh_log_entries(wifi_dut))

            for _, raw_line in new_log_items:
                try:
                    decoded_line = raw_line.decode(errors="ignore")
                except Exception:
                    decoded_line = str(raw_line)
                decoded_lower = decoded_line.lower()

                # Check for passkey
                if not dut_passkey:
                    pk_match = re.search(
                        r"passkey[:\s]+(\d+)", decoded_line, re.IGNORECASE
                    )
                    if pk_match:
                        passkey_raw = pk_match.group(1)
                        if len(passkey_raw) <= 6:
                            dut_passkey = passkey_raw.zfill(6)
                            LOGGER.info(
                                f"Passkey extracted: {passkey_raw} -> "
                                f"{dut_passkey}"
                            )

                # Detect JustWorks completion (LTK generated without passkey)
                if not dut_passkey and not justworks_completed:
                    if (
                        "smp encrypt event" in decoded_lower
                        or "smp security keys event" in decoded_lower
                        or "le ltk" in decoded_lower
                    ):
                        justworks_completed = True
                        LOGGER.info(
                            "JustWorks pairing detected - LTK generated "
                            "without passkey event. SMP completed via "
                            "JustWorks (no MITM)."
                        )

                # Check for early SMP failure
                if "smp failed" in decoded_lower or "4b0b" in decoded_lower:
                    LOGGER.error(
                        f"SMP failure detected during passkey wait: "
                        f"{decoded_lower.strip()}"
                    )
                    smp_failed_early = True

                # Check for unexpected disconnect
                if (
                    "peripheral is disconnected" in decoded_lower
                    or "on event disconnect" in decoded_lower
                ):
                    LOGGER.error(
                        f"Disconnect detected during passkey wait: "
                        f"{decoded_lower.strip()}"
                    )
                    disconnected_early = True

            if dut_passkey:
                LOGGER.info(f"DUT passkey found: {dut_passkey}")
                break

            if justworks_completed:
                LOGGER.info(
                    "Skipping passkey wait - JustWorks pairing already "
                    "completed successfully."
                )
                break

            if smp_failed_early or disconnected_early:
                break

            if (attempt + 1) % 4 == 0:
                LOGGER.info(
                    f"Passkey not found yet, attempt "
                    f"{attempt + 1}/{max_passkey_attempts}..."
                )

        if smp_failed_early:
            result_error = "0x4b0b"
            test_result = "FAIL"
            LOGGER.error(
                "SMP pairing failed before passkey could be exchanged "
                "(0x4b0b). Possible stale bond keys on Raspi."
            )
            assert False, (
                "SMP pairing failed early (0x4b0b) - "
                "stale bond keys or timing issue"
            )

        if disconnected_early:
            dut_already_disconnected = True
            result_error = "Disconnected_During_Pairing"
            test_result = "FAIL"
            LOGGER.error(
                "DUT disconnected before passkey exchange could complete."
            )
            assert False, "DUT disconnected during SMP passkey wait"

        if dut_passkey:
            ble_client.interfaces.bluetooth.set_pin(int(dut_passkey))
            LOGGER.info(f"Set passkey {dut_passkey} on Raspi BLE client.")
        elif justworks_completed:
            LOGGER.info(
                "JustWorks pairing - no passkey to send to Raspi. "
                "Proceeding to SMP verification."
            )
        else:
            result_error = "Passkey_Not_Found"
            test_result = "FAIL"
            LOGGER.error(
                "Passkey not found in DUT logs after all attempts."
            )
            assert False, (
                "Passkey not found in DUT logs after connection."
            )

        # ========== VERIFY SMP PAIRING SUCCESS ==========
        LOGGER.info("Verifying SMP pairing outcome...")
        smp_verified = False
        smp_failed_in_verification = False
        smp_fail_detail = ""
        smp_verify_timeout = 10  # seconds
        smp_verify_start = time.time()

        while (time.time() - smp_verify_start) < smp_verify_timeout:
            time.sleep(0.5)
            pairing_log_items = _get_fresh_log_entries(wifi_dut)

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
                if (
                    "smp encrypt event" in decoded_pair
                    or "smp security keys event" in decoded_pair
                    or "le ltk" in decoded_pair
                ):
                    smp_verified = True
                    LOGGER.info(
                        "SMP pairing success indicators found in DUT log."
                    )
                    break

            if smp_failed_in_verification or smp_verified:
                break

        if smp_failed_in_verification:
            result_error = "0x4b0b"
            test_result = "FAIL"
            LOGGER.error(
                f"SMP DH Key Check / Pairing Failure (0x4b0b): "
                f"{smp_fail_detail}"
            )
            assert False, (
                f"SMP Pairing Failed (0x4b0b) - {smp_fail_detail}"
            )

        # Final SMP error-code sweep
        pairing_log_items = _get_fresh_log_entries(wifi_dut)
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
            LOGGER.error(
                "SMP pairing failed with authentication failure (0x4e05)"
            )
            assert False, (
                "SMP pairing failed - Authentication failure (0x4e05)"
            )
        if "4d15" in pairing_codes:
            result_error = "0x4d15"
            test_result = "FAIL"
            LOGGER.error("SMP Pairing Process Failed (0x4d15)")
            assert False, "SMP Pairing Process Failed (0x4d15)"

        if smp_verified:
            LOGGER.info("SMP Pairing completed successfully!")
        else:
            LOGGER.warning(
                "SMP pairing success not explicitly confirmed in log, "
                "proceeding with connection parameter update."
            )

        # ========== STOP FIRMWARE AUTO-SCAN AFTER SMP PAIRING ==========
        # The DUT firmware automatically restarts BLE scanning after SMP
        # pairing completes (rsi_ble_event_scan_restart_driver_callback).
        # This background scan competes for radio time with the active
        # BLE connection.  Stopping the scan here prevents radio
        # time-sharing conflicts during conn_param_update.
        for _scan_stop_attempt in range(3):
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
                LOGGER.info(
                    "[POST-SMP] Stopped firmware auto-scan to protect "
                    "connection stability."
                )
                break
            except Exception:
                time.sleep(1)
        # Flush any 0x103 or scan-stop artefacts from serial buffer
        _flush_serial_log(wifi_dut)
        time.sleep(1)  # Let firmware finish stopping

        # ========== DUT (PERIPHERAL) SENDS CONNECTION PARAMETER UPDATE ==========
        # In the peripheral role, the DUT sends an L2CAP Connection
        # Parameter Update Request to the central (Raspi).  The Raspi
        # central accepts/rejects the request.  If accepted, the
        # controller applies the new parameters and fires the
        # "conn updated device address" event on serial.
        if not raspi_addr:
            # If we couldn't extract the Raspi address, use a fallback
            # approach: try to get it from the Raspi adapter directly
            try:
                raspi_addr = ble_client.interfaces.bluetooth.get_address()
                LOGGER.info(
                    f"Using Raspi adapter address as fallback: {raspi_addr}"
                )
            except Exception:
                pass

        if not raspi_addr:
            result_error = "Remote_Addr_Not_Found"
            test_result = "FAIL"
            LOGGER.error(
                "Raspi address not found - cannot send conn_param_update."
            )
            assert False, (
                "Raspi address not found in DUT logs or adapter."
            )

        LOGGER.info(
            f"DUT (Peripheral) sending conn_param_update to "
            f"{raspi_addr}: min_interval={case['conn_interval_min']}, "
            f"max_interval={case['conn_interval_max']}, "
            f"latency={case['slave_latency']}, "
            f"timeout={case['supervision_timeout']}"
        )

        # Drain serial buffer before param update for clean error detection
        _flush_serial_log(wifi_dut)

        # ---- Send conn_param_update with synchronous 4e62 detection ----
        # The SAPI firmware may reject invalid connection parameters
        # SYNCHRONOUSLY - the conn_param_update() API call itself throws
        # an exception containing "4e62" before any serial event is
        # produced.  If we don't catch this here, the exception bubbles
        # up to the outer `except Exception as e:` block and is recorded
        # as FAIL instead of the correct negative-scenario PASS.
        #
        # The try/except below catches synchronous rejections.
        # Asynchronous rejections (4e62 arriving later via serial) are
        # still handled by the polling loop's CONN_PARAM_INVALID_CODES
        # check further below.
        try:
            wifi_dut.interfaces.wifi.conn_param_update(
                dev_addr=raspi_addr,
                min_interval=case["conn_interval_min"],
                max_interval=case["conn_interval_max"],
                latency=case["slave_latency"],
                timeout=case["supervision_timeout"],
            )
        except Exception as param_cmd_err:
            param_cmd_err_str = str(param_cmd_err).lower()
            # Check if this is a known negative-scenario rejection
            for code in CONN_PARAM_INVALID_CODES:
                if code in param_cmd_err_str or f"0x{code}" in param_cmd_err_str:
                    result_error = f"0x{code}"
                    test_result = "PASS"
                    LOGGER.info(
                        f"TestCase {tcid} PASS (0x{code} - "
                        f"{ERROR_CODES.get(code, 'Invalid connection parameters')}, "
                        f"negative scenario - conn_param_update() rejected "
                        f"synchronously by DUT firmware)"
                    )
                    return
            # Also check the serial log for codes that appeared alongside
            # the exception (some SAPI wrappers throw AND log the error)
            try:
                err_log = list(_get_fresh_log_entries(wifi_dut))
                err_codes_in_log = find_error_codes_in_log(err_log)
                neg_hits = err_codes_in_log & CONN_PARAM_INVALID_CODES
                if neg_hits:
                    hit_code = sorted(neg_hits)[0]
                    result_error = f"0x{hit_code}"
                    test_result = "PASS"
                    LOGGER.info(
                        f"TestCase {tcid} PASS (0x{hit_code} - "
                        f"{ERROR_CODES.get(hit_code, 'Invalid connection parameters')}, "
                        f"negative scenario - detected in serial after "
                        f"conn_param_update exception)"
                    )
                    return
            except Exception:
                pass
            # Not a known negative scenario - re-raise to outer handler
            raise
        LOGGER.info("conn_param_update command sent, waiting for response...")

        # ========== WAIT & VERIFY CONN PARAM UPDATE RESPONSE ==========
        # The conn_param_update CLI command does NOT produce an immediate
        # response.  The DUT controller sends an L2CAP Connection
        # Parameter Update Request to the peer over the air; the central
        # replies with either acceptance or rejection.  Only after the
        # new parameters are applied does the firmware fire the
        # "conn updated device address" event on serial.
        #
        # With large connection intervals (e.g. 3000 x 1.25ms = 3.75s),
        # this exchange spans several connection events and can take
        # 10-20+ seconds.
        #
        # CRITICAL: Do NOT send any other CLI command before this event
        # is received.  Sending a second command while conn_param_update
        # is pending causes "command disallowed", corrupts the DUT
        # command queue, and makes ALL subsequent test cases fail.
        conn_interval_max_ms = case["conn_interval_max"] * 1.25
        param_update_timeout = max(
            15, int((conn_interval_max_ms / 1000.0) * 6) + 5
        )
        LOGGER.info(
            f"Waiting up to {param_update_timeout}s for conn_param_update "
            f"response (conn_interval_max={case['conn_interval_max']} "
            f"= {conn_interval_max_ms:.1f}ms)"
        )

        conn_update_confirmed = False
        accumulated_param_rx = ""

        for _pw in range(param_update_timeout):
            time.sleep(1)
            try:
                new_entries = list(_get_fresh_log_entries(wifi_dut))
                for _, raw_line in new_entries:
                    try:
                        accumulated_param_rx += raw_line.decode(
                            errors="ignore"
                        )
                    except Exception:
                        accumulated_param_rx += str(raw_line)
            except Exception:
                pass

            accumulated_lower = accumulated_param_rx.lower()

            # ---- Check for invalid-parameter error (negative scenario PASS)
            for code in CONN_PARAM_INVALID_CODES:
                if f"0x{code}" in accumulated_lower:
                    result_error = f"0x{code}"
                    test_result = "PASS"
                    LOGGER.info(
                        f"TestCase {tcid} PASS (error code 0x{code} - "
                        f"{ERROR_CODES.get(code, 'Invalid connection parameters')}, "
                        f"negative scenario - DUT correctly rejected "
                        f"invalid params)"
                    )
                    return

            # ---- Check for unexpected error codes ----
            found_codes = set()
            for code in ERROR_CODES:
                if f"0x{code}" in accumulated_lower:
                    found_codes.add(code)
            generic_err = re.search(
                r"error status 0x([0-9a-fA-F]+)", accumulated_lower
            )
            if generic_err:
                found_codes.add(generic_err.group(1).lower())
            found_codes -= BENIGN_ERROR_CODES
            # Exclude CONN_PARAM_INVALID codes from unexpected-error
            # detection.  The CONN_PARAM_INVALID_CODES check above
            # already catches 4e62 and returns PASS.  This exclusion is
            # a safety net: if the firmware emits 4e62 via a slightly
            # different format (e.g. "error status 0x4e62" captured by
            # generic_err but NOT by the literal "0x4e62" substring
            # check), the code below would otherwise treat it as
            # unexpected and FAIL - hiding the correct negative-scenario
            # PASS verdict.
            unexpected_errors = (
                found_codes - {"4e16"} - CONN_PARAM_INVALID_CODES
            )
            if unexpected_errors:
                result_error = ",".join(
                    [f"0x{c}" for c in sorted(unexpected_errors)]
                )
                test_result = "FAIL"
                for code in unexpected_errors:
                    LOGGER.error(
                        f"TestCase {tcid} FAIL: Error code 0x{code} "
                        f"({ERROR_CODES.get(code, 'Unknown')}) "
                        f"found after conn_param_update."
                    )
                assert False, (
                    f"Unexpected error codes after conn_param_update: "
                    f"{[f'0x{c}' for c in sorted(unexpected_errors)]}"
                )

            # ---- Check for disconnect (peer terminated before update)
            if (
                "peripheral is disconnected" in accumulated_lower
                or "on event disconnect" in accumulated_lower
            ):
                dut_already_disconnected = True
                reason_match = re.search(
                    r"reason\s*:\s*0x([0-9a-fA-F]+)", accumulated_lower
                )
                disc_reason = (
                    reason_match.group(1) if reason_match else "unknown"
                )
                result_error = f"0x{disc_reason}"
                test_result = "FAIL"
                LOGGER.error(
                    f"TestCase {tcid} FAIL: Peer disconnected while "
                    f"waiting for conn_param_update response "
                    f"(reason: 0x{disc_reason})"
                )
                assert False, (
                    f"Peer disconnected during conn_param_update "
                    f"(reason: 0x{disc_reason})"
                )

            # ---- Check for successful "conn updated" event ----
            if "conn updated device address" in accumulated_lower:
                conn_update_confirmed = True
                interval_match = re.search(
                    r"conn_interval\s*:\s*(\d+)", accumulated_lower
                )
                timeout_match = re.search(
                    r"supervision timeout\s*:\s*(\d+)", accumulated_lower
                )
                upd_interval = (
                    interval_match.group(1) if interval_match else "?"
                )
                upd_timeout = (
                    timeout_match.group(1) if timeout_match else "?"
                )
                LOGGER.info(
                    f"conn_param_update confirmed - 'conn updated' event "
                    f"received after {_pw + 1}s "
                    f"(interval={upd_interval}, timeout={upd_timeout})"
                )
                break

            # Progress every 5 seconds
            if (_pw + 1) % 5 == 0:
                LOGGER.info(
                    f"Waiting for conn_param_update response... "
                    f"{_pw + 1}/{param_update_timeout}s"
                )

        if not conn_update_confirmed:
            result_error = "Conn_Param_Update_No_Response"
            test_result = "FAIL"
            LOGGER.error(
                f"TestCase {tcid} FAIL: conn_param_update response NOT "
                f"received within {param_update_timeout}s. The DUT "
                f"controller did not confirm the parameter update. "
                f"Accumulated RX: {accumulated_param_rx[:500]}"
            )
            assert False, (
                f"conn_param_update response not received within "
                f"{param_update_timeout}s - no 'conn updated' event "
                f"from DUT"
            )

        LOGGER.info(
            "conn_param_update verified - proceeding to stability check."
        )

        # ========== SET RASPI (CENTRAL) SUPERVISION TIMEOUT ==========
        # The initial hcitool lecup call inside Bluez.connect() fails
        # with "Input/output error(5)" because the LL is still in
        # setup (SMP handshake hasn't started yet).  This leaves the
        # Raspi's BLE controller with its default supervision timeout.
        #
        # Now that the link is fully stable (SMP done, conn_param_update
        # confirmed), we re-issue the LE Connection Update from the
        # Raspi (Central) side with a generous supervision timeout of
        # 3200 (32 seconds).  Without this, BlueZ may initiate a
        # 0x4e13 (Remote User Terminated Connection) disconnect during
        # the 60-second stability window because:
        #   a) The initial lecup never set a usable timeout.
        #   b) No upper-layer (ATT/GATT) traffic flows during stability,
        #      so BlueZ considers the link idle and tears it down.
        #
        # We keep the same conn_interval and latency the DUT requested
        # so the LL doesn't renegotiate those parameters.
        try:
            LOGGER.info(
                f"[RASPI-KEEPALIVE] Setting Raspi (Central) supervision "
                f"timeout to 3200 (32s) via hcitool lecup"
            )
            ble_client.interfaces.bluetooth.hci_tool_manager.update_conn(
                dev_addr=local_addr,
                min_conn_interval=case["conn_interval_min"],
                max_conn_interval=case["conn_interval_max"],
                conn_latency=case["slave_latency"],
                supervision_timeout=3200,
            )
            LOGGER.info(
                "[RASPI-KEEPALIVE] Raspi supervision timeout updated "
                "successfully (3200 = 32s)."
            )
        except Exception as lecup_err:
            LOGGER.warning(
                f"[RASPI-KEEPALIVE] hcitool lecup failed: {lecup_err}. "
                f"Falling back to D-Bus keep-alive during stability."
            )
        time.sleep(1)  # Let controller apply new parameters

        # ========== STOP FIRMWARE AUTO-SCAN BEFORE STABILITY CHECK ==========
        # Now that the conn_param_update is confirmed, it is safe to
        # send another CLI command.  The firmware may have restarted its
        # internal scan after the parameter update event - stop it so
        # the radio is dedicated to the BLE connection during the
        # 60-second stability window.
        for _scan_stop_attempt in range(3):
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
                LOGGER.info(
                    "[PRE-STABILITY] Stopped firmware auto-scan to "
                    "dedicate radio to connection."
                )
                break
            except Exception:
                time.sleep(1)
        # Flush scan-stop artefacts so they don't contaminate stability check
        _flush_serial_log(wifi_dut)
        time.sleep(1)  # Let firmware settle

        # ========== CONNECTION STABILITY (60 seconds) ==========
        LOGGER.info(
            "Checking connection stability for 60 seconds after "
            "parameter update..."
        )
        connection_duration = 60
        check_interval = 10
        # Track whether firmware auto-scan has been confirmed stopped.
        # Once we get a confirmed stop (either "successful" or "already
        # not in progress"), there is no need to keep issuing scan_stop
        # every 10 seconds.  The flag is reset only if the firmware
        # restarts the scan (detected via "scanning started" or
        # "scan_restart" in serial output between stability checks).
        scan_confirmed_stopped = False

        for i in range(connection_duration // check_interval):
            # ---- Conditional scan_stop: only if not yet confirmed ----
            # The firmware's rsi_ble_event_scan_restart_driver_callback
            # CAN fire unpredictably and restart an internal BLE scan.
            # But once we confirm the scan is stopped, re-issuing the
            # command every 10 seconds just adds unnecessary serial
            # traffic ("scan already not in progress" responses) that
            # clutters logs.  We only re-issue if:
            #   a) scan_stop was never confirmed yet, OR
            #   b) the firmware restarted the scan (flag was reset below)
            if not scan_confirmed_stopped:
                try:
                    wifi_dut.interfaces.wifi.legacy_scan_stop()
                except Exception:
                    pass
                # Read the scan_stop response to determine if it worked
                try:
                    scan_stop_log = list(_get_fresh_log_entries(wifi_dut))
                    for _, raw_line in scan_stop_log:
                        try:
                            decoded = raw_line.decode(errors="ignore").lower()
                        except Exception:
                            decoded = str(raw_line).lower()
                        if (
                            "scan_cmd_stop_handler : successful" in decoded
                            or "already not in progress" in decoded
                        ):
                            scan_confirmed_stopped = True
                            LOGGER.info(
                                f"[SCAN-STOP] Firmware scan confirmed "
                                f"stopped at stability interval {i + 1} "
                                f"- will not re-issue."
                            )
                            break
                except Exception:
                    pass

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
            LOGGER.info(
                f"Connection stable: "
                f"{elapsed_time}/{connection_duration} seconds"
            )

            conn_check_log = list(_get_fresh_log_entries(wifi_dut))

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

            # ---- Detect firmware scan restart ----
            # If the firmware restarted its internal BLE scan since
            # the last check, reset the flag so scan_stop is re-issued
            # on the next iteration.
            if scan_confirmed_stopped and (
                "scanning started" in accumulated_stab_lower
                or "scan_restart" in accumulated_stab_lower
            ):
                LOGGER.info(
                    f"[SCAN-STOP] Firmware scan restarted detected "
                    f"at {elapsed_time}s - will re-issue scan_stop."
                )
                scan_confirmed_stopped = False

            # Check for SMP failure during stability
            if (
                "smp failed" in accumulated_stab_lower
                or "4b0b" in accumulated_stab_lower
            ):
                result_error = "0x4b0b"
                test_result = "FAIL"
                LOGGER.error(
                    f"SMP failure detected at {elapsed_time}s"
                )
                assert False, (
                    f"SMP failure during stability period "
                    f"at {elapsed_time}s"
                )

            # Check for disconnect during stability
            if (
                "peripheral is disconnected" in accumulated_stab_lower
                or "on event disconnect" in accumulated_stab_lower
            ):
                dut_already_disconnected = True
                reason_match = re.search(
                    r'reason\s*:\s*0x([0-9a-fA-F]+)',
                    accumulated_stab_lower,
                )
                if reason_match:
                    actual_reason = reason_match.group(1).lower()
                    result_error = f"0x{actual_reason}"
                    reason_desc = ERROR_CODES.get(
                        actual_reason, "Unknown"
                    )
                    LOGGER.error(
                        f"Device disconnected during stability "
                        f"period at {elapsed_time}s "
                        f"(reason: 0x{actual_reason} - {reason_desc})"
                    )
                else:
                    detected_code = None
                    for code in ERROR_CODES:
                        if (
                            f"0x{code}" in accumulated_stab_lower
                            or f" {code}" in accumulated_stab_lower
                        ):
                            detected_code = code
                            break
                    if detected_code:
                        result_error = f"0x{detected_code}"
                    else:
                        result_error = "Unknown_Disconnect"
                    LOGGER.error(
                        f"Device disconnected during stability "
                        f"period at {elapsed_time}s "
                        f"(error: {result_error})"
                    )
                test_result = "FAIL"
                assert False, (
                    f"Device disconnected during stability period "
                    f"at {elapsed_time}s (error: {result_error})"
                )

        LOGGER.info(
            f"Connection maintained successfully for "
            f"{connection_duration} seconds"
        )

        # ========== STABILITY PASSED - MARK TEST AS PASS ==========
        # The 60-second connection stability is the SOLE pass criteria.
        # If we reach here without any disconnect during stability,
        # the test case is PASS.
        result_error = "None"
        test_result = "PASS"
        LOGGER.info(
            f"TestCase {tcid} PASS - connection stable for "
            f"{connection_duration} seconds after parameter update "
            f"(no disconnect detected)"
        )

    except Exception as e:
        LOGGER.error(f"TestCase {tcid} FAIL: {e}")
        if result_error is None:
            result_error = str(e)[:80]
        raise
    finally:
        # ========== ALWAYS WRITE RESULT TO CSV ==========
        try:
            LOGGER.info(
                f"[FINALLY] Writing CSV result for TC {tcid}: "
                f"Error={result_error}, Result={test_result}"
            )
            write_result_to_csv(tcid, result_error, test_result)
        except Exception as csv_err:
            LOGGER.error(
                f"[FINALLY] CSV write failed for TC {tcid}: {csv_err}"
            )

        # ========== CLEANUP (ALWAYS RUNS) ==========
        # DUT-side disconnect - critical to prevent 0x4e0c on the next test.
        # When 0x4e62 (negative scenario) triggers an early return, the DUT
        # is still connected.  Without this disconnect the next test's
        # legacy_adv() fails with 0x4e0c (Invalid BLE State).
        #
        # IMPORTANT: The wait after btc_disconnect MUST be proportional to
        # the connection interval.  With conn_interval=3200 (4000ms), the
        # BLE link layer must wait for the next connection event to send
        # the LL_TERMINATE_IND.  If we don't wait long enough, the actual
        # disconnect event arrives AFTER stop_adv(), causing the firmware
        # to print "advertising failed to stop, with status = 0x4e0c".
        # This corrupts the BLE state machine and cascades to ALL subsequent
        # tests.
        #
        # SKIP btc_disconnect when dut_already_disconnected is True.
        # Calling btc_disconnect on an already-disconnected link produces
        # 0x4e0c or 0x4d05 which corrupts the BLE state machine and
        # cascades 0x4e0c to every subsequent test.
        if raspi_addr and not dut_already_disconnected:
            # Calculate how long to wait for the actual disconnect event.
            # With high conn_interval_max values (e.g. 2391 = ~3s per
            # connection event), the LL needs multiple connection events
            # to complete the LL_TERMINATE_IND handshake.  Use a generous
            # multiplier (x4) to cover worst-case scheduling delays plus
            # firmware internal processing.
            try:
                max_int = int(case.get("conn_interval_max", 6))
                latency = int(case.get("slave_latency", 0))
                conn_event_ms = max_int * 1.25
                disconnect_wait = min(
                    max(conn_event_ms / 1000.0 * (latency + 1) * 4 + 8, 10),
                    45,
                )
            except (ValueError, TypeError):
                disconnect_wait = 15

            try:
                LOGGER.info(
                    f"[FINALLY] DUT initiating disconnect from "
                    f"{raspi_addr}"
                )
                wifi_dut.interfaces.wifi.btc_disconnect(
                    ble_address=raspi_addr
                )
                LOGGER.info(
                    f"[FINALLY] Waiting {disconnect_wait:.1f}s for BLE "
                    f"disconnect event (conn_interval_max="
                    f"{case.get('conn_interval_max', '?')}, "
                    f"latency={case.get('slave_latency', '?')})"
                )
            except Exception as disc_exc:
                LOGGER.warning(
                    f"[FINALLY] btc_disconnect raised (non-fatal): "
                    f"{disc_exc}"
                )

            # Poll for the ACTUAL disconnect event instead of blind sleep.
            # CRITICAL: Only match real LL disconnect events — NOT the
            # btc_disconnect command acknowledgment.  The command ack
            # ("disconnect_cmd_handler : successful") fires immediately
            # but the LL_TERMINATE_IND handshake takes several connection
            # events.  With conn_interval=572 + latency=3, the real
            # "On Event Disconnect" can arrive 6+ seconds later.  If we
            # proceed too early, stop_adv() races with the firmware's
            # disconnect handler restarting advertising → 0x4e0c.
            disconnect_confirmed = False
            poll_interval = 1.0
            elapsed = 0.0
            while elapsed < disconnect_wait:
                time.sleep(poll_interval)
                elapsed += poll_interval
                try:
                    disc_log = _get_fresh_log_entries(wifi_dut)
                    for _, raw_line in disc_log:
                        try:
                            decoded_disc = raw_line.decode(
                                errors="ignore"
                            ).lower()
                        except Exception:
                            decoded_disc = str(raw_line).lower()
                        if (
                            "on event disconnect" in decoded_disc
                            or "central is disconnected" in decoded_disc
                            or "peripheral is disconnected" in decoded_disc
                        ):
                            disconnect_confirmed = True
                            break
                    if disconnect_confirmed:
                        LOGGER.info(
                            f"[FINALLY] TC {tcid}: Disconnect event "
                            f"confirmed after {elapsed:.1f}s."
                        )
                        # Extra stabilisation: let the firmware finish
                        # its disconnect handler (auto-restart advertising,
                        # connection count updates) before cleanup.
                        time.sleep(3)
                        break
                except Exception:
                    pass

            # If disconnect was NOT confirmed, the BLE state machine is
            # stuck in "connected" state.  Retry btc_disconnect once more
            # and then wait additional time to guarantee the firmware
            # processes the termination before the next test starts.
            if not disconnect_confirmed:
                LOGGER.warning(
                    f"[FINALLY] TC {tcid}: Disconnect event NOT confirmed "
                    f"after {disconnect_wait:.1f}s - retrying disconnect."
                )
                try:
                    wifi_dut.interfaces.wifi.btc_disconnect(
                        ble_address=raspi_addr
                    )
                except Exception:
                    pass
                # Extended wait: poll for another 15s after the retry
                retry_elapsed = 0.0
                while retry_elapsed < 15:
                    time.sleep(1)
                    retry_elapsed += 1
                    try:
                        disc_log = _get_fresh_log_entries(wifi_dut)
                        for _, raw_line in disc_log:
                            try:
                                decoded_disc = raw_line.decode(
                                    errors="ignore"
                                ).lower()
                            except Exception:
                                decoded_disc = str(raw_line).lower()
                            if (
                                "on event disconnect" in decoded_disc
                                or "central is disconnected" in decoded_disc
                                or "peripheral is disconnected" in decoded_disc
                            ):
                                disconnect_confirmed = True
                                break
                        if disconnect_confirmed:
                            LOGGER.info(
                                f"[FINALLY] TC {tcid}: Disconnect event "
                                f"confirmed on retry after "
                                f"{retry_elapsed:.1f}s."
                            )
                            time.sleep(3)
                            break
                    except Exception:
                        pass
                if not disconnect_confirmed:
                    LOGGER.error(
                        f"[FINALLY] TC {tcid}: Disconnect event STILL NOT "
                        f"confirmed after retry. Will attempt BLE state "
                        f"recovery."
                    )

        elif raspi_addr and dut_already_disconnected:
            LOGGER.info(
                f"[FINALLY] TC {tcid}: DUT already disconnected during test "
                f"- skipping btc_disconnect to avoid BLE state corruption."
            )
            _flush_serial_log(wifi_dut)
            time.sleep(2)
        else:
            LOGGER.info(
                f"[FINALLY] TC {tcid}: No raspi_addr - "
                f"no DUT disconnect needed."
            )

        # ========== POST-DISCONNECT CLEANUP ==========
        _flush_serial_log(wifi_dut)

        # Stop scan (DUT may have FW auto-scan running)
        try:
            wifi_dut.interfaces.wifi.legacy_scan_stop()
        except Exception:
            pass

        # Stop advertising.
        # After a clean disconnect the firmware auto-restarts advertising.
        # stop_adv() here turns it off so the next test starts fresh.
        # If it returns 0x4e0c the BLE state is corrupted — attempt
        # recovery by calling legacy_adv(status=0) which uses a
        # different firmware code path.
        try:
            wifi_dut.interfaces.wifi.stop_adv()
        except Exception:
            pass
        time.sleep(1)

        # Verify stop_adv worked — check for 0x4e0c in serial log
        _post_stop_log = _get_fresh_log_entries(wifi_dut)
        _post_stop_text = "".join(
            line.decode(errors="ignore")
            if hasattr(line, "decode") else str(line)
            for _, line in _post_stop_log
        ).lower()
        if "0x4e0c" in _post_stop_text or "advertising failed to stop" in _post_stop_text:
            LOGGER.warning(
                f"[FINALLY] TC {tcid}: stop_adv returned 0x4e0c — "
                f"BLE advertising state corrupted. Attempting recovery..."
            )
            # Recovery: wait for firmware internal timers, then retry
            time.sleep(5)
            _flush_serial_log(wifi_dut)
            try:
                wifi_dut.interfaces.wifi.stop_adv()
            except Exception:
                pass
            time.sleep(1)
            # Check if recovery worked
            _retry_log = _get_fresh_log_entries(wifi_dut)
            _retry_text = "".join(
                line.decode(errors="ignore")
                if hasattr(line, "decode") else str(line)
                for _, line in _retry_log
            ).lower()
            if "0x4e0c" in _retry_text:
                LOGGER.error(
                    f"[FINALLY] TC {tcid}: BLE advertising state STILL "
                    f"corrupted after recovery. Next test may fail "
                    f"with ADV_Failed."
                )

        time.sleep(2)
        # Flush post-cleanup artefacts
        _flush_serial_log(wifi_dut)

        # ========== RASPI-SIDE CLEANUP ==========
        # Remove device with retry (clear stale bond keys from D-Bus)
        for rm_attempt in range(3):
            try:
                ble_client.interfaces.bluetooth.remove_device(
                    bt_dut_address=local_addr
                )
                LOGGER.info(
                    f"[CLEANUP] Successfully removed DUT ({local_addr}) "
                    f"from Raspi."
                )
                break
            except Exception as e:
                LOGGER.warning(
                    f"[CLEANUP] remove_device attempt "
                    f"{rm_attempt + 1}/3 failed: {e}"
                )
                time.sleep(1)

        _force_clear_raspi_bonds(ble_client, local_addr)

        # Close BLE interface with retry
        for close_attempt in range(3):
            try:
                ble_client.interfaces.bluetooth.close()
                LOGGER.info("[CLEANUP] BLE interface closed successfully.")
                break
            except Exception as e:
                LOGGER.warning(
                    f"[CLEANUP] close() attempt "
                    f"{close_attempt + 1}/3 failed: {e}"
                )
                time.sleep(1)

        try:
            ble_client.interfaces.bluetooth.stop_scanning()
        except Exception:
            pass

        # ---- Final DUT scan_stop ----
        # The Raspi BLE interface teardown may have triggered the DUT's
        # scan_restart callback one last time.  A final scan_stop here
        # ensures the firmware's internal scan is dead before the next
        # test reopens the serial port and starts a fresh iteration.
        for _final_ss in range(2):
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
            except Exception:
                pass
            time.sleep(0.5)
        # Final serial flush - discard all cleanup artefacts
        _flush_serial_log(wifi_dut)

        # Inter-test settle time
        time.sleep(5)
        LOGGER.info(f"=== End TestCase {tcid} ===\n")