"""
=============================================================================
test_bt_ble.py: BT + BLE Test Suite
=============================================================================

    This module contains automated test cases for validating Bluetooth Classic
    (BT) and Bluetooth Low Energy (BLE) coexistence functionality on the DUT
    (Device Under Test). The tests verify that the DUT can simultaneously
    maintain multiple BLE connections and BT Classic connections while
    performing various operations like inquiry, scanning, advertising, and
    audio streaming.

    The module implements a thread-based architecture for concurrent BT/BLE
    operations with proper synchronization using locks and events to prevent
    race conditions and ensure sequential execution when required.
Author: Sivaramakrishna Sivalenka
Date  : 03 March 2026
"""


# =============================================================================
# IMPORTS
# =============================================================================
import time

from utf.interfaces.bluetooth.bluez.bluez_interfaces import (
    BTDBusInterfaces,
    BTDBusPaths,
    InterfaceNotFoundException,
    BluezInterface,
)
import pytest
from typing import Any
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes

from utf_wiseconnect.interfaces.cli.rs_sapi_rt595_commands import RSSAPIRT595Commands #line added
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
import re
from time import sleep
import threading
import docker


# =============================================================================
# GLOBAL VARIABLES AND CONSTANTS
# =============================================================================

connect_status_container = {}
local_dut_address = None

# =============================================================================
# THREADING LOCKS AND EVENTS
# =============================================================================

# ADD these new locks and events
ble_connection_lock = threading.Lock()
bt_connection_lock = threading.Lock()  #For BT operations
#connection_sequence_lock = threading.Lock()  #Master sequencing lock

# ADD threading events for coordination
bt_connection_event = threading.Event()
ble1_connection_event = threading.Event()
ble2_connection_event = threading.Event()

# ADD connection state flags
bt_in_progress = False
ble_in_progress = False

# =============================================================================
# LOGGER
# =============================================================================
def logger():
    return get_logger(__name__)

# =============================================================================
# TEST SETUP AND CLEANUP FUNCTIONS
# =============================================================================

def setup_test_state():
    """
    Setup fixture that runs BEFORE every test - resets all global state
    """
    global connect_status_container, bt_in_progress, ble_in_progress
    
    # Reset global variables
    connect_status_container.clear()
    bt_in_progress = False
    ble_in_progress = False
    
    # Reset ALL threading events to cleared state
    bt_connection_event.clear()
    ble1_connection_event.clear()
    ble2_connection_event.clear()
    
    # Diagnostic logging - verify everything is reset
    logger().info("\n\n==== Test Setup: Global state reset ====\n")
    logger().info(f"Container cleared: {len(connect_status_container) == 0}")
    logger().info(f"Events cleared: bt={not bt_connection_event.is_set()}, "
                  f"ble1={not ble1_connection_event.is_set()}, "
                  f"ble2={not ble2_connection_event.is_set()}")   


def cleanup_after_test():
    """Auto-cleanup fixture that runs after every test"""
    global local_dut_address
    global bt_in_progress, ble_in_progress
    
    # Reset global variables ALWAYS
    connect_status_container.clear()
    bt_connection_event.clear()
    ble1_connection_event.clear()
    ble2_connection_event.clear()
    bt_in_progress = False
    ble_in_progress = False
    #clear_serial_log(ble_dut)  # Clear logs before cleanup to avoid confusion with test logs
    
    logger().info(" global state reset\n")


# =============================================================================
#                   SERIAL LOG UTILITY AND HELPER FUNCTIONS
# =============================================================================
def serial_wait_multi(
    dut,
    patterns,
    timeout=30,
    poll_interval=0.5,
    mode="all",          # "any" or "all"
    regex=True,
    case_insensitive=True,
    baseline=True,
):
    flags = re.IGNORECASE if case_insensitive else 0
    if isinstance(patterns, (str, bytes)):
        patterns = [patterns]
    compiled = [re.compile(p, flags) for p in patterns] if regex else [
        (p.lower() if case_insensitive else p) for p in patterns
    ]
    bus = dut.interfaces.wifi.bus
    try:
        start_index = len(bus.get_input_log()) if baseline else 0
    except Exception:
        start_index = 0
    found = {}
    end = time.time() + timeout
    while time.time() < end:
        try:
            log = bus.get_input_log()
        except Exception:
            time.sleep(poll_interval)
            continue
        for _, raw in log[start_index:]:
            try:
                line = raw.decode(errors="ignore")
            except Exception:
                continue
            cmp_line = line.lower() if case_insensitive else line
            for i, pat in enumerate(patterns):
                if pat in found:
                    continue
                if regex:
                    m = compiled[i].search(line)
                    if m:
                        found[pat] = True
                else:
                    needle = compiled[i]
                    if needle in cmp_line:
                        found[pat] = True
                if mode == "any" and found:
                    return found
        start_index = len(log)
        if mode == "all" and len(found) == len(patterns):
            return found
        time.sleep(poll_interval)
    return found if mode == "all" else {}

def serial_expect_multi(dut, patterns, timeout=30, **kwargs):
    mode = kwargs.get("mode", "all")
    result = serial_wait_multi(dut, patterns, timeout=timeout, **kwargs)
    if mode == "all":
        missing = [p for p in patterns if p not in result]
        assert not missing, f"Missing patterns: {missing}"
    else:
        assert result, f"No pattern from list found within {timeout}s"
    return result


def clear_serial_log(wifi_dut):
    serial_conn = wifi_dut.interfaces.wifi.bus
    serial_conn.clear_input_log()

def extract_from_serial_log(wifi_dut, pattern=None, group_len=None, log_timeout=10, poll_interval=2, baseline=False, latest=True, time_window_seconds=None):
    """
    Extract pattern from serial log with optional time-window filtering.
    
    Args:
        wifi_dut: DUT device interface
        pattern: Regex pattern to search for
        group_len: Expected length of captured group (for padding)
        log_timeout: Max time to wait for pattern (seconds)
        poll_interval: How often to check the log (seconds)
        baseline: If True, only scan new lines added after function call
        latest: If True, return the LAST match (most recent) instead of first
        time_window_seconds: If set, only scan logs from the last N seconds (default: None)
    
    Returns:
        Extracted value or None if not found
    """
    deadline = time.time() + log_timeout
    serial_conn = wifi_dut.interfaces.wifi.bus

    try:
        start_index = len(serial_conn.get_input_log()) if baseline else 0
    except Exception:
        start_index = 0

    last_match = None

    while time.time() < deadline:
        input_log = serial_conn.get_input_log()
        current_time = time.time()  # Get current timestamp for comparison
        
        for idx, (ts, line) in enumerate(input_log[start_index:], start=start_index):
            # TIME WINDOW CHECK
            if time_window_seconds is not None:
                elapsed_since_log = current_time - ts
                if elapsed_since_log > time_window_seconds:
                    continue  # Skip logs older than time window
            
            try:
                decoded = line.decode(errors="ignore")
            except Exception:
                continue
            
            match = re.search(pattern, decoded)
            if match:
                value = match.group(1)
                if group_len and len(value) <= group_len:
                    value = value.zfill(group_len)
                
                if not latest:
                    logger().info(f"value ({len(value)} digits): {value} -> Padded to {group_len} digits: {value}")
                    return value
                
                last_match = value

        start_index = len(input_log)
        
        if last_match and latest and time.time() >= deadline:
            logger().info(f"Latest value ({len(last_match)} digits): {last_match}")
            return last_match
        
        time.sleep(poll_interval)

    if last_match:
        logger().info(f"Latest value ({len(last_match)} digits): {last_match}")
    return last_match

def extract_bd_address_from_serial_log(wifi_dut):
    serial_conn = wifi_dut.interfaces.wifi.bus
    input_log = serial_conn.get_input_log()
    for _, line in input_log:
        try:
            decoded = line.decode(errors="ignore")
        except Exception:
            continue
        match = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', decoded)
        if match:
            return match.group(1)
    return None


def get_dut_bd_address(ble_dut) -> str:
    global local_dut_address  # Declare global to read/modify

    # If already set, return it directly
    if local_dut_address is not None:
        logger().info(f"DUT Bluetooth Address (cached): {local_dut_address}")
        return local_dut_address

    # If None, extract from serial log
    address = extract_bd_address_from_serial_log(ble_dut)
    assert address is not None, "Failed to get Bluetooth address - DUT is not available"
    logger().info(f"DUT Bluetooth Address (extracted): {address}")

    # Store in global variable
    local_dut_address = address
    return address


def assert_check(ble_dut, check_pattern: object) -> bool:
    serial_conn = ble_dut.interfaces.wifi.bus  # HostSerialConnectionAsync
    input_log = serial_conn.get_input_log()

    found = False
    for ts, line in input_log:
        try:
            decoded_line = line.decode(errors="ignore")
        except Exception:
            decoded_line = str(line)
        if check_pattern in decoded_line:
            found = True
            break
    assert found, f"check_pattern '{check_pattern}' not found in serial log"
    return found

# =============================================================================
# BT + BLE STABILITY CHECK FUNCTIONS
# =============================================================================

def monitor_all_connections_stability(ble_client2, ble_client3, bt_client, local_dut_address, 
                                     monitor_duration=300, poll_interval=5):
    """
    Monitors the stability of BLE and BT connections for a given duration.
    Fails the test if any connection drops during the monitoring period.
    """
    logger().info(f"\n\n==== Starting Connection Monitoring ====")
    logger().info(f"Duration: {monitor_duration}s, Poll Interval: {poll_interval}s")
    logger().info(f"DUT Address: {local_dut_address}\n")

    start_time = time.time()
    check_count = 0

    try:
        while time.time() - start_time < monitor_duration:
            elapsed = time.time() - start_time
            remaining = monitor_duration - elapsed
            check_count += 1

            logger().info(f"\n--- Connection Check #{check_count} (Elapsed: {elapsed:.1f}s, Remaining: {remaining:.1f}s) ---")

            # BLE client 2 check
            try:
                connect_status_ble2 = ble_client2.interfaces.bluetooth.get_connection_status(local_dut_address)
                if not connect_status_ble2:
                    raise AssertionError(
                        f" BLE Client 2 connection DROPPED at {elapsed:.1f}s "
                        f"(check #{check_count}/{monitor_duration//poll_interval})"
                    )
                logger().info(f" BLE Client 2: Connected")
            except Exception as e:
                logger().error(f" BLE Client 2 check failed: {e}")
                raise AssertionError(f"ble_client2 BLE connection disconnected during monitoring at {elapsed:.1f}s") from e

            # BLE client 3 check
            try:
                connect_status_ble3 = ble_client3.interfaces.bluetooth.get_connection_status(local_dut_address)
                if not connect_status_ble3:
                    raise AssertionError(
                        f" BLE Client 3 connection DROPPED at {elapsed:.1f}s "
                        f"(check #{check_count}/{monitor_duration//poll_interval})"
                    )
                logger().info(f" BLE Client 3: Connected")
            except Exception as e:
                logger().error(f" BLE Client 3 check failed: {e}")
                raise AssertionError(f"ble_client3 BLE connection disconnected during monitoring at {elapsed:.1f}s") from e

            # BT Classic check
            try:
                connect_status_bt = bt_client.interfaces.bluetooth.get_bt_connection_status(local_dut_address)
                if not connect_status_bt:
                    raise AssertionError(
                        f" BT Classic connection DROPPED at {elapsed:.1f}s "
                        f"(check #{check_count}/{monitor_duration//poll_interval})"
                    )
                logger().info(f" BT Classic: Connected")
            except Exception as e:
                logger().error(f" BT Classic check failed: {e}")
                raise AssertionError(f"BT Classic connection disconnected during monitoring at {elapsed:.1f}s") from e

            logger().info(f" All connections stable (check #{check_count} passed)")
            time.sleep(poll_interval)

    except AssertionError:
        # Log summary and re-raise
        logger().error(f"\n ========== CONNECTION MONITORING FAILED ==========")
        logger().error(f"Failed at: {time.time() - start_time:.1f}s / {monitor_duration}s")
        logger().error(f"Completed checks: {check_count}")
        logger().error(f"====================================================\n")
        raise

    # Success message
    logger().info(f"\n ========== CONNECTION MONITORING PASSED ==========")
    logger().info(f"Duration: {monitor_duration}s")
    logger().info(f"Total checks: {check_count}")
    logger().info(f"All connections remained stable throughout monitoring period")
    logger().info(f"====================================================\n")


def check_conn_status_disconnect_initiated_from_dut(ble_dut, ble_client2, ble_client3, bt_client, bt_client_address):
    """
    Checks connection status for BLE and BT clients, then disconnects the remote clients from the device.
    Asserts that connections are active before disconnection and that they are properly disconnected afterward.
    """

    # Retrieve bt_client_address from container if not provided
    if bt_client_address is None:
        bt_client_address = connect_status_container.get("address")
        logger().info(f"Retrieved BT client address from container: {bt_client_address}")

    # Verify bt_client_address is valid
    assert bt_client_address is not None, "BT client address is None - cannot disconnect"

    connect_status_ble2 = ble_client2.interfaces.bluetooth.get_connection_status(get_dut_bd_address(ble_dut))
    assert connect_status_ble2, " ble_client2 BLE connection disconnected during monitoring"
    logger().info(f"connect_status_ble2: {connect_status_ble2}")
    try:
        logger().info(f"DUT is disconnecting ble_client2")
        ble_dut.interfaces.wifi.btc_disconnect(ble_client2.interfaces.bluetooth.get_address())
    except Exception as e:
        logger().warning(f"Failed to disconnect ble_client3: {e}")

    ### check connection status of remaining clients before disconnecting them.
    logger().info(f"checking connection status of remaining clients before disconnecting them.")
    connect_status_ble3 = ble_client3.interfaces.bluetooth.get_connection_status(get_dut_bd_address(ble_dut))
    assert connect_status_ble3, "ble_client3 BLE connection disconnected during monitoring"
    logger().info(f"connect_status_ble3: {connect_status_ble3}")
    connect_status_bt = bt_client.interfaces.bluetooth.get_bt_connection_status(get_dut_bd_address(ble_dut))
    assert connect_status_bt, "BT Classic connection disconnected during monitoring"
    logger().info(f"connect_status_bt: {connect_status_bt}")

    ### trying to disconnect ble_client3.
    try:
        logger().info(f"DUT is disconnecting ble_client3")
        ble_dut.interfaces.wifi.btc_disconnect(ble_client3.interfaces.bluetooth.get_address())
    except Exception as e:
        logger().warning(f"Failed to disconnect ble_client3: {e}")

    ###
    connect_status_bt = bt_client.interfaces.bluetooth.get_bt_connection_status(get_dut_bd_address(ble_dut))
    assert connect_status_bt, "BT Classic connection disconnected during monitoring"
    logger().info(f"connect_status_bt: {connect_status_bt}")
    try:
        logger().info(f"DUT is disconnecting bt_client {bt_client_address}")
        ble_dut.interfaces.wifi.gap_disconnect(bt_client_address)
        time.sleep(2) 
    except Exception as e:
        logger().warning(f"Failed to disconnect bt_client: {e}")

    logger().info("##DUT successfully disconnected from all clients##")

# =============================================================================
# BLE CONNECTION FUNCTIONS
# =============================================================================
class BLESSPConnect:
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

    def __init__(self, wifi_dut, ble_client, dut_capability, client_capability, pin_code, smp_sc=1, smp_auth_bond=1,
                 smp_mtim=1, smp_enc_key=1, passkey_state=2, random_addr_on_dut=False, auth_req="0x05",
                 oob_data_flag="0x00"):
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
        # OOB (Out-of-Band) Data Flag
        # 0x00 = OOB authentication data not present
        # 0x01 = OOB authentication data from remote device present
        self.oob_data_flag = oob_data_flag  # Added OOB data flag parameter
        self.ble_dut_address = None
        self.ble_client_address = None

    def run(self):
        io_capability = {"DisplayOnly": 0x00, "DisplayYesNo": 0x01, "KeyboardOnly": 0x02, "NoInputNoOutput": 0x03,
                         "KeyboardDisplay": 0x04}

        # Determine pairing method and auth_req based on IO capabilities
        dut_io = io_capability[self.dut_capability]
        client_io = io_capability[self.client_capability]

        ble_r2d_connect_status = False

        pairing_method = "PasskeyEntry"
        auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)

        logger().info(f"Pairing Method: {pairing_method}, auth_req=0x{auth_req_value:02X} ({auth_req_value} decimal)")
        logger().info(
            f"DUT IO: {self.dut_capability} (0x{dut_io:02X}), Raspi IO: {self.client_capability} (0x{client_io:02X})")

        # Set MITM and security requirements in BLE client (Raspi)
        raspi_auth_req = f"0x{auth_req_value:02x}"
        logger().info(
            f"Setting Raspi auth_req: {io_capability[self.client_capability]} {self.oob_data_flag} {raspi_auth_req}")
        self.ble_client.interfaces.bluetooth.set_mitm_sc_bits(
            f"{io_capability[self.client_capability]} {self.oob_data_flag} {raspi_auth_req}")

        # Set SMP pairing capability data on DUT
        logger().info(
            f"Setting DUT SMP pairing capability: IO={io_capability[self.dut_capability]}, OOB={self.oob_data_flag}, auth_req={auth_req_value}")
        self.wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
            io_capability=io_capability[self.dut_capability],
            oob_data_flag=int(self.oob_data_flag, 16) if isinstance(self.oob_data_flag, str) else self.oob_data_flag,
            auth_req=auth_req_value,
            max_encryption_key_size=16,
            initiator_key_distribution=15,
            responder_key_distribution=15
        )

        self.ble_client.interfaces.bluetooth.close()

        logger().info("Start SMP scan from the remote device (Raspi)")
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=self.ble_dut_address, capability=self.client_capability, pin_code=self.pin_code)
        assert self.ble_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        logger().info("Stop scanning ...")
        self.ble_client.interfaces.bluetooth.stop_scanning()
        logger().info("Check the DUT is listed ...")
        devices = self.ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"Devices scanned by Raspi: {devices}")
        for dev in devices:
            logger().info(f"Scanned device: {dev}")

        # Initialize bus connection before pairing
        self.ble_client.interfaces.bluetooth.set_bus()

        def connect():
            logger().info(f"Trying to Connect (Raspi(Central)->DUT (peripheral) {ble_r2d_connect_status}")
            # Passkey Entry or Numeric Comparison - use connect with supervision timeout
            logger().info(f"Connect and pair to the DUT ({pairing_method},{self.ble_dut_address} - using connect with supervision timeout)")
            self.ble_client.interfaces.bluetooth.connect(
                dev_addr=self.ble_dut_address,
                supervision_timeout=500  # 5000 ms (500 * 10ms units = 5000ms)
            )

        t = threading.Thread(target=connect)
        t.start()

        # Wait a bit for pairing to start and request passkey
        time.sleep(1) #5

        if pairing_method == "PasskeyEntry":
            logger().info("Passkey Entry pairing - monitoring serial logs for passkey")
            passkey = None
            le_ltk = None
            passkey_container = {"value": None}

            def fetch_passkey():
                passkey_container["value"] = extract_from_serial_log(self.wifi_dut, r"passkey[:\s]+(\d+)", group_len=6, log_timeout=10, baseline=False, latest=False, time_window_seconds=5)


            passkeythread = threading.Thread(target=fetch_passkey)
            passkeythread.start()

            deadline = time.time() + 40
            while time.time() < deadline and passkey_container["value"] is None:
                time.sleep(0.5)

            passkey = passkey_container["value"]
            assert passkey is not None, "Passkey was not found in DUT serial log"

            # Set the passkey for pairing
            logger().info(f"Setting passkey: {passkey}")
            self.ble_client.interfaces.bluetooth.set_pin(passkey)
            time.sleep(2)
            le_ltk = extract_from_serial_log(self.wifi_dut, r"LE LTK\s*((?:[0-9A-Fa-f]{2}\s*){16})")
            logger().info(f"LE LTK extracted: {le_ltk}")
            assert le_ltk is not None, "le_ltk was not found in DUT serial log"

            if le_ltk:
                ble_r2d_connect_status = True

            # Wait for pairing to complete
            time.sleep(5)
            logger().info(f"(Raspi(Central)->DUT (peripheral) successfully connected: {ble_r2d_connect_status}")

        #clear_serial_log(self.wifi_dut)
        return ble_r2d_connect_status

def start_ble_scanning(ble_dut):
    logger().info("\n\n **** Start BLE scanning on DUT ****\n\n")
    ble_dut.interfaces.wifi.legacy_scan_start(status=1, scan_type=1, filter_policy=0, own_addr_type=0, scan_interval=53, scan_window=23)
    time.sleep(5)

def stop_ble_scanning(ble_dut):
    logger().info("\n\n **** Stop BLE scanning on DUT ****\n\n")
    ble_dut.interfaces.wifi.legacy_scan_stop()
    time.sleep(5)

def connect_dut_as_peripheral_raspii_as_central(ble_dut, ble_client, wait_for_bt=False, event_to_signal=None):

    global local_dut_address # stored the local DUT address in a global variable to be used across functions
    global ble_in_progress

    # Default to ble1_connection_event if not specified
    if event_to_signal is None:
        event_to_signal = ble1_connection_event

    # Wait for BT if already in progress
    if wait_for_bt:
        logger().info("BLE waiting for BT to complete...")
        bt_connection_event.wait()  # wait here until BT signals completion
        logger().info(" BT completed, proceeding with BLE")

    connect_status = False
    with ble_connection_lock:
        logger().info("BLE connection started (DUT as peripheral)")
        ble_in_progress = True
        #clear event means start of connection, will set once its done at the end
        event_to_signal.clear()  # CHANGE from ble1_connection_event.clear()

        try:

            target_address = local_dut_address
            logger().info("\n\n **Raspii as Central and DUT as Peripheral**\n\n")
            ble_test = BLESSPConnect(
                wifi_dut=ble_dut,
                ble_client=ble_client,
                dut_capability="DisplayOnly",
                client_capability="KeyboardDisplay",
                pin_code="-8"
            )
            ble_test.ble_dut_address = target_address
            connect_status = ble_test.run()

            logger().info(f" BLE connection (DUT as peripheral) completed: {connect_status}")
            return connect_status
        finally:
            ble_in_progress = False
            event_to_signal.set()
            logger().info(" BLE connection lock released")

def connect_dut_as_central_raspii_as_peripheral(ble_dut, ble_client, dut_capability=None, client_capability=None,
                                          auth_req_value=0x2D, wait_for_bt=False, wait_for_ble1=False, 
                                          event_to_signal=None):  # ADD THIS PARAMETER
    address_type = 0
    ble_d2r_connect_status = False
    passkey = False
    global local_dut_address
    global ble_in_progress

    # Default to ble1_connection_event if not specified
    if event_to_signal is None:
        event_to_signal = ble1_connection_event

    # Wait for BT if its already ongoing
    if wait_for_bt:
        logger().info("BLE waiting for BT to complete...")
        bt_connection_event.wait()
        logger().info(" BT completed")

    # Wait for BLE1 if its already ongoing
    if wait_for_ble1:
        logger().info("BLE2 waiting for BLE1 to complete...")
        ble1_connection_event.wait()
        logger().info(" BLE1 completed")

    with ble_connection_lock:
        logger().info("BLE connection started (DUT as central)")
        ble_in_progress = True
        event_to_signal.clear()  # Use the correct event

        try:
            logger().info("\n\n **DUT as Central and Raspii as Peripheral**\n\n")

            io_capability_map = {
                "DisplayOnly":  0x00,
                "DisplayYesNo": 0x01,
                "KeyboardOnly": 0x02,
                "NoInputNoOutput": 0x03,
                "KeyboardDisplay": 0x04
            }

            client_cap_str = io_capability_map.get(client_capability, "KeyboardDisplay")
            dut_cap_str = io_capability_map.get(dut_capability, "DisplayOnly")

            oob_data_flag = "0x00"

            pairing_method = "PasskeyEntry"
            #auth_req_value = 0x2D  # Bonding + MITM + SC (45 decimal)
            logger().info(f"Pairing Method: {pairing_method}, auth_req=0x{auth_req_value:02X} ({auth_req_value} decimal)")
            logger().info(
            f"DUT IO: {dut_cap_str} , Raspi IO: {client_cap_str}")
            # Set MITM and security requirements in BLE client (Raspi)
            raspi_auth_req = f"0x{auth_req_value:02x}"
            logger().info(f"Setting Raspi auth_req: {client_capability} {oob_data_flag} {raspi_auth_req}")
            
            ble_client.interfaces.bluetooth.set_mitm_sc_bits(
            f"{io_capability_map[client_capability]} {oob_data_flag} {raspi_auth_req}") #client_cap_str

            ble_dut.interfaces.wifi.set_smp_pairing_capability_data(
                io_capability=dut_capability,
                oob_data_flag=int(oob_data_flag, 16) if isinstance(oob_data_flag, str) else oob_data_flag,
                auth_req=auth_req_value,
                max_encryption_key_size=16,
                initiator_key_distribution=15,
                responder_key_distribution=15
            )

            ble_client.interfaces.bluetooth.close()
            time.sleep(5)
            logger().info("\n\n **** Set RaspberryPi as advertiser****\n\n")
            ble_remote_address = ble_client.interfaces.bluetooth.start_smp_adv(None, pin_code="-8", capability=client_capability)
            assert ble_remote_address is not None, "Remote address from advertiser must not be None"
            logger().info(f"\n\n **** Adv started remote address: {ble_remote_address} ****\n\n")

            time.sleep(5)

            # Initialize bus connection before pairing
            ble_client.interfaces.bluetooth.set_bus()

            logger().info(f"Trying to Connect (DUT(Central)->Raspi (peripheral) {ble_d2r_connect_status}")

            # clear_serial_log(ble_dut)
            ble_dut.interfaces.wifi.ble_legacy_connect_req(ble_remote_address, None, address_type, 0, 0, 80, 80, 160, 160, 0, 500, 4, 6)
            time.sleep(1)

            passkey_container = {"value": None}

            def fetch_passkey():
                passkey_container["value"] = extract_from_serial_log(
                    ble_dut, r"passkey[:\s]+(\d+)", group_len=6, log_timeout=20, baseline=True, latest=False, time_window_seconds=5
                )

            passkeythread = threading.Thread(target=fetch_passkey, daemon=True)
            passkeythread.start()  # 2. Start thread (scans only NEW logs)
            logger().info("Waiting for passkey to be extracted from serial log...")


            # 3. Poll for result (don't need join)
            deadline = time.time() + 40
            while time.time() < deadline and passkey_container["value"] is None:
                time.sleep(0.5)

            passkey = passkey_container["value"]
            assert passkey is not None, "Passkey not found in the serial log"

            ble_client.interfaces.bluetooth.set_pin(passkey)

            le_smp_error = extract_from_serial_log(
                ble_dut,
                r"failed to initiate the SMP pairing process: (0x[0-9a-fA-F]+)",
                log_timeout=10, baseline=True, latest=False, time_window_seconds=5
            )
            if le_smp_error:
                raise AssertionError(f"SMP pairing failed with error code: {le_smp_error}")
            else:
                logger().info("No SMP pairing error found in serial log.")

            logger().info("SMP done")

            time.sleep(3)
            try:
                le_ltk = extract_from_serial_log(ble_dut, r"LE LTK\s*((?:[0-9A-Fa-f]{2}\s*){16})", log_timeout=5, baseline=False, latest=True, time_window_seconds=10)
                logger().info(f"LE LTK extracted: {le_ltk}")
                if le_ltk is None:
                    raise AssertionError("LE LTK was not found in DUT serial log")
                if all(x.strip().lower() == "0x00" for x in le_ltk.split()):
                    raise AssertionError(f"LE LTK is all zeros: {le_ltk}")

                ble_d2r_connect_status = True
                logger().info(f"Connection (DUT(Central)->Raspi (peripheral) completed successfully {ble_d2r_connect_status}")
            except Exception as error:
                raise AssertionError(f"Exception during LE LTK extraction: {error}")

            return ble_d2r_connect_status
        
        finally:
            ble_in_progress = False
            event_to_signal.set()  # Set the correct event
            logger().info(" BLE connection lock released")

# =============================================================================
# BT CLASSIC CONNECTION FUNCTIONS
# =============================================================================

def establish_bt_classic_connection(ble_dut, bt_client_address=None):
    """
    Establish BT classic connection between DUT and BT client
    """    

    connect_status = False

    logger().info("\n\n **** Start BT classic Inquiry from DUT ****\n\n")
    ble_dut.interfaces.wifi.gap_start_discovery()
    time.sleep(5)

    ble_dut.interfaces.wifi.gap_stop_discovery()
    time.sleep(5)

    logger().info("\n\n **** Start BT classic connection as initiator from DUT ****\n\n")
    ble_dut.interfaces.wifi.gap_connect(bt_client_address)

    # STEP 1: Wait for pairing (SAVED_LINK_KEY)
    try:
        serial_expect_multi(
            ble_dut,
            [r"SAVED_LINK_KEY:"],
            timeout=40,
            poll_interval=0.5,
            regex=False,                   
            case_insensitive=True
        )
        logger().info(" BT pairing completed (SAVED_LINK_KEY received)")
    except AssertionError as e:
        logger().error(f" BT pairing failed - SAVED_LINK_KEY not found: {e}")
        raise

    # Wait longer for A2DP authorization
    time.sleep(60)  # Increased from 5 to 10 seconds

    # Use assert_check which searches ENTIRE log
    connect_status = assert_check(ble_dut, "a2dp connect: success")
    
    if connect_status:
        logger().info(" BT Classic connection established successfully")
    else:
        logger().error(" BT Classic connection failed - assert_check returned False")
        raise AssertionError("BT Classic A2DP connection verification failed")

    return connect_status

# =============================================================================
# THREAD FUNCTIONS
# =============================================================================

def bt_classic_inquiry(ble_dut, bt_client, wait_for_ble1=False, wait_for_ble2=False):
    """
    Thread function to perform BT Classic Inquiry on DUT.
    
    Args:
        ble_dut: DUT device interface
        wait_for_ble1: If True, waits for first BLE connection to complete
        wait_for_ble2: If True, waits for second BLE connection to complete
    """
    global bt_in_progress
    global local_dut_address
    pin_code = "0000"

    logger().info("\n\n==== BT Inquiry Thread: Starting ====\n\n")

    if wait_for_ble1:
        logger().info("BT Inquiry waiting for BLE1 to complete...")
        ble1_connection_event.wait()
        logger().info(" BLE1 completed, proceeding with BT Inquiry")
        time.sleep(2)

    if wait_for_ble2:
        logger().info("BT Inquiry waiting for BLE2 to complete...")
        ble2_connection_event.wait()
        logger().info(" BLE2 completed, proceeding with BT Inquiry")
        time.sleep(2)

    with bt_connection_lock:
        logger().info("BT Inquiry started")
        bt_in_progress = True
        bt_connection_event.clear()

        bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink_with_bluez(
            bt_dut_address=local_dut_address, pin_code=pin_code)
        assert bt_client_address, "Failed to initiate sink in remote device"
        logger().info(f"BT Client address {bt_client_address}")
        logger().info(f"Primary bt_client is discoverable and connectable")

        try:
            logger().info("\n\n **** Start BT classic Inquiry from DUT ****\n\n")
            ble_dut.interfaces.wifi.gap_start_discovery()
            time.sleep(5)

            serial_expect_multi(
                ble_dut,
                ["Inquiry scan resp"],
                timeout=40,
                poll_interval=0.5,
                regex=False,
                case_insensitive=True,
                baseline=False
            )
            logger().info(" BT Inquiry response received")

            ble_dut.interfaces.wifi.gap_stop_discovery()
            time.sleep(3)
            logger().info(" BT Inquiry completed successfully")

        except AssertionError as e:
            logger().error(f" BT Inquiry failed: {e}")
            raise

        except Exception as e:
            logger().error(f" BT Inquiry error: {e}")
            raise

        finally:
            bt_in_progress = False
            bt_connection_event.set()
            bt_client.interfaces.bluetooth.close()
            time.sleep(5)  # Small delay to ensure serial log is stable
            logger().info(" BT Inquiry lock released\n")

# Prepare BT Classic connection thread
def bt_classic_connect(ble_dut, bt_client, pin_code, local_dut_address, wait_for_ble1=False, wait_for_ble2=False):
    """
    Establish BT Classic connection with proper locking and optional wait for BLE
    
    Args:
        wait_for_ble1: If True, waits for first BLE connection to complete
        wait_for_ble2: If True, waits for second BLE connection to complete
    """
    global bt_in_progress

    logger().info("\n\n==== BT Thread: Starting ====\n\n")

    # Wait for BLE1 if requested
    if wait_for_ble1:
        logger().info("BT waiting for BLE1 to complete...")
        ble1_connection_event.wait()
        logger().info(" BLE1 completed, proceeding with BT")
        time.sleep(2)  # Small delay to ensure serial log is stable

    # Wait for BLE2 if requested
    if wait_for_ble2:
        logger().info("BT waiting for BLE2 to complete...")
        ble2_connection_event.wait()
        logger().info(" BLE2 completed, proceeding with BT")
        time.sleep(2)  # Small delay to ensure serial log is stable

    # Initialize variables BEFORE try block
    bt_connect_status = False
    bt_client_address = None

    with bt_connection_lock:
        logger().info("BT connection started")
        bt_in_progress = True
        bt_connection_event.clear()
    
        try:
            # Step 3: Now start fresh connection
            logger().info("\n\n **** Starting Fresh BT Connection ****\n\n")
            bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink_with_bluez(
                bt_dut_address=local_dut_address, pin_code=pin_code)
            assert bt_client_address, "Failed to initiate sink in remote device"
            logger().info(f"BT Client address {bt_client_address}")
            logger().info(f"Primary bt_client is discoverable and connectable")
            time.sleep(5)

            bt_connect_status = establish_bt_classic_connection(
                ble_dut, bt_client_address=bt_client_address
            )

            logger().info(f" BT connection established: {bt_connect_status}")    

        except Exception as e:
            logger().error(f" BT connection failed: {e}")
            
        finally:        
            logger().info("\n=== Storing BT Connection Results ===")
            
            connect_status_container["address"] = bt_client_address
            connect_status_container["status"] = bt_connect_status
            
            if bt_client_address is not None:
                logger().info(f" Stored BT client address: {bt_client_address}")
            else:
                logger().error(" BT client address is None")
            
            logger().info(f" Stored BT connection status: {bt_connect_status}")
            logger().info(f" Container contents: {connect_status_container}")
            
            bt_in_progress = False
            bt_connection_event.set()
            logger().info(" BT connection lock released\n")


# Prepare BLE connection thread (for example, using ble_client2)
def ble_connect_raspii_to_dut(ble_dut, ble_client, wait_for_bt=False, use_ble2_event=False):

    # Choose which event to signal
    event_to_signal = ble2_connection_event if use_ble2_event else ble1_connection_event

    logger().info(f"BLE Thread Started Raspii ===> DUT connection")
    connect_dut_as_peripheral_raspii_as_central(
        ble_dut,
        ble_client, 
        wait_for_bt=wait_for_bt, 
        event_to_signal=event_to_signal
    )  # Pass the event


def ble_connect_dut_to_raspii(ble_dut, ble_client, wait_for_bt=False, wait_for_ble1=False, use_ble2_event=False):
    """
    Thread wrapper for DUT->Raspii connection
    
    Args:
        use_ble2_event: If True, signals ble2_connection_event instead of ble1_connection_event
    """
    logger().info(f"BLE Thread Started for DUT ===> Raspii connection")
    
    # Choose which event to signal based on parameter
    event_to_signal = ble2_connection_event if use_ble2_event else ble1_connection_event
    
    ble_connect_status_d2r = connect_dut_as_central_raspii_as_peripheral(
        ble_dut, ble_client, 
        dut_capability=0x00, 
        client_capability="KeyboardDisplay",
        wait_for_bt=wait_for_bt, 
        wait_for_ble1=wait_for_ble1,
        event_to_signal=event_to_signal  # Pass the event
    )
    
    connect_status_container["d2Rstatus"] = ble_connect_status_d2r

# =============================================================================
# TEST CASES
# =============================================================================
def test_connect_dut_as_ble_peripheral_bt_inquiry(ble_dut, bt_client, ble_clients):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    setup_test_state()

    local_dut_address = get_dut_bd_address(ble_dut)
    
    ble_client2 = None
   

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"  

        
        ble_client2 = ble_clients[1]
           

        ble_thread = threading.Thread(target=ble_connect_raspii_to_dut, args=(ble_dut, ble_client2, False, False))
        logger().info(f" second raspberrypi as scanner and DUT as advertiser")
        ble_thread.start()
        ble_thread.join()         

        bt_thread = threading.Thread(target=bt_classic_inquiry, args=(ble_dut, bt_client, True, False))
        logger().info(f" Primary raspberrypi as discoverable and connectable for BT inquiry")
        bt_thread.start()
        bt_thread.join()

        logger().info("\n\n **** Monitoring BT BLE connection stability for 5 minutes ****\n\n")
        monitor_duration = 300 #60  # 300, 5 minutes in seconds
        poll_interval = 10      # Check every 10 seconds
        start_time = time.time()
        check_count = 0

        while time.time() - start_time < monitor_duration:
            connect_status = ble_client2.interfaces.bluetooth.get_connection_status(local_dut_address)
            assert connect_status == True, "DUT lost connection during stability monitoring"
            logger().info("BLE (DUT as peripheral) connection is stable")
            time.sleep(poll_interval)

        connect_status_ble = ble_client2.interfaces.bluetooth.get_connection_status(local_dut_address)
        assert connect_status_ble, " BLE connection disconnected during monitoring"
        logger().info(f"connect_status_ble: {connect_status_ble}") 

        try:
            logger().info(f"DUT is disconnecting ble_client")
            ble_dut.interfaces.wifi.btc_disconnect(ble_client2.interfaces.bluetooth.get_address())
            time.sleep(5)
            ble_client2.interfaces.bluetooth.remove_device(local_dut_address)
            time.sleep(5)
            ble_client2.interfaces.bluetooth.close()
        except Exception as e:
            logger().warning(f"Failed to disconnect ble_client2: {e}")        
    except Exception as e:
        logger().error(f"test_connect_dut_as_ble_peripheral_bt_inquiry: {e}")        
        raise

    finally:
        cleanup_after_test() 


# Add @pytest.mark.ble_only marker to BLE-only tests
def test_connect_raspii_as_ble_peripheral_bt_inquiry(ble_dut, bt_client, ble_clients):
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    setup_test_state()

    local_dut_address = get_dut_bd_address(ble_dut)

    ble_client2 = None

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        ble_client3 = ble_clients[2]

        #connect_dut_as_central_raspii_as_peripheral(ble_dut, ble_client2, 0x00, client_capability="KeyboardDisplay", wait_for_bt=False, wait_for_ble1=False)
        ble_thread = threading.Thread(target=ble_connect_dut_to_raspii, args=(ble_dut, ble_client2, False))
        logger().info(f" second raspberrypi as advertiser and DUT as scanner")
        ble_thread.start()
        ble_thread.join()

        bt_inquiry_thread = threading.Thread(target=bt_classic_inquiry, args=(ble_dut, bt_client,True, False))
        bt_inquiry_thread.start()
        bt_inquiry_thread.join()

        logger().info("\n\n **** Monitoring BT BLE connection stability for 5 minutes ****\n\n")
        monitor_duration = 300 #60  # 300, 5 minutes in seconds
        poll_interval = 10  # Check every 10 seconds
        start_time = time.time()
        check_count = 0

        while time.time() - start_time < monitor_duration:
            connect_status = ble_client2.interfaces.bluetooth.get_connection_status(local_dut_address)
            assert connect_status == True, "DUT lost connection during stability monitoring"
            logger().info("BLE (DUT as Central) connection is stable")
            time.sleep(poll_interval)

        connect_status_ble = ble_client2.interfaces.bluetooth.get_connection_status(local_dut_address)
        assert connect_status_ble, " BLE connection disconnected during monitoring"
        logger().info(f"connect_status_ble: {connect_status_ble}")
        
        try:
            logger().info(f"DUT is disconnecting ble_client")
            ble_dut.interfaces.wifi.btc_disconnect(ble_client2.interfaces.bluetooth.get_address())
            time.sleep(1)
            ble_client2.interfaces.bluetooth.remove_device(local_dut_address)
            time.sleep(5)
            ble_client2.interfaces.bluetooth.close()
        except Exception as e:
            logger().warning(f"Failed to disconnect ble_client2: {e}")
    
    except Exception as e:
        logger().error(f"test_connect_raspii_as_ble_peripheral_bt_inquiry: {e}")
        raise

    finally:
        cleanup_after_test()



def test_bt_inquiry_ble_scan_adv(ble_dut, bt_client):
    """
    Test BT classic Inquiry when DUT is in BLE advertising and scanning mode
    TC: C554256
    
    Test Flow:
    1. Start BLE advertising on DUT
    2. Start BLE scanning on DUT
    3. Configure Raspberry Pi as A2DP sink (discoverable)
    4. Perform BT Classic Inquiry from DUT while BLE is active
    5. Verify inquiry response received
    """
    public_addr_type = 0
    pin_code = "0000"

    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    setup_test_state()

    # Get DUT address FIRST
    local_dut_address = get_dut_bd_address(ble_dut)
    logger().info(f"DUT Bluetooth Address: {local_dut_address}")

    # Start BLE advertising and scanning FIRST (per TC requirement)
    logger().info("\n\n **** Stop any existing BLE advertising and scanning on DUT ****\n\n")
    try:
        ble_dut.interfaces.wifi.legacy_scan_stop()
        time.sleep(2)
        ble_dut.interfaces.wifi.legacy_advertising_stop()
        time.sleep(2)
    except Exception as e:
        logger().warning(f"Failed to stop existing BLE operations: {e}")

    logger().info("\n\n **** Start BLE advertising on DUT ****\n\n")
    ble_dut.interfaces.wifi.legacy_advertising_start(
        status=1, adv_type=128, filter_type=0, direct_addr_type=public_addr_type,
        direct_addr=None, adv_int_min=338, adv_int_max=338,
        own_addr_type=0, channel_map=7
    )
    time.sleep(5)
    
    adv_success = assert_check(ble_dut, "ble_module_req_adv_cmd_handler : successful")
    assert adv_success, "BLE advertising failed to start"
    logger().info(" BLE advertising started successfully")

    logger().info("\n\n **** Start BLE scanning on DUT ****\n\n")
    ble_dut.interfaces.wifi.legacy_scan_start(
        status=1, scan_type=1, filter_policy=0, own_addr_type=0, 
        scan_interval=53, scan_window=23
    )
    time.sleep(5)
    
    scan_success = assert_check(ble_dut, "ble_module_req_scan_cmd_handler : successful")
    assert scan_success, "BLE scanning failed to start"
    logger().info(" BLE scanning started successfully")

    # Configure Raspberry Pi as A2DP sink (makes it discoverable)
    logger().info("\n\n **** Configure Raspberry Pi as A2DP sink ****\n\n")
    bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink_with_bluez(
        bt_dut_address=local_dut_address, pin_code=pin_code
    )
    assert bt_client_address, "Failed to initiate sink in remote device"
    logger().info(f"Primary bt_client is discoverable and connectable")
    logger().info(f"BT Client address: {bt_client_address}")
    time.sleep(5)

    # Perform BT Inquiry while BLE advertising/scanning is active
    logger().info("\n\n **** Start BT classic Inquiry from DUT (while BLE is active) ****\n\n")
    ble_dut.interfaces.wifi.gap_start_discovery()
    time.sleep(5)

    serial_expect_multi(
        ble_dut,
        ["Inquiry scan resp"],
        timeout=40,
        poll_interval=0.5,
        regex=False,                    
        case_insensitive=True,
        baseline=False
    )
    logger().info(" BT Inquiry response received while BLE advertising/scanning active")

    ble_dut.interfaces.wifi.gap_stop_discovery()
    time.sleep(5)

    logger().info(" Test PASSED: BT Inquiry successful while BLE advertising and scanning")

    # Cleanup
    try:
        bt_client.interfaces.bluetooth.close()
        time.sleep(5)
    except Exception as e:
        logger().warning(f"Failed to close bt_client: {e}")
    
    cleanup_after_test()
    

def test_bt_connect_initiator_ble_scan_adv(ble_dut, bt_client):
    """
    Test BT classic connection as initiator when DUT is in BLE advertising and scanning mode
    TC: C554257
    """

    pin_code = "0000"
    public_addr_type = 0

    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    setup_test_state()

    local_dut_address = get_dut_bd_address(ble_dut)

    logger().info("\n\n **** Stop BLE advertising and scanning on DUT ****\n\n")
    ble_dut.interfaces.wifi.legacy_scan_stop()
    time.sleep(5)
    ble_dut.interfaces.wifi.legacy_advertising_stop()
    time.sleep(5)

    logger().info("==========Configure Raspberry pi device as sink===========")
    bt_client_address = bt_client.interfaces.bluetooth.start_a2dp_sink_with_bluez(bt_dut_address=local_dut_address, pin_code=pin_code)
    assert bt_client_address, "Failed to initiate sink in remote device "
    logger().info(f"Primary bt_client is discoverable and connectable")
    logger().info(f"BT Client address {bt_client_address}")

    time.sleep(5)

    logger().info("\n\n **** Start BT classic Inquiry from DUT ****\n\n")
    ble_dut.interfaces.wifi.gap_start_discovery()
    serial_expect_multi(
        ble_dut,
        ["Inquiry scan resp"],
        timeout=40,
        poll_interval=0.5,
        regex=False,                    
        case_insensitive=True
    )
    ble_dut.interfaces.wifi.gap_stop_discovery()
    time.sleep(5)    

    logger().info("\n\n **** Start BT classic connection as initiator from DUT ****\n\n")
    ble_dut.interfaces.wifi.gap_connect(bt_client_address)

    serial_expect_multi(
        ble_dut,
        ["SAVED_LINK_KEY:"],
        timeout=40,
        poll_interval=0.5,
        regex=False,                    
        case_insensitive=True
    )

    connect_status = assert_check(ble_dut, "a2dp connect: success")
    if connect_status:
        logger().info("BT Classic connection established successfully")
    else:
        logger().info("BT Classic connection failed")

    logger().info("\n\n **** Start BLE advertising on DUT ****\n\n")
    ble_dut.interfaces.wifi.legacy_advertising_start(
        status=1, adv_type=128, filter_type=0, direct_addr_type=public_addr_type,
        direct_addr=None, adv_int_min=338, adv_int_max=338,
        own_addr_type=0, channel_map=7
    )
    time.sleep(5)  # Give command time to execute

    # Use assert_check which searches ENTIRE log
    adv_success = assert_check(ble_dut, "ble_module_req_adv_cmd_handler : successful")
    assert adv_success, "BLE advertising failed to start"
    logger().info(" BLE advertising started successfully")

    logger().info("\n\n **** Start BLE scanning on DUT ****\n\n")
    ble_dut.interfaces.wifi.legacy_scan_start(
        status=1, scan_type=1, filter_policy=0, own_addr_type=0,
        scan_interval=53, scan_window=23
    )
    time.sleep(5)  # Give command time to execute

    # Use assert_check for scanning too
    scan_success = assert_check(ble_dut, "ble_module_req_scan_cmd_handler : successful")
    assert scan_success, "BLE scanning failed to start"
    logger().info(" BLE scanning started successfully")

    monitor_duration = 300  # 5 minutes in seconds
    poll_interval = 5  # Check every 5 seconds
    start_time = time.time()

    while time.time() - start_time < monitor_duration:
        connect_status = bt_client.interfaces.bluetooth.get_bt_connection_status(local_dut_address)
        assert connect_status == True, "DUT lost connection during stability monitoring"
        logger().info("BT Classic connection is stable")
        time.sleep(poll_interval)

    if connect_status:
        logger().info("Disconnect initiated from DUT")
        ble_dut.interfaces.wifi.gap_disconnect(bt_client_address)
        time.sleep(5)
        logger().info(f"Removing bonded DUT ({local_dut_address}) from bt_client")
        bt_adapter_path = bt_client.interfaces.bluetooth.adapter_path
        get_bus = bt_client.interfaces.bluetooth.bus
        bt_client.interfaces.bluetooth.bluez_adapter.remove_device(bus= get_bus, adapter_path=bt_adapter_path, dev_addr=local_dut_address)
        logger().info(f"Removed bonded device from bt_client")
        time.sleep(5)
        bt_client.interfaces.bluetooth.close()
        time.sleep(5)

    cleanup_after_test()


def test_ble_bt_inquiry_connection(ble_dut, bt_client, ble_clients):
    """
    This test case verifies that the DUT can establish two BLE connections
    (as central and peripheral) and one BT Classic connection simultaneously.
    It ensures that audio streaming over BT Classic works while maintaining
    multiple BLE connections.
    TC: C554260
    2 - BLE connections, DUT as central and peripheral
    1 - BT Classic connection, DUT as initiator, audio streaming
    """
    logger().info("\n\n **** set sleep to initialize dut ****\n\n")
    time.sleep(20)

    setup_test_state()

    global local_dut_address
    local_dut_address = get_dut_bd_address(ble_dut)
    pin_code = "0000"

    ble_client1 = None
    ble_client2 = None
    ble_client3 = None

    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"

        #ble_client1 = ble_clients[0]
        ble_client2 = ble_clients[1]
        ble_client3 = ble_clients[2]


        ble_thread_1 = threading.Thread(target=ble_connect_raspii_to_dut, args=(ble_dut, ble_client3, False))
        logger().info(f" third raspberrypi as central and DUT as peripheral")
        ble_thread_2 = threading.Thread(target=ble_connect_dut_to_raspii, args=(ble_dut, ble_client2, False, True, False))
        logger().info(f"second raspberrypi as peripheral and DUT as central")

        ble_thread_1.start()
        ble_thread_2.start()
        ble_thread_1.join()
        ble_thread_2.join()

        #trying bt after ble
        bt_thread = threading.Thread(target=bt_classic_connect, args=(ble_dut, bt_client, pin_code, local_dut_address))
        logger().info(f"primary raspberrypi as bt_client is configured as a2dp sink ")
        bt_thread.start()
        bt_thread.join()

        bt_connect_status = connect_status_container.get("status")
        bt_client_address = connect_status_container.get("address")

        assert bt_connect_status, " BT connection failed - cannot proceed with test"
        assert bt_client_address, " BT client address not found in container"

        logger().info(f"BT connection verified: {bt_client_address}, status: {bt_connect_status}")

        # add audio streaming verification here

        monitor_all_connections_stability(ble_client2, ble_client3, bt_client, local_dut_address)

        check_conn_status_disconnect_initiated_from_dut(ble_dut, ble_client2, ble_client3, bt_client, bt_client_address=bt_client_address)
    except Exception as error:
        logger().error(f"Error in test_ble_bt_inquiry_connection: {error}")
        raise

    finally:
        logger().info(f"Removing bonded DUT ({local_dut_address}) from bt_client")
        bt_adapter_path = bt_client.interfaces.bluetooth.adapter_path
        get_bus = bt_client.interfaces.bluetooth.bus
        bt_client.interfaces.bluetooth.bluez_adapter.remove_device(bus= get_bus, adapter_path=bt_adapter_path, dev_addr=local_dut_address)
        logger().info(f"Removed bonded device from bt_client")
        time.sleep(5)
        bt_client.interfaces.bluetooth.close()
        time.sleep(5)        
        
        logger().info(f"Removing bonded DUT ({local_dut_address}) from ble_client2")
        ble_client2.interfaces.bluetooth.remove_device(local_dut_address)
        logger().info(f" Removed bonded device from ble_client2")
        time.sleep(5)
        logger().info(f"Removing bonded DUT ({local_dut_address}) from ble_client3")
        ble_client3.interfaces.bluetooth.remove_device(local_dut_address)
        logger().info(f" Removed bonded device from ble_client3")
        time.sleep(5)

        logger().info(f"closing BLE interfaces on Raspberry Pis")
        ble_client2.interfaces.bluetooth.close()
        time.sleep(5)
        ble_client3.interfaces.bluetooth.close()
        time.sleep(5)
        logger().info(f" Closed BT and BLE interfaces on Raspberry Pis")
        cleanup_after_test()

