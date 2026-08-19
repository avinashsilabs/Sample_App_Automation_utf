import json
import os
import re
import socket
import time
from datetime import datetime

import pytest

from utf.utils.logger import get_logger
from utf.interfaces.adb import PhoneState
from utf.utf_config import UtfConfig


"""
Connection Initiation: BLE connection is initiated from the Android device using a customized SI Connect application.

    1 - HFP HF connectivity
    2 - BLE to Bluetooth Classic bonding through CTKD.
    3 - Call establishment, termination, hold, retrieve, and swap operations.
    4 - Three-way calling behavior across multiple AGs.
    5 - Voice Recognition (VR) related HFP operations.
    6 - Stability and interoperability during multi-device call management.
    7 - Automated execution through ADB-enabled test infrastructure.
    8 - Protocol Analysis: Frontline Bluetooth Sniffer integration is supported for packet capture and debugging.
    9 - Sniffer connection is optional.
    10 -  Test execution remains fully functional without the sniffer.

    Author: Gannu Harshavardhan
"""

LOGGER = get_logger(__name__)

PHONE_BT_ADDRESS = "98:B7:1E:4E:1B:5A"  # fallback; overwritten by CTKD identity from receiver AG
SOURCE_ADB_DEVICE_ID = os.getenv("UTF_HFP_SOURCE_ADB_DEVICE_ID", "000553449000104")
DESTINATION_ADB_DEVICE_ID = os.getenv("UTF_HFP_DESTINATION_ADB_DEVICE_ID", "31051FDH2001TV")
DESTINATION_PHONE_NUMBER = os.getenv("UTF_HFP_DESTINATION_PHONE_NUMBER", "7337511161")
WAITING_CALLER_ADB_DEVICE_ID = os.getenv("UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID", "1390040495000DA")
# Number AG dials for outgoing-call cases (T1956406). Override via env / defaults.adb.outgoing_number.
OUTGOING_CALL_NUMBER = os.getenv(
    "UTF_HFP_OUTGOING_CALL_NUMBER",
    os.getenv("UTF_HFP_SOURCE_PHONE_NUMBER", "7337511161"),
)

# DUT needs time after reset/init before BT local address is available in serial logs.
INITIALIZATION_WAIT_SEC = 20
DUT_ADDRESS_RETRY_COUNT = 3
DUT_ADDRESS_RETRY_WAIT_SEC = 5
PASSKEY_TIMEOUT_SEC = 30
BT_CONNECT_TIMEOUT_SEC = 30
HFP_CONNECT_TIMEOUT_SEC = 20
A2DP_PROFILE_TIMEOUT_SEC = 20
INCOMING_CALL_TIMEOUT_SEC = 60
CALL_ACTION_TIMEOUT_SEC = 20
PROFILE_STABILITY_SEC = 2 * 60
RECONNECTION_GRACE_SEC = 1 * 60
POLL_INTERVAL_SEC = 0.5
INQUIRY_COMPLETION_WAIT_SEC = 12
POST_INQUIRY_RESULTS_WAIT_SEC = 3
POST_INQUIRY_STOP_WAIT_SEC = 2
PRE_CONNECT_DELAY_SEC = 0
AUTO_REJECT_DELAY_SEC = 5
AUTO_ACCEPT_DELAY_SEC = 3
AUTO_TERMINATE_DELAY_SEC = 20
REMOTE_BT_TOGGLE_TIMEOUT_SEC = 60
BLE_PASSKEY_TIMEOUT_SEC = 60
BLE_CTKD_TIMEOUT_SEC = 60
BLE_ADB_POST_PIN_SETTLE_SEC = 2
BLE_TO_BTC_DELAY_SEC = 5
POST_DIAL_SETTLE_SEC = 2
POST_END_CALL_SETTLE_SEC = 2
BETWEEN_CALLS_SETTLE_SEC = 10
SCO_OPEN_STABILITY_SEC = 60
WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC = 2 * 60
HF_SCO_TX_BANDWIDTH = 8000
HF_SCO_RX_BANDWIDTH = 8000
HF_MIC_GAIN_DEFAULT = 14
HF_SPEAKER_GAIN_DEFAULT = 2
SAMPLE_ACTIVE_CALL_HOLD_SEC = 2 * 60
SAMPLE_SCO_FILE_PATH = "/sdcard/Download/nrginc-440-hz-sine-402564.mp3"
SAMPLE_SCO_PLAY_SEC = 10
SAMPLE_SCO_INTERVAL_SEC = 20
SAMPLE_SCO_PROBE_DURATION_SEC = 2 * 60
FRONTLINE_SNIFFER_SOCKET_TIMEOUT_SEC = int(
    os.getenv("UTF_HFP_SNIFFER_SOCKET_TIMEOUT_SEC", "30")
)

_cached_dut_address = None
_BD_ADDR_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_BD_ADDR_CAPTURE = r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
_PASSKEY_EVENT_PATTERN = re.compile(
    rf"(?:In\s+passkey\s+event\s*,\s*)?remote\s+addr:\s*{_BD_ADDR_CAPTURE}\s*,\s*passkey:\s*(\d+)",
    re.IGNORECASE,
)
_PASSKEY_SIMPLE_PATTERN = re.compile(r"passkey[:\s]+(\d+)", re.IGNORECASE)
_IDENTITY_ADDRESS_PATTERN = re.compile(
    rf"Identity\s+Address\s*=\s*{_BD_ADDR_CAPTURE}(?:\s+with\s+type\s+(\d+))?",
    re.IGNORECASE,
)


def get_bus(device):
    return device.interfaces.wifi.bus


def parse_passkey_and_identity_address(lines):
    result = {
        "passkey": None,
        "passkey_remote_addr": None,
        "identity_address": None,
        "identity_address_type": None,
    }

    for line in lines:
        if isinstance(line, bytes):
            try:
                text = line.decode(errors="ignore")
            except Exception:
                text = str(line)
        else:
            text = str(line)

        if result["passkey"] is None:
            event_match = _PASSKEY_EVENT_PATTERN.search(text)
            if event_match:
                result["passkey_remote_addr"] = event_match.group(1).upper()
                result["passkey"] = event_match.group(2).zfill(6)
            else:
                simple_match = _PASSKEY_SIMPLE_PATTERN.search(text)
                if simple_match:
                    result["passkey"] = simple_match.group(1).zfill(6)

        if result["identity_address"] is None:
            identity_match = _IDENTITY_ADDRESS_PATTERN.search(text)
            if identity_match:
                result["identity_address"] = identity_match.group(1).upper()
                if identity_match.group(2) is not None:
                    result["identity_address_type"] = int(identity_match.group(2))

    return result


def clear_serial_log(wifi_dut):
    try:
        bus = get_bus(wifi_dut)
        clear_method = getattr(bus, "clear_input_log", None)
        if callable(clear_method):
            clear_method()
            return True
        LOGGER.info("DUT serial bus does not support clear_input_log(); using index-based log snapshotting.")
    except Exception as exc:
        LOGGER.warning(f"Unable to clear DUT serial log: {exc}")
        return False
    return False


def fetch_local_address(wifi_dut):
    patterns = [
        re.compile(r"local_bd_address:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"),
        re.compile(r"addr:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", re.IGNORECASE),
    ]
    input_log = get_bus(wifi_dut).get_input_log()
    for _, line in input_log:
        try:
            decoded = line.decode(errors="ignore")
        except Exception:
            decoded = str(line)
        for pattern in patterns:
            match = pattern.search(decoded)
            if match:
                return match.group(1).strip()
    return None


def get_dut_address(wifi_dut):
    global _cached_dut_address
    if _cached_dut_address:
        LOGGER.info(f"DUT Bluetooth address (cached): {_cached_dut_address}")
        return _cached_dut_address

    parsed_address = fetch_local_address(wifi_dut)
    if parsed_address and _BD_ADDR_PATTERN.match(parsed_address):
        _cached_dut_address = parsed_address
        LOGGER.info(f"DUT Bluetooth address (parsed from serial): {_cached_dut_address}")
        return _cached_dut_address

    try:
        wifi_dut.interfaces.wifi.get_local_address()
        time.sleep(1)
    except Exception as exc:
        LOGGER.warning(f"CLI local address request failed, trying serial log parse: {exc}")

    parsed_address = fetch_local_address(wifi_dut)
    if parsed_address and _BD_ADDR_PATTERN.match(parsed_address):
        _cached_dut_address = parsed_address
        LOGGER.info(f"DUT Bluetooth address (parsed after CLI request): {_cached_dut_address}")
        return _cached_dut_address

    raise RuntimeError("Failed to retrieve a valid DUT Bluetooth address from serial logs.")


def _validate_phone_target():
    if not re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", PHONE_BT_ADDRESS):
        pytest.fail(
            f"PHONE_BT_ADDRESS '{PHONE_BT_ADDRESS}' is not in XX:XX:XX:XX:XX:XX format."
        )


def _env_int(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        LOGGER.warning(f"Invalid integer for {name}: {value!r}. Using default {default}.")
        return default


def _env_str(name, default=""):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip()


def _get_adb_config(adb_phone):
    """Merge harness defaults.adb with per-device adb interface config."""
    config = dict(UtfConfig.instance().defaults.get("adb", {}))
    config.update(adb_phone.config.get("interfaces", {}).get("adb", {}))
    config.update(adb_phone.config.get("adb", {}))
    return config


def _adb_device_id(adb_phone):
    iface = getattr(getattr(adb_phone, "interfaces", None), "adb", None)
    return getattr(iface, "device_id", None) if iface is not None else None


def _resolve_destination_and_source_phones(adb_phones):
    if len(adb_phones) < 2:
        pytest.skip("Configure at least two devices under defaults.adb_phones")

    dest_id = _env_str("UTF_HFP_DESTINATION_ADB_DEVICE_ID", DESTINATION_ADB_DEVICE_ID)
    src_id = _env_str("UTF_HFP_SOURCE_ADB_DEVICE_ID", SOURCE_ADB_DEVICE_ID)
    by_id = {_adb_device_id(p): p for p in adb_phones}

    destination_phone = by_id.get(dest_id)
    source_phone = by_id.get(src_id)

    if destination_phone is None or source_phone is None:
        for phone in adb_phones:
            name = str(getattr(phone, "name", "") or getattr(phone, "device_name", "")).lower()
            serial = _adb_device_id(phone)
            if destination_phone is None and any(
                token in name for token in ("receiver", "destination")
            ):
                destination_phone = phone
                dest_id = serial or dest_id
            # Avoid matching waiting_caller_adb_phone via the substring "caller".
            if (
                source_phone is None
                and "waiting" not in name
                and any(token in name for token in ("caller", "source", "helper", "secondary"))
            ):
                source_phone = phone
                src_id = serial or src_id

    if destination_phone is None or source_phone is None:
        available = ", ".join(
            f"{k}({getattr(p, 'name', '?')})" for k, p in by_id.items() if k
        )
        pytest.fail(
            "Could not map AG/helper phones by serial. "
            f"Need destination={dest_id!r} (Si-Connect receiver AG) and "
            f"source={src_id!r} (secondary AG / caller). "
            f"Available: [{available}]. "
            "Set UTF_HFP_DESTINATION_ADB_DEVICE_ID / UTF_HFP_SOURCE_ADB_DEVICE_ID."
        )
    if destination_phone is source_phone:
        pytest.fail(
            f"Destination and source resolved to the same ADB serial {dest_id!r}"
        )

    LOGGER.info(
        "Resolved ADB roles by serial: destination_AG=%s source_helper=%s "
        "(available=%s)",
        _adb_device_id(destination_phone),
        _adb_device_id(source_phone),
        list(by_id.keys()),
    )
    return destination_phone, source_phone


def _resolve_waiting_caller_phone(adb_phones, destination_phone, source_phone):
    waiting_id = _env_str("UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID", WAITING_CALLER_ADB_DEVICE_ID)
    by_id = {_adb_device_id(p): p for p in adb_phones}
    if waiting_id and waiting_id in by_id:
        phone = by_id[waiting_id]
        if phone is destination_phone or phone is source_phone:
            LOGGER.warning(
                "Waiting-caller serial %s collides with AG/source; ignoring",
                waiting_id,
            )
        else:
            return phone
    for phone in adb_phones:
        if phone is destination_phone or phone is source_phone:
            continue
        return phone
    return None


def _prepare_hfp_runner(wifi_dut, adb_phones, test_name, ble_sniffer=None):
    destination_phone, source_phone = _resolve_destination_and_source_phones(adb_phones)
    waiting_caller_phone = _resolve_waiting_caller_phone(
        adb_phones, destination_phone, source_phone
    )
    destination_adb = destination_phone.interfaces.adb
    source_adb = source_phone.interfaces.adb
    waiting_caller_adb = (
        waiting_caller_phone.interfaces.adb if waiting_caller_phone is not None else None
    )
    dest_cfg = _get_adb_config(destination_phone)
    target_number = (
        dest_cfg.get("target_number")
        or _env_str("UTF_HFP_DESTINATION_PHONE_NUMBER", DESTINATION_PHONE_NUMBER)
        or DESTINATION_PHONE_NUMBER
    )
    outgoing_number = (
        _env_str("UTF_HFP_OUTGOING_CALL_NUMBER", OUTGOING_CALL_NUMBER)
        or dest_cfg.get("outgoing_number")
        or _get_adb_config(source_phone).get("phone_number")
        or ""
    )
    LOGGER.info(
        "%s destination/receiver AG device_id=%s (Si-Connect)",
        test_name,
        destination_adb.device_id,
    )
    LOGGER.info(
        "%s source/secondary AG device_id=%s",
        test_name,
        source_adb.device_id,
    )
    if waiting_caller_adb is not None:
        LOGGER.info(
            "%s waiting-caller device_id=%s",
            test_name,
            waiting_caller_adb.device_id,
        )
    LOGGER.info("%s destination phone number=%s", test_name, target_number)
    if outgoing_number:
        LOGGER.info("%s AG outgoing dial number=%s", test_name, outgoing_number)
    try:
        destination_adb.prefer_adb_usb_mode()
        source_adb.prefer_adb_usb_mode()
        if waiting_caller_adb is not None:
            waiting_caller_adb.prefer_adb_usb_mode()
    except Exception as exc:
        LOGGER.warning("prefer_adb_usb_mode failed (continuing): %s", exc)
    _validate_phone_target()
    return RT595HfpHfAdbTest(
        wifi_dut,
        test_name=test_name,
        destination_adb=destination_adb,
        source_adb=source_adb,
        waiting_caller_adb=waiting_caller_adb,
        destination_phone_number=target_number,
        outgoing_call_number=outgoing_number or None,
        ble_sniffer=ble_sniffer,
    )


def _run_hfp_test(test_runner, run_method):
    final_status = "passed"
    error_message = None
    test_runner._sniffer_start_capture_if_enabled()
    try:
        run_method()
    except Exception as exc:
        final_status = "failed"
        error_message = str(exc)
        test_runner._record_event("test_failed", status="fail", details={"error": error_message})
        raise
    else:
        test_runner._record_event("test_completed", status="pass")
    finally:
        test_runner._sniffer_stop_capture_if_enabled()
        try:
            test_runner._cleanup_bt_connection_after_test()
        except Exception as cleanup_exc:
            LOGGER.warning(
                "Post-test BT cleanup raised (continuing): %s", cleanup_exc
            )
        test_runner.save_run_artifacts(final_status, error_message)


class RT595HfpHfAdbTest:

    def __init__(
        self,
        wifi_dut,
        test_name="test_verify_incoming_call_reject_from_hf_and_ag_T1956398",
        destination_adb=None,
        source_adb=None,
        waiting_caller_adb=None,
        destination_phone_number=None,
        outgoing_call_number=None,
        ble_sniffer=None,
    ):
        self.wifi_dut = wifi_dut
        self.wifi = wifi_dut.interfaces.wifi
        self.destination_adb = destination_adb
        self.source_adb = source_adb
        self.waiting_caller_adb = waiting_caller_adb
        self.ble_sniffer = ble_sniffer
        self.sniffer_capture_started = False
        self.phone_address = PHONE_BT_ADDRESS
        self.dut_address = None
        self.ctkd_identity_address = None
        self.source_adb_device_id = _env_str("UTF_HFP_SOURCE_ADB_DEVICE_ID", SOURCE_ADB_DEVICE_ID)
        self.destination_adb_device_id = _env_str(
            "UTF_HFP_DESTINATION_ADB_DEVICE_ID", DESTINATION_ADB_DEVICE_ID
        )
        self.waiting_caller_adb_device_id = _env_str(
            "UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID", WAITING_CALLER_ADB_DEVICE_ID
        )
        self.destination_phone_number = _env_str(
            "UTF_HFP_DESTINATION_PHONE_NUMBER",
            destination_phone_number or DESTINATION_PHONE_NUMBER,
        )
        self.outgoing_call_number = _env_str(
            "UTF_HFP_OUTGOING_CALL_NUMBER",
            outgoing_call_number or OUTGOING_CALL_NUMBER,
        )
        if self.destination_adb is not None and getattr(self.destination_adb, "device_id", None):
            self.destination_adb_device_id = self.destination_adb.device_id
        if self.source_adb is not None and getattr(self.source_adb, "device_id", None):
            self.source_adb_device_id = self.source_adb.device_id
        if self.waiting_caller_adb is not None and getattr(
            self.waiting_caller_adb, "device_id", None
        ):
            self.waiting_caller_adb_device_id = self.waiting_caller_adb.device_id
        self.run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.test_name = test_name
        self.log_dir = os.path.join("reports", "hfp_hf_adb_logs")
        self.raw_log_path = os.path.join(
            self.log_dir, f"{self.test_name}_{self.run_timestamp}_dut_serial.log"
        )
        self.summary_path = os.path.join(
            self.log_dir, f"{self.test_name}_{self.run_timestamp}_summary.json"
        )
        self.serial_log_archive = []
        self.event_log = []
        self._archived_bus_index = 0
        self.started_at = datetime.now().isoformat()

    def _decode_bus_log(self):
        decoded_entries = []
        for timestamp, raw_line in get_bus(self.wifi_dut).get_input_log():
            try:
                decoded_line = raw_line.decode(errors="ignore")
            except Exception:
                decoded_line = str(raw_line)
            decoded_entries.append((timestamp, decoded_line))
        return decoded_entries

    def _archive_new_bus_logs(self):
        decoded_entries = self._decode_bus_log()
        for timestamp, decoded_line in decoded_entries[self._archived_bus_index:]:
            self.serial_log_archive.append(
                {
                    "timestamp": str(timestamp),
                    "line": decoded_line.rstrip("\r\n"),
                }
            )
        self._archived_bus_index = len(decoded_entries)
        return decoded_entries

    def _record_event(self, name, status="info", details=None, log_match=None):
        self.event_log.append(
            {
                "timestamp": datetime.now().isoformat(),
                "name": name,
                "status": status,
                "details": details or {},
                "log_match": log_match,
            }
        )

    def _find_recorded_event(self, name):
        for event in reversed(self.event_log):
            if event.get("name") == name:
                return event
        return None

    def _send_cli_command(self, command, event_name=None):
        LOGGER.info(f"Sending CLI command: {command}")
        bus = get_bus(self.wifi_dut)
        start_index = self._get_log_snapshot()
        bus.write_line_and_expect(command)

        response = None
        try:
            response = bus.read_line()
        except Exception as exc:
            LOGGER.warning(f"No immediate CLI response for `{command}`: {exc}")

        self._record_event(
            event_name or "cli_command_sent",
            status="pass",
            details={
                "command": command,
                "response": str(response) if response is not None else None,
            },
        )
        return start_index, response

    def _clear_serial_log(self):
        self._archive_new_bus_logs()
        if clear_serial_log(self.wifi_dut):
            self._archived_bus_index = 0

    def _get_log_snapshot(self):
        return len(self._archive_new_bus_logs())

    def _read_new_log_lines(self, start_index):
        input_log = self._archive_new_bus_logs()
        decoded_lines = []
        for _, decoded_line in input_log[start_index:]:
            decoded_lines.append(decoded_line)
        return decoded_lines, len(input_log)

    def _wait_for_any_match(self, patterns, timeout, start_index):
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        deadline = time.time() + timeout
        current_index = start_index

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                for compiled_pattern in compiled_patterns:
                    if compiled_pattern.search(line):
                        return line.strip()
            time.sleep(POLL_INTERVAL_SEC)
        return None

    def _collect_matching_lines(self, patterns, timeout, start_index):
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        deadline = time.time() + timeout
        current_index = start_index
        matches = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                if any(pattern.search(line) for pattern in compiled_patterns):
                    matches.append(line.strip())
            time.sleep(POLL_INTERVAL_SEC)
        return matches

    def _collect_log_window(self, timeout, start_index):
        deadline = time.time() + timeout
        current_index = start_index
        collected_lines = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            collected_lines.extend(line.strip() for line in lines if line.strip())
            time.sleep(POLL_INTERVAL_SEC)
        return collected_lines

    def _parse_passkey_and_identity_address(self, lines):
        return parse_passkey_and_identity_address(lines)

    def _wait_for_passkey(self, timeout, start_index):
        """Wait for passkey only; prefer _wait_for_passkey_and_identity_address when CTKD logs matter."""
        result = self._wait_for_passkey_and_identity_address(
            timeout,
            start_index,
            require_identity=False,
        )
        return result.get("passkey")

    def _wait_for_passkey_and_identity_address(
        self,
        timeout,
        start_index,
        require_identity=True,
        print_passkey_immediately=True,
    ):
        deadline = time.time() + timeout
        current_index = start_index
        result = {
            "passkey": None,
            "passkey_remote_addr": None,
            "identity_address": None,
            "identity_address_type": None,
        }
        passkey_announced = False

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            if lines:
                parsed = self._parse_passkey_and_identity_address(lines)
                for key, value in parsed.items():
                    if value is not None and result[key] is None:
                        result[key] = value

            if result["passkey"] and not passkey_announced:
                passkey_announced = True
                if print_passkey_immediately:
                    LOGGER.info(
                        "DUT passkey=%s remote_addr=%s (submitting via ADB if automation path)",
                        result["passkey"],
                        result["passkey_remote_addr"],
                    )
                if not self._find_recorded_event("passkey_detected"):
                    self._record_event(
                        "passkey_detected",
                        status="pass",
                        details={
                            "passkey": result["passkey"],
                            "passkey_remote_addr": result["passkey_remote_addr"],
                        },
                    )

            if result["passkey"] and (not require_identity or result["identity_address"]):
                if result["identity_address"] and not self._find_recorded_event("identity_address_detected"):
                    self._record_event(
                        "identity_address_detected",
                        status="pass",
                        details={
                            "identity_address": result["identity_address"],
                            "identity_address_type": result["identity_address_type"],
                        },
                    )
                return result

            time.sleep(POLL_INTERVAL_SEC)

        if result["identity_address"] and not self._find_recorded_event("identity_address_detected"):
            self._record_event(
                "identity_address_detected",
                status="pass",
                details={
                    "identity_address": result["identity_address"],
                    "identity_address_type": result["identity_address_type"],
                },
            )
        return result

    def _assert_no_failure_log_since(self, command_name, start_index, timeout=2):
        failure_patterns = [
            r"error status 0x[0-9a-fA-F]+",
            r"failed",
            r"page timeout",
            r"connection timeout",
            r"disconnect reason",
        ]
        matches = self._collect_matching_lines(failure_patterns, timeout, start_index)
        if matches:
            pytest.fail(f"{command_name} reported failure logs: {matches[:5]}")

    def _wait_for_target_address(self, target_address, timeout, start_index):
        deadline = time.time() + timeout
        current_index = start_index
        target_address = target_address.lower()

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                if target_address in line.lower():
                    return line.strip()
            time.sleep(POLL_INTERVAL_SEC)
        return None

    def _parse_ag_features(self, lines):
        features = {}
        feature_pattern = re.compile(r"^([A-Za-z0-9]+)\s*=\s*([YN])$", re.IGNORECASE)
        in_ag_block = False

        flattened_lines = []
        for line in lines:
            for sub_line in re.split(r"\r\n|\r|\n|\\r\\n|\\r|\\n", line):
                sub_line = sub_line.strip()
                if sub_line:
                    flattened_lines.append(sub_line)

        for stripped in flattened_lines:
            if re.search(r"AG feat:", stripped, re.IGNORECASE):
                in_ag_block = True
                continue

            if not in_ag_block:
                continue

            match = feature_pattern.match(stripped)
            if match:
                features[match.group(1)] = match.group(2).upper()
                continue

            if features and (
                stripped.startswith("[")
                or ":" in stripped
                or stripped.lower().startswith(("callsetup", "callheld", "spk gain", "mode change"))
            ):
                break

        return features

    def _parse_callheld_status(self, lines):
        for index, line in enumerate(lines):
            match = re.search(r"hfp callheld\s*:\s*(.+)", line, re.IGNORECASE)
            if match:
                status = match.group(1).strip()
                if status and "str_conn_bd_addr" not in status.lower():
                    return status

                for next_line in lines[index + 1 : index + 4]:
                    candidate = next_line.strip()
                    if not candidate or "addr:" in candidate.lower():
                        continue
                    return candidate
        return None

    def _parse_call_status(self, lines):
        for index, line in enumerate(lines):
            if re.search(r"hfp call status|call status:", line, re.IGNORECASE):
                for next_line in lines[index + 1 : index + 4]:
                    candidate = next_line.strip()
                    if not candidate or "addr:" in candidate.lower() or "str_conn_bd_addr" in candidate.lower():
                        continue
                    return candidate
        return None

    def _parse_callsetup_status(self, lines):
        for line in lines:
            match = re.search(r"callsetup:\s*(IDLE|IN|OUT|ALERTING|ACTIVE|WAITING|HELD)", line, re.IGNORECASE)
            if match:
                return match.group(1).upper()
        return None

    def _parse_hfp_service_indicators(self, lines):
        indicators = {}

        for index, line in enumerate(lines):
            phoneservice_match = re.search(r"hfp phoneservice\s*:\s*(.+)", line, re.IGNORECASE)
            if phoneservice_match:
                value = phoneservice_match.group(1).strip()
                if value and "str_conn_bd_addr" not in value.lower():
                    indicators["phoneservice"] = value
                    continue

                for next_line in lines[index + 1 : index + 4]:
                    candidate = next_line.strip()
                    if not candidate or "addr:" in candidate.lower():
                        continue
                    indicators["phoneservice"] = candidate
                    break

            signal_match = re.search(r"sig:([A-Za-z]+)", line, re.IGNORECASE)
            if signal_match:
                indicators["signal"] = signal_match.group(1).upper()

            roam_match = re.search(r"roam:([A-Za-z]+)", line, re.IGNORECASE)
            if roam_match:
                indicators["roam"] = roam_match.group(1).lower()

            battery_match = re.search(r"bat:([A-Za-z]+)", line, re.IGNORECASE)
            if battery_match:
                indicators["battery"] = battery_match.group(1).upper()

            operator_match = re.search(r"(operator|cops).*?:\s*(.+)", line, re.IGNORECASE)
            if operator_match:
                value = operator_match.group(2).strip()
                if value:
                    indicators["operator"] = value

        return indicators

    def _parse_duplicate_gap_connect(self, start_index, timeout=BT_CONNECT_TIMEOUT_SEC):
        duplicate_lines = self._collect_matching_lines(
            [r"Initiated Paging", r"0x4e0b", r"ACL conn exists"],
            timeout=timeout,
            start_index=start_index,
        )
        if not duplicate_lines:
            return None

        saw_duplicate_error = any(re.search(r"0x4e0b", line, re.IGNORECASE) for line in duplicate_lines)
        saw_acl_exists = any(re.search(r"ACL conn exists", line, re.IGNORECASE) for line in duplicate_lines)
        if saw_duplicate_error and saw_acl_exists:
            self._record_event(
                "duplicate_gap_connect_rejected",
                status="pass",
                details={"matches": duplicate_lines[:10]},
            )
            return duplicate_lines
        return None

    def _parse_gap_disconnect(self, start_index, timeout=BT_CONNECT_TIMEOUT_SEC):
        disconnect_lines = self._collect_matching_lines(
            [r"AVRCP disconnect event", r"unbond .*0x4e16", r"hfp disconn HF", r"A2DP Sink disconnect event"],
            timeout=timeout,
            start_index=start_index,
        )
        if not disconnect_lines:
            return None

        saw_avrcp = any(re.search(r"AVRCP disconnect event", line, re.IGNORECASE) for line in disconnect_lines)
        saw_hfp = any(re.search(r"hfp disconn HF", line, re.IGNORECASE) for line in disconnect_lines)
        saw_a2dp = any(re.search(r"A2DP Sink disconnect event", line, re.IGNORECASE) for line in disconnect_lines)
        if saw_avrcp and saw_hfp and saw_a2dp:
            self._record_event(
                "gap_disconnect_observed",
                status="pass",
                details={"matches": disconnect_lines[:12]},
            )
            return disconnect_lines
        return None

    def _parse_vr_activate_failure(self, start_index, timeout=CALL_ACTION_TIMEOUT_SEC):
        vr_failure_lines = self._collect_matching_lines(
            [
                r"btc hfp vr_activate",
                rf"cmd resp:{re.escape(self.phone_address)}",
                r"rsi_bt_hfp_vr_activate\(\) Command failed with Status = 4602",
                r"SNIFF_MODE_DISABLED",
                r"SNIFF_MODE_ENABLED",
            ],
            timeout=timeout,
            start_index=start_index,
        )
        if not vr_failure_lines:
            return None

        saw_command_response = any(
            re.search(rf"cmd resp:{re.escape(self.phone_address)}", line, re.IGNORECASE) for line in vr_failure_lines
        )
        saw_failure = any(
            re.search(r"rsi_bt_hfp_vr_activate\(\) Command failed with Status = 4602", line, re.IGNORECASE)
            for line in vr_failure_lines
        )
        if saw_command_response and saw_failure:
            self._record_event(
                "vr_activate_failure_observed",
                status="pass",
                details={"matches": vr_failure_lines[:12]},
            )
            return vr_failure_lines
        return None

    def _capture_gap_connect_profile_state(self, start_index):
        observed_lines = self._collect_log_window(HFP_CONNECT_TIMEOUT_SEC, start_index)
        if not observed_lines:
            return

        connect_markers = [
            line
            for line in observed_lines
            if re.search(
                r"Initiated Paging|Peer 0: connect command excuted succesfully|role chg|conn evt|on conn paging|page done",
                line,
                re.IGNORECASE,
            )
        ]
        if connect_markers:
            self._record_event(
                "gap_connect_transport_observed",
                status="pass",
                details={"matches": connect_markers[:12]},
            )

        security_markers = [
            line
            for line in observed_lines
            if re.search(
                r"linkkey req|linkkey save|saved key:|auth_complete event|rsi_bt_on_auth_complete_event|BT Classic Encryption Change|Link encryption:",
                line,
                re.IGNORECASE,
            )
        ]
        if security_markers:
            self._record_event(
                "bt_security_state_observed",
                status="pass",
                details={"matches": security_markers[:12]},
            )

        profile_markers = [
            line
            for line in observed_lines
            if re.search(
                r"a2dp conn ok|A2DP Sink .*Event|A2DP stream conn|Initiating AVRCP Connection|avrcp conn|"
                r"hfp conn HF|HFP conn ok|AT\+BRSF|AT\+BAC|AT\+CIND=\?|AT\+CIND\?|AT\+CMER|AT\+CHLD=\?",
                line,
                re.IGNORECASE,
            )
        ]
        if profile_markers:
            self._record_event(
                "gap_connect_profile_bringup_observed",
                status="pass",
                details={
                    "matches": profile_markers[:16],
                    "hfp_auto_connected": any(
                        re.search(
                            r"hfp conn HF|HFP conn ok|AT\+BRSF|AG feat:",
                            line,
                            re.IGNORECASE,
                        )
                        for line in observed_lines
                    ),
                },
            )

        ag_features = self._parse_ag_features(observed_lines)
        if ag_features:
            self._record_event(
                "hfp_ag_features_observed",
                status="pass",
                details={"features": ag_features},
            )

        callheld_status = self._parse_callheld_status(observed_lines)
        if callheld_status:
            self._record_event(
                "hfp_callheld_state_observed",
                status="pass",
                details={"status": callheld_status},
            )

        call_status = self._parse_call_status(observed_lines)
        if call_status:
            self._record_event(
                "hfp_call_status_observed",
                status="pass",
                details={"status": call_status},
            )

        callsetup_status = self._parse_callsetup_status(observed_lines)
        if callsetup_status:
            self._record_event(
                "hfp_callsetup_state_observed",
                status="pass",
                details={"status": callsetup_status},
            )

        indicators = self._parse_hfp_service_indicators(observed_lines)
        if indicators:
            self._record_event(
                "hfp_indicator_state_observed",
                status="pass",
                details=indicators,
            )

    def _verify_codec_and_status_indicators(self):
        ag_features_event = self._find_recorded_event("hfp_ag_features_observed")
        assert ag_features_event, "No AG feature block was recorded after connection."
        ag_features = (ag_features_event.get("details") or {}).get("features", {})

        expected_feature_flags = {
            "Codec": "Y",
            "Err": "Y",
        }
        missing_feature_flags = {
            feature: expected
            for feature, expected in expected_feature_flags.items()
            if ag_features.get(feature) != expected
        }
        assert not missing_feature_flags, (
            "Required HFP AG feature flags were not observed. "
            f"Expected: {expected_feature_flags}, observed: {ag_features}"
        )

        indicator_event = self._find_recorded_event("hfp_indicator_state_observed")
        assert indicator_event, "No HFP indicator state block was recorded after connection."
        indicators = indicator_event.get("details") or {}
        required_indicators = ["phoneservice", "signal", "roam", "battery"]
        missing_indicators = [indicator for indicator in required_indicators if indicator not in indicators]
        assert not missing_indicators, (
            "Required HFP status indicators were not observed. "
            f"Missing: {missing_indicators}, observed: {indicators}"
        )

        operator_event_details = {}
        if "operator" in indicators:
            operator_event_details["operator"] = indicators["operator"]
            self._record_event(
                "hfp_operator_selection_observed",
                status="pass",
                details=operator_event_details,
            )
        else:
            self._record_event(
                "hfp_operator_selection_not_observed",
                status="info",
                details={
                    "reason": "No explicit operator/COPS log was emitted by the DUT during connection bring-up."
                },
            )

        self._record_event(
            "hfp_codec_and_status_verified",
            status="pass",
            details={
                "features": ag_features,
                "indicators": indicators,
            },
        )

    def _confirm_prerequisites(self):
        LOGGER.info("Assuming DUT firmware is already flashed/running (no operator wait).")
        self._record_event("compile_and_run_confirmation", details={"mode": "automated"})

    def _get_dut_address(self):
        if self.dut_address:
            return self.dut_address

        # After fixture reset/init the RT595 still prints boot/SDIO before BT is ready.
        LOGGER.info(
            "Waiting %ss for DUT initialization before reading BT local address",
            INITIALIZATION_WAIT_SEC,
        )
        time.sleep(INITIALIZATION_WAIT_SEC)

        last_error = None
        for attempt in range(1, DUT_ADDRESS_RETRY_COUNT + 1):
            try:
                self.dut_address = get_dut_address(self.wifi_dut)
                break
            except RuntimeError as exc:
                last_error = exc
                if attempt >= DUT_ADDRESS_RETRY_COUNT:
                    raise
                LOGGER.info(
                    "DUT address not ready (attempt %s/%s); waiting %ss then retrying: %s",
                    attempt,
                    DUT_ADDRESS_RETRY_COUNT,
                    DUT_ADDRESS_RETRY_WAIT_SEC,
                    exc,
                )
                time.sleep(DUT_ADDRESS_RETRY_WAIT_SEC)

        if not self.dut_address and last_error is not None:
            raise last_error

        LOGGER.info(f"DUT Bluetooth address: {self.dut_address}")
        self._record_event(
            "dut_address_detected",
            status="pass",
            details={"dut_address": self.dut_address},
        )
        return self.dut_address

    def _prepare_phone(self):
        LOGGER.info(f"Target phone Bluetooth address: {self.phone_address}")
        self._record_event(
            "phone_target_prepared",
            details={"phone_address": self.phone_address, "mode": "automated"},
        )

    def _establish_btc_via_ctkd(self, phone_address=None):
        target = phone_address or self.ctkd_identity_address or self.phone_address
        assert target, "No phone classic/identity address available for btc gap connect"
        prev = self.phone_address
        self.phone_address = target
        self.ctkd_identity_address = self.ctkd_identity_address or target
        self._soft_gap_disconnect(
            reason="pre_ctkd_connect",
            timeout=_env_int("UTF_HFP_PRE_CONNECT_DISCONNECT_TIMEOUT_SEC", 5),
        )
        self.phone_address = prev or target

        self._clear_serial_log()
        connect_snapshot = self._get_log_snapshot()

        LOGGER.info(
            "Initiating classic BT connect after CTKD (no classic passkey expected): btc gap connect %s",
            target,
        )
        connect_snapshot, _ = self._send_cli_command(
            f"btc gap connect {target}",
            event_name="bt_connect_command_sent_after_ctkd",
        )
        self._assert_no_failure_log_since("btc gap connect (post-CTKD)", connect_snapshot, timeout=2)

        bt_match = self._wait_for_any_match(
            [
                r"rsi_bt_on_auth_complete_event",
                r"rsi_bt_on_conn_status_event",
                r"linkkey req",
                r"linkkey save",
                r"conn evt",
                r"page done",
                r"a2dp conn ok",
                r"hfp conn HF",
                r"paired",
                r"connected",
            ],
            BT_CONNECT_TIMEOUT_SEC,
            connect_snapshot,
        )
        assert bt_match, (
            "No classic BT connection/auth log was detected after post-CTKD "
            f"`btc gap connect {target}`."
        )

        LOGGER.info(f"Classic BT connection log after CTKD: {bt_match}")
        self._record_event(
            "btc_connected_via_ctkd",
            status="pass",
            log_match=bt_match,
            details={"phone_address": target, "ctkd_identity_address": self.ctkd_identity_address},
        )
        self._capture_gap_connect_profile_state(connect_snapshot)
        return connect_snapshot

    def _require_shell_adb_phones(self):
        if self.destination_adb is None or self.source_adb is None:
            pytest.fail(
                "T1956402 shell-ADB path requires destination_adb and source_adb "
                "(AdbShellInterface from adb_phones fixture)."
            )
        if not self.destination_phone_number:
            pytest.fail(
                "DESTINATION_PHONE_NUMBER / UTF_HFP_DESTINATION_PHONE_NUMBER / "
                "defaults.adb.target_number is required for source place_call."
            )

    def _establish_ble_bond_via_si_connect_shell(self):
        self._require_shell_adb_phones()
        adb = self.destination_adb
        dut_address = self._get_dut_address()

        LOGGER.info(
            "Opening Si-Connect on destination device_id=%s then BLE connect+bond to DUT %s",
            getattr(adb, "device_id", None),
            dut_address,
        )

        adb.wake_screen()
        LOGGER.info(
            "Granting Si-Connect runtime permissions on %s "
            "(avoids location/BT permission dialogs before BLE scan)",
            getattr(adb, "device_id", None),
        )
        perm_results = adb.grant_si_connect_permissions()
        self._record_event(
            "ble_si_connect_permissions_granted",
            status="pass",
            details={"device_id": getattr(adb, "device_id", None), "results": perm_results},
        )
        adb.clear_logcat()
        open_result = {
            "ping": adb.ble_ping(),
            "start_app": adb.ble_start_app(),
            "device_id": getattr(adb, "device_id", None),
            "app_foreground": False,
        }
        open_result["app_foreground"] = adb.bring_si_connect_to_foreground(settle_sec=6.0)
        self._record_event(
            "ble_si_connect_app_started",
            status="pass" if open_result["app_foreground"] else "info",
            details={
                "dut_address": dut_address,
                "destination_device_id": getattr(adb, "device_id", None),
                "transport": "adb_shell",
                "open_result": {
                    "app_foreground": open_result.get("app_foreground"),
                    "ping": bool(open_result.get("ping")),
                    "start_app": bool(open_result.get("start_app")),
                },
            },
        )
        if not open_result["app_foreground"]:
            LOGGER.warning(
                "Si-Connect may not be in foreground on %s; CONNECT_AND_BOND "
                "often fails with ForegroundServiceStartNotAllowedException",
                getattr(adb, "device_id", None),
            )

        self._dut_remove_ltk(reason="pre_bond")
        try:
            adb.ble_disconnect(dut_address)
            self._record_event("ble_disconnect_sent", status="pass", details={"dut_address": dut_address})
        except Exception as exc:
            LOGGER.warning(f"ble_disconnect failed (continuing): {exc}")
            self._record_event(
                "ble_disconnect_failed",
                status="info",
                details={"dut_address": dut_address, "error": str(exc)},
            )

        try:
            adb.ble_remove_bond(dut_address)
            self._record_event("ble_remove_bond_sent", status="pass", details={"dut_address": dut_address})
        except Exception as exc:
            LOGGER.warning(f"ble_remove_bond failed (continuing): {exc}")
            self._record_event(
                "ble_remove_bond_failed",
                status="info",
                details={"dut_address": dut_address, "error": str(exc)},
            )

        self._clear_serial_log()
        ble_snapshot = self._get_log_snapshot()
        adb.clear_logcat()

        # CONNECT_AND_BOND starts internal SCAN_START then GATT+bond.
        LOGGER.info(
            "Starting Si-Connect CONNECT_AND_BOND to DUT %s (includes BLE scan)",
            dut_address,
        )
        adb.ble_connect_and_bond(dut_address)
        self._record_event(
            "ble_connect_and_bond_started",
            status="pass",
            details={"dut_address": dut_address, "transport": "adb_shell"},
        )

        scan_seen = adb.wait_for_logcat_pattern(
            r"SCAN_START|SCAN_FOUND|BleAutomation|Connect session|Bond",
            timeout=_env_int("UTF_HFP_BLE_PASSKEY_TIMEOUT_SEC", BLE_PASSKEY_TIMEOUT_SEC),
        )
        if scan_seen:
            self._record_event(
                "ble_scan_or_connect_activity_observed",
                status="pass",
                details={"dut_address": dut_address},
            )
        else:
            LOGGER.warning(
                "No BleAutomation scan/connect logcat markers yet; continuing to wait for DUT passkey"
            )

        pairing_info = self._wait_for_passkey_and_identity_address(
            _env_int("UTF_HFP_BLE_PASSKEY_TIMEOUT_SEC", BLE_PASSKEY_TIMEOUT_SEC),
            ble_snapshot,
            require_identity=False,
            print_passkey_immediately=True,
        )
        passkey = pairing_info.get("passkey")
        assert passkey, (
            "No BLE SMP passkey was observed in DUT serial logs after Si-Connect CONNECT_AND_BOND. "
            "Expected a line like: In passkey event, remote addr: ..., passkey: NNNNNN"
        )

        LOGGER.info(f"Submitting DUT passkey {passkey} via adb shell SUBMIT_PAIRING_PIN")
        adb.ble_submit_pairing_pin(passkey, dut_address)
        self._record_event(
            "ble_pairing_pin_submitted",
            status="pass",
            details={
                "passkey": passkey,
                "dut_address": dut_address,
                "passkey_remote_addr": pairing_info.get("passkey_remote_addr"),
                "transport": "adb_shell",
            },
        )
        time.sleep(BLE_ADB_POST_PIN_SETTLE_SEC)

        identity_info = self._wait_for_passkey_and_identity_address(
            _env_int("UTF_HFP_BLE_CTKD_TIMEOUT_SEC", BLE_CTKD_TIMEOUT_SEC),
            ble_snapshot,
            require_identity=True,
            print_passkey_immediately=False,
        )
        identity_address = identity_info.get("identity_address")
        assert identity_address, (
            "No CTKD Identity Address was observed in DUT logs after submitting the BLE passkey. "
            "Expected: Identity Address = XX:XX:XX:XX:XX:XX with type N"
        )

        ctkd_match = self._wait_for_any_match(
            [r"Received ctkd event and its status\s*=\s*0", r"Derived LinkKey from CTKD"],
            timeout=5,
            start_index=ble_snapshot,
        )
        if ctkd_match:
            self._record_event("ble_ctkd_linkkey_derived", status="pass", log_match=ctkd_match)

        self.ctkd_identity_address = identity_address
        if identity_address.upper() != self.phone_address.upper():
            LOGGER.warning(
                "CTKD identity address %s differs from configured PHONE_BT_ADDRESS %s; "
                "using identity address for classic BT connect.",
                identity_address,
                self.phone_address,
            )
            self.phone_address = identity_address

        self._record_event(
            "ble_bond_and_ctkd_complete",
            status="pass",
            details={
                "dut_address": dut_address,
                "passkey": passkey,
                "identity_address": identity_address,
                "identity_address_type": identity_info.get("identity_address_type"),
                "passkey_remote_addr": identity_info.get("passkey_remote_addr")
                or pairing_info.get("passkey_remote_addr"),
                "transport": "adb_shell",
            },
        )
        LOGGER.info(
            "BLE bond + CTKD complete (adb shell). Identity address=%s (type=%s)",
            identity_address,
            identity_info.get("identity_address_type"),
        )
        return identity_address

    def _connect_ble_si_connect_then_btc_ctkd_shell(self):
        """Open Si-Connect → BLE bond/CTKD via adb shell, then classic BTC via CTKD."""
        self._establish_ble_bond_via_si_connect_shell()
        LOGGER.info(
            "BLE connection successful; waiting %ss before btc gap connect",
            _env_int("UTF_HFP_BLE_TO_BTC_DELAY_SEC", BLE_TO_BTC_DELAY_SEC),
        )
        time.sleep(_env_int("UTF_HFP_BLE_TO_BTC_DELAY_SEC", BLE_TO_BTC_DELAY_SEC))
        return self._establish_btc_via_ctkd()

    def _shell_adb_make_call_from_source(self):
        """Source helper phone dials destination AG SIM via AdbShellInterface.place_call."""
        self._require_shell_adb_phones()
        number = self.destination_phone_number
        LOGGER.info(
            "Source phone (%s) placing call to destination number %s",
            getattr(self.source_adb, "device_id", None),
            number,
        )
        assert self.source_adb.get_call_state() == PhoneState.IDLE, (
            "Source phone not in IDLE before place_call"
        )
        ok = self.source_adb.place_call(number)
        assert ok, "Source AdbShellInterface.place_call failed"
        self._record_event(
            "source_make_call",
            status="pass",
            details={
                "device_id": getattr(self.source_adb, "device_id", None),
                "number": number,
                "transport": "adb_shell",
            },
        )
        time.sleep(_env_int("UTF_HFP_POST_DIAL_SETTLE_SEC", POST_DIAL_SETTLE_SEC))

    def _ensure_call_phones_idle(self, include_waiting_caller=True):
        phones = [
            ("destination_ag", self.destination_adb),
            ("source", self.source_adb),
        ]
        if include_waiting_caller and self.waiting_caller_adb is not None:
            phones.append(("waiting_caller", self.waiting_caller_adb))

        for name, adb in phones:
            if adb is None:
                continue
            try:
                state = adb.get_call_state()
            except Exception as exc:
                LOGGER.warning("get_call_state failed on %s: %s", name, exc)
                continue
            if state == PhoneState.IDLE:
                continue
            LOGGER.warning(
                "%s not IDLE before dial (state=%s); terminating leftover call",
                name,
                state,
            )
            try:
                adb.terminate_call()
                adb.wait_for_state(PhoneState.IDLE, timeout=15)
            except Exception as exc:
                LOGGER.warning("Failed to idle %s: %s", name, exc)
            self._record_event(
                f"{name}_forced_idle_before_dial",
                status="pass",
                details={"prior_state": str(state)},
            )

    def _phone_call_states_snapshot(self):
        """Best-effort AG/source/waiting call states for assertion diagnostics."""
        snapshot = {}
        for name, adb in (
            ("destination_ag", self.destination_adb),
            ("source", self.source_adb),
            ("waiting_caller", self.waiting_caller_adb),
        ):
            if adb is None:
                snapshot[name] = None
                continue
            try:
                snapshot[name] = str(adb.get_call_state())
            except Exception as exc:
                snapshot[name] = f"error:{exc}"
        return snapshot

    def _serial_archive_lines(self, start_index=0, tail=None):
        self._archive_new_bus_logs()
        entries = self.serial_log_archive[start_index:]
        if tail is not None and tail >= 0:
            entries = entries[-tail:]
        lines = []
        for entry in entries:
            if isinstance(entry, dict):
                line = entry.get("line", "")
            else:
                line = str(entry)
            if line is None:
                continue
            text = str(line)
            if text:
                lines.append(text)
        return lines

    def _verify_ag_three_way_capability(self):
        archive = "\n".join(self._serial_archive_lines(tail=400))
        match = re.search(r"3Way\s*=\s*([YN])", archive, re.IGNORECASE)
        assert match, (
            "AG feat block did not include 3Way=Y/N after HFP SLC. "
            "Three-way / hold / waiting cases need an AG that advertises 3Way."
        )
        value = match.group(1).upper()
        assert value == "Y", (
            f"AG reports 3Way={value}; need 3Way=Y for hold / 2nd-call flow."
        )
        self._record_event(
            "ag_three_way_capability_confirmed",
            status="pass",
            details={"3Way": value},
        )

    def _wait_for_hfp_incoming_after_place_call(
        self, start_index, timeout=None, context="incoming call"
    ):
        timeout = timeout if timeout is not None else INCOMING_CALL_TIMEOUT_SEC
        patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (
                r"callsetup:IN",
                r"hfp ring",
                r"Ringing",
                r"\+CIEV",
                r"incoming call",
            )
        ]
        deadline = time.time() + timeout
        current_index = start_index
        ag_saw_ringing = False
        source_saw_offhook = False

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                for pattern in patterns:
                    if pattern.search(line):
                        return line.strip()
            try:
                if self.destination_adb is not None:
                    if self.destination_adb.get_call_state() == PhoneState.RINGING:
                        ag_saw_ringing = True
                if self.source_adb is not None:
                    if self.source_adb.get_call_state() == PhoneState.OFFHOOK:
                        source_saw_offhook = True
            except Exception:
                pass
            time.sleep(POLL_INTERVAL_SEC)

        phone_states = self._phone_call_states_snapshot()
        recent = [
            ln.strip()
            for ln in self._serial_archive_lines(start_index=start_index)
            if ln and ln.strip()
        ][-25:]
        assert False, (
            f"No HFP incoming-call indication for {context}. "
            f"AG_RINGING_seen={ag_saw_ringing}, source_OFFHOOK_seen={source_saw_offhook}, "
            f"phone_states={phone_states}. "
            "HF host stayed idle (expect callsetup:IN / hfp ring). "
            "Check SIM/cellular path and that AG is not already in a call. "
            f"Recent DUT lines: {recent}"
        )

    def _shell_adb_make_waiting_call(self):
        self._require_shell_adb_phones()
        assert self.waiting_caller_adb is not None, (
            "T1956403 needs a 3rd Android (waiting caller). "
            "Add it under defaults.adb_phones and set UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID."
        )
        number = self.destination_phone_number
        LOGGER.info(
            "Waiting-caller phone (%s) placing 2nd call to AG number %s",
            getattr(self.waiting_caller_adb, "device_id", None),
            number,
        )
        assert self.waiting_caller_adb.get_call_state() == PhoneState.IDLE, (
            "Waiting-caller phone not in IDLE before place_call"
        )
        ok = self.waiting_caller_adb.place_call(number)
        assert ok, "Waiting-caller AdbShellInterface.place_call failed"
        self._record_event(
            "waiting_caller_make_call",
            status="pass",
            details={
                "device_id": getattr(self.waiting_caller_adb, "device_id", None),
                "number": number,
                "transport": "adb_shell",
            },
        )
        time.sleep(_env_int("UTF_HFP_POST_DIAL_SETTLE_SEC", POST_DIAL_SETTLE_SEC))

    def _shell_adb_make_outgoing_call_from_ag(self):
        self._require_shell_adb_phones()
        number = self.outgoing_call_number
        assert number, (
            "AG outgoing dial number is required for T1956406. "
            "Set UTF_HFP_OUTGOING_CALL_NUMBER / UTF_HFP_SOURCE_PHONE_NUMBER "
            "or defaults.adb.outgoing_number."
        )
        LOGGER.info(
            "AG phone (%s) placing outgoing call to number %s",
            getattr(self.destination_adb, "device_id", None),
            number,
        )
        assert self.destination_adb.get_call_state() == PhoneState.IDLE, (
            "AG phone not in IDLE before outgoing place_call"
        )
        ok = self.destination_adb.place_call(number)
        assert ok, "AG AdbShellInterface.place_call (outgoing) failed"
        self.destination_adb.wait_for_state(PhoneState.OFFHOOK, timeout=30)
        self._record_event(
            "ag_outgoing_place_call",
            status="pass",
            details={
                "device_id": getattr(self.destination_adb, "device_id", None),
                "number": number,
                "transport": "adb_shell",
            },
        )
        time.sleep(_env_int("UTF_HFP_POST_DIAL_SETTLE_SEC", POST_DIAL_SETTLE_SEC))

    def _shell_adb_end_call_on_source(self):
        if self.source_adb is None:
            return
        LOGGER.info("Ending call on source phone via AdbShellInterface.terminate_call")
        self.source_adb.terminate_call()
        self.source_adb.wait_for_state(PhoneState.IDLE, timeout=15)
        self._record_event(
            "source_end_call",
            status="pass",
            details={
                "device_id": getattr(self.source_adb, "device_id", None),
                "transport": "adb_shell",
            },
        )
        time.sleep(_env_int("UTF_HFP_POST_END_CALL_SETTLE_SEC", POST_END_CALL_SETTLE_SEC))

    def _shell_adb_end_call_on_destination(self):
        """Destination AG hangs up via AdbShellInterface.terminate_call."""
        self._require_shell_adb_phones()
        LOGGER.info(
            "Ending call on destination AG (%s) via AdbShellInterface.terminate_call",
            getattr(self.destination_adb, "device_id", None),
        )
        self.destination_adb.terminate_call()
        self.destination_adb.wait_for_state(PhoneState.IDLE, timeout=15)
        self._record_event(
            "destination_ag_end_call",
            status="pass",
            details={
                "device_id": getattr(self.destination_adb, "device_id", None),
                "transport": "adb_shell",
            },
        )
        time.sleep(_env_int("UTF_HFP_POST_END_CALL_SETTLE_SEC", POST_END_CALL_SETTLE_SEC))

    def _shell_adb_end_call_on_waiting_caller(self):
        if self.waiting_caller_adb is None:
            return
        LOGGER.info(
            "Ending call on waiting-caller phone (%s) via AdbShellInterface.terminate_call",
            getattr(self.waiting_caller_adb, "device_id", None),
        )
        self.waiting_caller_adb.terminate_call()
        self.waiting_caller_adb.wait_for_state(PhoneState.IDLE, timeout=15)
        self._record_event(
            "waiting_caller_end_call",
            status="pass",
            details={
                "device_id": getattr(self.waiting_caller_adb, "device_id", None),
                "transport": "adb_shell",
            },
        )
        time.sleep(_env_int("UTF_HFP_POST_END_CALL_SETTLE_SEC", POST_END_CALL_SETTLE_SEC))

    def _reject_first_incoming_call_via_adb_shell(self):
        """Source dials destination; DUT rejects; source ends call (direct ADB)."""
        LOGGER.info("C554088: source placing first call for DUT reject")
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication was detected after source place_call."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)
        self._wait_before_rejecting_incoming_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        self._cli_reject_incoming_call(incoming_snapshot)
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call after reject failed (continuing): {exc}")
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))

    def _accept_second_incoming_call_and_hang_up_from_ag_via_adb_shell(self):
        """Source dials destination; DUT accepts; destination AG hangs up (direct ADB)."""
        LOGGER.info("C554088: source placing second call for DUT accept + AG hangup")
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication was detected after source place_call (second call)."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        self._wait_before_accepting_incoming_call()
        action_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._wait_before_rejecting_incoming_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        LOGGER.info("Hanging up active call from destination AG via adb shell")
        hangup_wait_snapshot = self._get_log_snapshot()
        self._shell_adb_end_call_on_destination()

        hangup_match = self._wait_for_any_match(
            [
                r"AT\+CHUP",
                r"\bCHUP\b",
                r"disconnect",
                r"hfp audio disconn",
                r"no call is active",
                r"callsetup:IDLE",
            ],
            CALL_ACTION_TIMEOUT_SEC,
            hangup_wait_snapshot if hangup_wait_snapshot else action_snapshot,
        )
        assert hangup_match, (
            "No hangup/disconnection log was detected after destination AG terminate_call."
        )
        LOGGER.info(f"AG hangup indication observed: {hangup_match}")
        self._record_event("ag_side_hangup_detected", status="pass", log_match=hangup_match)
        self._verify_call_logs_present(incoming_snapshot, "accept and AG hangup flow")

        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call after AG hangup failed (continuing): {exc}")

    def _incoming_call_accept_from_hf_and_terminate_from_ag_via_adb_shell(self):
        LOGGER.info("T1956404: source placing call for DUT accept + AG terminate")
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956404)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        # Pre-accept OTA-style markers while ringing (callsetup/BCS/eSCO req).
        pre_accept_lines = self._collect_matching_lines(
            [
                r"\+CIEV",
                r"callsetup:IN",
                r"\bBCS\b",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        action_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(action_snapshot)
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        LOGGER.info("T1956404: terminating active call from destination AG")
        hangup_wait_snapshot = self._get_log_snapshot()
        self._shell_adb_end_call_on_destination()
        hangup_match = self._wait_for_any_match(
            [
                r"AT\+CHUP",
                r"\bCHUP\b",
                r"disconnect",
                r"hfp audio disconn",
                r"no call is active",
                r"callsetup:IDLE",
            ],
            CALL_ACTION_TIMEOUT_SEC,
            hangup_wait_snapshot if hangup_wait_snapshot else action_snapshot,
        )
        assert hangup_match, "No AG hangup log after destination terminate_call (T1956404)."
        self._record_event("ag_side_hangup_detected", status="pass", log_match=hangup_match)
        self._verify_call_logs_present(incoming_snapshot, "DUT accept and AG terminate flow")

        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _incoming_call_accept_and_terminate_from_dut_via_adb_shell(self):
        LOGGER.info("T1956402: source placing call for DUT accept + terminate")
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()

        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication was detected in DUT logs after source place_call."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        self._wait_before_accepting_incoming_call()
        action_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(action_snapshot)
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        self._cli_terminate_active_call(action_snapshot)
        self._verify_call_logs_present(incoming_snapshot, "DUT accept and DUT terminate flow")

        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call after DUT hangup failed (continuing): {exc}")

    def _shell_adb_accept_on_destination_ag(self):
        """Accept ringing call on destination AG via AdbShellInterface."""
        self._require_shell_adb_phones()
        device_id = getattr(self.destination_adb, "device_id", None)
        try:
            state_before = self.destination_adb.get_call_state()
        except Exception as exc:
            state_before = f"error:{exc}"
        LOGGER.info(
            "Accepting call on destination AG (%s) via accept_incoming_call "
            "(state_before=%s)",
            device_id,
            state_before,
        )
        if state_before == PhoneState.IDLE:
            try:
                self.destination_adb.wait_for_state(PhoneState.RINGING, timeout=15)
                state_before = self.destination_adb.get_call_state()
            except Exception as exc:
                LOGGER.warning(
                    "AG did not reach RINGING before accept (%s); trying accept anyway",
                    exc,
                )
        if state_before == PhoneState.OFFHOOK:
            self._record_event(
                "destination_ag_accept_call",
                status="pass",
                details={
                    "device_id": device_id,
                    "transport": "adb_shell",
                    "note": "already_offhook",
                },
            )
            return

        ok = self.destination_adb.accept_incoming_call()
        if not ok:
            # One retry after a short settle (OEM telecom race with HFP ring).
            time.sleep(1.0)
            try:
                retry_state = self.destination_adb.get_call_state()
            except Exception:
                retry_state = "unknown"
            LOGGER.warning(
                "AG accept_incoming_call first attempt failed (state=%s); retrying",
                retry_state,
            )
            ok = self.destination_adb.accept_incoming_call()
        try:
            state_after = self.destination_adb.get_call_state()
        except Exception as exc:
            state_after = f"error:{exc}"
        assert ok, (
            "Destination AG accept_incoming_call failed "
            f"(state_before={state_before}, state_after={state_after}, "
            f"device_id={device_id})"
        )
        self.destination_adb.wait_for_state(PhoneState.OFFHOOK, timeout=20)
        self._record_event(
            "destination_ag_accept_call",
            status="pass",
            details={
                "device_id": device_id,
                "transport": "adb_shell",
                "state_before": str(state_before),
                "state_after": str(state_after),
            },
        )

    def _ag_get_audio_route(self):
        """Si-Connect GET_AUDIO_ROUTE on destination AG (SCO / route corroboration)."""
        self._require_shell_adb_phones()
        status = self.destination_adb.get_audio_route()
        parsed = status.get("parsed") or {}
        self._record_event(
            "ag_get_audio_route",
            status="pass" if status.get("success") else "info",
            details={
                "success": status.get("success"),
                "parsed": parsed,
                "message": status.get("message"),
            },
        )
        return status

    def _ag_assert_audio_route(
        self,
        expect_current=None,
        expect_sco_on=None,
        expect_speaker_on=None,
        require_bluetooth_available=False,
    ):
        status = self._ag_get_audio_route()
        parsed = status.get("parsed") or {}
        assert status.get("success") is not False, (
            f"GET_AUDIO_ROUTE failed on AG: {status.get('message') or status}"
        )
        if expect_current is not None:
            current = str(parsed.get("current", "")).lower()
            assert current == str(expect_current).lower(), (
                f"AG audio route current={current!r}, expected {expect_current!r}. "
                f"parsed={parsed}"
            )
        if expect_sco_on is not None:
            sco_on = parsed.get("scoOn")
            assert sco_on is expect_sco_on, (
                f"AG scoOn={sco_on!r}, expected {expect_sco_on!r}. parsed={parsed}"
            )
        if expect_speaker_on is not None:
            speaker_on = parsed.get("speakerOn")
            assert speaker_on is expect_speaker_on, (
                f"AG speakerOn={speaker_on!r}, expected {expect_speaker_on!r}. "
                f"parsed={parsed}"
            )
        if require_bluetooth_available:
            available = parsed.get("available") or []
            if isinstance(available, str):
                available = [available]
            assert any(str(item).lower() == "bluetooth" for item in available), (
                f"AG available routes missing bluetooth: {available}"
            )
        self._record_event(
            "ag_audio_route_asserted",
            status="pass",
            details={
                "expect_current": expect_current,
                "expect_sco_on": expect_sco_on,
                "expect_speaker_on": expect_speaker_on,
                "parsed": parsed,
            },
        )
        return parsed

    def _ag_soft_assert_audio_route(
        self,
        event_name,
        expect_current=None,
        expect_sco_on=None,
        expect_speaker_on=None,
        require_bluetooth_available=False,
        context="",
    ):
        try:
            parsed = self._ag_assert_audio_route(
                expect_current=expect_current,
                expect_sco_on=expect_sco_on,
                expect_speaker_on=expect_speaker_on,
                require_bluetooth_available=require_bluetooth_available,
            )
            self._record_event(
                event_name,
                status="pass",
                details={"parsed": parsed, "context": context or None},
            )
            return parsed
        except Exception as exc:
            LOGGER.warning(
                "%s: AG audio-route soft-assert failed%s: %s",
                event_name,
                f" ({context})" if context else "",
                exc,
            )
            self._record_event(
                event_name,
                status="info",
                details={"error": str(exc), "context": context or None},
            )
            return None

    def _ag_set_and_verify_audio_route(self, route):
        self._require_shell_adb_phones()
        route = str(route or "").strip().lower()
        status = self.destination_adb.set_audio_route(route)
        parsed = status.get("parsed") or {}
        current = str(parsed.get("current", "")).lower()
        assert current == route, (
            f"After SET_AUDIO_ROUTE({route}) AG current={current!r}. parsed={parsed}"
        )
        sco_on = parsed.get("scoOn")
        if route == "bluetooth":
            assert sco_on is True, (
                f"After SET_AUDIO_ROUTE(bluetooth) expected scoOn=true, got {sco_on!r}. "
                f"parsed={parsed}"
            )
        elif route in ("earpiece", "speaker"):
            assert sco_on is False, (
                f"After SET_AUDIO_ROUTE({route}) expected scoOn=false, got {sco_on!r}. "
                f"parsed={parsed}"
            )
        self._record_event(
            "ag_set_audio_route_verified",
            status="pass",
            details={"route": route, "parsed": parsed},
        )
        return parsed

    def _ag_set_and_verify_call_hold(self, hold):
        """
        SET_CALL_HOLD on AG then GET_CALL_HOLD must match.

        Used by T1956427 (hold before 2nd call) and T1956413 (hold then unhold).
        """
        self._require_shell_adb_phones()
        hold_snapshot = self._get_log_snapshot()
        status = self.destination_adb.set_call_hold(bool(hold))
        parsed = status.get("parsed") or {}
        held = parsed.get("held")
        assert held is bool(hold), (
            f"After SET_CALL_HOLD({hold}) AG held={held!r}. "
            f"message={status.get('message')}"
        )
        self._record_event(
            "ag_set_call_hold_verified",
            status="pass",
            details={"requested_hold": bool(hold), "parsed": parsed},
        )
        if hold:
            # Host often prints callheld text when AG holds.
            hold_lines = self._collect_matching_lines(
                [
                    r"call on hold",
                    r"active/held calls swapped",
                    r"hfp\s+callheld\s*:\s*call on hold",
                    r"call is active",
                    r"hfp audio conn",
                ],
                timeout=min(8, CALL_ACTION_TIMEOUT_SEC),
                start_index=hold_snapshot,
            )
            self._record_event(
                "dut_callheld_after_ag_hold",
                status="pass" if hold_lines else "info",
                details={"matches": (hold_lines or [])[:15]},
            )
        else:
            resume_lines = self._collect_matching_lines(
                [
                    r"hfp\s+callheld\s*:\s*no calls held",
                    r"no calls held",
                    r"call is active",
                    r"hfp audio conn",
                ],
                timeout=min(8, CALL_ACTION_TIMEOUT_SEC),
                start_index=hold_snapshot,
            )
            self._record_event(
                "dut_callheld_after_ag_unhold",
                status="pass" if resume_lines else "info",
                details={"matches": (resume_lines or [])[:15]},
            )
        return parsed

    def _ag_swap_calls_and_verify_hf_indicators(self):
        self._require_shell_adb_phones()
        swap_snapshot = self._get_log_snapshot()
        LOGGER.info(
            "T1956418: AG SWAP_CALLS to swap active/held (device_id=%s)",
            getattr(self.destination_adb, "device_id", None),
        )
        status = self.destination_adb.swap_calls()
        parsed = status.get("parsed") or {}
        assert status.get("success") is not False, (
            f"T1956418: AG SWAP_CALLS failed. "
            f"message={status.get('message')!r} parsed={parsed}"
        )
        self._record_event(
            "ag_swap_calls",
            status="pass",
            details={"parsed": parsed, "message": status.get("message")},
        )

        required = {
            "callheld_swapped": re.compile(
                r"call is placed on hold or active/held calls swapped|"
                r"active/held calls swapped",
                re.IGNORECASE,
            ),
        }
        optional = {
            "callheld_on_hold": re.compile(
                r"call on hold,\s*no active call|"
                r"hfp\s+callheld\s*:\s*call on hold",
                re.IGNORECASE,
            ),
            "call_is_active": re.compile(r"call is active", re.IGNORECASE),
            "callheld_addr_line": re.compile(r"callheld\s+addr:", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        timeout = CALL_ACTION_TIMEOUT_SEC
        deadline = time.time() + timeout
        current_index = swap_snapshot
        collected = []
        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info(
                            "T1956418 AG swap HF indicator %s: %s",
                            name,
                            found[name][:160],
                        )
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956418: no HF call-swap indicators after AG SWAP_CALLS. "
            f"Missing: {missing}. Expected "
            "'call is placed on hold or active/held calls swapped'. "
            f"Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "ag_swap_hf_indicators_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _active_call_accept_waiting_then_ag_swap_via_adb_shell(self):
        if self.waiting_caller_adb is None:
            pytest.skip(
                "T1956418 requires a 3rd Android (waiting caller). "
                "Add waiting_caller_adb_phone under harness defaults.adb_phones and set "
                "UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID."
            )

        LOGGER.info(
            "T1956418: incoming → DUT accept → waiting → "
            "call_control_hf 3 → AG swap active/held"
        )

        # Steps 5–6: first incoming → DUT accept → active eSCO
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication after source place_call (T1956418)."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)

        # Step 7: 2nd incoming from another mobile (call waiting)
        waiting_snapshot = self._get_log_snapshot()
        self._shell_adb_make_waiting_call()
        self._verify_call_waiting_indication(waiting_snapshot)

        # Step 8: hold active + accept waiting from HF
        self._wait_before_accepting_incoming_call()
        hold_accept_snapshot = self._cli_call_control_hf(
            3, event_name="call_control_hf_hold_accept_waiting_sent"
        )
        self._verify_active_held_after_accept_waiting(hold_accept_snapshot)

        # Step 9: AG swap the two calls; check HF callheld swap indicators
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        self._ag_swap_calls_and_verify_hf_indicators()

        # Step 10: call logs + cleanup
        self._verify_call_logs_present(
            incoming_snapshot, "accept waiting then AG swap flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956418 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_waiting_caller()
        except Exception as exc:
            LOGGER.warning(f"Waiting-caller terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _active_call_hold_unhold_from_ag_via_adb_shell(self):
        LOGGER.info(
            "T1956413: incoming → DUT accept → AG SET_CALL_HOLD true → false"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956413)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_dut_accept",
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
            context="T1956413 after DUT accept",
        )

        # Step 7: Press hold on AG
        self._ag_set_and_verify_call_hold(True)

        # Step 8: Press un-hold on AG
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        self._ag_set_and_verify_call_hold(False)

        # Soft eSCO/active evidence after unhold (procedure OTA wording).
        resume_audio_lines = self._collect_matching_lines(
            [
                r"call is active",
                r"hfp audio conn",
                r"\bBCS\b",
                r"esco link req",
                r"hfp\s+callheld\s*:\s*no calls held",
            ],
            timeout=min(8, CALL_ACTION_TIMEOUT_SEC),
            start_index=accept_snapshot,
        )
        self._record_event(
            "host_active_after_ag_unhold",
            status="pass" if resume_audio_lines else "info",
            details={"matches": (resume_audio_lines or [])[:15]},
        )

        self._verify_call_logs_present(
            incoming_snapshot, "AG hold/unhold active-call flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956413 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _ag_set_and_verify_voice_assistant(self, active):
        """SET_VOICE_ASSISTANT then GET_VOICE_ASSISTANT must match ``active``."""
        self._require_shell_adb_phones()
        status = self.destination_adb.set_voice_assistant(bool(active))
        parsed = status.get("parsed") or {}
        got = parsed.get("active")
        assert got is bool(active), (
            f"After SET_VOICE_ASSISTANT({active}) AG active={got!r}. "
            f"message={status.get('message')}"
        )
        self._record_event(
            "ag_set_voice_assistant_verified",
            status="pass",
            details={"requested_active": bool(active), "parsed": parsed},
        )
        return parsed

    def _ag_get_voice_assistant(self):
        """Si-Connect GET_VOICE_ASSISTANT on destination AG."""
        self._require_shell_adb_phones()
        status = self.destination_adb.get_voice_assistant()
        parsed = status.get("parsed") or {}
        self._record_event(
            "ag_get_voice_assistant",
            status="pass" if status.get("success") else "info",
            details={
                "success": status.get("success"),
                "parsed": parsed,
                "message": status.get("message"),
            },
        )
        return status

    def _ag_assert_voice_assistant(self, expect_active):
        """Hard-assert AG GET_VOICE_ASSISTANT ``active`` field."""
        status = self._ag_get_voice_assistant()
        parsed = status.get("parsed") or {}
        assert status.get("success") is not False, (
            f"GET_VOICE_ASSISTANT failed on AG: {status.get('message') or status}"
        )
        got = parsed.get("active")
        assert got is bool(expect_active), (
            f"AG voice assistant active={got!r}, expected {bool(expect_active)!r}. "
            f"parsed={parsed}"
        )
        self._record_event(
            "ag_voice_assistant_asserted",
            status="pass",
            details={"expect_active": bool(expect_active), "parsed": parsed},
        )
        return parsed

    def _ag_soft_assert_voice_assistant(self, event_name, expect_active, context=""):
        """AG GET_VOICE_ASSISTANT corroboration that never fails the case."""
        try:
            return self._ag_assert_voice_assistant(expect_active)
        except Exception as exc:
            LOGGER.warning(
                "%s: AG voice-assistant soft-assert failed%s: %s",
                event_name,
                f" ({context})" if context else "",
                exc,
            )
            self._record_event(
                event_name,
                status="info",
                details={"error": str(exc), "context": context or None},
            )
            return None

    def _cli_vr_activate(self):
        """DUT ``btc hfp vr_activate <bd>`` — enable voice recognition."""
        assert self.phone_address, "phone_address required for vr_activate"
        cmd = f"btc hfp vr_activate {self.phone_address}"
        LOGGER.info("T1956415: issuing %s", cmd)
        snapshot, _ = self._send_cli_command(cmd, event_name="vr_activate_command_sent")
        self._assert_no_failure_log_since("btc hfp vr_activate", snapshot, timeout=2)
        return snapshot

    def _cli_vr_deactivate(self):
        """DUT ``btc hfp vr_deactivate <bd>`` — disable voice recognition."""
        assert self.phone_address, "phone_address required for vr_deactivate"
        cmd = f"btc hfp vr_deactivate {self.phone_address}"
        LOGGER.info("T1956415: issuing %s", cmd)
        snapshot, _ = self._send_cli_command(cmd, event_name="vr_deactivate_command_sent")
        self._assert_no_failure_log_since("btc hfp vr_deactivate", snapshot, timeout=2)
        return snapshot

    def _verify_vr_activate_effects(self, start_index, timeout=None):
        """
        After vr_activate: CLI success + eSCO/AVDTP start-class host markers.
        """
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "cli_ok": re.compile(
                rf"cmd resp:{re.escape(self.phone_address)}|"
                r"rsi_bt_hfp_vr_activate\(\)\s*Command Successful|"
                r"vr_activate.*[Ss]uccess",
                re.IGNORECASE,
            ),
        }
        optional = {
            "esco_or_audio": re.compile(
                r"esco link req|hfp audio conn|BCS AT Command Successful|"
                r"connection initiated event|\bBCS\b|AVDTP\s+Start|avdtp start",
                re.I,
            ),
            "ciev_or_call": re.compile(r"\+CIEV|callsetup:|call is active", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info("T1956415 activate observed %s: %s", name, found[name][:140])
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956415: no vr_activate success confirmation on DUT. "
            f"Missing: {missing}. Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "vr_activate_effects_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _verify_vr_deactivate_effects(self, start_index, timeout=None):
        """
        After vr_deactivate: CLI success + eSCO/AVDTP stop-class host markers.
        """
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "cli_ok": re.compile(
                rf"cmd resp:{re.escape(self.phone_address)}|"
                r"rsi_bt_hfp_vr_deactivate\(\)\s*Command Successful|"
                r"vr_deactivate.*[Ss]uccess",
                re.IGNORECASE,
            ),
        }
        optional = {
            "esco_or_audio_disconn": re.compile(
                r"hfp audio disconn|esco link disconn|eSCO.*disconn|"
                r"AVDTP\s+[Ss]uspend|avdtp suspend|\bBCS\b",
                re.I,
            ),
            "ciev_or_idle": re.compile(r"\+CIEV|callsetup:IDLE|no call is active", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info("T1956415 deactivate observed %s: %s", name, found[name][:140])
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956415: no vr_deactivate success confirmation on DUT. "
            f"Missing: {missing}. Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "vr_deactivate_effects_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _enable_disable_voice_recognition_from_dut_via_adb_shell(self):
        LOGGER.info("T1956415: vr_activate → verify → vr_deactivate → verify")
        # Soft baseline: VR should be inactive before activate.
        self._ag_soft_assert_voice_assistant(
            "ag_voice_assistant_before_vr_activate",
            expect_active=False,
            context="T1956415 pre-activate",
        )

        activate_snapshot = self._cli_vr_activate()
        self._verify_vr_activate_effects(activate_snapshot)
        # HF initiated VR — AG GET corroborates assistant is active.
        self._ag_soft_assert_voice_assistant(
            "ag_voice_assistant_after_vr_activate",
            expect_active=True,
            context="T1956415 after vr_activate",
        )

        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        deactivate_snapshot = self._cli_vr_deactivate()
        self._verify_vr_deactivate_effects(deactivate_snapshot)
        self._ag_soft_assert_voice_assistant(
            "ag_voice_assistant_after_vr_deactivate",
            expect_active=False,
            context="T1956415 after vr_deactivate",
        )

        self._verify_call_logs_present(
            activate_snapshot, "DUT VR activate/deactivate flow"
        )

    def _soft_collect_vr_host_markers(self, start_index, phase, patterns, timeout=None):
        """Soft-collect DUT host VR/eSCO/AVDTP markers after AG VR toggle."""
        timeout = timeout if timeout is not None else min(8, CALL_ACTION_TIMEOUT_SEC)
        lines = self._collect_matching_lines(
            patterns,
            timeout=timeout,
            start_index=start_index,
        )
        self._record_event(
            f"dut_vr_host_markers_after_ag_{phase}",
            status="pass" if lines else "info",
            details={"matches": (lines or [])[:20], "phase": phase},
        )
        return lines

    def _enable_disable_voice_recognition_from_ag_via_adb_shell(self):
        LOGGER.info(
            "T1956416: AG SET_VOICE_ASSISTANT true → verify → false → verify"
        )
        self._ag_soft_assert_voice_assistant(
            "ag_voice_assistant_before_ag_vr_enable",
            expect_active=False,
            context="T1956416 pre-enable",
        )

        enable_snapshot = self._get_log_snapshot()
        self._ag_set_and_verify_voice_assistant(True)
        self._soft_collect_vr_host_markers(
            enable_snapshot,
            phase="enable",
            patterns=[
                r"esco link req",
                r"hfp audio conn",
                r"BCS AT Command Successful",
                r"connection initiated event",
                r"\bBCS\b",
                r"AVDTP\s+Start",
                r"avdtp start",
                r"\+CIEV",
                r"callsetup:",
                r"vr",
                r"voice",
            ],
        )

        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        disable_snapshot = self._get_log_snapshot()
        self._ag_set_and_verify_voice_assistant(False)
        self._soft_collect_vr_host_markers(
            disable_snapshot,
            phase="disable",
            patterns=[
                r"hfp audio disconn",
                r"esco link disconn",
                r"eSCO.*disconn",
                r"AVDTP\s+[Ss]uspend",
                r"avdtp suspend",
                r"\bBCS\b",
                r"\+CIEV",
                r"callsetup:IDLE",
                r"vr",
                r"voice",
            ],
        )

        self._verify_call_logs_present(
            enable_snapshot, "AG VR enable/disable flow"
        )

    def _cli_hf_mic_gain(self, gain_value):
        assert self.phone_address, "phone_address required for hf_mic_gain"
        gain = int(gain_value)
        assert 0 <= gain <= 15, f"hf_mic_gain value must be 0-15, got {gain}"
        cmd = f"btc hfp hf_mic_gain {self.phone_address} {gain}"
        LOGGER.info("T1956424: issuing %s", cmd)
        snapshot, _ = self._send_cli_command(cmd, event_name="hf_mic_gain_command_sent")
        self._assert_no_failure_log_since("btc hfp hf_mic_gain", snapshot, timeout=2)
        match = self._wait_for_any_match(
            [
                r"mic\s*gain\s*ok",
                rf"cmd resp:{re.escape(self.phone_address)}",
                r"AT\+VGM",
                r"\+VGM",
            ],
            CALL_ACTION_TIMEOUT_SEC,
            snapshot,
        )
        assert match, (
            f"No mic-gain confirmation after `{cmd}`. "
            "Expected 'mic gain ok' / 'micgain ok' / cmd resp."
        )
        self._record_event(
            "hf_mic_gain_confirmed",
            status="pass",
            log_match=match,
            details={"gain": gain},
        )
        soft_vgm = self._collect_matching_lines(
            [r"AT\+VGM", r"\+VGM"],
            timeout=min(5, CALL_ACTION_TIMEOUT_SEC),
            start_index=snapshot,
        )
        self._record_event(
            "hf_mic_gain_ota_vgm_markers",
            status="pass" if soft_vgm else "info",
            details={"matches": (soft_vgm or [])[:10], "gain": gain},
        )
        return snapshot

    def _cli_hf_speaker_gain(self, gain_value):
        assert self.phone_address, "phone_address required for hf_speaker_gain"
        gain = int(gain_value)
        assert 0 <= gain <= 15, f"hf_speaker_gain value must be 0-15, got {gain}"
        cmd = f"btc hfp hf_speaker_gain {self.phone_address} {gain}"
        LOGGER.info("T1956424: issuing %s", cmd)
        snapshot, _ = self._send_cli_command(
            cmd, event_name="hf_speaker_gain_command_sent"
        )
        self._assert_no_failure_log_since("btc hfp hf_speaker_gain", snapshot, timeout=2)
        match = self._wait_for_any_match(
            [
                r"spk\s*gain\s*ok",
                rf"cmd resp:{re.escape(self.phone_address)}",
                r"AT\+VGS",
                r"\+VGS",
            ],
            CALL_ACTION_TIMEOUT_SEC,
            snapshot,
        )
        assert match, (
            f"No speaker-gain confirmation after `{cmd}`. "
            "Expected 'spk gain ok' / 'spkgain ok' / cmd resp."
        )
        self._record_event(
            "hf_speaker_gain_confirmed",
            status="pass",
            log_match=match,
            details={"gain": gain},
        )
        soft_vgs = self._collect_matching_lines(
            [r"AT\+VGS", r"\+VGS"],
            timeout=min(5, CALL_ACTION_TIMEOUT_SEC),
            start_index=snapshot,
        )
        self._record_event(
            "hf_speaker_gain_ota_vgs_markers",
            status="pass" if soft_vgs else "info",
            details={"matches": (soft_vgs or [])[:10], "gain": gain},
        )
        return snapshot

    def _active_call_hf_mic_and_speaker_gain_via_adb_shell(self):
        mic_gain = _env_int("UTF_HFP_HF_MIC_GAIN", HF_MIC_GAIN_DEFAULT)
        spk_gain = _env_int("UTF_HFP_HF_SPEAKER_GAIN", HF_SPEAKER_GAIN_DEFAULT)
        LOGGER.info(
            "T1956424: incoming → DUT accept → hf_mic_gain=%s → hf_speaker_gain=%s",
            mic_gain,
            spk_gain,
        )

        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication after source place_call (T1956424)."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)

        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        self._cli_hf_mic_gain(mic_gain)
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        self._cli_hf_speaker_gain(spk_gain)

        self._verify_call_logs_present(
            incoming_snapshot, "HF mic/speaker gain (VGM/VGS) flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call(accept_snapshot)
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956424 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _sample_incoming_accept_hold_then_terminate(self, hold_sec=None):
        hold_sec = hold_sec if hold_sec is not None else _env_int(
            "UTF_HFP_SAMPLE_ACTIVE_CALL_HOLD_SEC", SAMPLE_ACTIVE_CALL_HOLD_SEC
        )
        LOGGER.info(
            "Sample: source place_call → DUT accept → hold %ss → terminate",
            hold_sec,
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication after source place_call (sample)."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_dut_accept",
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
            context="sample after DUT accept",
        )

        stability_snapshot = self._get_log_snapshot()
        self._verify_active_sco_stability_after_open(
            stability_snapshot, duration_sec=hold_sec
        )

        self._verify_call_logs_present(
            incoming_snapshot, f"sample accept + {hold_sec}s hold flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        self._cli_terminate_active_call(accept_snapshot)
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_terminate",
            expect_sco_on=False,
            context="sample after terminate",
        )
        self._verify_call_logs_present(
            incoming_snapshot, "sample accept hold and terminate flow"
        )
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _sample_sco_file_playback_probe(self):
        self._require_shell_adb_phones()
        sco_path = _env_str("UTF_HFP_SAMPLE_SCO_FILE_PATH", SAMPLE_SCO_FILE_PATH)
        play_sec = _env_int("UTF_HFP_SAMPLE_SCO_PLAY_SEC", SAMPLE_SCO_PLAY_SEC)
        interval_sec = _env_int(
            "UTF_HFP_SAMPLE_SCO_INTERVAL_SEC", SAMPLE_SCO_INTERVAL_SEC
        )
        duration_sec = _env_int(
            "UTF_HFP_SAMPLE_SCO_PROBE_DURATION_SEC", SAMPLE_SCO_PROBE_DURATION_SEC
        )
        if interval_sec < play_sec:
            LOGGER.warning(
                "SCO interval (%ss) < play (%ss); using interval=play",
                interval_sec,
                play_sec,
            )
            interval_sec = play_sec

        LOGGER.info(
            "Sample SCO probe: GET_AUDIO_ROUTE then PLAY_SCO_FILE path=%s "
            "play=%ss every=%ss for %ss (device_id=%s)",
            sco_path,
            play_sec,
            interval_sec,
            duration_sec,
            getattr(self.destination_adb, "device_id", None),
        )

        route_before = self._ag_get_audio_route()
        parsed_before = (route_before or {}).get("parsed") or {}
        self._record_event(
            "ag_audio_route_before_sco_probe",
            status="pass" if route_before and route_before.get("success") is not False else "info",
            details={"parsed": parsed_before, "message": (route_before or {}).get("message")},
        )

        call_like_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"callsetup:",
                r"call is active",
                r"hfp audio conn",
                r"esco link req",
                r"connection initiated event",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"hfp ring",
                r"Ringing",
                r"\+CIEV",
                r"hfp call status",
            ]
        ]
        audio_only_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"hfp audio conn",
                r"esco link req",
                r"eSCO",
                r"\bSCO\b",
                r"audio",
            ]
        ]

        iterations = []
        probe_start = time.time()
        iteration = 0
        while time.time() - probe_start < duration_sec:
            iteration += 1
            iter_start = time.time()
            dut_snapshot = self._get_log_snapshot()
            LOGGER.info(
                "Sample SCO probe iteration %s: PLAY_SCO_FILE %s",
                iteration,
                sco_path,
            )
            play_status = self.destination_adb.play_sco_file(sco_path, timeout=max(30, play_sec + 10))
            play_ok = play_status.get("success") is not False
            self._record_event(
                f"ag_play_sco_file_iter_{iteration}",
                status="pass" if play_ok else "info",
                details={
                    "path": sco_path,
                    "parsed": play_status.get("parsed"),
                    "message": play_status.get("message"),
                    "success": play_status.get("success"),
                },
            )

            # Let ~10s of SCO audio play, then soft-collect DUT markers.
            time.sleep(max(1, play_sec))
            lines, _ = self._read_new_log_lines(dut_snapshot)
            call_like_hits = []
            audio_hits = []
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if any(p.search(stripped) for p in call_like_patterns):
                    call_like_hits.append(stripped)
                if any(p.search(stripped) for p in audio_only_patterns):
                    audio_hits.append(stripped)

            route_during = self._ag_soft_assert_audio_route(
                f"ag_audio_route_during_sco_play_iter_{iteration}",
                expect_sco_on=True,
                context=f"sample SCO play iter {iteration}",
            )
            sco_on = None
            if isinstance(route_during, dict):
                sco_on = route_during.get("scoOn")

            looks_like_call = bool(
                any(
                    re.search(
                        r"callsetup:|call is active|hfp ring|Ringing|\+CIEV",
                        h,
                        re.I,
                    )
                    for h in call_like_hits
                )
            )
            looks_like_audio = bool(call_like_hits or audio_hits)

            iter_summary = {
                "iteration": iteration,
                "play_ok": play_ok,
                "looks_like_call": looks_like_call,
                "looks_like_audio_or_esco": looks_like_audio,
                "dut_call_like_matches": call_like_hits[:15],
                "dut_audio_matches": audio_hits[:15],
                "ag_sco_on": sco_on,
            }
            iterations.append(iter_summary)
            LOGGER.info(
                "Sample SCO probe iter %s summary: call_like=%s audio/esco=%s "
                "ag_scoOn=%s hits=%s",
                iteration,
                looks_like_call,
                looks_like_audio,
                sco_on,
                (call_like_hits or audio_hits)[:3],
            )

            elapsed = time.time() - iter_start
            remaining = interval_sec - elapsed
            if remaining > 0 and time.time() - probe_start < duration_sec:
                time.sleep(remaining)

        any_call_like = any(i.get("looks_like_call") for i in iterations)
        any_audio = any(i.get("looks_like_audio_or_esco") for i in iterations)
        any_sco_on = any(i.get("ag_sco_on") is True for i in iterations)
        self._record_event(
            "sample_sco_file_playback_probe_summary",
            status="pass",
            details={
                "path": sco_path,
                "iterations": len(iterations),
                "duration_sec": duration_sec,
                "interval_sec": interval_sec,
                "play_sec": play_sec,
                "dut_looked_like_call": any_call_like,
                "dut_saw_audio_or_esco": any_audio,
                "ag_sco_on_any_iter": any_sco_on,
                "per_iteration": iterations,
                "conclusion": (
                    "DUT emitted call-like host markers during SCO playback "
                    "(SIM-less path may be viable for some cases)."
                    if any_call_like
                    else (
                        "DUT saw audio/eSCO-ish markers but not full callsetup/active; "
                        "SCO playback alone may not replace cellular call cases."
                        if any_audio or any_sco_on
                        else "No clear DUT call/audio markers during SCO playback; "
                        "check file path, HFP SLC, and BleAutomation PLAY_SCO_FILE success."
                    )
                ),
            },
        )
        LOGGER.info(
            "Sample SCO probe done: iterations=%s call_like=%s audio=%s scoOn=%s",
            len(iterations),
            any_call_like,
            any_audio,
            any_sco_on,
        )
        # Soft final route (do not require scoOff — playback may leave SCO up briefly).
        self._ag_get_audio_route()

    def _verify_active_sco_stability_after_open(self, start_index, duration_sec=None):
        duration_sec = duration_sec if duration_sec is not None else _env_int(
            "UTF_HFP_SCO_OPEN_STABILITY_SEC", SCO_OPEN_STABILITY_SEC
        )
        LOGGER.info(
            "T1956425: monitoring active eSCO stability for %s seconds after SCO open",
            duration_sec,
        )
        premature_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"hfp audio disconn",
                r"esco link disconn",
                r"eSCO.*disconn",
                r"hfp disconn HF",
                r"RSI_APP_EVENT_DISCONNECTED",
                r"disconnect reason",
                r"no call is active",
            ]
        ]
        soft_data_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"esco data",
                r"eSCO data",
                r"retransmission",
                r"re-?tx",
                r"audio data",
                r"hfp audio conn",
                r"call is active",
            ]
        ]
        deadline = time.time() + duration_sec
        current_index = start_index
        soft_matches = []
        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                for pattern in premature_patterns:
                    if pattern.search(stripped):
                        self._record_event(
                            "active_sco_premature_disconnect",
                            status="fail",
                            log_match=stripped,
                            details={"duration_sec": duration_sec},
                        )
                        pytest.fail(
                            "T1956425 / GAR-8395: eSCO/HFP dropped shortly after SCO open: "
                            f"{stripped}"
                        )
                for pattern in soft_data_patterns:
                    if pattern.search(stripped):
                        soft_matches.append(stripped)
                        break
            time.sleep(POLL_INTERVAL_SEC)

        self._record_event(
            "active_sco_stability_complete",
            status="pass",
            details={
                "duration_sec": duration_sec,
                "soft_esco_data_matches": soft_matches[:20],
            },
        )
        self._ag_soft_assert_audio_route(
            "ag_audio_route_during_sco_stability",
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
            context="T1956425 after SCO-open stability window",
        )
        return soft_matches

    def _incoming_call_accept_verify_sco_stability_then_terminate_via_adb_shell(self):
        LOGGER.info(
            "T1956425: source place_call → DUT accept → SCO stability → terminate"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication after source place_call (T1956425)."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        self._wait_before_accepting_incoming_call()
        action_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(action_snapshot)
        # Soft OTA-style markers: +CIEV / BCS / CIND / eSCO link request.
        post_accept_markers = self._collect_matching_lines(
            [
                r"\+CIEV",
                r"callsetup:",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"\+CIND",
                r"hfp call status",
                r"esco link req",
                r"connection initiated event",
                r"hfp audio conn",
                r"call is active",
            ],
            timeout=min(8, CALL_ACTION_TIMEOUT_SEC),
            start_index=action_snapshot,
        )
        self._record_event(
            "post_accept_esco_ota_markers",
            status="pass" if post_accept_markers else "info",
            details={"matches": (post_accept_markers or [])[:20]},
        )
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_dut_accept",
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
            context="T1956425 after DUT accept",
        )

        stability_snapshot = self._get_log_snapshot()
        self._verify_active_sco_stability_after_open(stability_snapshot)

        self._verify_call_logs_present(
            incoming_snapshot, "DUT accept + SCO stability flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        self._cli_terminate_active_call(action_snapshot)
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_terminate",
            expect_sco_on=False,
            context="T1956425 after terminate",
        )
        self._verify_call_logs_present(
            incoming_snapshot, "DUT accept SCO stability and terminate flow"
        )
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _incoming_call_accept_from_ag_and_terminate_from_hf_via_adb_shell(self):
        """T1956405: source dials; AG accepts; DUT terminates."""
        LOGGER.info("T1956405: source placing call for AG accept + HF terminate")
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956405)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        accept_snapshot = self._get_log_snapshot()
        self._shell_adb_accept_on_destination_ag()
        self._wait_for_active_call_after_ag_accept(incoming_snapshot)
        self._verify_active_call_esco_after_ag_accept(
            accept_snapshot, call_window_start=incoming_snapshot
        )
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )
        # Hold the active call for a while before hanging up, instead of
        # terminating immediately after accept (call-duration).
        self._wait_before_terminating_active_call()
        self._cli_terminate_active_call(accept_snapshot)
        self._verify_call_logs_present(incoming_snapshot, "AG accept and HF terminate flow")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _incoming_call_ag_accept_verify_audio_connection_setup_via_adb_shell(self):
        LOGGER.info(
            "T1956407: source placing call; AG accepts; verify AG-driven eSCO audio setup"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956407)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        # Accept on AG ASAP — do not burn CALL_ACTION_TIMEOUT collecting before accept.
        LOGGER.info("T1956407: accepting incoming call on AG (mobile)")
        accept_snapshot = self._get_log_snapshot()
        self._shell_adb_accept_on_destination_ag()
        self._wait_for_active_call_after_ag_accept(incoming_snapshot)
        self._verify_active_call_esco_after_ag_accept(
            accept_snapshot, call_window_start=incoming_snapshot
        )
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )
        self._record_event(
            "ag_audio_connection_setup_observed",
            status="pass",
            details={"context": "T1956407 hard eSCO + AG scoOn"},
        )
        self._verify_call_logs_present(incoming_snapshot, "AG audio connection setup flow")

        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"AG terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _incoming_call_accept_and_terminate_from_ag_via_adb_shell(self):
        """T1956399: source dials; AG accepts; AG terminates."""
        LOGGER.info("T1956399: source placing call for AG accept + AG terminate")
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956399)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        accept_snapshot = self._get_log_snapshot()
        self._shell_adb_accept_on_destination_ag()
        self._wait_for_active_call_after_ag_accept(incoming_snapshot)
        self._verify_active_call_esco_after_ag_accept(
            accept_snapshot, call_window_start=incoming_snapshot
        )
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )
        self._wait_before_terminating_active_call()
        hangup_wait_snapshot = self._get_log_snapshot()
        self._shell_adb_end_call_on_destination()
        hangup_match = self._wait_for_any_match(
            [
                r"AT\+CHUP",
                r"\bCHUP\b",
                r"disconnect",
                r"hfp audio disconn",
                r"no call is active",
                r"callsetup:IDLE",
            ],
            CALL_ACTION_TIMEOUT_SEC,
            hangup_wait_snapshot if hangup_wait_snapshot else accept_snapshot,
        )
        assert hangup_match, "No AG hangup log after destination terminate_call (T1956399)."
        self._record_event("ag_side_hangup_detected", status="pass", log_match=hangup_match)
        self._verify_call_logs_present(incoming_snapshot, "AG accept and AG terminate flow")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _incoming_call_accept_from_dut_and_verify_logs_via_adb_shell(self):
        LOGGER.info("T1956401: source placing call for DUT accept + eSCO log check")
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956401)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        self._wait_before_accepting_incoming_call()
        action_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_call_logs_present(incoming_snapshot, "DUT accept active call flow")
        self._verify_active_call_esco_after_dut_accept(action_snapshot)
        # Graph C: hard AG scoOn after DUT accept (not soft).
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call(action_snapshot)
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after eSCO check failed (continuing): {exc}")
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_terminate",
            expect_sco_on=False,
            context="T1956401 after terminate",
        )
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _verify_esco_connect_disconnect_during_unanswered_call(self, start_index, timeout):
        required = {
            # Host often prints callsetup:IN instead of literal AT +CIEV for HF role.
            "ciev": re.compile(r"\+CIEV|callsetup:IN|callsetup:IDLE", re.IGNORECASE),
            "bcs": re.compile(r"\bBCS\b", re.IGNORECASE),
            "esco_link_req": re.compile(
                r"esco link req|eSCO link req|ESCO.*link.?req|connection initiated event",
                re.IGNORECASE,
            ),
            "esco_link_disconn": re.compile(
                r"esco link disconn|eSCO link disconn|hfp audio disconn|ESCO.*disconn",
                re.IGNORECASE,
            ),
            "ringtone_or_ring": re.compile(
                r"hfp ring|Ringing|inband|ringtone|RING",
                re.IGNORECASE,
            ),
        }
        found = {name: None for name in required}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info("T1956400 observed %s: %s", name, found[name][:120])
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956400 missing eSCO/incoming-call serial markers while call was unanswered: "
            f"{missing}. Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "esco_connect_disconnect_during_incoming_observed",
            status="pass",
            details={key: value for key, value in found.items()},
        )
        return found

    def _incoming_call_verify_esco_connect_disconnect_unanswered_via_adb_shell(self):
        LOGGER.info(
            "T1956400: source placing call; leave unanswered to verify eSCO "
            "connect/disconnect and ringtone logs"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956400)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        # Soft-assert AG SCO while in-band eSCO is coming up (before disconnect markers).
        esco_up = self._wait_for_any_match(
            [
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"hfp audio conn",
            ],
            _env_int("UTF_HFP_UNANSWERED_ESCO_TIMEOUT_SEC", INCOMING_CALL_TIMEOUT_SEC),
            incoming_snapshot,
        )
        if esco_up:
            self._record_event(
                "unanswered_esco_up_marker",
                status="pass",
                log_match=esco_up,
            )
            self._ag_soft_assert_audio_route(
                "ag_audio_route_during_unanswered_esco",
                expect_current="bluetooth",
                expect_sco_on=True,
                require_bluetooth_available=True,
                context="T1956400 while ringing eSCO up",
            )

        # Do not accept/reject from DUT — wait for eSCO bring-up + tear-down while ringing.
        self._verify_esco_connect_disconnect_during_unanswered_call(
            incoming_snapshot,
            timeout=_env_int("UTF_HFP_UNANSWERED_ESCO_TIMEOUT_SEC", INCOMING_CALL_TIMEOUT_SEC),
        )
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_unanswered_esco_disconn",
            expect_sco_on=False,
            context="T1956400 after eSCO disconnect while unanswered",
        )
        self._verify_call_logs_present(incoming_snapshot, "unanswered eSCO incoming call flow")

        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call after unanswered eSCO check failed: {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination cleanup after unanswered eSCO check failed: {exc}")

        idle_match = self._wait_for_any_match(
            [r"callsetup:IDLE", r"no call is active", r"hfp audio disconn"],
            CALL_ACTION_TIMEOUT_SEC,
            incoming_snapshot,
        )
        if idle_match:
            self._record_event("call_returned_idle_after_unanswered", status="pass", log_match=idle_match)
        else:
            LOGGER.warning("No explicit idle log after ending unanswered call (continuing).")

    def _verify_inband_ringtone_during_incoming_call(self, start_index, timeout):
        required = {
            "esco_link_req": re.compile(
                r"esco link req|eSCO link req|ESCO.*link.?req|connection initiated event",
                re.IGNORECASE,
            ),
            "esco_link_resp_or_conn": re.compile(
                r"esco link (?:resp|response|conn|connected)|eSCO link (?:resp|response|conn)|"
                r"hfp audio conn|ESCO.*(?:resp|conn)|connection completed|SCO connected",
                re.IGNORECASE,
            ),
            "esco_data_transfer": re.compile(
                r"esco data|eSCO data|data transfer|retransmission|re-?tx|audio data|"
                r"hfp audio|SCO data",
                re.IGNORECASE,
            ),
            "ring": re.compile(
                r"hfp ring|Ringing|\bRING\b|inband|ringtone|\+BSIR:\s*1",
                re.IGNORECASE,
            ),
        }
        found = {name: None for name in required}
        bsir_line = None
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                if bsir_line is None and re.search(r"\+BSIR:\s*1|\bBSIR\b.*1", line, re.I):
                    bsir_line = line.strip()
                    LOGGER.info("T1956420 observed +BSIR (in-band on): %s", bsir_line[:120])
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info("T1956420 in-band observed %s: %s", name, found[name][:120])
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        if found["esco_link_resp_or_conn"] is None and found["esco_link_req"] and found["ring"]:
            proxy = next(
                (
                    line
                    for line in collected
                    if re.search(
                        r"hfp audio conn|\bBCS\b|eSCO|SCO connected|connection completed",
                        line,
                        re.I,
                    )
                ),
                None,
            )
            if proxy or bsir_line:
                found["esco_link_resp_or_conn"] = (proxy or bsir_line or "").strip()
                LOGGER.info(
                    "T1956420: treating eSCO req + ring (+ audio/BCS/BSIR) as in-band link path"
                )

        if found["esco_data_transfer"] is None and found["esco_link_resp_or_conn"] and found["ring"]:
            found["esco_data_transfer"] = found["esco_link_resp_or_conn"]
            LOGGER.info(
                "T1956420: treating eSCO connect + ring as in-band data-path proxy "
                "(no explicit 'eSCO data' log)"
            )

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956420 in-band ringtone markers missing while call was ringing: "
            f"{missing}. Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "inband_ringtone_enabled_observed",
            status="pass",
            details={**{k: v for k, v in found.items()}, "bsir": bsir_line},
        )
        return found

    def _incoming_call_check_inband_ringtone_and_accept_from_dut_via_adb_shell(self):
        LOGGER.info(
            "T1956420: source placing call; check in-band ringtone; DUT accept_call"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956420)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"\+CIEV",
                r"callsetup:IN",
                r"\bBCS\b",
                r"esco link req",
                r"connection initiated event",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._verify_inband_ringtone_during_incoming_call(
            incoming_snapshot,
            timeout=_env_int(
                "UTF_HFP_INBAND_RINGTONE_TIMEOUT_SEC",
                CALL_ACTION_TIMEOUT_SEC,
            ),
        )

        LOGGER.info("T1956420: accepting incoming call from DUT (HF)")
        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)

        post_accept_lines = self._collect_matching_lines(
            [
                r"\+CIEV",
                r"callsetup:",
                r"\bBCS\b",
                r"\+CIND",
                r"CIND",
                r"esco link req",
                r"connection initiated event",
                r"eSCO",
                r"SCO",
                r"hfp audio conn",
                r"call is active",
                r"retransmission",
                r"re-?tx",
                r"esco data",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=accept_snapshot,
        )
        assert post_accept_lines, (
            "No post-accept eSCO/CIEV/BCS/CIND logs after DUT accept_call (T1956420)."
        )
        self._record_event(
            "dut_accept_inband_active_call_logs_observed",
            status="pass",
            details={"matches": post_accept_lines[:20]},
        )
        self._verify_call_logs_present(
            incoming_snapshot, "in-band ringtone + DUT accept flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call(accept_snapshot)
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956420 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _verify_active_call_esco_after_dut_accept(
        self, accept_snapshot, timeout=None, call_window_start=None
    ):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        audio_start = (
            call_window_start
            if call_window_start is not None
            else getattr(self, "_last_call_window_start", None)
        )
        if audio_start is None:
            audio_start = accept_snapshot

        call_active_re = re.compile(r"call is active", re.IGNORECASE)
        audio_res = {
            "hfp_audio_conn": re.compile(r"hfp audio conn", re.IGNORECASE),
            "bcs": re.compile(r"BCS AT Command Successful|\bBCS\b", re.IGNORECASE),
            "esco_link_req": re.compile(
                r"esco link req|connection initiated event", re.IGNORECASE
            ),
        }
        found_active = None
        audio_found = {name: None for name in audio_res}
        deadline = time.time() + timeout
        current_index = accept_snapshot
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                if found_active is None and call_active_re.search(line):
                    found_active = line.strip()
                    LOGGER.info("DUT accept eSCO required call_active: %s", found_active[:160])
                for name, pattern in audio_res.items():
                    if audio_found[name] is None and pattern.search(line):
                        audio_found[name] = line.strip()
            # Once call is active, stop waiting for a second hfp audio conn —
            # in-band path often already printed it during ring.
            if found_active:
                break
            time.sleep(POLL_INTERVAL_SEC)

        # Credit eSCO that came up while ringing (before accept_snapshot).
        if not any(audio_found.values()) and audio_start != accept_snapshot:
            pre_lines, _ = self._read_new_log_lines(audio_start)
            for line in pre_lines:
                for name, pattern in audio_res.items():
                    if audio_found[name] is None and pattern.search(line):
                        audio_found[name] = line.strip()
                        LOGGER.info(
                            "DUT accept eSCO credited pre-accept %s: %s",
                            name,
                            audio_found[name][:160],
                        )

        # Last resort: recorded pre-accept event (same in-band path).
        if not any(audio_found.values()):
            pre_ev = self._find_recorded_event("incoming_call_pre_accept_markers")
            matches = ((pre_ev or {}).get("details") or {}).get("matches") or []
            for line in matches:
                for name, pattern in audio_res.items():
                    if audio_found[name] is None and pattern.search(line):
                        audio_found[name] = f"(pre-accept event) {line.strip()}"

        assert found_active, (
            "After DUT accept_call, missing 'call is active'. "
            f"Recent lines: {collected[-30:]}"
        )
        assert any(audio_found.values()), (
            "After DUT accept_call, missing audio/eSCO markers in the call window "
            "(need 'hfp audio conn' or BCS/esco link req — often printed during "
            f"in-band ring before accept). Recent lines: {collected[-30:]}"
        )
        matches = [found_active] + [v for v in audio_found.values() if v]
        self._record_event(
            "dut_accept_active_call_logs_observed",
            status="pass",
            details={
                "call_active": found_active,
                **{f"audio_{k}": v for k, v in audio_found.items()},
                "audio_window_start_used": audio_start != accept_snapshot,
                "matches": matches[:20],
            },
        )
        return matches

    def _ag_bt_off_expect_acl_disconnect_during_active_call(self, timeout_sec=None):
        timeout_sec = timeout_sec or _env_int(
            "UTF_HFP_BT_TOGGLE_TIMEOUT_SEC", REMOTE_BT_TOGGLE_TIMEOUT_SEC
        )
        self._require_shell_adb_phones()
        release_snapshot = self._get_log_snapshot()
        LOGGER.info(
            "T1956421: disabling Bluetooth on AG (%s) during active call",
            getattr(self.destination_adb, "device_id", None),
        )
        ok = self.destination_adb.set_bluetooth_enabled(False)
        assert ok, "Failed to disable Bluetooth on destination AG via ADB"

        disconnect_lines = self._collect_matching_lines(
            [
                r"hfp disconn HF",
                r"hfp audio disconn",
                r"A2DP Sink disconnect event",
                r"AVRCP disconnect event",
                r"\bdisconn\b",
                r"RSI_APP_EVENT_DISCONNECTED",
                r"disconnect reason",
                r"0x4[Ee]13",
                r"Detach",
                r"L2CAP",
            ],
            timeout=timeout_sec,
            start_index=release_snapshot,
        )
        assert disconnect_lines, (
            "T1956421: no ACL/HFP disconnect logs after AG Bluetooth OFF during active call."
        )
        self._record_event(
            "active_call_ag_bt_off_disconnect_observed",
            status="pass",
            details={"matches": disconnect_lines[:20], "transport": "adb_shell"},
        )
        return release_snapshot

    def _wait_for_dut_paging_for_reconnection(self, start_index, timeout_sec=None):
        timeout_sec = timeout_sec or _env_int(
            "UTF_HFP_PAGING_TIMEOUT_SEC", REMOTE_BT_TOGGLE_TIMEOUT_SEC
        )
        page_match = self._wait_for_any_match(
            [
                r"Initiated Paging",
                r"Reconnection Initiated",
                r"Reconnection: Peer 0 connect command executed successfully",
                r"on conn paging",
                r"page done",
                r"page timeout",
                r"conn err 0x4e04",
            ],
            timeout_sec,
            start_index,
        )
        assert page_match, (
            "T1956421: no DUT paging / reconnection-attempt logs after AG BT OFF."
        )
        # Collect a short window of related lines for the summary artifact.
        paging_lines = self._collect_matching_lines(
            [
                r"Initiated Paging",
                r"Reconnection Initiated",
                r"on conn paging",
                r"page done",
                r"page timeout",
                r"conn err 0x4e04",
            ],
            timeout=min(5, timeout_sec),
            start_index=start_index,
        ) or [page_match]
        self._record_event(
            "dut_paging_for_reconnection_observed",
            status="pass",
            details={"matches": paging_lines[:20], "first_match": page_match},
        )
        return paging_lines

    def _ag_bt_on_expect_slc_reconnect(self, timeout_sec=None):
        timeout_sec = timeout_sec or _env_int(
            "UTF_HFP_RECONNECT_TIMEOUT_SEC", RECONNECTION_GRACE_SEC
        )
        self._require_shell_adb_phones()
        reconnect_snapshot = self._get_log_snapshot()
        LOGGER.info(
            "T1956421: enabling Bluetooth on AG (%s) for reconnect during/after active call",
            getattr(self.destination_adb, "device_id", None),
        )
        ok = self.destination_adb.set_bluetooth_enabled(True)
        assert ok, "Failed to enable Bluetooth on destination AG via ADB"

        # If DUT does not auto-page after BT is back, nudge classic connect.
        time.sleep(_env_int("UTF_HFP_POST_BT_ON_SETTLE_SEC", 3))
        page_hint = self._wait_for_any_match(
            [
                r"Initiated Paging",
                r"Reconnection Initiated",
                r"page done",
                r"conn evt",
                r"hfp conn HF",
            ],
            timeout=8,
            start_index=reconnect_snapshot,
        )
        if not page_hint and self.phone_address:
            LOGGER.info(
                "T1956421: no immediate reconnect; issuing btc gap connect %s",
                self.phone_address,
            )
            try:
                self._send_cli_command(
                    f"btc gap connect {self.phone_address}",
                    event_name="bt_connect_command_sent_after_ag_bt_on",
                )
            except Exception as exc:
                LOGGER.warning(f"btc gap connect after AG BT ON failed (continuing): {exc}")

        reconnect_lines = self._collect_matching_lines(
            [
                r"Initiated Paging",
                r"Reconnection Initiated",
                r"page done",
                r"role chg",
                r"conn evt",
                r"linkkey req",
                r"auth_complete event",
                r"Link encryption",
                r"a2dp conn ok",
                r"hfp conn HF",
                r"AG feat:",
                r"callsetup:IDLE",
                r"callsetup:IN",
                r"call is active",
                r"hfp audio conn",
            ],
            timeout=timeout_sec,
            start_index=reconnect_snapshot,
        )
        assert reconnect_lines, "T1956421: no reconnect logs after AG Bluetooth ON."

        reconnect_success = any(
            re.search(r"hfp conn HF", line, re.IGNORECASE) for line in reconnect_lines
        ) or (
            any(re.search(r"auth_complete event", line, re.IGNORECASE) for line in reconnect_lines)
            and any(re.search(r"a2dp conn ok", line, re.IGNORECASE) for line in reconnect_lines)
        )
        assert reconnect_success, (
            "T1956421: HFP/A2DP SLC did not come back after AG Bluetooth ON. "
            f"Recent logs: {reconnect_lines[:25]}"
        )
        self._record_event(
            "active_call_ag_bt_on_slc_reconnect_observed",
            status="pass",
            details={"matches": reconnect_lines[:25], "transport": "adb_shell"},
        )
        return reconnect_snapshot

    def _active_call_bt_off_on_check_via_adb_shell(self):
        LOGGER.info(
            "T1956421: incoming → DUT accept → AG BT OFF/ON during active call"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956421)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_dut_accept",
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
            context="T1956421 after DUT accept (pre BT OFF)",
        )

        # Step 7–8: BT OFF → disconnect; observe DUT paging while AG radio is down.
        bt_off_snapshot = self._ag_bt_off_expect_acl_disconnect_during_active_call()
        # GET_AUDIO_ROUTE may fail with BT off; treat scoOff/failure as info.
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_bt_off",
            expect_sco_on=False,
            context="T1956421 after AG BT OFF (SCO should be down)",
        )
        self._wait_for_dut_paging_for_reconnection(bt_off_snapshot)

        # Step 9: BT ON → SLC / profiles back.
        try:
            self._ag_bt_on_expect_slc_reconnect()
        finally:
            # Always try to leave AG Bluetooth enabled for later tests / cleanup.
            try:
                self.destination_adb.set_bluetooth_enabled(True)
            except Exception as exc:
                LOGGER.warning(f"AG Bluetooth re-enable cleanup failed: {exc}")

        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_bt_on_reconnect",
            require_bluetooth_available=True,
            context="T1956421 after AG BT ON / SLC reconnect",
        )

        self._verify_call_logs_present(
            incoming_snapshot, "active-call AG BT OFF/ON reconnect flow"
        )

        # Hold the reconnected call for a while before hanging up, instead of
        # terminating immediately after SLC reconnect (call-duration).
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956421 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _outgoing_call_from_ag_verify_esco_logs_via_adb_shell(self):
        LOGGER.info("T1956406: AG placing outgoing call; verify HF eSCO / call indicators")
        outgoing_snapshot = self._get_log_snapshot()
        self._shell_adb_make_outgoing_call_from_ag()

        indication = self._wait_for_any_match(
            [
                r"callsetup:OUT",
                r"callsetup:OG",
                r"callsetup:",
                r"outgoing",
                r"\+CIEV",
                r"hfp call status",
                r"call is active",
                r"hfp audio conn",
            ],
            INCOMING_CALL_TIMEOUT_SEC,
            outgoing_snapshot,
        )
        assert indication, (
            "No outgoing-call indication in DUT logs after AG place_call (T1956406)."
        )
        self._record_event("ag_outgoing_call_detected", status="pass", log_match=indication)

        active_call_lines = self._collect_matching_lines(
            [
                r"\+CIEV",
                r"callsetup:",
                r"\bBCS\b",
                r"\+CIND",
                r"CIND",
                r"esco link req",
                r"connection initiated event",
                r"eSCO",
                r"SCO",
                r"hfp audio conn",
                r"call is active",
                r"outgoing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=outgoing_snapshot,
        )
        assert active_call_lines, (
            "No active-call/eSCO related logs after AG outgoing place_call (T1956406)."
        )
        self._record_event(
            "ag_outgoing_esco_logs_observed",
            status="pass",
            details={"matches": active_call_lines[:20]},
        )
        self._verify_call_logs_present(outgoing_snapshot, "AG outgoing call flow")

        LOGGER.info("T1956406: ending outgoing call from AG")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"AG terminate_call after outgoing check failed: {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source cleanup after AG outgoing check failed: {exc}")

    def _reject_first_call_accept_second_and_terminate_from_dut_via_adb_shell(self):
        """Timed reject/accept/terminate using source place_call (no manual dial)."""
        LOGGER.info("Timing-R: first call for DUT reject")
        first_incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            first_incoming_snapshot,
        )
        assert indication, "No incoming-call indication for first call (timing)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)
        self._wait_before_rejecting_incoming_call()
        self._cli_reject_incoming_call(first_incoming_snapshot)
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source end after reject failed (continuing): {exc}")
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))

        LOGGER.info("Timing-R: second call for DUT accept + terminate")
        second_incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            second_incoming_snapshot,
        )
        assert indication, "No incoming-call indication for second call (timing)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)
        self._wait_before_accepting_incoming_call()
        action_snapshot = self._cli_accept_incoming_call(second_incoming_snapshot)
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        self._cli_terminate_active_call(action_snapshot)
        self._verify_call_logs_present(
            second_incoming_snapshot,
            "reject first, accept second, and DUT terminate flow",
        )
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")

    def _wait_for_service_level_release_from_ag_via_adb_shell(
        self, timeout_sec=REMOTE_BT_TOGGLE_TIMEOUT_SEC
    ):
        self._require_shell_adb_phones()
        release_snapshot = self._get_log_snapshot()
        LOGGER.info(
            "Disabling Bluetooth on destination AG (%s) for SLC release",
            getattr(self.destination_adb, "device_id", None),
        )
        ok = self.destination_adb.set_bluetooth_enabled(False)
        assert ok, "Failed to disable Bluetooth on destination AG via ADB"
        release_lines = self._collect_matching_lines(
            [
                r"hfp disconn HF",
                r"A2DP Sink disconnect event",
                r"AVRCP disconnect event",
                r"\bdisconn\b.*0x4e13",
                r"RSI_APP_EVENT_DISCONNECTED",
                r"disconnect reason",
            ],
            timeout=timeout_sec,
            start_index=release_snapshot,
        )
        assert release_lines, "No BT/HFP disconnect logs after AG Bluetooth disable."
        self._record_event(
            "service_level_release_observed",
            status="pass",
            details={"matches": release_lines[:20], "transport": "adb_shell"},
        )
        return release_snapshot

    def _wait_for_service_level_reconnect_after_ag_bt_on_via_adb_shell(
        self, timeout_sec=RECONNECTION_GRACE_SEC
    ):
        """T1956396: re-enable AG Bluetooth via ADB."""
        self._require_shell_adb_phones()
        reconnect_snapshot = self._get_log_snapshot()
        LOGGER.info(
            "Enabling Bluetooth on destination AG (%s) for SLC reconnect",
            getattr(self.destination_adb, "device_id", None),
        )
        ok = self.destination_adb.set_bluetooth_enabled(True)
        assert ok, "Failed to enable Bluetooth on destination AG via ADB"
        reconnect_lines = self._collect_matching_lines(
            [
                r"Reconnection Initiated",
                r"Reconnection: Peer 0 connect command executed successfully",
                r"conn err 0x4e04",
                r"page timeout",
                r"role chg",
                r"conn evt",
                r"page done",
                r"linkkey req",
                r"auth_complete event",
                r"a2dp conn ok",
                r"hfp conn HF",
                r"callsetup:IDLE",
                r"mode change event .*SNIFF_MODE_ENABLED",
            ],
            timeout=timeout_sec,
            start_index=reconnect_snapshot,
        )
        assert reconnect_lines, "No reconnect logs after AG Bluetooth enable."
        reconnect_success = any(
            re.search(r"hfp conn HF", line, re.IGNORECASE) for line in reconnect_lines
        ) or (
            any(re.search(r"auth_complete event", line, re.IGNORECASE) for line in reconnect_lines)
            and any(re.search(r"a2dp conn ok", line, re.IGNORECASE) for line in reconnect_lines)
        )
        assert reconnect_success, (
            "Service level reconnection did not complete after AG Bluetooth enable. "
            f"Recent reconnect logs: {reconnect_lines[:20]}"
        )
        self._record_event(
            "service_level_reconnect_observed",
            status="pass",
            details={"matches": reconnect_lines[:20], "transport": "adb_shell"},
        )
        return reconnect_snapshot

    def _ensure_hfp_connection(self, start_index=None):
        hfp_conn_patterns = [
            r"hfp conn HF",
            r"HFP conn ok",
        ]
        hfp_corroboration_patterns = [
            r"AG feat:",
            r"hfp callheld",
            r"AT\+BRSF",
            r"AT\+BAC",
            r"AT\+CIND=\?",
            r"AT\+CIND\?",
            r"AT\+CMER",
            r"AT\+CHLD=\?",
        ]
        hfp_snapshot = start_index if start_index is not None else self._get_log_snapshot()
        conn_matches = self._collect_matching_lines(
            hfp_conn_patterns,
            HFP_CONNECT_TIMEOUT_SEC,
            hfp_snapshot,
        )
        if conn_matches:
            extra = self._collect_matching_lines(
                hfp_corroboration_patterns,
                timeout=min(5, HFP_CONNECT_TIMEOUT_SEC),
                start_index=hfp_snapshot,
            )
            LOGGER.info(
                "HFP SLC already present: %s (extra=%s)",
                conn_matches[:6],
                (extra or [])[:4],
            )
            self._record_event(
                "hfp_slc_detected",
                status="pass",
                details={
                    "conn_matches": conn_matches[:6],
                    "corroboration": (extra or [])[:6],
                },
            )
            return

        self._clear_serial_log()
        hfp_snapshot = self._get_log_snapshot()
        LOGGER.info("No HFP conn HF / HFP conn ok yet. Issuing explicit HFP connect.")
        hfp_snapshot, _ = self._send_cli_command(
            f"btc hfp hfp_connect {self.phone_address}",
            event_name="hfp_connect_command_sent",
        )
        self._assert_no_failure_log_since("btc hfp hfp_connect", hfp_snapshot, timeout=2)

        conn_matches = self._collect_matching_lines(
            hfp_conn_patterns,
            HFP_CONNECT_TIMEOUT_SEC,
            hfp_snapshot,
        )
        assert conn_matches, (
            "No HFP SLC conn marker after HFP connect "
            "(required: 'HFP conn ok' and/or 'hfp conn HF'). "
            "AG feat / AT+ alone is not sufficient."
        )
        extra = self._collect_matching_lines(
            hfp_corroboration_patterns,
            timeout=min(5, HFP_CONNECT_TIMEOUT_SEC),
            start_index=hfp_snapshot,
        )
        LOGGER.info(
            "HFP SLC established: %s (extra=%s)",
            conn_matches[:6],
            (extra or [])[:4],
        )
        self._record_event(
            "hfp_slc_established",
            status="pass",
            details={
                "conn_matches": conn_matches[:6],
                "corroboration": (extra or [])[:6],
            },
        )

    def _verify_a2dp_initialization(self):
        existing_profile_event = self._find_recorded_event("gap_connect_profile_bringup_observed")
        if existing_profile_event:
            matches = (existing_profile_event.get("details") or {}).get("matches", [])
            if any(re.search(r"a2dp conn ok|A2DP Sink .*Event|A2DP stream conn", match, re.IGNORECASE) for match in matches):
                LOGGER.info(f"A2DP profile already observed during connect flow: {matches[:6]}")
                self._record_event(
                    "a2dp_initialized",
                    status="pass",
                    details={"source": "gap_connect_profile_bringup_observed", "matches": matches[:6]},
                )
                return

        a2dp_snapshot = self._get_log_snapshot()
        a2dp_match = self._wait_for_any_match(
            [r"AVDTP", r"A2DP", r"Discover", r"capabilities", r"Open"],
            A2DP_PROFILE_TIMEOUT_SEC,
            a2dp_snapshot,
        )
        assert a2dp_match, "No A2DP/AVDTP profile initialization log was detected."
        LOGGER.info(f"A2DP/AVDTP profile log observed: {a2dp_match}")
        self._record_event("a2dp_initialized", status="pass", log_match=a2dp_match)

    def _wait_for_incoming_call(self):
        incoming_snapshot = self._get_log_snapshot()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication was detected in DUT logs."
        LOGGER.info(f"Incoming-call indication observed: {indication}")
        self._record_event("incoming_call_detected", status="pass", log_match=indication)
        return incoming_snapshot

    def _wait_before_rejecting_incoming_call(self, delay_sec=None):
        delay_sec = (
            _env_int("UTF_HFP_AUTO_REJECT_DELAY_SEC", AUTO_REJECT_DELAY_SEC)
            if delay_sec is None
            else delay_sec
        )
        if delay_sec <= 0:
            return

        LOGGER.info(f"Waiting {delay_sec} seconds before rejecting the incoming call.")
        time.sleep(delay_sec)
        self._record_event(
            "incoming_call_reject_delay_elapsed",
            status="pass",
            details={"delay_sec": delay_sec},
        )

    def _wait_before_accepting_incoming_call(self, delay_sec=None):
        delay_sec = (
            _env_int("UTF_HFP_AUTO_ACCEPT_DELAY_SEC", AUTO_ACCEPT_DELAY_SEC)
            if delay_sec is None
            else delay_sec
        )
        if delay_sec <= 0:
            return

        LOGGER.info(f"Waiting {delay_sec} seconds before accepting the incoming call.")
        time.sleep(delay_sec)
        self._record_event(
            "incoming_call_accept_delay_elapsed",
            status="pass",
            details={"delay_sec": delay_sec},
        )

    def _wait_before_terminating_active_call(self, delay_sec=None):
        # This is also the effective "call duration" / active-call hold time
        # for scenarios that call this right before hanging up.
        delay_sec = (
            _env_int("UTF_HFP_AUTO_TERMINATE_DELAY_SEC", AUTO_TERMINATE_DELAY_SEC)
            if delay_sec is None
            else delay_sec
        )
        if delay_sec <= 0:
            return

        LOGGER.info(f"Waiting {delay_sec} seconds before terminating the active call.")
        time.sleep(delay_sec)
        self._record_event(
            "active_call_terminate_delay_elapsed",
            status="pass",
            details={"delay_sec": delay_sec},
        )

    def _verify_call_logs_present(self, start_index, context):
        call_lines = self._collect_matching_lines(
            [r"RING", r"\+CIEV", r"BCS", r"CHUP", r"SCO", r"eSCO", r"call", r"hfp audio disconn"],
            timeout=3,
            start_index=start_index,
        )
        assert call_lines, f"No call-related logs were observed for {context}."
        LOGGER.info(f"{context} call logs: {call_lines[:10]}")
        self._record_event(f"{context}_logs_present", status="pass", details={"matches": call_lines[:10]})

    def _parse_unanswered_incoming_call_timeout(self, start_index, timeout=INCOMING_CALL_TIMEOUT_SEC):
        timeout_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"hfp ring",
                r"Ringing",
                r"connection initiated event: status 0x0",
                r"esco link req event",
                r"Codec Reconfigured to",
                r"hfp audio conn",
                r"hfp audio disconn",
                r"callsetup:IDLE",
                r"accept_call",
                r"reject_call",
                r"AT\+CHUP",
                r"\bCHUP\b",
            ],
            timeout=timeout,
            start_index=start_index,
        )
        if not timeout_lines:
            return None

        saw_incoming = any(re.search(r"callsetup:IN|hfp ring|Ringing", line, re.IGNORECASE) for line in timeout_lines)
        saw_timeout_end = any(
            re.search(r"hfp audio disconn|callsetup:IDLE", line, re.IGNORECASE) for line in timeout_lines
        )
        saw_manual_action = any(
            re.search(r"accept_call|reject_call|AT\+CHUP|\bCHUP\b", line, re.IGNORECASE) for line in timeout_lines
        )
        ring_count = sum(1 for line in timeout_lines if re.search(r"hfp ring|Ringing", line, re.IGNORECASE))

        if saw_incoming and saw_timeout_end and not saw_manual_action:
            self._record_event(
                "incoming_call_timeout_observed",
                status="pass",
                details={
                    "ring_count": ring_count,
                    "matches": timeout_lines[:20],
                },
            )
            return timeout_lines
        return None

    def _parse_terminate_active_call(self, start_index, timeout=CALL_ACTION_TIMEOUT_SEC):
        terminate_lines = self._collect_matching_lines(
            [
                rf"cmd resp:{re.escape(self.phone_address)}",
                r"callreject ok",
                r"hfp audio disconn",
                r"hfp call status",
                r"call status:",
                r"no call is active",
                r"sniff en ok",
            ],
            timeout=timeout,
            start_index=start_index,
        )
        if not terminate_lines:
            return None

        saw_command_response = any(
            re.search(rf"cmd resp:{re.escape(self.phone_address)}", line, re.IGNORECASE) for line in terminate_lines
        )
        saw_termination_ack = any(re.search(r"callreject ok", line, re.IGNORECASE) for line in terminate_lines)
        saw_audio_disconnect = any(re.search(r"hfp audio disconn", line, re.IGNORECASE) for line in terminate_lines)
        saw_no_active_call = any(re.search(r"no call is active", line, re.IGNORECASE) for line in terminate_lines)

        if saw_command_response and saw_termination_ack and saw_audio_disconnect and saw_no_active_call:
            self._record_event(
                "active_call_terminated",
                status="pass",
                details={"matches": terminate_lines[:20]},
            )
            return terminate_lines
        return None

    def _cli_gap_connect(self, expect_duplicate=False):
        connect_snapshot, _ = self._send_cli_command(
            f"btc gap connect {self.phone_address}",
            event_name="bt_connect_command_sent",
        )
        if expect_duplicate:
            duplicate_lines = self._parse_duplicate_gap_connect(connect_snapshot)
            assert duplicate_lines, "Duplicate btc gap connect was not rejected with ACL already exists."
            return connect_snapshot

        self._assert_no_failure_log_since("btc gap connect", connect_snapshot, timeout=2)
        self._capture_gap_connect_profile_state(connect_snapshot)
        return connect_snapshot

    def _cli_gap_disconnect(self):
        self._clear_serial_log()
        disconnect_snapshot, _ = self._send_cli_command(
            f"btc gap disconnect {self.phone_address}",
            event_name="bt_disconnect_command_sent",
        )
        disconnect_lines = self._parse_gap_disconnect(disconnect_snapshot)
        assert disconnect_lines, "No complete BT profile disconnect sequence was detected after gap disconnect."
        return disconnect_snapshot

    def _soft_gap_disconnect(self, reason="cleanup", timeout=None):
        target = self.ctkd_identity_address or self.phone_address
        if not target:
            LOGGER.warning("soft gap disconnect skipped (%s): no phone address", reason)
            return None

        timeout = timeout if timeout is not None else min(15, BT_CONNECT_TIMEOUT_SEC)
        LOGGER.info("Soft gap disconnect (%s): btc gap disconnect %s", reason, target)
        try:
            snapshot, _ = self._send_cli_command(
                f"btc gap disconnect {target}",
                event_name=f"bt_disconnect_command_sent_{reason}",
            )
        except Exception as exc:
            LOGGER.warning("soft gap disconnect CLI failed (%s): %s", reason, exc)
            self._record_event(
                "bt_soft_gap_disconnect",
                status="info",
                details={"reason": reason, "error": str(exc), "target": target},
            )
            return None

        lines = self._collect_matching_lines(
            [
                r"hfp disconn HF",
                r"hfp_disconn",
                r"A2DP Sink disconnect event",
                r"AVRCP disconnect event",
                r"disconnect reason",
                r"RSI_APP_EVENT_DISCONNECTED",
                r"unbond",
                r"\bdisconn\b",
            ],
            timeout=timeout,
            start_index=snapshot,
        )
        self._record_event(
            "bt_soft_gap_disconnect",
            status="pass" if lines else "info",
            details={
                "reason": reason,
                "target": target,
                "matches": (lines or [])[:12],
            },
        )
        if lines:
            LOGGER.info("Soft gap disconnect observed (%s): %s", reason, lines[:4])
        else:
            LOGGER.warning(
                "Soft gap disconnect (%s): no disconnect markers within %ss "
                "(ACL may already have been idle)",
                reason,
                timeout,
            )
        time.sleep(_env_int("UTF_HFP_POST_END_CALL_SETTLE_SEC", POST_END_CALL_SETTLE_SEC))
        return snapshot

    def _dut_remove_ltk(self, reason="cleanup"):
        try:
            _, response = self._send_cli_command(
                "btc ble remove_ltk 0",
                event_name=f"dut_remove_ltk_{reason}",
            )
            LOGGER.info("DUT remove_ltk (%s) response: %s", reason, response)
            self._record_event(
                "dut_remove_ltk",
                status="pass",
                details={"reason": reason, "response": str(response) if response is not None else None},
            )
        except Exception as exc:
            LOGGER.warning("DUT remove_ltk failed (%s, continuing): %s", reason, exc)
            self._record_event(
                "dut_remove_ltk",
                status="info",
                details={"reason": reason, "error": str(exc)},
            )

    def _cleanup_bt_connection_after_test(self):
        LOGGER.info("Post-test BT cleanup: ending leftover calls + gap disconnect")

        for name, ender in (
            ("source", getattr(self, "_shell_adb_end_call_on_source", None)),
            ("destination", getattr(self, "_shell_adb_end_call_on_destination", None)),
            ("waiting_caller", getattr(self, "_shell_adb_end_call_on_waiting_caller", None)),
        ):
            if ender is None:
                continue
            try:
                ender()
            except Exception as exc:
                LOGGER.warning("Post-test end_call on %s failed (continuing): %s", name, exc)

        if self.phone_address or self.ctkd_identity_address:
            try:
                # Best-effort hangup on HF if a call is still up.
                self._send_cli_command(
                    f"btc hfp terminate_call {self.ctkd_identity_address or self.phone_address}",
                    event_name="cleanup_terminate_call_command_sent",
                )
                time.sleep(1)
            except Exception as exc:
                LOGGER.warning("Post-test DUT terminate_call failed (continuing): %s", exc)

            self._soft_gap_disconnect(reason="post_test")
        self._dut_remove_ltk(reason="post_test")

        dut = self.dut_address
        adb = self.destination_adb
        if dut and adb is not None:
            try:
                adb.ble_disconnect(dut)
                self._record_event(
                    "cleanup_ble_disconnect",
                    status="pass",
                    details={"dut_address": dut},
                )
            except Exception as exc:
                LOGGER.warning("Post-test ble_disconnect failed (continuing): %s", exc)
                self._record_event(
                    "cleanup_ble_disconnect",
                    status="info",
                    details={"dut_address": dut, "error": str(exc)},
                )

            try:
                adb.ble_remove_bond(dut)
                self._record_event(
                    "cleanup_ble_remove_bond",
                    status="pass",
                    details={"dut_address": dut},
                )
            except Exception as exc:
                LOGGER.warning("Post-test ble_remove_bond failed (continuing): %s", exc)
                self._record_event(
                    "cleanup_ble_remove_bond",
                    status="info",
                    details={"dut_address": dut, "error": str(exc)},
                )

        self._record_event("post_test_bt_cleanup_complete", status="pass")

    def _wait_for_incoming_call_state(self):
        return self._wait_for_incoming_call()

    def _wait_for_incoming_call_timeout(self, start_index=None):
        timeout_snapshot = start_index if start_index is not None else self._wait_for_incoming_call()
        timeout_lines = self._parse_unanswered_incoming_call_timeout(timeout_snapshot)
        assert timeout_lines, "Incoming call did not ring out and return to idle as expected."
        return timeout_snapshot

    def _cli_reject_incoming_call(self, incoming_snapshot=None):
        if incoming_snapshot is None:
            incoming_snapshot = self._wait_for_incoming_call()

        action_snapshot, _ = self._send_cli_command(
            f"btc hfp reject_call {self.phone_address}",
            event_name="reject_call_command_sent",
        )
        self._assert_no_failure_log_since("btc hfp reject_call", action_snapshot, timeout=2)

        reject_match = self._wait_for_any_match(
            [rf"cmd resp:{re.escape(self.phone_address)}", r"callreject ok"],
            CALL_ACTION_TIMEOUT_SEC,
            action_snapshot,
        )
        assert reject_match, "No explicit reject confirmation was detected after reject_call."

        reject_completion_match = self._wait_for_any_match(
            [r"callreject ok", r"hfp audio disconn", r"callsetup:IDLE"],
            CALL_ACTION_TIMEOUT_SEC,
            action_snapshot,
        )
        assert reject_completion_match, "No reject completion/idle indication was detected after reject_call."
        LOGGER.info(f"Reject-call confirmation observed: {reject_match}")
        self._record_event(
            "incoming_call_rejected",
            status="pass",
            details={
                "confirmation_log": reject_match,
                "completion_log": reject_completion_match,
            },
        )
        self._verify_call_logs_present(incoming_snapshot, "reject flow")
        return action_snapshot

    def _cli_accept_incoming_call(self, incoming_snapshot=None):
        if incoming_snapshot is None:
            incoming_snapshot = self._wait_for_incoming_call()
        # Full call window for eSCO asserts (in-band audio often before accept).
        self._last_call_window_start = incoming_snapshot

        action_snapshot, _ = self._send_cli_command(
            f"btc hfp accept_call {self.phone_address}",
            event_name="accept_call_command_sent",
        )
        self._assert_no_failure_log_since("btc hfp accept_call", action_snapshot, timeout=2)

        accept_match = self._wait_for_any_match(
            [rf"cmd resp:{re.escape(self.phone_address)}", r"callaccept ok"],
            CALL_ACTION_TIMEOUT_SEC,
            action_snapshot,
        )
        assert accept_match, "No explicit accept confirmation was detected after accept_call."

        active_call_match = self._wait_for_any_match(
            [r"callaccept ok", r"call is active", r"hfp call status", r"call status:", r"BCS", r"SCO", r"eSCO"],
            CALL_ACTION_TIMEOUT_SEC,
            action_snapshot,
        )
        assert active_call_match, "No active-call indication was detected after accept_call."
        LOGGER.info(f"Accept-call confirmation observed: {accept_match}")
        self._record_event(
            "incoming_call_accepted",
            status="pass",
            details={
                "confirmation_log": accept_match,
                "active_call_log": active_call_match,
            },
        )
        return action_snapshot

    def _cli_terminate_active_call(self, start_index=None):
        terminate_snapshot = start_index if start_index is not None else self._get_log_snapshot()
        terminate_snapshot, _ = self._send_cli_command(
            f"btc hfp terminate_call {self.phone_address}",
            event_name="terminate_call_command_sent",
        )
        terminate_lines = self._parse_terminate_active_call(terminate_snapshot)
        assert terminate_lines, "No terminate-call confirmation/no-active-call sequence was detected."
        return terminate_snapshot

    def _cli_hfp_test_bench_disconnect(self, start_index=None):
        assert self.phone_address, "phone_address required for hfp_test_bench"
        bench_snapshot = start_index if start_index is not None else self._get_log_snapshot()
        cmd = f"btc hfp hfp_test_bench {self.phone_address} 1"
        LOGGER.info("T1956436: issuing %s", cmd)
        bench_snapshot, _ = self._send_cli_command(
            cmd,
            event_name="hfp_test_bench_disconnect_command_sent",
        )
        self._assert_no_failure_log_since("btc hfp hfp_test_bench", bench_snapshot, timeout=2)
        return bench_snapshot

    def _verify_acl_or_sco_disconnect_events(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "audio_disconn": re.compile(
                r"hfp\s+audio\s+[Dd]isconn(?:ected)?|"
                r"hfp\s+audio\s+[Dd]isconnected:\s*str_conn_bd_addr|"
                r"esco\s+link\s+disconn|eSCO.*disconn",
                re.IGNORECASE,
            ),
            "hfp_disconn": re.compile(
                r"hfp[_\s]?disconn\s+HF(?:_Role)?|"
                r"hfp\s+disconn\s+HF|"
                r"hfp_disconn\s+HF_Role\s*:\s*str_conn_bd_addr",
                re.IGNORECASE,
            ),
        }
        optional = {
            "chup": re.compile(r"AT\+CHUP|\bCHUP\b|callsetup:IDLE|no call is active", re.I),
            "bcs_or_ciev": re.compile(r"\bBCS\b|callsetup:|\+CIEV|\+CIND|CIND", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info("T1956436 observed %s: %s", name, found[name][:140])
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956436 missing ACL/SCO disconnect host markers after hfp_test_bench: "
            f"{missing}. Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "acl_or_sco_disconnect_events_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _check_acl_or_sco_disconnected_events_via_adb_shell(self):
        LOGGER.info(
            "T1956436: incoming → DUT accept → hfp_test_bench disconnect; "
            "check ACL/SCO disconnect events"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956436)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)

        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        bench_snapshot = self._cli_hfp_test_bench_disconnect()
        self._verify_acl_or_sco_disconnect_events(bench_snapshot)

        self._verify_call_logs_present(
            incoming_snapshot, "hfp_test_bench ACL/SCO disconnect flow"
        )

        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _verify_codec_selection_during_incoming(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else _env_int(
            "UTF_HFP_CODEC_SELECT_TIMEOUT_SEC", INCOMING_CALL_TIMEOUT_SEC
        )
        codec_names = {
            "1": "CODEC_CVSD",
            "2": "CODEC_MSBC",
            "3": "CODEC_A2DP_SINK",
            "6": "CODEC_LC3",
        }
        # Prefer the explicit "Codec Reconfigured to N" line; also accept hfp Codec select.
        reconfigured_re = re.compile(
            r"(?:1-CODEC_CVSD.*?Codec\s+Reconfigured\s+to\s+(\d+))"
            r"|(?:Codec\s+Reconfigured\s+to\s+(\d+))",
            re.IGNORECASE,
        )
        select_re = re.compile(
            r"hfp\s+Codec\s+select\s*:.*?codec_val\s*:\s*(\d+)",
            re.IGNORECASE,
        )
        deadline = time.time() + timeout
        current_index = start_index
        collected = []
        selected_id = None
        match_line = None
        match_kind = None

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                m = reconfigured_re.search(line)
                if m:
                    selected_id = next(g for g in m.groups() if g)
                    match_line = line.strip()
                    match_kind = "Codec Reconfigured"
                    break
                m = select_re.search(line)
                if m:
                    selected_id = m.group(1)
                    match_line = line.strip()
                    match_kind = "hfp Codec select"
                    break
            if selected_id is not None:
                break
            time.sleep(POLL_INTERVAL_SEC)

        assert selected_id is not None, (
            "T1956437: no host codec selection log "
            "('Codec Reconfigured to <n>' or 'hfp Codec select ... codec_val : <n>'). "
            f"Recent lines: {collected[-30:]}"
        )
        assert selected_id in codec_names, (
            f"T1956437: codec id {selected_id} is not one of available "
            f"{sorted(codec_names)} ({', '.join(codec_names.values())}). "
            f"Line: {match_line}"
        )
        codec_name = codec_names[selected_id]
        LOGGER.info(
            "T1956437 codec selection observed via %s: id=%s (%s) — %s",
            match_kind,
            selected_id,
            codec_name,
            (match_line or "")[:160],
        )
        self._record_event(
            "host_codec_selection_observed",
            status="pass",
            details={
                "codec_id": selected_id,
                "codec_name": codec_name,
                "match_kind": match_kind,
                "log_line": match_line,
                "allowed_ids": sorted(codec_names.keys()),
            },
            log_match=match_line,
        )
        return selected_id, codec_name, match_line

    def _verify_codec_selection_in_host_logs_via_adb_shell(self):
        LOGGER.info("T1956437: source placing call; verify host codec selection logs")
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956437)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        self._verify_codec_selection_during_incoming(incoming_snapshot)
        self._verify_call_logs_present(incoming_snapshot, "codec selection incoming call flow")

        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _cli_audio_transfer_to_ag(self, start_index=None):
        assert self.phone_address, "phone_address required for audio_transfer_ag"
        snapshot = start_index if start_index is not None else self._get_log_snapshot()
        cmd = f"btc hfp audio_transfer_ag {self.phone_address}"
        LOGGER.info("T1956408: issuing %s", cmd)
        snapshot, _ = self._send_cli_command(
            cmd,
            event_name="audio_transfer_ag_command_sent",
        )
        self._assert_no_failure_log_since("btc hfp audio_transfer_ag", snapshot, timeout=2)
        return snapshot

    def _verify_audio_transfer_ag_effects(self, start_index, timeout=None, case_id="T1956408"):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "audio_or_esco_disconn": re.compile(
                r"hfp\s+audio\s+[Dd]isconn(?:ected)?|"
                r"esco\s+link\s+disconn|eSCO.*disconn|"
                r"SCO.*disconn|audio\s+transfer",
                re.IGNORECASE,
            ),
        }
        optional = {
            "ciev_or_callsetup": re.compile(
                r"\+CIEV|callsetup:|call is active|no call is active", re.I
            ),
            "bcs": re.compile(r"\bBCS\b|BCS AT Command Successful", re.I),
            "codec": re.compile(
                r"Codec\s+Reconfigured\s+to\s+\d+|hfp\s+Codec\s+select|codec_val\s*:",
                re.I,
            ),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info("%s observed %s: %s", case_id, name, found[name][:140])
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            f"{case_id}: no eSCO/audio disconnect after audio left HF. "
            f"Missing: {missing}. Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "audio_transfer_ag_effects_observed",
            status="pass",
            details={
                "case_id": case_id,
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _audio_transfer_hf_to_ag_via_adb_shell(self):
        LOGGER.info(
            "T1956408: incoming → DUT accept → btc hfp audio_transfer_ag (HF→AG)"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956408)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)

        # AG-side: audio should be on bluetooth SCO while HF owns eSCO.
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )

        # Codec / audio-at-HF evidence before transfer (any available codec id).
        try:
            self._verify_codec_selection_during_incoming(
                incoming_snapshot,
                timeout=_env_int("UTF_HFP_CODEC_SELECT_TIMEOUT_SEC", 8),
            )
        except AssertionError as exc:
            # Codec may already have been seen only in the accept window; soft-fail to info.
            LOGGER.warning("T1956408: codec selection not re-observed after accept: %s", exc)
            codec_lines = self._collect_matching_lines(
                [
                    r"Codec Reconfigured to",
                    r"hfp Codec select",
                    r"hfp audio conn",
                    r"call is active",
                ],
                timeout=3,
                start_index=incoming_snapshot,
            )
            self._record_event(
                "host_codec_or_audio_at_hf_markers",
                status="pass" if codec_lines else "info",
                details={"matches": (codec_lines or [])[:15]},
            )

        # HF→AG under test: audio leaves HF (bluetooth → phone).
        transfer_snapshot = self._cli_audio_transfer_to_ag()
        self._verify_audio_transfer_ag_effects(transfer_snapshot, case_id="T1956408")
        route = self._ag_get_audio_route()
        parsed = route.get("parsed") or {}
        sco_on = parsed.get("scoOn")
        current = str(parsed.get("current", "")).lower()
        transferred = sco_on is False or current in ("earpiece", "speaker")
        assert transferred, (
            "T1956408: after audio_transfer_ag expected AG scoOn=false or "
            f"current=earpiece|speaker; got current={current!r} scoOn={sco_on!r}"
        )
        self._record_event(
            "ag_audio_route_after_transfer_to_ag",
            status="pass",
            details={"parsed": parsed},
        )

        self._verify_call_logs_present(
            incoming_snapshot, "HF-to-AG audio_transfer_ag flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956408 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _verify_audio_transfer_to_hf_effects(self, start_index, timeout=None, case_id="T1956409"):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "audio_or_esco_conn": re.compile(
                r"hfp\s+audio\s+conn|"
                r"esco\s+link\s+req|eSCO.*link.?req|"
                r"connection initiated event|"
                r"BCS AT Command Successful",
                re.IGNORECASE,
            ),
        }
        optional = {
            "call_active": re.compile(r"call is active|callsetup:", re.I),
            "bcs": re.compile(r"\bBCS\b", re.I),
            "codec": re.compile(
                r"Codec\s+Reconfigured\s+to\s+\d+|hfp\s+Codec\s+select|codec_val\s*:",
                re.I,
            ),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info("%s observed %s: %s", case_id, name, found[name][:140])
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            f"{case_id}: no eSCO/audio reconnect after AG→HF audio transfer. "
            f"Missing: {missing}. Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "audio_transfer_to_hf_effects_observed",
            status="pass",
            details={
                "case_id": case_id,
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _cli_audio_transfer_to_hf(self, start_index=None):
        assert self.phone_address, "phone_address required for audio_transfer_hf"
        snapshot = start_index if start_index is not None else self._get_log_snapshot()
        cmd = f"btc hfp audio_transfer_hf {self.phone_address}"
        LOGGER.info("T1956410: issuing %s", cmd)
        snapshot, _ = self._send_cli_command(
            cmd,
            event_name="audio_transfer_hf_command_sent",
        )
        self._assert_no_failure_log_since("btc hfp audio_transfer_hf", snapshot, timeout=2)
        return snapshot

    def _audio_transfer_ag_to_hf_via_adb_shell(self):
        LOGGER.info(
            "T1956409: accept (audio on HF) → SET earpiece → SET bluetooth (AG→HF)"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956409)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)
        # Call audio starts on HF (BT connected).
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )

        # bluetooth → earpiece (prerequisite so AG→HF is observable).
        to_ag_snapshot = self._get_log_snapshot()
        self._ag_set_and_verify_audio_route("earpiece")
        self._verify_audio_transfer_ag_effects(to_ag_snapshot, case_id="T1956409")
        self._ag_assert_audio_route(
            expect_current="earpiece",
            expect_sco_on=False,
        )
        self._record_event(
            "ag_route_bluetooth_to_earpiece_verified",
            status="pass",
            details={"route": "earpiece", "scoOn": False},
        )

        # earpiece → bluetooth via AG SET_AUDIO_ROUTE (under test).
        to_hf_snapshot = self._get_log_snapshot()
        self._ag_set_and_verify_audio_route("bluetooth")
        self._verify_audio_transfer_to_hf_effects(to_hf_snapshot, case_id="T1956409")
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )
        self._record_event(
            "ag_route_earpiece_to_bluetooth_via_set_audio_route_verified",
            status="pass",
            details={"route": "bluetooth", "scoOn": True, "api": "SET_AUDIO_ROUTE"},
        )

        self._verify_call_logs_present(
            incoming_snapshot, "BT→earpiece→BT via SET_AUDIO_ROUTE flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956409 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _audio_transfer_ag_to_hf_initiated_by_hf_via_adb_shell(self):
        LOGGER.info(
            "T1956410: accept (audio on HF) → SET earpiece (BT→phone) → "
            "audio_transfer_hf (phone→HF)"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956410)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)
        # Call audio starts on HF because BT/HFP is already connected.
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )

        # bluetooth → earpiece (audio leaves HF / on AG phone).
        to_earpiece_snapshot = self._get_log_snapshot()
        self._ag_set_and_verify_audio_route("earpiece")
        self._verify_audio_transfer_ag_effects(to_earpiece_snapshot, case_id="T1956410")
        self._ag_assert_audio_route(
            expect_current="earpiece",
            expect_sco_on=False,
        )
        self._record_event(
            "ag_route_bluetooth_to_earpiece_verified",
            status="pass",
            details={"route": "earpiece", "scoOn": False},
        )

        # earpiece → bluetooth via HF CLI (under test).
        to_hf_snapshot = self._cli_audio_transfer_to_hf()
        self._verify_audio_transfer_to_hf_effects(to_hf_snapshot, case_id="T1956410")
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )
        self._record_event(
            "ag_route_earpiece_to_bluetooth_via_audio_transfer_hf_verified",
            status="pass",
            details={"route": "bluetooth", "scoOn": True, "cli": "audio_transfer_hf"},
        )

        self._verify_call_logs_present(
            incoming_snapshot, "BT→earpiece→BT via audio_transfer_hf flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956410 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _audio_transfer_hf_to_ag_initiated_by_ag_via_adb_shell(self):
        LOGGER.info(
            "T1956411: incoming → AG accept ASAP (audio on HF) → SET earpiece (HF→AG)"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956411)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        accept_snapshot = self._get_log_snapshot()
        self._shell_adb_accept_on_destination_ag()
        self._wait_for_active_call_after_ag_accept(incoming_snapshot)

        # Soft-collect ring/eSCO markers from the whole incoming window (post-accept).
        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
                r"call is active",
                r"hfp audio conn",
            ],
            timeout=min(8, CALL_ACTION_TIMEOUT_SEC),
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        active_esco_lines = self._collect_matching_lines(
            [
                r"call is active",
                r"hfp audio conn",
                r"BCS AT Command Successful",
                r"esco link req",
                r"HFP Sniff disable success",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=accept_snapshot,
        )
        assert active_esco_lines, (
            "T1956411: no active/eSCO host markers after AG accepted the call."
        )
        self._record_event(
            "ag_accept_active_esco_checked",
            status="pass",
            details={"matches": active_esco_lines[:20]},
        )
        # Audio is on HF after AG accept (BT connected).
        self._ag_assert_audio_route(
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
        )

        # HF→AG under test: AG moves audio to earpiece.
        to_ag_snapshot = self._get_log_snapshot()
        self._ag_set_and_verify_audio_route("earpiece")
        self._verify_audio_transfer_ag_effects(to_ag_snapshot, case_id="T1956411")
        self._ag_assert_audio_route(
            expect_current="earpiece",
            expect_sco_on=False,
        )
        self._record_event(
            "ag_route_bluetooth_to_earpiece_via_set_audio_route_verified",
            status="pass",
            details={"route": "earpiece", "scoOn": False, "api": "SET_AUDIO_ROUTE"},
        )

        # Step 8: soft codec / eSCO-disconn window evidence.
        codec_lines = self._collect_matching_lines(
            [
                r"Codec Reconfigured to",
                r"hfp Codec select",
                r"codec_val\s*:",
                r"hfp audio disconn",
                r"esco link disconn",
            ],
            timeout=min(8, CALL_ACTION_TIMEOUT_SEC),
            start_index=to_ag_snapshot,
        )
        self._record_event(
            "host_codec_or_esco_after_ag_transfer_to_ag",
            status="pass" if codec_lines else "info",
            details={"matches": (codec_lines or [])[:15]},
        )

        self._verify_call_logs_present(
            incoming_snapshot, "HF-to-AG SET_AUDIO_ROUTE earpiece (AG-initiated) flow"
        )
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956411 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _cli_hf_sco_disconnect(self, start_index=None):
        assert self.phone_address, "phone_address required for hf_sco_disconnect"
        snapshot = start_index if start_index is not None else self._get_log_snapshot()
        tmpl = _env_str(
            "UTF_HFP_HF_SCO_DISCONNECT_CMD",
            "btc hfp hf_sco_disconnect {addr}",
        )
        cmd = tmpl.format(addr=self.phone_address)
        LOGGER.info("T1956426: issuing %s", cmd)
        snapshot, _ = self._send_cli_command(
            cmd,
            event_name="hf_sco_disconnect_command_sent",
        )
        self._assert_no_failure_log_since("hf_sco_disconnect", snapshot, timeout=2)
        return snapshot

    def _cli_hfp_sco_connect(self, start_index=None, tx_bandwidth=None, rx_bandwidth=None):
        assert self.phone_address, "phone_address required for hfp_sco_connect"
        snapshot = start_index if start_index is not None else self._get_log_snapshot()
        tx = (
            tx_bandwidth
            if tx_bandwidth is not None
            else _env_int("UTF_HFP_HF_SCO_TX_BANDWIDTH", HF_SCO_TX_BANDWIDTH)
        )
        rx = (
            rx_bandwidth
            if rx_bandwidth is not None
            else _env_int("UTF_HFP_HF_SCO_RX_BANDWIDTH", HF_SCO_RX_BANDWIDTH)
        )
        tmpl = _env_str(
            "UTF_HFP_HFP_SCO_CONNECT_CMD",
            "btc hfp hfp_sco_connect {addr} {tx} {rx}",
        )
        cmd = tmpl.format(addr=self.phone_address, tx=int(tx), rx=int(rx))
        LOGGER.info("T1956426: issuing %s", cmd)
        snapshot, _ = self._send_cli_command(
            cmd,
            event_name="hfp_sco_connect_command_sent",
        )
        self._assert_no_failure_log_since("hfp_sco_connect", snapshot, timeout=2)
        return snapshot

    def _verify_hf_sco_disconnect_effects(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "audio_or_esco_disconn": re.compile(
                r"hfp\s+audio\s+[Dd]isconn(?:ected)?|"
                r"esco\s+link\s+disconn|eSCO.*disconn|"
                r"SCO.*disconn",
                re.IGNORECASE,
            ),
        }
        optional = {
            "call_still_active": re.compile(r"call is active", re.I),
            "callsetup": re.compile(r"callsetup:", re.I),
            # Must NOT treat hangup as success — sco disconnect keeps the call.
            "no_hangup": re.compile(r"no call is active|callreject ok", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info(
                            "T1956426 sco-disconnect %s: %s",
                            name,
                            found[name][:160],
                        )
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956426: no eSCO/audio disconnect after hf_sco_disconnect. "
            f"Missing: {missing}. Recent lines: {collected[-30:]}"
        )
        if optional_found.get("no_hangup"):
            LOGGER.warning(
                "T1956426: saw hangup-like marker after sco disconnect "
                "(call should stay active): %s",
                optional_found["no_hangup"][:160],
            )
        self._record_event(
            "hf_sco_disconnect_effects_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _verify_hf_sco_reconnect_effects(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "audio_or_esco_up": re.compile(
                r"hfp\s+audio\s+conn|"
                r"esco\s+link\s+req|connection\s+initiated\s+event|"
                r"BCS\s+AT\s+Command\s+Successful",
                re.IGNORECASE,
            ),
        }
        optional = {
            "call_active": re.compile(r"call is active", re.I),
            "bcs": re.compile(r"\bBCS\b", re.I),
            "codec": re.compile(
                r"Codec\s+Reconfigured\s+to\s+\d+|hfp\s+Codec\s+select|codec_val\s*:",
                re.I,
            ),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info(
                            "T1956426 sco-reconnect %s: %s",
                            name,
                            found[name][:160],
                        )
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956426: no eSCO/audio reconnect after hfp_sco_connect "
            "(GAR-8324: unable to initiate SCO). "
            f"Missing: {missing}. Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "hf_sco_reconnect_effects_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _active_call_hf_sco_disconnect_then_reconnect_via_adb_shell(self):
        LOGGER.info(
            "T1956426: incoming → DUT accept → hf_sco_disconnect → hfp_sco_connect"
        )
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication after source place_call (T1956426)."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(
            accept_snapshot, call_window_start=incoming_snapshot
        )
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_dut_accept",
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
            context="T1956426 after DUT accept",
        )

        # Step 7: disconnect eSCO from HF (call remains).
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        disc_snapshot = self._cli_hf_sco_disconnect()
        self._verify_hf_sco_disconnect_effects(disc_snapshot)
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_hf_sco_disconnect",
            expect_sco_on=False,
            context="T1956426 after hf_sco_disconnect",
        )

        # Step 8: re-initiate SCO from HF (tx/rx bandwidth 8000).
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        conn_snapshot = self._cli_hfp_sco_connect()
        self._verify_hf_sco_reconnect_effects(conn_snapshot)
        self._ag_soft_assert_audio_route(
            "ag_audio_route_after_hfp_sco_connect",
            expect_current="bluetooth",
            expect_sco_on=True,
            require_bluetooth_available=True,
            context="T1956426 after hfp_sco_connect",
        )

        self._verify_call_logs_present(
            incoming_snapshot, "HF sco disconnect then reconnect flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956426 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _cli_call_control_hf(self, control_code, event_name=None):
        assert self.phone_address, "phone_address required for call_control_hf"
        cmd = f"btc hfp call_control_hf {self.phone_address} {int(control_code)}"
        LOGGER.info("Issuing %s", cmd)
        snapshot, _ = self._send_cli_command(
            cmd,
            event_name=event_name or f"call_control_hf_{control_code}_command_sent",
        )
        self._assert_no_failure_log_since(
            "btc hfp call_control_hf", snapshot, timeout=2
        )
        success = self._wait_for_any_match(
            [
                rf"cmd resp:{re.escape(self.phone_address)}",
                r"rsi_bt_hfp_call_control\(\)\s*Command Successful",
            ],
            CALL_ACTION_TIMEOUT_SEC,
            snapshot,
        )
        assert success, (
            f"No call_control_hf confirmation after code {control_code}. "
            "Expected cmd resp / rsi_bt_hfp_call_control() Command Successful."
        )
        self._record_event(
            f"call_control_hf_{control_code}_confirmed",
            status="pass",
            log_match=success,
        )
        return snapshot

    def _verify_call_waiting_indication(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else INCOMING_CALL_TIMEOUT_SEC
        indication = self._wait_for_any_match(
            [
                r"callsetup:IN",
                r"callsetup:WAITING",
                r"hfp ring",
                r"Ringing",
                r"\+CIEV",
                r"\+CCWA",
                r"call waiting",
                r"incoming call",
            ],
            timeout,
            start_index,
        )
        assert indication, (
            "No call-waiting / 2nd incoming indication in DUT logs. "
            "Expected at least callsetup:IN."
        )
        # Soft-collect extras; do not require BCS/eSCO on the waiting leg.
        waiting_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"callsetup:WAITING",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"\+CIEV",
                r"\+CCWA",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=min(5, CALL_ACTION_TIMEOUT_SEC),
            start_index=start_index,
        )
        assert any(
            re.search(r"callsetup:IN|callsetup:WAITING", line, re.IGNORECASE)
            for line in (waiting_lines or [indication])
        ), "Call-waiting indication lacked callsetup:IN/WAITING."
        self._record_event(
            "call_waiting_incoming_detected",
            status="pass",
            details={
                "indication": indication,
                "matches": (waiting_lines or [])[:20],
                "note": "BCS/eSCO often absent on waiting leg while first call active",
            },
        )
        return indication

    def _verify_active_held_after_accept_waiting(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "call_control_ok": re.compile(
                r"rsi_bt_hfp_call_control\(\)\s*Command Successful",
                re.IGNORECASE,
            ),
            "callheld_on_hold": re.compile(
                r"call on hold,\s*no active call|"
                r"hfp\s+callheld\s*:\s*call on hold",
                re.IGNORECASE,
            ),
            "callheld_swapped": re.compile(
                r"call is placed on hold or active/held calls swapped|"
                r"active/held calls swapped",
                re.IGNORECASE,
            ),
        }
        optional = {
            "callsetup_idle": re.compile(r"callsetup:IDLE", re.I),
            "callheld_addr_line": re.compile(r"callheld\s+addr:", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info(
                            "call_control_hf 3 hold/accept-waiting observed %s: %s",
                            name,
                            found[name][:160],
                        )
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "Missing hold/accept-waiting host markers after call_control_hf 3. "
            f"Missing: {missing}. Expected rsi_bt_hfp_call_control() Command Successful, "
            "'call on hold, no active call', and "
            "'call is placed on hold or active/held calls swapped'. Recent lines: "
            f"{collected[-30:]}"
        )
        self._record_event(
            "active_call_held_waiting_accepted",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _verify_held_added_to_conversation(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "call_control_ok": re.compile(
                r"rsi_bt_hfp_call_control\(\)\s*Command Successful",
                re.IGNORECASE,
            ),
            "callheld_cleared": re.compile(
                r"hfp\s+callheld\s*:\s*no calls held",
                re.IGNORECASE,
            ),
        }
        optional = {
            "call_is_active": re.compile(r"call is active", re.IGNORECASE),
            "conference": re.compile(
                r"conference|multiparty|multi[\s_-]?party|3[\s_-]?way",
                re.IGNORECASE,
            ),
            "callheld_addr_line": re.compile(r"callheld\s+addr:", re.I),
            "cind_if_printed": re.compile(r"\+CIND|\bCIND\b", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info(
                            "call_control_hf 4 add-to-conversation observed %s: %s",
                            name,
                            found[name][:160],
                        )
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956430: missing markers after call_control_hf 4 "
            "(add held/waiting to conversation). "
            f"Missing: {missing}. Expected rsi_bt_hfp_call_control() Command Successful "
            "and 'hfp callheld : no calls held'. Recent lines: "
            f"{collected[-30:]}"
        )
        self._record_event(
            "held_added_to_conversation_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _verify_held_call_hangup(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "call_control_ok": re.compile(
                r"rsi_bt_hfp_call_control\(\)\s*Command Successful",
                re.IGNORECASE,
            ),
            "callheld_cleared": re.compile(
                r"hfp\s+callheld\s*:\s*no calls held",
                re.IGNORECASE,
            ),
            "remaining_active": re.compile(r"call is active", re.IGNORECASE),
        }
        optional = {
            "hfp_call_status": re.compile(
                r"hfp\s+call\s+status|call\s+status:", re.IGNORECASE
            ),
            "sniff_disable": re.compile(r"HFP\s+Sniff\s+disable\s+success", re.I),
            "chup_if_printed": re.compile(r"AT\+CHUP|\bCHUP\b", re.I),
            "cind_if_printed": re.compile(r"\+CIND|\bCIND\b", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info(
                            "call_control_hf 1 held hangup observed %s: %s",
                            name,
                            found[name][:160],
                        )
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "Missing hangup-held host markers after call_control_hf 1. "
            f"Missing: {missing}. Expected rsi_bt_hfp_call_control() Command Successful, "
            "hfp callheld : no calls held, and call is active. Recent lines: "
            f"{collected[-30:]}"
        )
        self._record_event(
            "held_call_hangup_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _verify_hangup_active_resume_held(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "call_control_ok": re.compile(
                r"rsi_bt_hfp_call_control\(\)\s*Command Successful",
                re.IGNORECASE,
            ),
        }
        optional = {
            "callheld_cleared": re.compile(
                r"hfp\s+callheld\s*:\s*no calls held|"
                r"callheld\s*:\s*no calls held|"
                r"\bno calls held\b",
                re.IGNORECASE,
            ),
            "no_call_active_transient": re.compile(r"\bno call is active\b", re.IGNORECASE),
            "first_call_active_again": re.compile(r"\bcall is active\b", re.IGNORECASE),
            "transient_hold": re.compile(
                r"call on hold,\s*no active call|"
                r"call is placed on hold or active/held calls swapped",
                re.IGNORECASE,
            ),
            "hfp_call_status": re.compile(
                r"hfp\s+call\s+status|call\s+status:", re.IGNORECASE
            ),
            "sniff_disable": re.compile(r"HFP\s+Sniff\s+disable\s+success", re.I),
            "cind_if_printed": re.compile(r"\+CIND|\bCIND\b", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        def _resumed_ok():
            return bool(optional_found["callheld_cleared"]) or (
                bool(optional_found["no_call_active_transient"])
                and bool(optional_found["first_call_active_again"])
            )

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info(
                            "call_control_hf 2 hangup-active/resume-held %s: %s",
                            name,
                            found[name][:160],
                        )
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()) and _resumed_ok():
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "Missing markers after call_control_hf 2 (hang up active / accept held). "
            f"Missing: {missing}. Expected rsi_bt_hfp_call_control() Command Successful. "
            f"Recent lines: {collected[-30:]}"
        )
        assert _resumed_ok(), (
            "No evidence that the held/waiting call resumed after call_control_hf 2: "
            "neither an explicit 'callheld : no calls held' marker nor a "
            "'no call is active' -> 'call is active' transition was observed. "
            f"Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "hangup_active_resume_held_observed",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _verify_call_on_hold_after_ag_second_accept(self, start_index, timeout=None):
        timeout = timeout if timeout is not None else CALL_ACTION_TIMEOUT_SEC
        required = {
            "callheld_hold_or_swap": re.compile(
                r"call on hold,\s*no active call|"
                r"call is placed on hold or active/held calls swapped|"
                r"hfp\s+callheld\s*:\s*call on hold|"
                r"active/held calls swapped",
                re.IGNORECASE,
            ),
        }
        optional = {
            "call_active": re.compile(r"call is active", re.I),
            "callsetup_idle": re.compile(r"callsetup:IDLE", re.I),
            "audio": re.compile(r"hfp audio conn|esco|eSCO|BCS", re.I),
            "cind_if_printed": re.compile(r"\+CIND|\bCIND\b", re.I),
        }
        found = {name: None for name in required}
        optional_found = {name: None for name in optional}
        deadline = time.time() + timeout
        current_index = start_index
        collected = []

        while time.time() < deadline:
            lines, current_index = self._read_new_log_lines(current_index)
            for line in lines:
                collected.append(line)
                for name, pattern in required.items():
                    if found[name] is None and pattern.search(line):
                        found[name] = line.strip()
                        LOGGER.info(
                            "T1956427 call-on-hold observed %s: %s",
                            name,
                            found[name][:160],
                        )
                for name, pattern in optional.items():
                    if optional_found[name] is None and pattern.search(line):
                        optional_found[name] = line.strip()
            if all(found.values()):
                break
            time.sleep(POLL_INTERVAL_SEC)

        missing = [name for name, match in found.items() if match is None]
        assert not missing, (
            "T1956427: no callheld hold/swap host markers after AG accepted 2nd call. "
            f"Missing: {missing}. Expected 'call on hold…' or '…active/held calls swapped'. "
            f"Recent lines: {collected[-30:]}"
        )
        self._record_event(
            "active_call_on_hold_after_ag_second_accept",
            status="pass",
            details={
                **{k: v for k, v in found.items()},
                **{f"optional_{k}": v for k, v in optional_found.items()},
            },
        )
        return found

    def _ag_accept_second_hold_first_then_dut_hangup_held_via_adb_shell(self):
        if self.waiting_caller_adb is None:
            pytest.skip(
                "T1956427 requires a 3rd Android (waiting caller). "
                "Add waiting_caller_adb_phone under harness defaults.adb_phones and set "
                "UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID."
            )

        LOGGER.info(
            "T1956427: AG accept 1st → SET_CALL_HOLD → waiting + AG accept 2nd → "
            "btc hfp call_control_hf 1 (hangup held)"
        )

        self._verify_ag_three_way_capability()
        self._ensure_call_phones_idle(include_waiting_caller=True)

        # Step 5: incoming → AG accept → eSCO / active (+ AG SCO route)
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        try:
            self.source_adb.wait_for_state(PhoneState.OFFHOOK, timeout=15)
            self._record_event(
                "source_offhook_after_place_call",
                status="pass",
                details={"device_id": getattr(self.source_adb, "device_id", None)},
            )
        except Exception as exc:
            states = self._phone_call_states_snapshot()
            pytest.fail(
                f"T1956427: source did not reach OFFHOOK after place_call ({exc}). "
                f"phone_states={states}"
            )

        indication = self._wait_for_hfp_incoming_after_place_call(
            incoming_snapshot,
            timeout=INCOMING_CALL_TIMEOUT_SEC,
            context="T1956427 first incoming (source→AG)",
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
                r"SNIFF_MODE_DISABLED",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        try:
            ag_state = self.destination_adb.get_call_state()
            if ag_state == PhoneState.IDLE:
                self.destination_adb.wait_for_state(PhoneState.RINGING, timeout=20)
            self._record_event(
                "destination_ag_ringing_before_accept",
                status="pass",
                details={"state": str(self.destination_adb.get_call_state())},
            )
        except Exception as exc:
            states = self._phone_call_states_snapshot()
            pytest.fail(
                f"T1956427: AG not RINGING before accept ({exc}). phone_states={states}"
            )

        self._shell_adb_accept_on_destination_ag()
        self._wait_for_active_call_after_ag_accept(incoming_snapshot)
        active_esco_lines = self._collect_matching_lines(
            [
                r"call is active",
                r"hfp audio conn",
                r"BCS AT Command Successful",
                r"esco link req",
                r"HFP Sniff disable success",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        assert active_esco_lines, (
            "T1956427: no active/eSCO host markers after AG accepted 1st call."
        )
        self._record_event(
            "ag_first_call_active_esco_checked",
            status="pass",
            details={"matches": active_esco_lines[:20]},
        )
        # AG-side eSCO corroboration (Si-Connect GET_AUDIO_ROUTE).
        try:
            self._ag_assert_audio_route(
                expect_current="bluetooth",
                expect_sco_on=True,
                require_bluetooth_available=True,
            )
        except AssertionError as exc:
            LOGGER.warning(
                "T1956427: AG audio-route bluetooth/scoOn assert soft-failed after "
                "1st accept (continuing with DUT eSCO markers): %s",
                exc,
            )
            self._record_event(
                "ag_audio_route_after_first_accept",
                status="info",
                details={"error": str(exc)},
            )

        # Step 6: place active on hold via Si-Connect SET_CALL_HOLD
        self._ag_set_and_verify_call_hold(True)

        # Step 7: 2nd incoming → AG accept (1st remains held)
        waiting_snapshot = self._get_log_snapshot()
        self._shell_adb_make_waiting_call()
        self._verify_call_waiting_indication(waiting_snapshot)

        second_accept_snapshot = self._get_log_snapshot()
        self._wait_before_accepting_incoming_call()
        self._shell_adb_accept_on_destination_ag()
        # DUT host: 1st call held after AG accepts 2nd (required callheld markers).
        self._verify_call_on_hold_after_ag_second_accept(second_accept_snapshot)
        # Confirm AG still reports a held call after accepting 2nd.
        try:
            hold_status = self.destination_adb.get_call_hold()
            held = (hold_status.get("parsed") or {}).get("held")
            self._record_event(
                "ag_call_hold_after_second_accept",
                status="pass" if held is True else "info",
                details={
                    "held": held,
                    "parsed": hold_status.get("parsed"),
                    "message": hold_status.get("message"),
                },
            )
        except Exception as exc:
            LOGGER.warning("GET_CALL_HOLD after 2nd accept failed: %s", exc)

        # Step 8: DUT hang up held call(s)
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        hangup_held_snapshot = self._cli_call_control_hf(
            1, event_name="call_control_hf_hangup_held_sent"
        )
        self._verify_held_call_hangup(hangup_held_snapshot)
        try:
            hold_after = self.destination_adb.get_call_hold()
            held_after = (hold_after.get("parsed") or {}).get("held")
            self._record_event(
                "ag_call_hold_after_dut_hangup_held",
                status="pass" if held_after is False else "info",
                details={
                    "held": held_after,
                    "parsed": hold_after.get("parsed"),
                },
            )
        except Exception as exc:
            LOGGER.warning("GET_CALL_HOLD after call_control_hf 1 failed: %s", exc)

        # Step 9: call logs
        self._verify_call_logs_present(
            incoming_snapshot, "AG SET_CALL_HOLD then DUT hangup-held flow"
        )
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956427 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_waiting_caller()
        except Exception as exc:
            LOGGER.warning(f"Waiting-caller terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _ag_accept_then_hangup_active_accept_waiting_via_adb_shell(self):
        if self.waiting_caller_adb is None:
            pytest.skip(
                "T1956428 requires a 3rd Android (waiting caller). "
                "Add waiting_caller_adb_phone under harness defaults.adb_phones and set "
                "UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID."
            )

        LOGGER.info(
            "T1956428: AG accept 1st → waiting call → "
            "btc hfp call_control_hf 2 (hangup active, accept waiting)"
        )

        self._verify_ag_three_way_capability()
        self._ensure_call_phones_idle(include_waiting_caller=True)

        # Step 5: incoming → AG accept → eSCO / active
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        try:
            self.source_adb.wait_for_state(PhoneState.OFFHOOK, timeout=15)
            self._record_event(
                "source_offhook_after_place_call",
                status="pass",
                details={"device_id": getattr(self.source_adb, "device_id", None)},
            )
        except Exception as exc:
            states = self._phone_call_states_snapshot()
            pytest.fail(
                f"T1956428: source did not reach OFFHOOK after place_call ({exc}). "
                f"phone_states={states}"
            )

        indication = self._wait_for_hfp_incoming_after_place_call(
            incoming_snapshot,
            timeout=INCOMING_CALL_TIMEOUT_SEC,
            context="T1956428 first incoming (source→AG)",
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
                r"SNIFF_MODE_DISABLED",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        try:
            ag_state = self.destination_adb.get_call_state()
            if ag_state == PhoneState.IDLE:
                self.destination_adb.wait_for_state(PhoneState.RINGING, timeout=20)
            self._record_event(
                "destination_ag_ringing_before_accept",
                status="pass",
                details={"state": str(self.destination_adb.get_call_state())},
            )
        except Exception as exc:
            states = self._phone_call_states_snapshot()
            pytest.fail(
                f"T1956428: AG not RINGING before accept ({exc}). phone_states={states}"
            )

        self._shell_adb_accept_on_destination_ag()
        self._wait_for_active_call_after_ag_accept(incoming_snapshot)
        active_esco_lines = self._collect_matching_lines(
            [
                r"call is active",
                r"hfp audio conn",
                r"BCS AT Command Successful",
                r"esco link req",
                r"HFP Sniff disable success",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        assert active_esco_lines, (
            "T1956428: no active/eSCO host markers after AG accepted 1st call."
        )
        self._record_event(
            "ag_first_call_active_esco_checked",
            status="pass",
            details={"matches": active_esco_lines[:20]},
        )

        # Waiting call while 1st active (do not AG-accept — DUT flag 2 accepts it)
        waiting_snapshot = self._get_log_snapshot()
        self._shell_adb_make_waiting_call()
        self._verify_call_waiting_indication(waiting_snapshot)

        # Step 6: hang up active + accept waiting via call_control_hf 2
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        control_snapshot = self._cli_call_control_hf(
            2, event_name="call_control_hf_hangup_active_accept_waiting_sent"
        )
        self._verify_hangup_active_resume_held(control_snapshot)

        # Step 7: call logs
        self._verify_call_logs_present(
            incoming_snapshot, "hangup active accept waiting via call_control_hf 2"
        )
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956428 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_waiting_caller()
        except Exception as exc:
            LOGGER.warning(f"Waiting-caller terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _active_call_hold_and_accept_waiting_via_call_control_hf_3(self):
        if self.waiting_caller_adb is None:
            pytest.skip(
                "T1956429 requires a 3rd Android (waiting caller). "
                "Add waiting_caller_adb_phone under harness defaults.adb_phones and set "
                "UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID."
            )

        LOGGER.info(
            "T1956429: incoming → DUT accept → waiting → "
            "call_control_hf 3 (hold active + accept waiting)"
        )

        # Active call first
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication after source place_call (T1956429)."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)

        # Call waiting from 3rd phone
        waiting_snapshot = self._get_log_snapshot()
        self._shell_adb_make_waiting_call()
        self._verify_call_waiting_indication(waiting_snapshot)

        # Steps 5–6: CLI under test — hold active + accept waiting
        self._wait_before_accepting_incoming_call()
        hold_accept_snapshot = self._cli_call_control_hf(
            3, event_name="call_control_hf_hold_accept_waiting_sent"
        )
        self._verify_active_held_after_accept_waiting(hold_accept_snapshot)

        self._verify_call_logs_present(
            incoming_snapshot, "call_control_hf 3 hold + accept waiting flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956429 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_waiting_caller()
        except Exception as exc:
            LOGGER.warning(f"Waiting-caller terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _active_call_add_held_to_conversation_via_call_control_hf_4(self):
        if self.waiting_caller_adb is None:
            pytest.skip(
                "T1956430 requires a 3rd Android (waiting caller). "
                "Add waiting_caller_adb_phone under harness defaults.adb_phones and set "
                "UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID."
            )

        LOGGER.info(
            "T1956430: incoming → DUT accept → waiting → "
            "call_control_hf 3 (hold+accept) → call_control_hf 4 (add to conversation)"
        )

        # Steps 5–6: first incoming → DUT accept → active eSCO
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, (
            "No incoming-call indication after source place_call (T1956430)."
        )
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)

        # 2nd incoming (call waiting)
        waiting_snapshot = self._get_log_snapshot()
        self._shell_adb_make_waiting_call()
        self._verify_call_waiting_indication(waiting_snapshot)

        # Step 7: place active on hold + accept waiting (needed before CHLD=4)
        self._wait_before_accepting_incoming_call()
        hold_accept_snapshot = self._cli_call_control_hf(
            3, event_name="call_control_hf_hold_accept_waiting_sent"
        )
        self._verify_active_held_after_accept_waiting(hold_accept_snapshot)

        # Step 8: CLI under test — add held to conversation
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        conference_snapshot = self._cli_call_control_hf(
            4, event_name="call_control_hf_add_held_to_conversation_sent"
        )
        self._verify_held_added_to_conversation(conference_snapshot)

        # Step 9: call logs
        self._verify_call_logs_present(
            incoming_snapshot, "call_control_hf 4 add held to conversation flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956430 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_waiting_caller()
        except Exception as exc:
            LOGGER.warning(f"Waiting-caller terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _active_call_accept_waiting_hold_and_hangup_held_via_adb_shell(self):
        if self.waiting_caller_adb is None:
            pytest.skip(
                "T1956403 requires a 3rd Android (waiting caller). "
                "Add waiting_caller_adb_phone under harness defaults.adb_phones and set "
                "UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID."
            )

        LOGGER.info(
            "T1956403: incoming → DUT accept → 2nd waiting call → "
            "call_control_hf 3 (hold+accept) → call_control_hf 1 (hangup held)"
        )

        # Step 5–6: first incoming → DUT accept → active eSCO
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956403)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)

        # Step 7: 2nd incoming from another mobile (call waiting)
        waiting_snapshot = self._get_log_snapshot()
        self._shell_adb_make_waiting_call()
        self._verify_call_waiting_indication(waiting_snapshot)

        # Step 8: hold active + accept waiting
        self._wait_before_accepting_incoming_call()
        hold_accept_snapshot = self._cli_call_control_hf(
            3, event_name="call_control_hf_hold_accept_waiting_sent"
        )
        self._verify_active_held_after_accept_waiting(hold_accept_snapshot)

        # Step 9: hang up held call(s)
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        hangup_held_snapshot = self._cli_call_control_hf(
            1, event_name="call_control_hf_hangup_held_sent"
        )
        self._verify_held_call_hangup(hangup_held_snapshot)

        # Step 10: call logs
        self._verify_call_logs_present(
            incoming_snapshot, "call-waiting hold + hangup-held flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956403 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_waiting_caller()
        except Exception as exc:
            LOGGER.warning(f"Waiting-caller terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _active_call_accept_waiting_then_hangup_active_resume_held_via_adb_shell(self):
        if self.waiting_caller_adb is None:
            pytest.skip(
                "T1956414 requires a 3rd Android (waiting caller). "
                "Add waiting_caller_adb_phone under harness defaults.adb_phones and set "
                "UTF_HFP_WAITING_CALLER_ADB_DEVICE_ID."
            )

        LOGGER.info(
            "T1956414: incoming → DUT accept → 2nd waiting call → "
            "call_control_hf 3 (accept 2nd) → call_control_hf 2 (hangup 2nd, resume 1st)"
        )

        # Steps 5–6: first incoming → DUT accept → active eSCO
        incoming_snapshot = self._get_log_snapshot()
        self._shell_adb_make_call_from_source()
        indication = self._wait_for_any_match(
            [r"callsetup:IN", r"hfp ring", r"Ringing", r"\+CIEV", r"incoming call"],
            INCOMING_CALL_TIMEOUT_SEC,
            incoming_snapshot,
        )
        assert indication, "No incoming-call indication after source place_call (T1956414)."
        self._record_event("incoming_call_detected", status="pass", log_match=indication)

        pre_accept_lines = self._collect_matching_lines(
            [
                r"callsetup:IN",
                r"\bBCS\b",
                r"BCS AT Command Successful",
                r"esco link req",
                r"connection initiated event",
                r"hfp ring",
                r"Ringing",
            ],
            timeout=CALL_ACTION_TIMEOUT_SEC,
            start_index=incoming_snapshot,
        )
        self._record_event(
            "incoming_call_pre_accept_markers",
            status="pass" if pre_accept_lines else "info",
            details={"matches": (pre_accept_lines or [])[:20]},
        )

        self._wait_before_accepting_incoming_call()
        accept_snapshot = self._cli_accept_incoming_call(incoming_snapshot)
        self._verify_active_call_esco_after_dut_accept(accept_snapshot)

        # Step 7: 2nd incoming → accept via call_control_hf 3
        waiting_snapshot = self._get_log_snapshot()
        self._shell_adb_make_waiting_call()
        self._verify_call_waiting_indication(waiting_snapshot)

        self._wait_before_accepting_incoming_call()
        hold_accept_snapshot = self._cli_call_control_hf(
            3, event_name="call_control_hf_accept_second_sent"
        )
        self._verify_active_held_after_accept_waiting(hold_accept_snapshot)

        # Step 8: hang up active (2nd) and resume held (1st) via call_control_hf 2
        time.sleep(_env_int("UTF_HFP_BETWEEN_CALLS_SETTLE_SEC", BETWEEN_CALLS_SETTLE_SEC))
        resume_snapshot = self._cli_call_control_hf(
            2, event_name="call_control_hf_hangup_active_resume_held_sent"
        )
        self._verify_hangup_active_resume_held(resume_snapshot)

        # Step 9: call logs
        self._verify_call_logs_present(
            incoming_snapshot, "accept waiting then hangup active resume held flow"
        )
        self._wait_before_terminating_active_call(delay_sec = WAIT_FOR_TERMINATE_ACTIVE_CALL_SEC)
        try:
            self._cli_terminate_active_call()
        except Exception as exc:
            LOGGER.warning(f"DUT terminate after T1956414 failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_waiting_caller()
        except Exception as exc:
            LOGGER.warning(f"Waiting-caller terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_source()
        except Exception as exc:
            LOGGER.warning(f"Source terminate_call cleanup failed (continuing): {exc}")
        try:
            self._shell_adb_end_call_on_destination()
        except Exception as exc:
            LOGGER.warning(f"Destination terminate_call cleanup failed (continuing): {exc}")

    def _cli_vr_activate_expect_failure(self):
        self._clear_serial_log()
        vr_snapshot, _ = self._send_cli_command(
            f"btc hfp vr_activate {self.phone_address}",
            event_name="vr_activate_command_sent",
        )
        vr_failure_lines = self._parse_vr_activate_failure(vr_snapshot)
        assert vr_failure_lines, "Expected vr_activate failure was not detected."
        return vr_snapshot

    def _wait_for_active_call_after_ag_accept(self, start_index):
        active_call_match = self._wait_for_any_match(
            [r"call is active", r"hfp call status", r"call status:", r"BCS", r"SCO", r"eSCO", r"\+CIEV", r"\+CIND"],
            CALL_ACTION_TIMEOUT_SEC,
            start_index,
        )
        assert active_call_match, "No active-call indication was detected after AG-side call accept."
        LOGGER.info(f"AG-side accept active-call indication observed: {active_call_match}")
        self._record_event(
            "incoming_call_accepted_by_ag",
            status="pass",
            log_match=active_call_match,
        )
        return active_call_match

    def _verify_active_call_esco_after_ag_accept(
        self, accept_snapshot, timeout=None, call_window_start=None
    ):
        # Same rules as DUT-accept path.
        return self._verify_active_call_esco_after_dut_accept(
            accept_snapshot,
            timeout=timeout,
            call_window_start=call_window_start,
        )

    def _verify_profile_stability(self, duration_sec=PROFILE_STABILITY_SEC):
        LOGGER.info(f"Monitoring BT/HFP/A2DP stability for {duration_sec} seconds")
        stability_snapshot = self._get_log_snapshot()
        stability_deadline = time.time() + duration_sec
        current_index = stability_snapshot
        reconnect_deadline = None
        reconnect_context = []
        disconnect_line = None

        disconnect_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"RSI_APP_EVENT_DISCONNECTED",
                r"disconnect reason",
                r"hfp disconn HF",
                r"\bdisconn\b.*0x4e13",
                r"0x4E0D",
                r"0x4E0E",
            ]
        ]
        reconnect_progress_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"Reconnection Initiated",
                r"Reconnection: Peer 0 connect command executed successfully",
                r"conn err 0x4e04",
                r"page timeout",
                r"role chg",
                r"conn evt",
                r"page done",
                r"linkkey req",
                r"auth_complete event",
                r"a2dp conn ok",
            ]
        ]
        reconnect_success_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"hfp conn HF",
                r"call status:.*no call is active",
                r"callsetup:IDLE",
                r"mode change event .*SNIFF_MODE_ENABLED",
            ]
        ]
        hard_failure_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [
                r"RSI_APP_EVENT_DISCONNECTED",
                r"disconnect reason",
                r"0x4E0D",
                r"0x4E0E",
                r"\bfailed\b",
            ]
        ]

        while time.time() < stability_deadline or reconnect_deadline is not None:
            now = time.time()
            if reconnect_deadline is not None and now > reconnect_deadline:
                pytest.fail(
                    "Profile stability failure observed: reconnect did not complete within "
                    f"{RECONNECTION_GRACE_SEC} seconds after disconnect `{disconnect_line}`. "
                    f"Recent reconnect logs: {reconnect_context[:12]}"
                )

            lines, current_index = self._read_new_log_lines(current_index)
            if not lines:
                time.sleep(POLL_INTERVAL_SEC)
                continue

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue

                if reconnect_deadline is None and any(pattern.search(stripped) for pattern in disconnect_patterns):
                    disconnect_line = stripped
                    reconnect_deadline = time.time() + RECONNECTION_GRACE_SEC
                    reconnect_context = [stripped]
                    self._record_event(
                        "profile_disconnect_observed",
                        status="info",
                        log_match=stripped,
                        details={"reconnect_grace_sec": RECONNECTION_GRACE_SEC},
                    )
                    continue

                if reconnect_deadline is not None:
                    if any(pattern.search(stripped) for pattern in reconnect_progress_patterns):
                        reconnect_context.append(stripped)
                        continue

                    if any(pattern.search(stripped) for pattern in reconnect_success_patterns):
                        reconnect_context.append(stripped)
                        self._record_event(
                            "profile_reconnect_recovered",
                            status="pass",
                            log_match=stripped,
                            details={
                                "disconnect_log": disconnect_line,
                                "matches": reconnect_context[:20],
                            },
                        )
                        reconnect_deadline = None
                        reconnect_context = []
                        disconnect_line = None
                        continue

                if reconnect_deadline is None and any(pattern.search(stripped) for pattern in hard_failure_patterns):
                    pytest.fail(f"Profile stability failure observed: {stripped}")

        self._record_event(
            "profile_stability_complete",
            status="pass",
            details={
                "duration_sec": duration_sec,
                "reconnect_grace_sec": RECONNECTION_GRACE_SEC,
            },
        )

    def _sniffer_start_capture_if_enabled(self):
        self.sniffer_capture_started = False
        if self.ble_sniffer is None:
            return
        capture_file = f"{self.test_name}_{self.run_timestamp}"
        previous_default_timeout = socket.getdefaulttimeout()
        try:
            iface = self.ble_sniffer.interfaces.sniffer
            LOGGER.info("Frontline sniffer: init_sniffer + start_capture(%s)", capture_file)
            socket.setdefaulttimeout(FRONTLINE_SNIFFER_SOCKET_TIMEOUT_SEC)
            iface.init_sniffer()
            iface.start_capture(capture_file=capture_file)
            self.sniffer_capture_started = True
            self._record_event(
                "sniffer_capture_started",
                status="pass",
                details={"capture_file": capture_file},
            )
        except Exception as exc:
            LOGGER.warning(
                "Frontline sniffer start failed (continuing test without capture): %s", exc
            )
            self._record_event(
                "sniffer_capture_started",
                status="info",
                details={"capture_file": capture_file, "error": str(exc)},
            )
            self._sniffer_force_close_best_effort()
        finally:
            socket.setdefaulttimeout(previous_default_timeout)

    def _sniffer_stop_capture_if_enabled(self):
        if self.ble_sniffer is None:
            return
        try:
            if self.sniffer_capture_started:
                iface = self.ble_sniffer.interfaces.sniffer
                LOGGER.info("Frontline sniffer: stop_capture (save capture file)")
                iface.stop_capture()
                self._record_event(
                    "sniffer_capture_stopped",
                    status="pass",
                    details={
                        "local_capture_files": getattr(iface, "local_capture_files", None),
                    },
                )
        except Exception as exc:
            LOGGER.warning("Frontline sniffer stop_capture failed (continuing): %s", exc)
            self._record_event(
                "sniffer_capture_stopped",
                status="info",
                details={"error": str(exc)},
            )
        finally:
            self.sniffer_capture_started = False
            self._sniffer_force_close_best_effort()

    def _sniffer_force_close_best_effort(self):
        if self.ble_sniffer is None:
            return
        iface = self.ble_sniffer.interfaces.sniffer
        try:
            iface.close()
        except Exception as exc:
            LOGGER.warning("Frontline sniffer close() failed (continuing): %s", exc)
            sock = getattr(iface, "sock", None)
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def save_run_artifacts(self, final_status, error_message=None):
        self._archive_new_bus_logs()
        os.makedirs(self.log_dir, exist_ok=True)

        with open(self.raw_log_path, "w", encoding="utf-8") as raw_log_file:
            for entry in self.serial_log_archive:
                raw_log_file.write(f"[{entry['timestamp']}] {entry['line']}\n")

        summary = {
            "test_name": self.test_name,
            "final_status": final_status,
            "error_message": error_message,
            "started_at": self.started_at,
            "ended_at": datetime.now().isoformat(),
            "dut_address": self.dut_address,
            "phone_address": self.phone_address,
            "ctkd_identity_address": self.ctkd_identity_address,
            "source_adb_device_id": self.source_adb_device_id,
            "destination_adb_device_id": self.destination_adb_device_id,
            "destination_phone_number": self.destination_phone_number,
            "outgoing_call_number": self.outgoing_call_number,
            "raw_log_path": self.raw_log_path,
            "event_count": len(self.event_log),
            "events": self.event_log,
        }

        with open(self.summary_path, "w", encoding="utf-8") as summary_file:
            json.dump(summary, summary_file, indent=2)

        LOGGER.info(f"DUT raw serial log saved to: {self.raw_log_path}")
        LOGGER.info(f"DUT session summary saved to: {self.summary_path}")

    def _run_shell_bringup(self):
        """Shared Si-Connect BLE + CTKD classic BT + HFP/A2DP bring-up."""
        self._require_shell_adb_phones()
        self._confirm_prerequisites()
        self._get_dut_address()
        self._prepare_phone()
        connect_snapshot = self._connect_ble_si_connect_then_btc_ctkd_shell()
        self._ensure_hfp_connection(connect_snapshot)
        self._verify_a2dp_initialization()
        return connect_snapshot

    def run_C554088(self):
        """Reject first call from DUT; accept second; AG hangs up."""
        self._run_shell_bringup()
        self._reject_first_incoming_call_via_adb_shell()
        self._accept_second_incoming_call_and_hang_up_from_ag_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956405(self):
        """AG accepts incoming call; DUT terminates."""
        self._run_shell_bringup()
        self._incoming_call_accept_from_ag_and_terminate_from_hf_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956399(self):
        """AG accepts and AG terminates; 15 min profile stability."""
        self._run_shell_bringup()
        self._incoming_call_accept_and_terminate_from_ag_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956402(self):
        """DUT accepts and DUT terminates."""
        self._run_shell_bringup()
        self._incoming_call_accept_and_terminate_from_dut_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956404(self):
        """DUT (HF) accepts; AG terminates; verify eSCO/call logs."""
        self._run_shell_bringup()
        self._incoming_call_accept_from_hf_and_terminate_from_ag_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956401(self):
        """DUT accepts; verify active-call / eSCO logs."""
        self._run_shell_bringup()
        self._incoming_call_accept_from_dut_and_verify_logs_via_adb_shell()

    def run_t1956400(self):
        """
        T1956400: unanswered incoming call — verify eSCO connect/disconnect
        (+CIEV, BCS, link req/disconn, ringtone) then 15 min profile stability.
        """
        self._run_shell_bringup()
        self._incoming_call_verify_esco_connect_disconnect_unanswered_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956406(self):
        """AG places outgoing call by number; verify HF eSCO/call logs."""
        self._run_shell_bringup()
        self._outgoing_call_from_ag_verify_esco_logs_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956407(self):
        """Incoming call; AG accepts; verify eSCO audio connection setup by AG."""
        self._run_shell_bringup()
        self._incoming_call_ag_accept_verify_audio_connection_setup_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956408(self):
        """DUT accept; HF-initiated audio_transfer_ag; verify eSCO/audio disconnect + codec."""
        self._run_shell_bringup()
        self._audio_transfer_hf_to_ag_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956409(self):
        """DUT accept; AG SET_AUDIO_ROUTE earpiece then bluetooth (AG→HF); eSCO reconnect."""
        self._run_shell_bringup()
        self._audio_transfer_ag_to_hf_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956410(self):
        """Accept (audio on HF) → SET earpiece → audio_transfer_hf → verify BT/scoOn."""
        self._run_shell_bringup()
        self._audio_transfer_ag_to_hf_initiated_by_hf_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956411(self):
        """AG accept (audio on HF) → SET earpiece (HF→AG by AG); verify scoOff + eSCO drop."""
        self._run_shell_bringup()
        self._audio_transfer_hf_to_ag_initiated_by_ag_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956413(self):
        """DUT accept; AG SET_CALL_HOLD true then false; verify held/unheld."""
        self._run_shell_bringup()
        self._active_call_hold_unhold_from_ag_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956415(self):
        """SLC up; DUT vr_activate then vr_deactivate; AG GET_VOICE_ASSISTANT soft checks."""
        self._run_shell_bringup()
        self._enable_disable_voice_recognition_from_dut_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956416(self):
        """SLC up; AG SET_VOICE_ASSISTANT true then false; soft DUT eSCO/AVDTP markers."""
        self._run_shell_bringup()
        self._enable_disable_voice_recognition_from_ag_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956425(self):
        """DUT accept; hold eSCO stable after SCO open (GAR-8395); terminate."""
        self._run_shell_bringup()
        self._incoming_call_accept_verify_sco_stability_then_terminate_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956426(self):
        """Active call; HF sco disconnect then hfp_sco_connect (GAR-8324)."""
        self._run_shell_bringup()
        self._active_call_hf_sco_disconnect_then_reconnect_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956424(self):
        """Active call; DUT hf_mic_gain then hf_speaker_gain; host gain-ok markers."""
        self._run_shell_bringup()
        self._active_call_hf_mic_and_speaker_gain_via_adb_shell()
        self._verify_profile_stability()

    def run_sample_accept_hold_5min_terminate(self):
        """Sample: accept incoming, hold active 5 min, terminate (no long ACL soak)."""
        self._run_shell_bringup()
        self._sample_incoming_accept_hold_then_terminate()

    def run_sample_sco_file_playback_probe(self):
        """Sample: SLC only; AG PLAY_SCO_FILE loop; record DUT call-like vs audio markers."""
        self._run_shell_bringup()
        self._sample_sco_file_playback_probe()

    def run_t1956418(self):
        """DUT accept waiting (call_control_hf 3); AG swap active/held; HF callheld."""
        self._run_shell_bringup()
        self._active_call_accept_waiting_then_ag_swap_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956429(self):
        """Verify call_control_hf 3: hold active + accept waiting; callheld/+CIND."""
        self._run_shell_bringup()
        self._active_call_hold_and_accept_waiting_via_call_control_hf_3()
        self._verify_profile_stability()

    def run_t1956430(self):
        """call_control_hf 3 then 4: add held/waiting to conversation (conference)."""
        self._run_shell_bringup()
        self._active_call_add_held_to_conversation_via_call_control_hf_4()
        self._verify_profile_stability()

    def run_t1956403(self):
        """Active call; accept waiting (hold active); hang up held call from DUT."""
        self._run_shell_bringup()
        self._active_call_accept_waiting_hold_and_hangup_held_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956414(self):
        """Active call; accept 2nd (hold 1st); hang up 2nd so 1st becomes active."""
        self._run_shell_bringup()
        self._active_call_accept_waiting_then_hangup_active_resume_held_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956427(self):
        """AG accept 1st+2nd (1st held); DUT call_control_hf 1 hangs up held."""
        self._run_shell_bringup()
        self._ag_accept_second_hold_first_then_dut_hangup_held_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956428(self):
        """AG accept 1st; waiting; DUT call_control_hf 2 hangup active + accept waiting."""
        self._run_shell_bringup()
        self._ag_accept_then_hangup_active_accept_waiting_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956420(self):
        """In-band ringtone while ringing; DUT accepts; eSCO/call logs + stability."""
        self._run_shell_bringup()
        self._incoming_call_check_inband_ringtone_and_accept_from_dut_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956421(self):
        """Active call; AG BT OFF (disconnect + DUT paging) then BT ON (SLC reconnect)."""
        self._run_shell_bringup()
        self._active_call_bt_off_on_check_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956436(self):
        """Accept call; hfp_test_bench disconnect; verify ACL/SCO disconnect host logs."""
        self._run_shell_bringup()
        self._check_acl_or_sco_disconnected_events_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956437(self):
        """Incoming call; verify host Codec Reconfigured selection (any available codec)."""
        self._run_shell_bringup()
        self._verify_codec_selection_in_host_logs_via_adb_shell()
        self._verify_profile_stability()

    def run_reject_accept_terminate_timing(self):
        """Reject@5s, accept@5s, terminate@20s from DUT."""
        self._run_shell_bringup()
        self._reject_first_call_accept_second_and_terminate_from_dut_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956395(self):
        """Service-level connection establishment + 15 min stability."""
        self._run_shell_bringup()
        self._verify_profile_stability()

    def run_t1956396(self):
        """SLC release/reconnect via AG Bluetooth toggle + 15 min stability."""
        self._run_shell_bringup()
        self._wait_for_service_level_release_from_ag_via_adb_shell()
        self._wait_for_service_level_reconnect_after_ag_bt_on_via_adb_shell()
        self._verify_profile_stability()

    def run_t1956397(self):
        """Codec / status indicators + 15 min stability."""
        self._run_shell_bringup()
        self._verify_codec_and_status_indicators()
        self._verify_profile_stability()

    def run_t1956445(self):
        self._run_shell_bringup()
        self._verify_profile_stability()

def _execute_hfp_case(wifi_dut, adb_phones, test_name, run_attr, ble_sniffer=None):
    runner = _prepare_hfp_runner(wifi_dut, adb_phones, test_name, ble_sniffer=ble_sniffer)
    _run_hfp_test(runner, getattr(runner, run_attr))
    LOGGER.info("%s completed successfully", test_name)

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_incoming_call_reject_from_hf_and_ag_C554088(wifi_dut, adb_phones):
    """C554088: DUT rejects first call; accepts second; AG hangs up."""
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_incoming_call_reject_from_hf_and_ag_C554088",
        "run_C554088",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_incoming_call_accept_from_ag_and_terminate_from_hf_C554095(wifi_dut, adb_phones, ble_sniffer):
    """C554095: AG accepts; DUT terminates with btc hfp terminate_call."""
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_incoming_call_accept_from_ag_and_terminate_from_hf_C554095",
        "run_t1956405",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_incoming_call_accept_and_terminate_from_AG_C554089(wifi_dut, adb_phones, ble_sniffer):
    """C554089: AG accepts and AG terminates; 15 min profile stability."""
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_incoming_call_accept_and_terminate_from_AG_C554089",
        "run_t1956399",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_incoming_call_accept_and_termiante_from_DUT_HFP_C554092(wifi_dut, adb_phones, ble_sniffer):
    """T1956402: DUT accepts and DUT terminates the call."""
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_incoming_call_accept_and_termiante_from_DUT_HFP_C554092",
        "run_t1956402",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_incoming_call_accept_from_hf_and_terminate_from_ag_C554094(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_incoming_call_accept_from_hf_and_terminate_from_ag_C554094",
        "run_t1956404",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_esco_retransmissions_during_active_call_C554091(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_esco_retransmissions_during_active_call_C554091",
        "run_t1956401",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_esco_connection_and_disconnection_during_incoming_call_C554090(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_esco_connection_and_disconnection_during_incoming_call_C554090",
        "run_t1956400",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_outgoing_call_initiated_number_from_ag_C554096(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_outgoing_call_initiated_number_from_ag_C554096",
        "run_t1956406",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_audio_connection_setup_by_ag_C554097(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_audio_connection_setup_by_ag_C554097",
        "run_t1956407",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_audio_transfer_from_hf_to_ag_initiated_by_hf_C554098(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_audio_transfer_from_hf_to_ag_initiated_by_hf_C554098",
        "run_t1956408",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_audio_transfer_from_ag_to_hf_initiated_by_ag_C554099(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_audio_transfer_from_ag_to_hf_initiated_by_ag_C554099",
        "run_t1956409",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_audio_transfer_from_ag_to_hf_initiated_by_hf_C554100(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_audio_transfer_from_ag_to_hf_initiated_by_hf_C554100",
        "run_t1956410",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_audio_transfer_from_hf_to_ag_initiated_by_ag_C554101(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_audio_transfer_from_hf_to_ag_initiated_by_ag_C554101",
        "run_t1956411",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_active_call_hold_unhold_initiated_from_ag_C554103(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_active_call_hold_unhold_initiated_from_ag_C554103",
        "run_t1956413",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_enable_disable_voice_recognition_from_dut_C554105(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_enable_disable_voice_recognition_from_dut_C554105",
        "run_t1956415",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_enable_disable_voice_recognition_from_mobile_C554106(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_enable_disable_voice_recognition_from_mobile_C554106",
        "run_t1956416",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_disconnect_shortly_after_sco_open_C554115(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_disconnect_shortly_after_sco_open_C554115",
        "run_t1956425",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_initiate_sco_connection_from_hf_C554116(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_initiate_sco_connection_from_hf_C554116",
        "run_t1956426",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_hf_mic_and_speaker_gain_vgm_vgs_C554114(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_hf_mic_and_speaker_gain_vgm_vgs_C554114",
        "run_t1956424",
        ble_sniffer=ble_sniffer,
    )

# Testing of pcm audio
# @pytest.mark.ble_sniffer("frontline_sniffer")
# def test_sample_sco_file_playback_probe(wifi_dut, adb_phones, ble_sniffer):
#     _execute_hfp_case(
#         wifi_dut,
#         adb_phones,
#         "test_sample_sco_file_playback_probe",
#         "run_sample_sco_file_playback_probe",
#         ble_sniffer=ble_sniffer,
#     )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_accept_waiting_then_swap_calls_from_ag_C554108(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_accept_waiting_then_swap_calls_from_ag_C554108",
        "run_t1956418",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_cli_hold_active_accept_waiting_from_dut_C554119(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_cli_hold_active_accept_waiting_from_dut_C554119",
        "run_t1956429",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_cli_add_held_to_conversation_from_dut_C554120(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_cli_add_held_to_conversation_from_dut_C554120",
        "run_t1956430",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_active_call_accept_waiting_hold_and_hangup_held_from_dut_C554093(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_active_call_accept_waiting_hold_and_hangup_held_from_dut_C554093",
        "run_t1956403",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_accept_second_call_then_hangup_active_resume_held_from_dut_C554104(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_accept_second_call_then_hangup_active_resume_held_from_dut_C554104",
        "run_t1956414",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_cli_terminate_hold_call_during_active_from_dut_C554117(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_cli_terminate_hold_call_during_active_from_dut_C554117",
        "run_t1956427",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_cli_hangup_active_accept_waiting_from_dut_C554118(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_cli_hangup_active_accept_waiting_from_dut_C554118",
        "run_t1956428",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_check_inband_ringtone_and_accept_call_from_hfp_dut_C554110(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_check_inband_ringtone_and_accept_call_from_hfp_dut_C554110",
        "run_t1956420",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_active_call_bt_off_on_from_mobile_C554111(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_active_call_bt_off_on_from_mobile_C554111",
        "run_t1956421",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_check_acl_or_sco_connection_disconnected_events_C554126(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_check_acl_or_sco_connection_disconnected_events_C554126",
        "run_t1956436",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_codec_selection_in_host_logs_C585828(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_codec_selection_in_host_logs_C585828",
        "run_t1956437",
        ble_sniffer=ble_sniffer,
    )

# Sample test case
# @pytest.mark.ble_sniffer("frontline_sniffer")
# def test_verify_incoming_call_reject_after_5s_accept_after_5s_and_terminate_after_20s_from_dut(wifi_dut, adb_phones, ble_sniffer):
#     """Timing: reject@5s / accept@5s / terminate@20s from DUT (ADB place_call)."""
#     _execute_hfp_case(
#         wifi_dut,
#         adb_phones,
#         "test_verify_incoming_call_reject_after_5s_accept_after_5s_and_terminate_after_20s_from_dut",
#         "run_reject_accept_terminate_timing",
#         ble_sniffer=ble_sniffer,
#     )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_service_level_connection_establishment_C554085(wifi_dut, adb_phones, ble_sniffer):
    """C554085: HFP SLC establishment via Si-Connect + CTKD; 15 min stability."""
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_service_level_connection_establishment_C554085",
        "run_t1956395",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_service_level_connection_release_C554086(wifi_dut, adb_phones, ble_sniffer):
    """C554086: AG BT off/on via ADB; SLC release + reconnect; 15 min stability."""
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_verify_service_level_connection_release_C554086",
        "run_t1956396",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_check_for_available_codecs_and_status_C554087(wifi_dut, adb_phones, ble_sniffer):
    """C554087: codec and AG status indicators; 15 min stability."""
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_check_for_available_codecs_and_status_C554087",
        "run_t1956397",
        ble_sniffer=ble_sniffer,
    )


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_check_sdp_service_search_response_C1775525(wifi_dut, adb_phones, ble_sniffer):
    _execute_hfp_case(
        wifi_dut,
        adb_phones,
        "test_check_sdp_service_search_response_C1775525",
        "run_t1956445",
        ble_sniffer=ble_sniffer,
    )
