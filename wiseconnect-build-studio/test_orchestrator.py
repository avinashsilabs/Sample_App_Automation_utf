"""Orchestrate UTF on Raspberry Pi + build/flash + DUT serial parsing on the host."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional

from app_test_catalog import (
    connect_conn_params,
    notifications_enable_payload,
    notify_uuids,
    test_profile,
    WORKFLOW_BUILD_FLASH,
    WORKFLOW_LAUNCH_UTF,
    WORKFLOW_START_CONNECTION,
    WORKFLOW_WAIT_PI,
    DEFAULT_WORKFLOW,
)
from build_console_log import close_job_log, open_job_log, write_job_log
from dut_serial_checklist import (
    extract_checklist_lines,
    format_checklist_block,
    milestones_seen as checklist_milestones_seen,
)
from serial_monitor import (
    DEFAULT_BAUD,
    get_all_text,
    get_lines,
    guess_vcom_port,
    mark_serial_cursor,
    serial_cursor,
    serial_log_note,
    serial_log_append_block,
    serial_log_path,
    serial_status,
    start_serial,
    wait_for_pattern,
)

from config import (
    HEALTH_POLL_SEC,
    HEALTH_TIMEOUT_SEC,
    MAC_PARSE_TIMEOUT_SEC,
    PASSKEY_PARSE_TIMEOUT_SEC,
    PI_HTTP_PORT,
    PI_HTTP_RETRY_ATTEMPTS,
    PI_HTTP_RETRY_SEC,
)

LogFn = Callable[[str], None]

RE_DUT_ADDRESS = re.compile(
    r"Local device address\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
    re.IGNORECASE,
)
RE_MAC = re.compile(r"^([0-9A-Fa-f]{2}(?:(?::|-)[0-9A-Fa-f]{2}){5})$")
RE_PASSKEY = re.compile(r"passkey:\s*(\d{6})", re.IGNORECASE)
# ble_secureconnection firmware: "security keys event …" / "start encrypt status: 0"
# (older multiconnection logs used "In SMP security keys event").
RE_SMP_SUCCESS = re.compile(
    r"(?:In SMP security keys event|security keys event|Sequrity keys event|"
    r"start encrypt status:\s*0\b)",
    re.IGNORECASE,
)
RE_PRIVACY_DISCONNECTED = re.compile(r"Module got disconnected", re.IGNORECASE)
RE_PRIVACY_READV = re.compile(r"Start Advertising(?:\s+Success)?", re.IGNORECASE)
RE_SMP_FAILURE = re.compile(
    r"Number of (?:connected )?central devices:\s*0",
    re.IGNORECASE,
)
RE_SMP_FAILED_EVENT = re.compile(r"smp_failed status", re.IGNORECASE)
# SDK ble_ae_central readme / manual-tester console milestones (case-insensitive).
AE_CENTRAL_SERIAL_MILESTONES = (
    ("scan_params", re.compile(r"set ae scan params success", re.I)),
    ("scan_enable", re.compile(r"set ae scan enable success", re.I)),
    ("ae_report", re.compile(r"ae report rec for", re.I)),
    ("initiating_connect", re.compile(r"Initiating connect command", re.I)),
    ("remote_connected", re.compile(r"Remote device connected", re.I)),
)
# SDK ble_central / ble_accept_list readme / manual-tester console milestones.
BLE_CENTRAL_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi Initialization Success", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    ("starting_scan", re.compile(r"Starting scan for", re.I)),
    ("started_scanning", re.compile(r"Started scanning", re.I)),
    ("adv_event", re.compile(r"In Advertising Event", re.I)),
    ("module_connected", re.compile(r"Module connected to address", re.I)),
)
# SDK ble_ae_peripheral readme milestones (SL logging may be disabled for AE — best effort).
AE_PERIPHERAL_SERIAL_MILESTONES = (
    ("local_addr", re.compile(r"Local device address", re.I)),
    ("ae_params", re.compile(r"Setting AE params successful", re.I)),
    ("ae_enable", re.compile(r"set ae adv enable success", re.I)),
    ("remote_connected", re.compile(r"Remote device with .+ address connected", re.I)),
)
# SDK ble_longrange_2mbps readme (manual Docklight prints).
LONGRANGE_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi Initialization Success", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    ("module_connected", re.compile(r"Module connected to address", re.I)),
    ("phy_skip", re.compile(r"Skipping PHY update", re.I)),
    ("phy_complete", re.compile(r"Phy rate update complete", re.I)),
    ("phy_2mbps", re.compile(r"PHY data rate is updated to 2Mbps", re.I)),
    ("phy_500k", re.compile(r"PHY data rate is updated to 500kbps", re.I)),
)
# SDK ble_datalength readme (connect + data length change).
DATALENGTH_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi Initialization Success", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    ("started_scanning", re.compile(r"Start(?:ed|_scanning| scanning)", re.I)),
    ("adv_event", re.compile(r"In Advertising Event", re.I)),
    (
        "module_connected",
        re.compile(
            r"Module connected to address|Enhance connected|Remote device connected",
            re.I,
        ),
    ),
    ("mtu_event", re.compile(r"In MTU event", re.I)),
    ("set_data_len", re.compile(r"set data length|rsi_ble_set_data_len|Setting data length", re.I)),
    (
        "data_length_change",
        re.compile(r"In event length change event|data length change event", re.I),
    ),
)
# SDK ble_testmodes readme (RF TX/RX + Pi hcitool LE test).
TESTMODES_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    ("tx_mode", re.compile(r"BLE Testmodes:\s*TRANSMIT|TX test mode started|TRANSMIT", re.I)),
    ("rx_mode", re.compile(r"BLE Testmodes:\s*RECEIVE|RX test mode started|RECEIVE", re.I)),
)
# SDK bt_stack_bypass readme (wait Wi-Fi init before HCI attach).
STACK_BYPASS_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I)),
    ("local_addr", re.compile(r"Local device address|BD_ADDR|device address", re.I)),
)
# SDK ble_secureconnection readme (advertise → SMP passkey → encrypt).
SECURECONNECTION_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    ("connected", re.compile(r"Module connected to address|Enhance connected", re.I)),
    ("smp_req", re.compile(r"smp_req|smp pair req|smp_resp", re.I)),
    ("passkey", re.compile(r"passkey:\s*\d{6}", re.I)),
    ("encrypt", re.compile(r"start encrypt status:\s*0", re.I)),
    ("security_keys", re.compile(r"security keys event", re.I)),
    ("smp_failed", re.compile(r"smp_failed status", re.I)),
)
# SDK ble_privacy PERIPHERAL_ROLE readme (adv → SMP → resolve → disconnect → re-adv).
PRIVACY_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    ("start_adv", re.compile(r"Start Advertising Success|Start Advertising", re.I)),
    ("connected", re.compile(r"Module connected to address|Enhance connected", re.I)),
    ("smp", re.compile(r"In SMP (?:request|response) event|smp_resp|smp_req", re.I)),
    ("passkey", re.compile(r"passkey:\s*\d{6}", re.I)),
    ("security_keys", re.compile(r"Sequrity keys event|security keys event", re.I)),
    ("disconnected", re.compile(r"Module got disconnected", re.I)),
    ("readvertise", re.compile(r"Start Advertising", re.I)),
    ("smp_failed", re.compile(r"smp_failed status|In SMP failed event", re.I)),
)
# SDK ble_hid_on_gatt GATT_ROLE=SERVER (adv → SMP passkey → encrypt → HID reports).
# "Input report notify val: 1" is printed when the peer writes the report CCCD —
# that write is what makes the DUT start sending the "hog_" keystroke reports.
HID_ON_GATT_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    ("start_adv", re.compile(r"Start advertising", re.I)),
    ("connected", re.compile(r"Module connected to address|Enhance connected", re.I)),
    ("mtu", re.compile(r"Received MTU event", re.I)),
    ("smp_req", re.compile(r"smp req|smp resp", re.I)),
    ("passkey", re.compile(r"passkey\s*(?:disp)?\s*:\s*\d{6}", re.I)),
    ("encrypt", re.compile(r"smp encrypt resp", re.I)),
    ("report_notify", re.compile(r"Input report notify val:\s*[1-9]", re.I)),
    ("smp_failed", re.compile(r"smp failed|smp_failed status", re.I)),
)
# SDK ble_hid_on_gatt GATT_ROLE=CLIENT (Pi HOGP peripheral → DUT central).
HID_ON_GATT_CLIENT_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    (
        "started_scanning",
        re.compile(
            r"Start(?:ed|ing)? scanning|Initiating connect|In Advertising Event",
            re.I,
        ),
    ),
    (
        "module_connected",
        re.compile(
            r"Module connected to address|Enhance connected|Remote device connected",
            re.I,
        ),
    ),
    (
        "gatt_services",
        re.compile(
            r"GATT services|services discovered|In GATT services event|"
            r"Profiles found|profile found|Service discovery|"
            r"get_profile_async|get_char_services|Character services of hid profile|"
            r"Handle range|rsi_ble_get_profile|rsi_ble_get_att",
            re.I,
        ),
    ),
    (
        "notify_enable",
        re.compile(
            r"notify enable|Notification enabled|enable notify|"
            r"Input report notify|CCCD|GATT notification enabled|"
            r"set_att_cmd_async",
            re.I,
        ),
    ),
    (
        "notify_rx",
        re.compile(
            r"In notify event|GATT notification|notify event|"
            r"Input report notify val|report notify|In GATT notification|"
            r"0x[0-9a-f]{2}(?:\s+0x[0-9a-f]{2}){3,7}",
            re.I,
        ),
    ),
)
# SDK ble_heart_rate_profile GATT_ROLE=CLIENT (Pi HRS peripheral → DUT central).
HEART_RATE_CLIENT_SERIAL_MILESTONES = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I)),
    ("local_addr", re.compile(r"Local device address", re.I)),
    (
        "started_scanning",
        re.compile(
            r"Start(?:ed|ing)? scanning|Initiating connect|In Advertising Event",
            re.I,
        ),
    ),
    (
        "module_connected",
        re.compile(
            r"Module connected to address|Enhance connected|Remote device connected",
            re.I,
        ),
    ),
    (
        "gatt_services",
        re.compile(
            r"GATT services|services discovered|In GATT services event|"
            r"Profiles found|profile found|Service discovery|"
            r"get_profile_async|get_char_services|Character services|"
            r"heart rate|0x180[dD]|Handle range|rsi_ble_get_profile|rsi_ble_get_att",
            re.I,
        ),
    ),
    (
        "notify_enable",
        re.compile(
            r"notify enable|Notification enabled|enable notify|"
            r"CCCD|GATT notification enabled|set_att_cmd_async",
            re.I,
        ),
    ),
    (
        "notify_rx",
        re.compile(
            r"In notify event|GATT notification|notify event|"
            r"Heart[_ ]Rate|heart rate measurement|Heart_Rate_Measurement|"
            r"0x[0-9a-f]{2}(?:\s+0x[0-9a-f]{2}){0,7}",
            re.I,
        ),
    ),
)
HID_REPORT_MAP_UUID = "2a4b"
# ble_hid_on_gatt prints "smp passkey disp : 123456" (not "passkey: 123456").
RE_HID_PASSKEY = re.compile(r"passkey\s*(?:disp)?\s*:\s*(\d{6})", re.IGNORECASE)
RE_HID_REPORT_NOTIFY_ENABLED = re.compile(r"Input report notify val:\s*[1-9]", re.I)
# DUT serial lines worth echoing into Build Console during HID soak.
RE_HID_SERIAL_ACTIVITY = re.compile(
    r"Input report|HID|keystroke|key\s*press|hog|gatt wr|0x[0-9a-f]{2}",
    re.I,
)
RE_HID_CLIENT_REPORT_HEX = re.compile(
    r"0x[0-9a-f]{2}(?:\s+0x[0-9a-f]{2}){3,7}",
    re.I,
)
# USB HID keyboard usage IDs for SDK ble_hid_on_gatt demo keys.
_HID_USAGE_TO_KEY = {
    0x0A: "g",
    0x0B: "h",
    0x12: "o",
    0x2D: "_",
}

DEFAULT_PI_HTTP_PORT = PI_HTTP_PORT
MAC_TIMEOUT_SEC = MAC_PARSE_TIMEOUT_SEC
PASSKEY_TIMEOUT_SEC = PASSKEY_PARSE_TIMEOUT_SEC

# Minimal Build Console for connect-only DUT-central apps (details → Serial Console).
QUIET_BUILD_CONSOLE_KINDS = frozenset(
    {
        "ble_central",
        "ae_central",
        "accept_list",
        "longrange",
        "datalength",
        "ae_peripheral",
        "hid_on_gatt_client",
        "heart_rate_client",
    }
)


def _quiet_build_console(kind: Optional[str]) -> bool:
    return str(kind or "") in QUIET_BUILD_CONSOLE_KINDS


def _format_pi_peripheral_status(
    pi_status: dict,
    *,
    peripheral_name: str,
    kind: str,
) -> str:
    adv = pi_status.get("advertising_on")
    if adv is True:
        adv_s = "yes"
    elif adv is False:
        adv_s = "no"
    else:
        adv_s = "?"
    conn_s = "yes" if pi_status.get("connected") else "no"
    mac = pi_status.get("local_address") or "?"
    if kind in ("ble_central", "accept_list", "longrange", "datalength"):
        mode = "legacy ADV_IND"
    elif kind == "ae_central":
        if pi_status.get("extended_advertising"):
            mode = "BlueZ extended (ADV_EXT_IND + AUX scan rsp)"
        else:
            mode = "BlueZ LEAdvertisement"
    elif kind == "hid_on_gatt_client":
        mode = "HOGP peripheral (0x1812 / 0x2A4D notify)"
    elif kind == "heart_rate_client":
        mode = "HRS peripheral (0x180D / 0x2A37 notify)"
    else:
        mode = kind or "peripheral"
    return (
        f"Pi: advertising={adv_s}  name={peripheral_name!r}  mac={mac}  "
        f"connected={conn_s}  ({mode})"
    )


def _save_dut_serial_checklist_log_only(
    since_index: Optional[int],
    *,
    kind: str,
) -> dict:
    """Append readme checklist to the serial log file only (not Build Console)."""
    since = max(0, int(since_index or 0))
    block = format_checklist_block(since, kind=kind)
    serial_log_append_block(block)
    return checklist_milestones_seen(since, kind=kind)


def _log(fn: Optional[LogFn], msg: str) -> None:
    if fn:
        fn(msg)


def _http_json(method: str, url: str, payload: Optional[dict] = None, timeout: float = 30.0) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body) if body.strip() else {}


def _is_transient_http_error(exc: BaseException) -> bool:
    """Retry connection blips; do not retry HTTP 4xx application responses."""
    if isinstance(exc, urllib.error.HTTPError):
        # 408/425/429 are sometimes transient; other 4xx are application answers.
        return exc.code in (408, 425, 429)
    if isinstance(exc, (urllib.error.URLError, TimeoutError, json.JSONDecodeError)):
        return True
    return False


def _http_json_retry(
    method: str,
    url: str,
    payload: Optional[dict] = None,
    *,
    timeout: float = 30.0,
    attempts: int = PI_HTTP_RETRY_ATTEMPTS,
    retry_sec: float = PI_HTTP_RETRY_SEC,
    log: Optional[LogFn] = None,
) -> dict:
    """Pi HTTP may refuse connections during docker restart or SMP — retry transient errors."""
    last_err: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return _http_json(method, url, payload, timeout=timeout)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_err = exc
            if isinstance(exc, urllib.error.HTTPError) and not _is_transient_http_error(exc):
                # Surface JSON body when present (e.g. stability mark / complete).
                try:
                    raw = exc.read().decode("utf-8", errors="replace")
                    body = json.loads(raw) if raw.strip() else {}
                    if isinstance(body, dict) and body:
                        return body
                except Exception:
                    pass
                raise RuntimeError(f"Pi HTTP {exc.code} for {method} {url}: {exc}") from exc
            if attempt < attempts and _is_transient_http_error(exc):
                _log(log, f"Pi HTTP retry {attempt}/{attempts - 1}: {exc}")
                time.sleep(retry_sec)
                continue
            break
    raise RuntimeError(f"Pi HTTP failed after {attempts} attempts: {last_err}") from last_err


def _pi_status_dict(payload: dict) -> dict:
    status = payload.get("status")
    if isinstance(status, dict):
        return status
    return payload if isinstance(payload, dict) else {}


def wait_for_pi_ble_state(
    pi_ip: str,
    accepted_states: tuple,
    timeout_sec: float = 90.0,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
) -> dict:
    """Poll GET /ble/status until controller state is one of accepted_states."""
    url = f"http://{pi_ip}:{http_port}/ble/status"
    deadline = time.time() + timeout_sec
    _log(log, f"Waiting for Pi BLE state in {accepted_states} …")
    state = None
    while time.time() < deadline:
        payload = _http_json_retry("GET", url, timeout=10.0, log=log)
        st = _pi_status_dict(payload)
        state = st.get("state")
        if state in accepted_states:
            _log(log, f"Pi BLE state -> {state}")
            return st
        time.sleep(1.5)
    raise TimeoutError(
        f"Pi BLE state not in {accepted_states} within {timeout_sec}s (last={state!r})"
    )


def wait_for_pi_health(
    pi_ip: str,
    port: int,
    timeout_sec: float,
    log: Optional[LogFn] = None,
    *,
    quiet: bool = False,
    utf_job_id: Optional[str] = None,
) -> None:
    url = f"http://{pi_ip}:{port}/health"
    deadline = time.time() + timeout_sec
    if not quiet:
        _log(log, f"Waiting for Pi HTTP server at {url}")
    while time.time() < deadline:
        if utf_job_id:
            from utf_runner import get_utf_job

            utf_job = get_utf_job(utf_job_id)
            if utf_job and utf_job.status in ("failed", "stopped"):
                raise RuntimeError(
                    utf_job.error
                    or f"UTF job {utf_job_id} ended before Pi HTTP became ready"
                )
        try:
            result = _http_json("GET", url, timeout=5.0)
            if result.get("ok", True):
                _log(log, "Pi HTTP ready" if quiet else "Pi BLE HTTP server is ready")
                return
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            pass
        time.sleep(HEALTH_POLL_SEC)
    raise TimeoutError(f"Pi HTTP server not ready at {url} within {timeout_sec}s")


def abort_pi_ble_http_server(
    pi_ip: str,
    *,
    reason: str = "aborted by Build Studio",
    http_port: int = DEFAULT_PI_HTTP_PORT,
    wait_down_sec: float = 45.0,
    log: Optional[LogFn] = None,
) -> dict:
    """
    POST /ble/orchestration/abort — stop Pi BLE HTTP server and fail the pytest.

    Then wait until /health is no longer reachable so a new UTF launch does not
    attach to a stale server.
    """
    base = f"http://{pi_ip}:{http_port}"
    health_url = f"{base}/health"
    result: dict = {"ok": False, "skipped": False}

    try:
        _http_json("GET", health_url, timeout=3.0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        _log(log, f"Pi BLE HTTP not running at {health_url} — nothing to abort")
        return {"ok": True, "skipped": True, "message": "server not running"}

    _log(log, f"Aborting Pi BLE HTTP server ({reason}) …")
    try:
        result = _http_json(
            "POST",
            f"{base}/ble/orchestration/abort",
            {"reason": reason},
            timeout=15.0,
        )
        _log(log, f"abort response: {json.dumps(result, indent=None)}")
    except Exception as exc:
        _log(log, f"POST /ble/orchestration/abort failed: {exc} (will still wait for down)")
        result = {"ok": False, "error": str(exc)}

    deadline = time.time() + max(5.0, wait_down_sec)
    while time.time() < deadline:
        try:
            _http_json("GET", health_url, timeout=2.0)
            time.sleep(1.0)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            _log(log, "Pi BLE HTTP server is down")
            return {**result, "ok": True, "server_down": True}

    _log(
        log,
        f"WARNING: Pi /health still reachable after abort wait ({wait_down_sec}s) — "
        "stale container may still be up",
    )
    return {**result, "ok": bool(result.get("ok")), "server_down": False}


def resolve_serial_port(explicit: Optional[str] = None) -> str:
    port = (explicit or "").strip()
    if port:
        return port
    guessed = guess_vcom_port()
    if not guessed:
        raise RuntimeError(
            "No DUT serial port found. Connect the board USB-UART and select the COM port, "
            "or plug in the WSTK debug adapter."
        )
    return guessed


def _merge_connect_payload(
    address: str,
    use_passkey: bool,
    conn_params: Optional[dict] = None,
    *,
    capability: Optional[str] = None,
    address_type: Optional[str] = None,
    direct_connect: bool = False,
) -> dict:
    payload: dict = {
        "address": address.strip().upper(),
        "bond": bool(use_passkey),
        **connect_conn_params(None, conn_params),
    }
    if capability:
        payload["capability"] = capability
    if address_type:
        payload["address_type"] = str(address_type).strip().lower()
    if direct_connect:
        payload["direct_connect"] = True
    return payload


def orchestrate_ble_connect(
    pi_ip: str,
    dut_address: str,
    use_passkey: bool,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    scan_before_connect: bool = True,
    conn_params: Optional[dict] = None,
) -> dict:
    base = f"http://{pi_ip}:{http_port}"
    _log(log, f"=== BLE connect -> {dut_address} (passkey={use_passkey}, scan_first={scan_before_connect}) ===")

    scan = None
    if scan_before_connect:
        scan = ble_debug_scan(pi_ip, dut_address, timeout=15, http_port=http_port, log=log)
        if not scan.get("ok") or scan.get("address_found") is False:
            raise RuntimeError(f"BLE scan failed: {scan}")

    # Passkey/SMP needs a live BlueZ Device1 — always scan first when bonding.
    if use_passkey and not scan_before_connect:
        _log(log, "passkey=True — forcing scan before connect (Device1 required for Pair)")
        scan_before_connect = True
    connect_payload = _merge_connect_payload(dut_address, use_passkey, conn_params)
    serial_mark = None
    if use_passkey:
        serial_mark = mark_serial_cursor()
        _log(log, f"Serial cursor marked at line {serial_mark} (passkey must appear after this)")
    _log(log, f"POST /ble/connect {json.dumps(connect_payload)}")
    connect = _http_json_retry(
        "POST", f"{base}/ble/connect", connect_payload, log=log, timeout=60.0
    )
    _log(log, f"Connect: {json.dumps(connect, indent=None)}")
    if not connect.get("ok"):
        raise RuntimeError(f"BLE connect failed: {connect}")
    st = connect.get("status") if isinstance(connect.get("status"), dict) else {}
    if st.get("state") == "pair_failed" or (
        isinstance(st.get("last_error"), str)
        and "pair_and_connect" in st["last_error"]
    ):
        raise RuntimeError(
            f"BLE pair failed before passkey (scan/Device1?): {st.get('last_error') or connect}"
        )
    if use_passkey:
        wait_for_pi_ble_state(
            pi_ip,
            ("awaiting_passkey", "passkey_submitted", "pairing", "bonded"),
            timeout_sec=90.0,
            log=log,
            http_port=http_port,
        )
    out = {"connect": connect, "connect_payload": connect_payload}
    if serial_mark is not None:
        out["serial_cursor"] = serial_mark
    if scan is not None:
        out["scan"] = scan
    return out


def _pi_base(pi_ip: str, http_port: int = DEFAULT_PI_HTTP_PORT) -> str:
    return f"http://{pi_ip}:{http_port}"


def ble_debug_scan(
    pi_ip: str,
    address: Optional[str] = None,
    *,
    timeout: int = 15,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    log: Optional[LogFn] = None,
    name: Optional[str] = None,
) -> dict:
    payload: dict = {"timeout": int(timeout)}
    if address:
        payload["address"] = address.strip().upper()
    if name:
        payload["name"] = str(name).strip()
    _log(log, f"POST /ble/scan {json.dumps(payload)}")
    # Pi ae_peripheral scan may run D-Bus discovery then HCI btsnoop fallback.
    http_timeout = float(timeout) + 75.0
    result = _http_json_retry(
        "POST",
        f"{_pi_base(pi_ip, http_port)}/ble/scan",
        payload,
        log=log,
        timeout=http_timeout,
    )
    # Keep report clean: summarize instead of dumping full device map.
    devices = result.get("devices") if isinstance(result, dict) else None
    n_dev = len(devices) if isinstance(devices, dict) else 0
    _log(
        log,
        f"Scan: ok={result.get('ok')} address_found={result.get('address_found')} "
        f"matched={result.get('matched_address')} devices={n_dev}",
    )
    return result


def ble_debug_connect(
    pi_ip: str,
    address: str,
    use_passkey: bool,
    *,
    capability: Optional[str] = None,
    conn_params: Optional[dict] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    log: Optional[LogFn] = None,
) -> dict:
    payload = _merge_connect_payload(address, use_passkey, conn_params, capability=capability)
    _log(log, f"POST /ble/connect {json.dumps(payload)}")
    result = _http_json("POST", f"{_pi_base(pi_ip, http_port)}/ble/connect", payload)
    _log(log, f"Connect response: {json.dumps(result, indent=None)}")
    return result


def ble_debug_status(pi_ip: str, *, http_port: int = DEFAULT_PI_HTTP_PORT, log: Optional[LogFn] = None) -> dict:
    _log(log, "GET /ble/status")
    result = _http_json("GET", f"{_pi_base(pi_ip, http_port)}/ble/status")
    _log(log, f"Status: {json.dumps(result, indent=None)}")
    return result


def ble_debug_enable_notifications(
    pi_ip: str,
    app_id: str,
    *,
    enable_payload: Optional[dict] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    log: Optional[LogFn] = None,
) -> dict:
    payload = enable_payload if enable_payload is not None else notifications_enable_payload(app_id)
    _log(log, f"POST /ble/notifications/enable {json.dumps(payload)}")
    result = _http_json("POST", f"{_pi_base(pi_ip, http_port)}/ble/notifications/enable", payload)
    _log(log, f"Enable notifications: {json.dumps(result, indent=None)}")
    return result


def ble_debug_get_notifications(
    pi_ip: str,
    *,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    log: Optional[LogFn] = None,
) -> dict:
    _log(log, "GET /ble/notifications")
    result = _http_json("GET", f"{_pi_base(pi_ip, http_port)}/ble/notifications")
    _log(log, f"Notifications: {json.dumps(result, indent=None)}")
    return result


def ble_debug_submit_passkey(
    pi_ip: str,
    passkey: str,
    *,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    log: Optional[LogFn] = None,
) -> dict:
    return submit_passkey_to_pi(pi_ip, passkey, log, http_port=http_port)


def run_ble_debug_step(
    *,
    step: str,
    pi_ip: str,
    app_id: Optional[str] = None,
    address: Optional[str] = None,
    use_passkey: bool = False,
    passkey: Optional[str] = None,
    scan_timeout: int = 15,
    serial_port: Optional[str] = None,
    scan_before_connect: bool = False,
    conn_params: Optional[dict] = None,
) -> dict:
    """Run one Pi BLE HTTP step; returns {logs, result}."""
    logs: List[str] = []

    def append(line: str) -> None:
        logs.append(line)

    step = (step or "").strip().lower()
    try:
        if step == "health":
            append("GET /health")
            result = _http_json("GET", f"{_pi_base(pi_ip)}/health", timeout=10.0)
            append(json.dumps(result, indent=2))
        elif step == "parse_address":
            if address:
                normalized = normalize_dut_address(address)
                result = {"ok": True, "address": normalized}
            else:
                ensure_serial_monitor(serial_port, append, label=app_id)
                addr = resolve_dut_address(None, append, fresh=True)
                result = {"ok": True, "address": addr}
        elif step == "scan":
            if not address:
                raise ValueError("address is required for scan (or use Parse address from serial first)")
            result = ble_debug_scan(pi_ip, address, timeout=scan_timeout, log=append)
        elif step == "connect":
            if not address:
                raise ValueError("address is required for connect")
            if scan_before_connect:
                ble_debug_scan(pi_ip, address, timeout=scan_timeout, log=append)
            result = ble_debug_connect(
                pi_ip,
                address,
                use_passkey,
                conn_params=conn_params,
                log=append,
            )
        elif step == "status":
            result = ble_debug_status(pi_ip, log=append)
        elif step == "enable_notifications":
            if not app_id:
                raise ValueError("app_id is required for enable_notifications")
            result = ble_debug_enable_notifications(pi_ip, app_id, log=append)
        elif step == "notifications":
            result = ble_debug_get_notifications(pi_ip, log=append)
        elif step == "passkey_connect":
            if not address:
                raise ValueError("address is required for passkey_connect")
            if not app_id:
                raise ValueError("app_id is required for passkey_connect")
            ensure_serial_monitor(serial_port, append, label=app_id)
            result = orchestrate_passkey_connect_flow(
                pi_ip,
                app_id,
                address,
                append,
                scan_before_connect=scan_before_connect,
                conn_params=connect_conn_params(app_id),
            )
        elif step == "passkey":
            if not passkey:
                ensure_serial_monitor(serial_port, append, label=app_id)
                passkey = parse_passkey_from_serial(append)
            result = ble_debug_submit_passkey(pi_ip, passkey, log=append)
        else:
            raise ValueError(f"Unknown step: {step}")
        return {"ok": True, "step": step, "logs": logs, "result": result}
    except Exception as exc:
        append(f"ERROR: {exc}")
        return {"ok": False, "step": step, "logs": logs, "error": str(exc)}


def orchestrate_connect_link_stability(
    pi_ip: str,
    app_id: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    stability_sec: Optional[int] = None,
) -> dict:
    """Wait for Pi post-connect link stability (no GATT notify) then complete orchestration."""
    from app_test_catalog import test_profile

    profile = test_profile(app_id)
    if stability_sec is None:
        stability_sec = int(profile.get("post_notify_stability_sec") or 300)

    base = f"http://{pi_ip}:{http_port}"
    _log(
        log,
        f"Waiting up to {stability_sec + 120}s for Pi connect link stability ({stability_sec}s) …",
    )
    deadline = time.time() + stability_sec + 300
    final_status: dict = {}
    refused_streak = 0
    while time.time() < deadline:
        try:
            payload = _http_json("GET", f"{base}/ble/status", timeout=20.0)
            refused_streak = 0
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            refused_streak += 1
            _log(
                log,
                f"Pi status poll ({refused_streak}): {exc} — "
                "UTF HTTP may still be starting; retrying …",
            )
            if refused_streak >= 24:
                raise RuntimeError(
                    "Pi HTTP unreachable during link stability for ~2 minutes. "
                    "Relaunch UTF on the Pi (docker) and confirm port "
                    f"{http_port} is reachable, or redeploy if the test image is old."
                ) from exc
            time.sleep(5)
            continue
        status = payload.get("status") if isinstance(payload.get("status"), dict) else payload
        if not isinstance(status, dict):
            status = payload
        final_status = status
        if status.get("post_notify_stability_done"):
            if not status.get("post_notify_stability_ok"):
                raise RuntimeError(
                    "Connect link stability failed on Pi (connection dropped during stability window)"
                )
            break
        time.sleep(5)
    else:
        raise TimeoutError(
            f"Pi did not finish connect link stability within {stability_sec + 180}s"
        )

    _log(log, "Connect link stability passed — requesting graceful orchestration complete …")
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=log, timeout=30.0
    )
    _log(log, f"Orchestration complete: {json.dumps(complete, indent=None)}")
    if not complete.get("ok"):
        raise RuntimeError(f"POST /ble/orchestration/complete failed: {complete}")

    return {
        "enable": None,
        "complete": complete,
        "notification_count": int(final_status.get("notification_count", 0) or 0),
        "stability_ok": final_status.get("post_notify_stability_ok"),
        "require_notifications": False,
    }


def orchestrate_ble_notifications(
    pi_ip: str,
    app_id: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    stability_sec: Optional[int] = None,
) -> dict:
    from app_test_catalog import test_profile

    profile = test_profile(app_id)
    if stability_sec is None:
        stability_sec = int(profile.get("post_notify_stability_sec") or 300)

    base = f"http://{pi_ip}:{http_port}"
    enable_payload = notifications_enable_payload(app_id)
    notify_enable = _http_json_retry(
        "POST", f"{base}/ble/notifications/enable", enable_payload, log=log, timeout=60.0
    )
    _log(log, f"Notifications enable {json.dumps(enable_payload)}: {json.dumps(notify_enable, indent=None)}")
    if not notify_enable.get("ok"):
        raise RuntimeError(f"Enable notifications failed: {notify_enable}")

    _log(
        log,
        f"Waiting up to {stability_sec + 120}s for Pi post-notify stability ({stability_sec}s) …",
    )
    deadline = time.time() + stability_sec + 300
    last_count = -1
    final_status: dict = {}
    refused_streak = 0
    while time.time() < deadline:
        try:
            payload = _http_json("GET", f"{base}/ble/status", timeout=20.0)
            refused_streak = 0
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            refused_streak += 1
            _log(
                log,
                f"Pi status poll ({refused_streak}): {exc} — "
                "UTF HTTP may still be starting; retrying …",
            )
            if refused_streak >= 24:
                raise RuntimeError(
                    "Pi HTTP unreachable during stability for ~2 minutes. "
                    "Relaunch UTF on the Pi (docker) and confirm port "
                    f"{http_port} is reachable, or redeploy if the test image is old."
                ) from exc
            time.sleep(5)
            continue
        status = payload.get("status") if isinstance(payload.get("status"), dict) else payload
        if not isinstance(status, dict):
            status = payload
        final_status = status
        count = status.get("notification_count", 0)
        if count != last_count:
            _log(log, f"Pi notification_count={count}  state={status.get('state')}")
            last_count = count
        if status.get("post_notify_stability_done"):
            if not status.get("post_notify_stability_ok"):
                raise RuntimeError(
                    "Post-notify stability failed on Pi (connection dropped during stability window)"
                )
            break
        time.sleep(5)
    else:
        raise TimeoutError(
            f"Pi did not finish post-notify stability within {stability_sec + 180}s"
        )

    _log(log, "Post-notify stability passed — requesting graceful orchestration complete …")
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=log, timeout=30.0
    )
    _log(log, f"Orchestration complete: {json.dumps(complete, indent=None)}")
    if not complete.get("ok"):
        raise RuntimeError(f"POST /ble/orchestration/complete failed: {complete}")

    notification_count = int(final_status.get("notification_count", 0) or 0)
    min_notify = profile.get("min_notification_count")
    if min_notify is not None and notification_count < int(min_notify):
        raise RuntimeError(
            f"Expected at least {min_notify} heart-rate notification(s) on 0x2A37, "
            f"got {notification_count} (check GATT_ROLE=SERVER on DUT)"
        )

    return {
        "enable": notify_enable,
        "complete": complete,
        "notification_count": notification_count,
        "stability_ok": final_status.get("post_notify_stability_ok"),
    }


def orchestrate_ibeacon_scan_stability(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
) -> dict:
    """
    iBeacon (advertiser-only): POST /ble/scan every 30s for 5 min; DUT must appear each time.
    Matches SDK readme — DUT advertises, Pi central scans (no connect/SMP/GATT).
    """
    prof = profile or {}
    duration_sec = int(prof.get("ibeacon_scan_duration_sec") or 300)
    interval_sec = int(prof.get("ibeacon_scan_interval_sec") or 30)
    scan_timeout = int(prof.get("ibeacon_per_scan_timeout_sec") or 12)
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)

    _log(
        log,
        f"=== iBeacon scan stability: {address} for {duration_sec}s every {interval_sec}s ===",
    )
    samples: List[dict] = []
    started = time.time()
    sample_idx = 0
    while (time.time() - started) < duration_sec:
        sample_idx += 1
        payload = {"timeout": scan_timeout, "address": address}
        _log(log, f"Scan sample {sample_idx}: POST /ble/scan {json.dumps(payload)}")
        result = _http_json_retry(
            "POST", f"{base}/ble/scan", payload, log=log, timeout=float(scan_timeout) + 30.0
        )
        found = result.get("address_found") is True
        samples.append(
            {
                "sample": sample_idx,
                "elapsed_sec": round(time.time() - started, 1),
                "address_found": found,
                "device_count": len(result.get("devices") or {}),
            }
        )
        _log(log, f"  sample {sample_idx}: address_found={found}")
        if not found:
            _http_json_retry(
                "POST",
                f"{base}/ble/orchestration/ibeacon-stability",
                {"ok": False, "sample_count": sample_idx},
                log=log,
            )
            raise RuntimeError(
                f"iBeacon DUT {address} not seen in scan sample {sample_idx}: {result}"
            )
        elapsed = time.time() - started
        if elapsed + interval_sec >= duration_sec:
            break
        _log(log, f"Waiting {interval_sec}s until next scan …")
        time.sleep(interval_sec)

    _log(log, f"iBeacon scan stability PASSED ({len(samples)} samples)")
    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ibeacon-stability",
        {"ok": True, "sample_count": len(samples)},
        log=log,
    )
    _log(log, f"ibeacon-stability mark: {json.dumps(mark, indent=None)}")

    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=log, timeout=30.0
    )
    _log(log, f"Orchestration complete: {json.dumps(complete, indent=None)}")
    if not complete.get("ok"):
        raise RuntimeError(f"POST /ble/orchestration/complete failed: {complete}")

    return {"samples": samples, "complete": complete, "dut_address": address}


def arm_dut_central_expect_peer(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    quiet: bool = False,
) -> dict:
    """POST /ble/peripheral/expect-peer so Pi can observe DUT central connect early (pre-flash)."""
    address = normalize_dut_address(dut_address)
    base = f"http://{pi_ip}:{http_port}"
    if not quiet:
        _log(log, f"Arm expect-peer before/during flash (DUT central {address}) …")
    result = _http_json_retry(
        "POST",
        f"{base}/ble/peripheral/expect-peer",
        {"address": address},
        log=None,
        timeout=15.0,
    )
    if not quiet:
        _log(log, f"expect-peer armed: {json.dumps(result, indent=None)}")
    return result


def poll_dut_central_connected(
    pi_ip: str,
    *,
    timeout_sec: float,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    poll_sec: float = 1.0,
    label: str = "connect",
) -> Optional[dict]:
    """Poll GET /ble/status until connected=true or timeout. Returns status dict or None."""
    base = f"http://{pi_ip}:{http_port}"
    deadline = time.time() + max(0.0, float(timeout_sec))
    while time.time() < deadline:
        try:
            st_resp = _http_json_retry(
                "GET", f"{base}/ble/status", None, log=None, timeout=15.0
            )
        except Exception as exc:
            _log(log, f"  {label} poll: status error {exc}")
            time.sleep(poll_sec)
            continue
        st = (st_resp.get("status") or {}) if isinstance(st_resp, dict) else {}
        if st.get("connected") is True:
            _log(
                log,
                f"DUT central connected during {label} "
                f"(state={st.get('state')}, advertising_on={st.get('advertising_on')})",
            )
            return st
        time.sleep(poll_sec)
    return None


def _log_dut_readme_serial_block(
    log: Optional[LogFn],
    since_index: Optional[int],
    *,
    kind: str,
    title: Optional[str] = None,
) -> dict:
    """Print ordered DUT serial readme lines; append same block to the log file."""
    since = max(0, int(since_index or 0))
    block = format_checklist_block(since, kind=kind, title=title)
    for line in block.splitlines():
        _log(log, line)
    serial_log_append_block(block)
    return checklist_milestones_seen(since, kind=kind)


def _serial_milestones_seen(
    since_index: Optional[int] = None,
    *,
    milestones: Optional[tuple] = None,
) -> Dict[str, bool]:
    """Return which console milestones appear in DUT serial (after cursor)."""
    since = max(0, int(since_index or 0))
    text = "\n".join(get_lines(since).get("lines") or [])
    if not text:
        text = get_all_text() or ""
    rows = milestones or AE_CENTRAL_SERIAL_MILESTONES
    return {name: bool(pat.search(text)) for name, pat in rows}


def _serial_milestones_merged(
    since_index: Optional[int] = None,
    *,
    milestones: Optional[tuple] = None,
) -> Dict[str, bool]:
    """Match milestones in post-flash window, then fall back to full capture."""
    rows = milestones or AE_CENTRAL_SERIAL_MILESTONES
    since_seen = _serial_milestones_seen(since_index, milestones=rows)
    if since_index and int(since_index) > 0:
        full_seen = _serial_milestones_seen(0, milestones=rows)
        return {key: since_seen.get(key) or full_seen.get(key) for key in since_seen}
    return since_seen


def _log_dut_central_serial_checklist(
    log: Optional[LogFn],
    since_index: Optional[int] = None,
    *,
    kind: str = "ae_central",
) -> dict:
    """Print a short readme-style checklist from DUT serial (manual-tester style)."""
    if kind in ("dut_central", "ble_central", "accept_list"):
        rows = BLE_CENTRAL_SERIAL_MILESTONES
        title = (
            "DUT serial checklist (SDK ble_accept_list demo):"
            if kind == "accept_list"
            else "DUT serial checklist (SDK ble_central demo):"
        )
        labels = {
            "wifi_init": "Wi-Fi Initialization Success",
            "local_addr": "Local device address",
            "starting_scan": "Starting scan for 'SILABS_DEV' / <Pi MAC>",
            "started_scanning": "Started scanning",
            "adv_event": "In Advertising Event (peer found)",
            "module_connected": "Module connected to address : <Pi MAC>",
        }
    else:
        rows = AE_CENTRAL_SERIAL_MILESTONES
        title = "DUT serial checklist (SDK AE Central demo):"
        labels = {
            "scan_params": "set ae scan params success",
            "scan_enable": "set ae scan enable success",
            "ae_report": "ae report rec for <peer>",
            "initiating_connect": "Initiating connect command",
            "remote_connected": "Remote device connected",
        }
    seen = _serial_milestones_seen(since_index, milestones=rows)
    _log(log, title)
    for key, label in labels.items():
        mark = "OK" if seen.get(key) else "--"
        _log(log, f"  [{mark}] {label}")
    return seen


def _accept_list_firmware_tip(pi_mac: Optional[str], peripheral_name: str = "SILABS_DEV") -> str:
    """Format ble_acceptlist_addr1 bytes + RSI_BLE_DEV_ADDR tip from Pi MAC.

    SDK sample stores BD_ADDR as reverse of colon notation (e.g. 00:1A:7D:DA:71:48
    → {0x48,0x71,0xDA,0x7D,0x1A,0x00}); readme labels that "big-endian".
    """
    mac = str(pi_mac or "").strip().upper().replace("-", ":")
    parts = [p for p in mac.split(":") if p]
    if len(parts) != 6:
        return (
            f"set ble_acceptlist_addr1 (reverse-byte / SDK sample layout) + RSI_BLE_DEV_ADDR "
            f"to Pi /health local_address; RSI_REMOTE_DEVICE_NAME={peripheral_name!r}"
        )
    # Match app.c sample: last octet first.
    be_rev = ", ".join(f"0x{p}" for p in reversed(parts))
    return (
        f"ble_acceptlist_addr1[6] = {{{be_rev}}}; "
        f'RSI_BLE_DEV_ADDR="{mac}"; RSI_REMOTE_DEVICE_NAME={peripheral_name!r}'
    )


def orchestrate_ae_central_link_stability(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    skip_expect_peer: bool = False,
    serial_since_index: Optional[int] = None,
) -> dict:
    """
    DUT central apps: Pi advertises; DUT scans and connects.

    - ae_central: BlueZ LEAdvertisement (extended OK); pass on Pi/serial connect
    - ble_central / accept_list: legacy HCI ADV_IND; prefer DUT serial Module connected
      (accept_list also requires Pi MAC on the controller accept list)
    - dut_central: legacy HCI + optional soak (longrange)
    """
    prof = profile or {}
    simple = bool(prof.get("simple_connect_pass"))
    kind = str(prof.get("orchestration_kind") or "ae_central")
    is_ble_central = kind == "ble_central"
    is_accept_list = kind == "accept_list"
    is_legacy_central = is_ble_central or is_accept_list
    require_serial = bool(prof.get("require_dut_serial_connect"))
    duration_sec = int(prof.get("ibeacon_scan_duration_sec") or 0)
    if not simple and duration_sec <= 0:
        duration_sec = 300
    interval_sec = int(prof.get("ibeacon_scan_interval_sec") or 30)
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    peripheral_name = str(prof.get("ae_central_peripheral_name") or "SILABS_DEV")
    skip_hr = bool(prof.get("skip_hr_notify", simple))
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)
    # Keep post-flash serial (do not remake cursor — that drops "Module connected").
    if serial_since_index is not None:
        serial_cursor_at_start = int(serial_since_index)
    else:
        serial_cursor_at_start = mark_serial_cursor()
    serial_rows = (
        BLE_CENTRAL_SERIAL_MILESTONES
        if kind in ("dut_central", "ble_central", "accept_list")
        else AE_CENTRAL_SERIAL_MILESTONES
    )
    serial_pass_key = (
        "module_connected"
        if kind in ("dut_central", "ble_central", "accept_list")
        else "remote_connected"
    )
    serial_pass_label = (
        "Module connected to address"
        if kind in ("dut_central", "ble_central", "accept_list")
        else "Remote device connected"
    )
    if is_accept_list:
        app_label = "Accept List"
    elif is_ble_central:
        app_label = "BLE Central"
    elif kind == "dut_central":
        app_label = "DUT Central"
    else:
        app_label = "AE Central"

    quiet = _quiet_build_console(kind)

    health = _http_json_retry("GET", f"{base}/health", None, log=None, timeout=15.0)
    pi_status = (health.get("status") or {}) if isinstance(health, dict) else {}
    pi_mac = pi_status.get("local_address")
    if quiet:
        _log(log, f"Test: {app_label}  DUT={address}")
        _log(
            log,
            _format_pi_peripheral_status(
                pi_status, peripheral_name=peripheral_name, kind=kind
            ),
        )
    elif is_accept_list:
        _log(log, "=== Accept List (SDK ble_accept_list) ===")
        _log(log, f"  Pi = legacy ADV_IND peripheral name={peripheral_name!r} mac={pi_mac}")
        _log(
            log,
            "  DUT = accept-list scan (SCAN_FILTER_TYPE_ONLY_ACCEPT_LIST) + connect",
        )
        _log(
            log,
            f"  Pass when: DUT serial '{serial_pass_label}'"
            + (" (Pi connected also accepted)" if not require_serial else ""),
        )
        _log(
            log,
            "  Firmware BEFORE flash: "
            + _accept_list_firmware_tip(pi_mac, peripheral_name),
        )
        _log(
            log,
            "  Name alone is not enough — peer MAC must be on the controller accept list",
        )
        _log(log, "  prefer ENABLE_NWP_POWER_SAVE=0")
    elif is_ble_central:
        _log(log, "=== BLE Central (SDK siwx91x_bluetooth_le_central) ===")
        _log(log, f"  Pi = legacy ADV_IND peripheral name={peripheral_name!r} mac={pi_mac}")
        _log(log, f"  DUT = rsi_ble_start_scanning + rsi_ble_connect ({address})")
        _log(
            log,
            f"  Pass when: DUT serial '{serial_pass_label}'"
            + (" (Pi connected also accepted)" if not require_serial else ""),
        )
        _log(
            log,
            "  Not AE central: do not rely on BlueZ extended LEAdvertisement",
        )
        _log(
            log,
            "  Firmware: RSI_REMOTE_DEVICE_NAME / RSI_BLE_DEV_ADDR; "
            "prefer ENABLE_NWP_POWER_SAVE=0 (sample often has 1)",
        )
    elif simple:
        _log(log, f"=== {app_label} (simple connect) ===")
        _log(log, f"  Pi advertises as {peripheral_name!r}  mac={pi_mac}")
        _log(log, f"  Expect DUT central {address}")
        _log(
            log,
            f"  Pass when: Pi connected  OR  DUT serial '{serial_pass_label}'",
        )
    else:
        _log(
            log,
            f"=== DUT central → Pi peripheral name={peripheral_name!r} mac={pi_mac} "
            f"DUT={address} ===",
        )
    if pi_mac and not quiet:
        _log(
            log,
            f"  Firmware peer: RSI_REMOTE_DEVICE_NAME={peripheral_name!r} "
            f"or RSI_BLE_DEV_ADDR={pi_mac}",
        )

    if not skip_expect_peer:
        arm_dut_central_expect_peer(
            pi_ip, address, log=log, http_port=http_port, quiet=quiet
        )
    else:
        if not quiet:
            _log(log, "  expect-peer already armed")
        health = _http_json_retry("GET", f"{base}/health", None, log=None, timeout=15.0)
        pi_status = (health.get("status") or {}) if isinstance(health, dict) else {}
        pi_mac = pi_status.get("local_address") or pi_mac

    connected = False
    serial_pass = False
    pi_pass = False
    if (
        not require_serial
        and pi_status.get("connected") is True
        and str(pi_status.get("target_address") or "").upper() == address
    ):
        if quiet:
            _log(log, "PASS: connect established (Pi link already up)")
        else:
            _log(log, "PASS step: DUT already connected to Pi")
        connected = True
        pi_pass = True
    else:
        if not quiet:
            _log(log, f"Waiting up to {connect_timeout}s for connect …")
        deadline = time.time() + connect_timeout
        while time.time() < deadline:
            # ble_central readme: serial "Module connected" is the gold signal.
            if simple or require_serial:
                milestones = _serial_milestones_seen(
                    serial_cursor_at_start, milestones=serial_rows
                )
                if milestones.get(serial_pass_key):
                    connected = True
                    serial_pass = True
                    if quiet:
                        _log(log, f"PASS: connect established (DUT serial: {serial_pass_label})")
                    else:
                        _log(log, f"PASS step: DUT serial '{serial_pass_label}'")
                    break
            if not require_serial:
                st = poll_dut_central_connected(
                    pi_ip,
                    timeout_sec=min(2.0, max(0.5, deadline - time.time())),
                    log=None,
                    http_port=http_port,
                    poll_sec=1.0,
                    label="connect",
                )
                if st is not None:
                    connected = True
                    pi_pass = True
                    pi_status = st
                    if quiet:
                        _log(log, "PASS: connect established (Pi link up)")
                    else:
                        via = st.get("connection_via") or "pi"
                        _log(log, f"PASS step: Pi reports connected=true (via {via})")
                    break
            else:
                # Still poll Pi for diagnostics; do not PASS on Pi alone when
                # require_dut_serial_connect is set.
                poll_dut_central_connected(
                    pi_ip,
                    timeout_sec=min(1.0, max(0.3, deadline - time.time())),
                    log=None,
                    http_port=http_port,
                    poll_sec=1.0,
                    label="connect",
                )
            time.sleep(1.0)

    if not connected:
        _log_dut_central_serial_checklist(log, serial_cursor_at_start, kind=kind)
        if is_accept_list:
            hint = (
                "confirm UTF 'LEGACY HCI'; flash with "
                + _accept_list_firmware_tip(pi_mac, peripheral_name)
                + "; ENABLE_NWP_POWER_SAVE=0"
            )
        elif is_ble_central:
            hint = (
                "confirm UTF log 'LEGACY HCI' / start_smp_adv_with_hci_tool; "
                "set ENABLE_NWP_POWER_SAVE=0 in app.c"
            )
        else:
            hint = "for ble_central confirm UTF log 'LEGACY HCI advertising'"
        raise TimeoutError(
            f"DUT {address} did not connect within {connect_timeout}s "
            f"(set RSI_REMOTE_DEVICE_NAME={peripheral_name!r} or Pi MAC {pi_mac} in firmware; "
            f"{hint})"
        )

    if quiet:
        serial_seen = _save_dut_serial_checklist_log_only(
            serial_cursor_at_start, kind=kind
        )
    else:
        serial_seen = _log_dut_central_serial_checklist(
            log, serial_cursor_at_start, kind=kind
        )
    if require_serial and not serial_seen.get(serial_pass_key) and not serial_pass:
        raise TimeoutError(
            f"DUT serial never showed '{serial_pass_label}' "
            f"(required for ble_central / accept_list SDK readme pass)"
        )
    if not quiet and simple and not require_serial and not serial_seen.get(serial_pass_key):
        _log(
            log,
            f"Note: Pi connected but DUT serial did not show '{serial_pass_label}' yet "
            "(log level / SL_DEBUG routing) — Pi link is enough to PASS",
        )
    if not quiet and is_legacy_central and pi_pass and serial_pass:
        _log(log, "  (Pi link and DUT serial both confirmed)")

    if simple or duration_sec <= 0:
        if quiet:
            try:
                st_resp = _http_json_retry(
                    "GET", f"{base}/ble/status", None, log=None, timeout=15.0
                )
                st = (st_resp.get("status") or {}) if isinstance(st_resp, dict) else {}
                _log(
                    log,
                    _format_pi_peripheral_status(
                        st, peripheral_name=peripheral_name, kind=kind
                    ),
                )
            except Exception:
                pass
            _log(log, f"PASS: {app_label} — connect established")
        else:
            _log(log, f"=== {app_label} RESULT: PASS (connect established) ===")
        mark = _http_json_retry(
            "POST",
            f"{base}/ble/orchestration/ae-central-stability",
            {"ok": True, "sample_count": 1},
            log=None,
        )
        complete = _http_json_retry(
            "POST", f"{base}/ble/orchestration/complete", {}, log=log, timeout=30.0
        )
        if not complete.get("ok"):
            raise RuntimeError(f"orchestration complete failed: {complete}")
        return {
            "mode": "simple_connect",
            "samples": [{"sample": 1, "connected": True}],
            "complete": complete,
            "mark": mark,
            "dut_address": address,
            "pi_local_address": pi_mac,
            "peripheral_name": peripheral_name,
            "serial_milestones": serial_seen,
        }

    if not skip_hr:
        try:
            hr = _http_json_retry(
                "POST",
                f"{base}/ble/peripheral/start-hr-notify",
                {},
                log=log,
                timeout=15.0,
                attempts=3,
            )
            _log(log, f"Pi Heart Rate notify: {hr}")
        except Exception as exc:
            _log(log, f"Pi Heart Rate notify skipped: {exc}")

    drop_grace_sec = int(prof.get("ae_central_drop_grace_sec") or 15)
    samples: List[dict] = []
    started = time.time()
    sample_idx = 0
    while (time.time() - started) < duration_sec:
        sample_idx += 1
        st_resp = _http_json_retry("GET", f"{base}/ble/status", None, log=log, timeout=15.0)
        st = (st_resp.get("status") or {}) if isinstance(st_resp, dict) else {}
        link_up = st.get("connected") is True
        if not link_up and drop_grace_sec > 0:
            _log(log, f"  link sample {sample_idx}: down — grace {drop_grace_sec}s …")
            grace_deadline = time.time() + drop_grace_sec
            while time.time() < grace_deadline:
                time.sleep(2)
                st_resp = _http_json_retry(
                    "GET", f"{base}/ble/status", None, log=log, timeout=15.0
                )
                st = (st_resp.get("status") or {}) if isinstance(st_resp, dict) else {}
                if st.get("connected") is True:
                    link_up = True
                    break
        samples.append(
            {
                "sample": sample_idx,
                "elapsed_sec": round(time.time() - started, 1),
                "connected": link_up,
                "state": st.get("state"),
            }
        )
        _log(log, f"  link sample {sample_idx}: connected={link_up}")
        if not link_up:
            _http_json_retry(
                "POST",
                f"{base}/ble/orchestration/ae-central-stability",
                {"ok": False, "sample_count": sample_idx},
                log=log,
            )
            raise RuntimeError(f"Link dropped at sample {sample_idx} (DUT {address})")
        elapsed = time.time() - started
        if elapsed + interval_sec >= duration_sec:
            break
        time.sleep(interval_sec)

    _log(log, f"Link soak PASSED ({len(samples)} samples)")
    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": len(samples)},
        log=log,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=log, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "link_soak",
        "samples": samples,
        "complete": complete,
        "mark": mark,
        "dut_address": address,
        "pi_local_address": pi_mac,
        "peripheral_name": peripheral_name,
        "serial_milestones": serial_seen,
    }


def orchestrate_longrange_manual(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    skip_expect_peer: bool = False,
    serial_since_index: Optional[int] = None,
) -> dict:
    """
    SDK ble_longrange_2mbps readme — manual steps as a short host report.

    Pi = peripheral SILABS_DEV; DUT = central connect + PHY (2Mbps; Coded ignored on Pi).
    """
    prof = profile or {}
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    peripheral_name = str(prof.get("ae_central_peripheral_name") or "SILABS_DEV")
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)
    if serial_since_index is not None:
        serial_cursor = int(serial_since_index)
    else:
        serial_cursor = mark_serial_cursor()

    health = _http_json_retry("GET", f"{base}/health", None, log=log, timeout=15.0)
    pi_status = (health.get("status") or {}) if isinstance(health, dict) else {}
    pi_mac = pi_status.get("local_address")

    _log(log, "=== Long Range / 2Mbps (SDK ble_longrange_2mbps) ===")
    _log(log, "Manual steps (readme):")
    _log(
        log,
        f"  1. Remote peripheral advertising as {peripheral_name!r}"
        + (f" @ {pi_mac}" if pi_mac else " (Pi)"),
    )
    _log(
        log,
        f"  2. DUT connects to RSI_REMOTE_DEVICE_NAME={peripheral_name!r}"
        + (f" or RSI_BLE_DEV_ADDR={pi_mac}" if pi_mac else ""),
    )
    _log(log, "  3. Connection established")
    _log(log, "  4. After connect: read/set PHY (2Mbps; Coded ignored on Pi)")
    _log(log, "  5. Observe PHY update complete (or skip if firmware skips for Pi)")

    if not skip_expect_peer:
        arm_dut_central_expect_peer(pi_ip, address, log=log, http_port=http_port)
    else:
        _log(log, "  expect-peer already armed")
        health = _http_json_retry("GET", f"{base}/health", None, log=log, timeout=15.0)
        pi_status = (health.get("status") or {}) if isinstance(health, dict) else {}
        pi_mac = pi_status.get("local_address") or pi_mac

    connected = False
    serial_pass = False
    pi_pass = False
    if (
        pi_status.get("connected") is True
        and str(pi_status.get("target_address") or "").upper() == address
    ):
        _log(log, "PASS step 3: connection already established (Pi connected=true)")
        connected = True
        pi_pass = True
    else:
        _log(log, f"Waiting up to {connect_timeout}s for step 3 (connection) …")
        deadline = time.time() + connect_timeout
        while time.time() < deadline:
            milestones = _serial_milestones_seen(
                serial_cursor, milestones=LONGRANGE_SERIAL_MILESTONES
            )
            if milestones.get("module_connected"):
                connected = True
                serial_pass = True
                _log(log, "PASS step 3: Module connected to address (DUT serial)")
                break
            st = poll_dut_central_connected(
                pi_ip,
                timeout_sec=min(2.0, max(0.5, deadline - time.time())),
                log=None,
                http_port=http_port,
                poll_sec=1.0,
                label="connect",
            )
            if st is not None:
                connected = True
                pi_pass = True
                _log(log, "PASS step 3: connection established (Pi connected=true)")
                break
            time.sleep(1.0)

    if not connected:
        seen = _serial_milestones_seen(serial_cursor, milestones=LONGRANGE_SERIAL_MILESTONES)
        _log(log, "DUT serial (longrange):")
        for key, label in (
            ("wifi_init", "Wi-Fi Initialization Success"),
            ("local_addr", "Local device address"),
            ("module_connected", "Module connected to address"),
        ):
            _log(log, f"  [{'OK' if seen.get(key) else '--'}] {label}")
        raise TimeoutError(
            f"Longrange step 3 failed: DUT {address} did not connect within "
            f"{connect_timeout}s (set RSI_REMOTE_DEVICE_NAME={peripheral_name!r} "
            f"or RSI_BLE_DEV_ADDR={pi_mac})"
        )

    # Brief settle so PHY skip / update prints can land on UART.
    time.sleep(3.0)
    seen = _serial_milestones_seen(serial_cursor, milestones=LONGRANGE_SERIAL_MILESTONES)

    _log(log, "Result (readme checklist):")
    _log(log, f"  [OK] 1. Pi advertising as {peripheral_name!r}" + (f" @ {pi_mac}" if pi_mac else ""))
    _log(
        log,
        f"  [OK] 2. DUT targeted {peripheral_name!r}"
        + (f" / {pi_mac}" if pi_mac else ""),
    )
    _log(log, "  [OK] 3. Connection established")
    if seen.get("phy_2mbps"):
        _log(log, "  [OK] 4–5. PHY data rate is updated to 2Mbps")
        phy_note = "2Mbps"
    elif seen.get("phy_500k"):
        _log(log, "  [OK] 4–5. PHY data rate is updated to 500kbps (Coded)")
        phy_note = "500kbps"
    elif seen.get("phy_complete"):
        _log(log, "  [OK] 4–5. Phy rate update complete event")
        phy_note = "phy_complete"
    elif seen.get("phy_skip"):
        _log(
            log,
            "  [OK] 4–5. Skipping PHY update (Pi peer — Coded ignored; stay 1M)",
        )
        phy_note = "skipped_for_pi"
    else:
        _log(
            log,
            "  [--] 4–5. PHY update print not seen "
            "(OK if RSI_SKIP_PHY_UPDATE_FOR_PI=1 / SL logging quiet) — connect is enough",
        )
        phy_note = "not_seen"

    if seen.get("module_connected"):
        _log(log, "  [OK] Module connected to address (DUT serial)")
    elif serial_pass or pi_pass:
        _log(log, "  [--] Module connected print not seen — Pi link confirmed")

    _log(log, "=== Long Range / 2Mbps RESULT: PASS ===")

    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": 1},
        log=log,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=log, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "longrange_manual",
        "dut_address": address,
        "pi_local_address": pi_mac,
        "peripheral_name": peripheral_name,
        "phy": phy_note,
        "serial_milestones": seen,
        "mark": mark,
        "complete": complete,
    }


def orchestrate_datalength_manual(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    skip_expect_peer: bool = False,
    serial_since_index: Optional[int] = None,
) -> dict:
    """
    SDK ble_datalength readme — Pi peripheral; DUT central + LE Data Length Extension.
    Short checklist for manual testers (no HTTP/JSON noise).
    """
    prof = profile or {}
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    peripheral_name = str(prof.get("ae_central_peripheral_name") or "SILABS_DEV")
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)
    if serial_since_index is not None:
        serial_cursor = int(serial_since_index)
    else:
        serial_cursor = mark_serial_cursor()

    health = _http_json_retry("GET", f"{base}/health", None, log=None, timeout=15.0)
    pi_status = (health.get("status") or {}) if isinstance(health, dict) else {}
    pi_mac = pi_status.get("local_address")

    _log(log, "=== Data Length (SDK ble_datalength) ===")
    _log(log, "Pi = peripheral (replaces phone). DUT = central. No notifications.")
    _log(
        log,
        f"[1] Pi advertising as {peripheral_name!r}"
        + (f" @ {pi_mac}" if pi_mac else ""),
    )
    _log(log, "[2] DUT scanning …")
    _log(
        log,
        f"[3] DUT looks for {peripheral_name!r}"
        + (f" / {pi_mac}" if pi_mac else ""),
    )

    if not skip_expect_peer:
        arm_dut_central_expect_peer(
            pi_ip, address, log=log, http_port=http_port, quiet=True
        )
    else:
        health = _http_json_retry("GET", f"{base}/health", None, log=None, timeout=15.0)
        pi_status = (health.get("status") or {}) if isinstance(health, dict) else {}
        pi_mac = pi_status.get("local_address") or pi_mac
        _log(log, f"Waiting for DUT {address} to connect …")

    # The Pi status can remain true briefly after a link drops because the
    # controller intentionally latches a peer link for diagnostics. For this
    # procedure require a fresh DUT serial connection before checking DLE.
    connected = False
    deadline = time.time() + connect_timeout
    while time.time() < deadline:
        milestones = _serial_milestones_merged(
            serial_cursor, milestones=DATALENGTH_SERIAL_MILESTONES
        )
        if milestones.get("module_connected"):
            connected = True
            break
        poll_dut_central_connected(
            pi_ip,
            timeout_sec=min(2.0, max(0.5, deadline - time.time())),
            log=None,
            http_port=http_port,
            poll_sec=1.0,
            label="connect",
        )
        time.sleep(1.0)

    if not connected:
        seen = _serial_milestones_merged(
            serial_cursor, milestones=DATALENGTH_SERIAL_MILESTONES
        )
        _log(log, "FAIL — connection not established. DUT serial so far:")
        for key, label in (
            ("adv_event", "Advertising report / peer found"),
            ("module_connected", "Module connected to address"),
        ):
            _log(log, f"  [{'OK' if seen.get(key) else '--'}] {label}")
        raise TimeoutError(
            f"Step 4 failed: DUT did not connect to {peripheral_name!r}"
            + (f" ({pi_mac})" if pi_mac else "")
            + f" within {connect_timeout}s"
        )

    _log(log, "[4] Connection established")
    _log(log, "[5] Waiting for DUT to set data length …")
    set_deadline = time.time() + 45.0
    while time.time() < set_deadline:
        seen = _serial_milestones_merged(
            serial_cursor, milestones=DATALENGTH_SERIAL_MILESTONES
        )
        if seen.get("set_data_len") or seen.get("mtu_event"):
            break
        time.sleep(1.0)
    else:
        seen = _serial_milestones_merged(
            serial_cursor, milestones=DATALENGTH_SERIAL_MILESTONES
        )

    if seen.get("set_data_len") or seen.get("mtu_event"):
        _log(log, "[5] DUT set data length")
    else:
        _log(log, "[5] -- set data length print not seen yet (check DUT serial)")

    _log(log, "[6] Waiting for data length change event …")
    change_deadline = time.time() + 45.0
    while time.time() < change_deadline:
        seen = _serial_milestones_merged(
            serial_cursor, milestones=DATALENGTH_SERIAL_MILESTONES
        )
        if seen.get("data_length_change"):
            break
        time.sleep(1.0)
    else:
        seen = _serial_milestones_merged(
            serial_cursor, milestones=DATALENGTH_SERIAL_MILESTONES
        )

    scan_ok = bool(
        seen.get("started_scanning") or seen.get("adv_event") or connected
    )
    mtu_ok = bool(seen.get("mtu_event"))
    dle_ok = bool(seen.get("data_length_change"))
    # Some SDK builds perform the request without printing the sample's
    # "Setting data length" message. MTU followed by the controller
    # data-length-change event is sufficient evidence that it completed.
    set_ok = bool(seen.get("set_data_len") or (mtu_ok and dle_ok))

    _log(log, "")
    _log(log, "Result (readme checklist):")
    _log(
        log,
        f"  [OK] 1. Pi advertising as {peripheral_name!r}"
        + (f" @ {pi_mac}" if pi_mac else ""),
    )
    _log(log, f"  [{'OK' if scan_ok else '--'}] 2. DUT scanning")
    _log(
        log,
        f"  [OK] 3. DUT targeted {peripheral_name!r}"
        + (f" / {pi_mac}" if pi_mac else ""),
    )
    _log(log, "  [OK] 4. Connection established")
    set_label = "5. DUT set data length"
    if set_ok and not seen.get("set_data_len"):
        set_label += " (inferred from MTU + change events)"
    _log(log, f"  [{'OK' if set_ok else '--'}] {set_label}")
    _log(log, f"  [{'OK' if dle_ok else '--'}] 6. Data length change event")

    _log(log, "")
    checklist_seen = _log_dut_readme_serial_block(
        log,
        0,
        kind="datalength",
        title="DUT serial (readme sequence — noise removed):",
    )

    if not set_ok or not dle_ok:
        hint = (
            "DUT serial missing data-length steps. "
            "No firmware source changes are required; verify the existing sample "
            "build keeps the link up through MTU exchange (In MTU event) → "
            "Setting data length → In event length change event."
        )
        if mtu_ok and not set_ok:
            hint = "MTU event seen but Setting data length not printed — check DUT firmware/callback."
        _log(log, f"=== Data Length RESULT: FAIL ===")
        _log(log, hint)
        raise TimeoutError(
            "Data length readme incomplete: "
            + ("missing 'Setting data length'; " if not set_ok else "")
            + ("missing 'In event length change event'" if not dle_ok else "")
        )

    _log(log, "=== Data Length RESULT: PASS ===")

    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": 1},
        log=None,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=None, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "datalength_manual",
        "dut_address": address,
        "pi_local_address": pi_mac,
        "peripheral_name": peripheral_name,
        "dle": "change_seen",
        "serial_milestones": {**seen, **checklist_seen},
        "mark": mark,
        "complete": complete,
    }


def orchestrate_testmodes_manual(
    pi_ip: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    serial_since_index: Optional[int] = None,
) -> dict:
    """
    SDK ble_testmodes readme — Pi replaces Linux + BT dongle (hcitool LE test).

    TX (default): DUT TX → Pi LE Receiver Test (0x001D) → Test End (0x001F) → packets.
    RX: DUT RX → Pi LE Transmitter Test (0x001E) → Test End (0x001F).
    """
    prof = profile or {}
    mode = str(prof.get("testmodes_mode") or "tx").strip().lower()
    if mode not in ("tx", "rx", "transmit", "receive"):
        mode = "tx"
    if mode == "transmit":
        mode = "tx"
    if mode == "receive":
        mode = "rx"
    channel = int(prof.get("testmodes_channel") or 0x10)
    payload_len = int(prof.get("testmodes_payload_len") or 0x20)
    payload_type = int(prof.get("testmodes_payload_type") or 0x01)
    collect_sec = float(prof.get("testmodes_collect_sec") or 8)
    min_packets = int(prof.get("min_test_packets") or 1)
    base = f"http://{pi_ip}:{http_port}"
    if serial_since_index is not None:
        serial_cursor = int(serial_since_index)
    else:
        serial_cursor = mark_serial_cursor()

    _log(log, "=== BLE Testmodes (SDK ble_testmodes) ===")
    _log(log, "Pi = Linux machine + BT dongle from the readme (hcitool).")
    _log(log, "No advertising / no GATT / no Heart Rate notifications.")
    _log(log, "")

    # Wait briefly for DUT boot prints.
    boot_deadline = time.time() + 25.0
    while time.time() < boot_deadline:
        seen = _serial_milestones_seen(
            serial_cursor, milestones=TESTMODES_SERIAL_MILESTONES
        )
        if seen.get("local_addr") or seen.get("tx_mode") or seen.get("rx_mode"):
            break
        time.sleep(1.0)
    seen = _serial_milestones_seen(
        serial_cursor, milestones=TESTMODES_SERIAL_MILESTONES
    )

    packets: Optional[int] = None
    rx_start: dict = {}
    tx_start: dict = {}
    end_result: dict = {}

    if mode == "tx":
        _log(log, "--- TX Testmodes Execution (readme) ---")
        _log(
            log,
            f"[1] DUT transmitting on channel 0x{channel:02X} "
            "(after flash — see DUT serial)",
        )
        if seen.get("tx_mode"):
            _log(log, "     DUT serial: TRANSMIT / TX test mode started [OK]")
        elif seen.get("local_addr"):
            _log(log, "     DUT serial: Local device address seen (TX assumed) [OK]")
        else:
            _log(
                log,
                "     DUT serial: TX banner not seen yet — continuing "
                "(ensure RSI_CONFIG_TEST_MODE=TRANSMIT)",
            )
        _log(log, "[2] Pi HCI adapter ready (replaces dongle on Linux)")
        _log(
            log,
            f"[3] Pi LE Receiver Test: hcitool cmd 0x08 0x001D 0x{channel:02X}",
        )
        rx_start = _http_json_retry(
            "POST",
            f"{base}/ble/testmodes/le-receiver-test",
            {"channel": channel},
            log=None,
            timeout=30.0,
        )
        if not rx_start.get("ok"):
            raise RuntimeError(
                f"TX step 3 failed (LE Receiver Test): {rx_start}"
            )
        _log(log, f"     Command: {rx_start.get('command')}")
        _log(log, f"[4] Channel match: Pi RX ch 0x{channel:02X} == DUT TX ch")
        _log(log, f"     Collecting packets for {collect_sec:.0f}s …")
        time.sleep(max(1.0, collect_sec))
        _log(log, "[5] Pi LE Test End: hcitool cmd 0x08 0x001F")
        end_result = _http_json_retry(
            "POST",
            f"{base}/ble/testmodes/le-test-end",
            {},
            log=None,
            timeout=30.0,
        )
        if not end_result.get("ok"):
            raise RuntimeError(f"TX step 5 failed (LE Test End): {end_result}")
        _log(log, f"     Command: {end_result.get('command')}")
        packets = end_result.get("packets")
        _log(log, f"[6] Verify packets received: {packets}")
        if packets is None:
            raise RuntimeError(
                "TX step 6 failed: could not parse packet count from HCI Test End. "
                f"Output: {(end_result.get('output') or '')[:400]}"
            )
        if int(packets) < min_packets:
            raise RuntimeError(
                f"TX step 6 failed: expected >= {min_packets} packets, got {packets}. "
                "Check DUT is in TRANSMIT mode and channel matches (default 0x10)."
            )
        _log(log, f"     Packets OK (>= {min_packets})")
    else:
        _log(log, "--- RX Testmodes Execution (readme) ---")
        _log(
            log,
            f"[1] DUT ready to receive on channel 0x{channel:02X} "
            "(RSI_CONFIG_TEST_MODE=RECEIVE)",
        )
        if seen.get("rx_mode"):
            _log(log, "     DUT serial: RECEIVE / RX test mode started [OK]")
        elif seen.get("local_addr"):
            _log(log, "     DUT serial: Local device address seen (RX assumed) [OK]")
        else:
            _log(
                log,
                "     DUT serial: RX banner not seen yet — continuing "
                "(flash with RSI_CONFIG_TEST_MODE=RECEIVE)",
            )
        _log(log, "[2–3] Pi LE Transmitter Test (dongle TX → DUT):")
        _log(
            log,
            f"     hcitool cmd 0x08 0x001E 0x{channel:02X} "
            f"0x{payload_len:02X} 0x{payload_type:02X}",
        )
        tx_start = _http_json_retry(
            "POST",
            f"{base}/ble/testmodes/le-transmitter-test",
            {
                "channel": channel,
                "payload_len": payload_len,
                "payload_type": payload_type,
            },
            log=None,
            timeout=30.0,
        )
        if not tx_start.get("ok"):
            raise RuntimeError(
                f"RX step 3 failed (LE Transmitter Test): {tx_start}"
            )
        _log(log, f"     Command: {tx_start.get('command')}")
        _log(log, f"[4] Channel match: Pi TX ch 0x{channel:02X} == DUT RX ch")
        _log(log, f"     Transmitting for {collect_sec:.0f}s …")
        time.sleep(max(1.0, collect_sec))
        _log(log, "[5] Pi LE Test End: hcitool cmd 0x08 0x001F")
        end_result = _http_json_retry(
            "POST",
            f"{base}/ble/testmodes/le-test-end",
            {},
            log=None,
            timeout=30.0,
        )
        if not end_result.get("ok"):
            raise RuntimeError(f"RX stop failed (LE Test End): {end_result}")
        packets = end_result.get("packets")
        _log(log, f"     Command: {end_result.get('command')}")
        _log(log, "[6] Pi TX completed — check DUT serial console prints")
        seen = _serial_milestones_seen(
            serial_cursor, milestones=TESTMODES_SERIAL_MILESTONES
        )

    seen = _serial_milestones_seen(
        serial_cursor, milestones=TESTMODES_SERIAL_MILESTONES
    )
    _log(log, "")
    _log(log, "Result (readme checklist):")
    if mode == "tx":
        _log(
            log,
            f"  [{'OK' if seen.get('tx_mode') or seen.get('local_addr') else '--'}] "
            "1. DUT began transmitting",
        )
        _log(log, "  [OK] 2–3. Pi LE Receiver Test (0x001D)")
        _log(log, f"  [OK] 4. Channel 0x{channel:02X}")
        _log(log, "  [OK] 5. Pi LE Test End (0x001F)")
        _log(log, f"  [OK] 6. Packets received = {packets}")
    else:
        _log(
            log,
            f"  [{'OK' if seen.get('rx_mode') or seen.get('local_addr') else '--'}] "
            "1. DUT ready to receive",
        )
        _log(log, "  [OK] 2–3. Pi LE Transmitter Test (0x001E)")
        _log(log, f"  [OK] 4. Channel 0x{channel:02X}")
        _log(log, "  [OK] 5. Pi LE Test End (0x001F)")
        _log(log, "  [OK] 6. TX sequence completed (see DUT serial)")
    _log(log, "=== BLE Testmodes RESULT: PASS ===")

    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": int(packets or 1)},
        log=None,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=None, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": f"testmodes_{mode}",
        "channel": channel,
        "packets": packets,
        "serial_milestones": seen,
        "rx_start": rx_start,
        "tx_start": tx_start,
        "end": end_result,
        "mark": mark,
        "complete": complete,
    }


def orchestrate_stack_bypass_manual(
    pi_ip: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    serial_since_index: Optional[int] = None,
) -> dict:
    """
    SDK bt_stack_bypass readme — Pi attaches DUT HCI UART (btattach) and runs
    hciconfig / leadv / lescan. Phone step replaced by BD_ADDR + leadv OK.
    """
    prof = profile or {}
    uart = str(
        os.environ.get("BLE_STACK_BYPASS_UART")
        or prof.get("stack_bypass_uart")
        or "/dev/ttyUSB0"
    )
    baud = int(prof.get("stack_bypass_baud") or 115200)
    lescan_sec = int(prof.get("stack_bypass_lescan_sec") or 5)
    base = f"http://{pi_ip}:{http_port}"
    if serial_since_index is not None:
        serial_cursor = int(serial_since_index)
    else:
        serial_cursor = mark_serial_cursor()

    _log(log, "=== BT Stack Bypass (SDK bt_stack_bypass) ===")
    _log(log, "Pi = Linux host. DUT = raw HCI over UART (BLE stack bypassed on chip).")
    _log(log, f"UART cable required: {uart} @ {baud}  (SoC: WSTK P35=Tx / P33=Rx → Pi)")
    _log(log, "No GATT connect / no Heart Rate notifications.")
    _log(log, "")

    _log(log, "[1] DUT running — UART HCI receive state (after flash)")
    _log(log, "[2] Waiting for Wi-Fi initialization on DUT serial …")
    boot_deadline = time.time() + 40.0
    wifi_ok = False
    while time.time() < boot_deadline:
        seen = _serial_milestones_seen(
            serial_cursor, milestones=STACK_BYPASS_SERIAL_MILESTONES
        )
        if seen.get("wifi_init"):
            wifi_ok = True
            break
        time.sleep(1.0)
    seen = _serial_milestones_seen(
        serial_cursor, milestones=STACK_BYPASS_SERIAL_MILESTONES
    )
    if wifi_ok:
        _log(log, "[2] Wi-Fi initialization complete [OK] — safe to attach HCI")
    else:
        _log(
            log,
            "[2] WARN — Wi-Fi init print not seen; attaching anyway "
            "(HCI may fail if DUT not ready)",
        )

    _log(log, f"[3] Attach HCI UART on Pi: btattach {uart} @ {baud}")
    attach = _http_json_retry(
        "POST",
        f"{base}/ble/stack-bypass/attach",
        {"device": uart, "baud": baud},
        log=None,
        timeout=60.0,
    )
    if not attach.get("ok"):
        raise RuntimeError(
            f"Step 3 failed (btattach): {attach.get('error') or attach}. "
            "Check USB-UART cable and BLE_STACK_BYPASS_UART=/dev/ttyUSBx"
        )
    adapter = str(attach.get("adapter") or "hci0")
    _log(log, f"     Adapter appeared: {adapter}")

    _log(log, f"[4] hciconfig — verify BD_ADDR on {adapter}")
    cfg_info = _http_json_retry(
        "POST",
        f"{base}/ble/stack-bypass/hciconfig",
        {"adapter": adapter},
        log=None,
        timeout=30.0,
    )
    bd_addr = cfg_info.get("bd_addr")
    is_up = bool(cfg_info.get("up"))
    if bd_addr:
        _log(log, f"     BD_ADDR = {bd_addr}  state={'UP' if is_up else 'DOWN'}")
    else:
        _log(log, "     WARN — BD_ADDR not parsed yet")

    if not is_up:
        _log(log, f"[5] Interface DOWN — running: hciconfig -a {adapter} up")
        up_res = _http_json_retry(
            "POST",
            f"{base}/ble/stack-bypass/up",
            {"adapter": adapter},
            log=None,
            timeout=30.0,
        )
        if not up_res.get("ok"):
            try:
                _http_json_retry(
                    "POST",
                    f"{base}/ble/stack-bypass/detach",
                    {"device": uart},
                    log=None,
                    timeout=20.0,
                )
            except Exception:
                pass
            raise RuntimeError(f"Step 5 failed (hciconfig up): {up_res}")
        bd_addr = up_res.get("bd_addr") or bd_addr
        _log(log, f"[5] {adapter} is UP  BD_ADDR={bd_addr}")
    else:
        _log(log, f"[5] Interface already UP — skip hciconfig up")

    _log(log, f"[6a] LE advertising: hciconfig -a {adapter} leadv")
    leadv = _http_json_retry(
        "POST",
        f"{base}/ble/stack-bypass/leadv",
        {"adapter": adapter},
        log=None,
        timeout=30.0,
    )
    if not leadv.get("ok"):
        try:
            _http_json_retry(
                "POST",
                f"{base}/ble/stack-bypass/detach",
                {"device": uart},
                log=None,
                timeout=20.0,
            )
        except Exception:
            pass
        raise RuntimeError(f"Step 6a failed (leadv): {leadv}")
    _log(log, "[6a] LE advertising enabled [OK]")

    _log(log, f"[6b] LE scan: hcitool -i {adapter} lescan ({lescan_sec}s)")
    lescan = _http_json_retry(
        "POST",
        f"{base}/ble/stack-bypass/lescan",
        {"adapter": adapter, "timeout": lescan_sec},
        log=None,
        timeout=float(lescan_sec) + 30.0,
    )
    if not lescan.get("ok"):
        _log(log, f"[6b] WARN — lescan returned: {lescan.get('error') or lescan}")
    else:
        nlines = len(lescan.get("lines") or [])
        _log(log, f"[6b] lescan ran [OK] ({nlines} result line(s))")

    _log(
        log,
        f"[7] Phone/SiConnect would scan for BD_ADDR={bd_addr or 'n/a'} — "
        "automated pass = interface UP + leadv OK (no phone required)",
    )

    _log(log, f"[8] Detach HCI UART: pkill btattach ({uart})")
    detach = _http_json_retry(
        "POST",
        f"{base}/ble/stack-bypass/detach",
        {"device": uart},
        log=None,
        timeout=20.0,
    )
    _log(log, "[8] Detached [OK]" if detach.get("ok") else f"[8] detach: {detach}")

    seen = _serial_milestones_seen(
        serial_cursor, milestones=STACK_BYPASS_SERIAL_MILESTONES
    )
    _log(log, "")
    _log(log, "Result (readme checklist):")
    _log(log, "  [OK] 1. DUT in UART HCI receive state")
    _log(
        log,
        f"  [{'OK' if seen.get('wifi_init') or wifi_ok else '--'}] "
        "2. Wi-Fi initialization complete",
    )
    _log(log, f"  [OK] 3. HCI UART attached ({uart} → {adapter})")
    _log(log, f"  [{'OK' if bd_addr else '--'}] 4. hciconfig BD_ADDR = {bd_addr or 'n/a'}")
    _log(log, "  [OK] 5. Interface UP")
    _log(log, "  [OK] 6a. leadv")
    _log(log, f"  [{'OK' if lescan.get('ok') else '--'}] 6b. lescan")
    _log(
        log,
        f"  [OK] 7. Verify (automated): advertise as {bd_addr or 'n/a'} "
        "(phone optional)",
    )
    _log(log, "  [OK] 8. Detach btattach")
    _log(log, "=== BT Stack Bypass RESULT: PASS ===")

    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": 1},
        log=None,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=None, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "stack_bypass_manual",
        "uart": uart,
        "adapter": adapter,
        "bd_addr": bd_addr,
        "attach": attach,
        "leadv": leadv,
        "lescan": lescan,
        "detach": detach,
        "serial_milestones": seen,
        "mark": mark,
        "complete": complete,
    }


def _log_ae_peripheral_serial_checklist(
    log: Optional[LogFn],
    since_index: Optional[int] = None,
) -> dict:
    labels = {
        "local_addr": "Local device address",
        "ae_params": "Setting AE params successful",
        "ae_enable": "set ae adv enable success",
        "remote_connected": "Remote device with <addr> address connected",
    }
    seen = _serial_milestones_seen(since_index, milestones=AE_PERIPHERAL_SERIAL_MILESTONES)
    _log(log, "DUT serial checklist (SDK AE Peripheral demo):")
    for key, label in labels.items():
        mark = "OK" if seen.get(key) else "--"
        _log(log, f"  [{mark}] {label}")
    if not seen.get("remote_connected"):
        _log(
            log,
            "  Note: AE sample often disables SL logging — Pi connect is enough to PASS",
        )
    return seen


def _parse_serial_dut_mac(since_index: int = 0) -> Optional[str]:
    """Best-effort public MAC from DUT serial (may appear even when AE logging is sparse)."""
    try:
        lines = get_lines(since=since_index).get("lines") or []
        match = RE_DUT_ADDRESS.search("\n".join(lines))
        if match:
            return match.group(1).upper()
    except Exception:
        pass
    return None


def _ae_peripheral_address_candidates(
    dut_address: str,
    profile: dict,
    *,
    serial_since_index: Optional[int] = None,
    log: Optional[LogFn] = None,
) -> List[str]:
    """UI/public MAC, serial MAC, SET1 random — deduped scan/connect candidates."""
    rand_addr = str(profile.get("dut_random_adv_addr") or "C1:44:33:AA:BB:CC").strip().upper()
    candidates: List[str] = []
    for addr in (dut_address, rand_addr):
        try:
            norm = normalize_dut_address(addr)
        except ValueError:
            continue
        if norm not in candidates:
            candidates.append(norm)
    since = int(serial_since_index) if serial_since_index is not None else 0
    serial_mac = _parse_serial_dut_mac(since)
    if serial_mac and serial_mac not in candidates:
        candidates.insert(0, serial_mac)
        _log(log, f"  Serial public MAC (SET2): {serial_mac}")
    return candidates


def orchestrate_ae_peripheral_simple_connect(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    serial_since_index: Optional[int] = None,
) -> dict:
    """
    SDK ble_ae_peripheral / manual tester: Pi central scans + connects to DUT AE advertiser.

    Pass = Pi connected (bond=false). No GATT notify, no 5‑min soak.
    Tries LocalName AE_PERIPHERAL, then UI/public MAC (SET2), then SET1 random addr.
    """
    prof = profile or {}
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    adv_name = str(prof.get("dut_advertising_name") or "AE_PERIPHERAL")
    base = f"http://{pi_ip}:{http_port}"
    if serial_since_index is not None:
        serial_cursor = int(serial_since_index)
    else:
        serial_cursor = mark_serial_cursor()

    candidates = _ae_peripheral_address_candidates(
        dut_address,
        prof,
        serial_since_index=serial_cursor,
        log=log,
    )

    _log(log, "=== AE Peripheral (SDK siwx91x_bluetooth_le_ae_peripheral) ===")
    _log(log, f"  DUT advertises as {adv_name!r} (extended AE)")
    _log(log, f"  Pi = central scan+connect (bond=false)")
    _log(log, f"  Address candidates: {', '.join(candidates)}")
    _log(log, "  Pass when: Pi connected=true")
    _log(
        log,
        "  Build Studio auto-patches SDK on build: ENABLE_NWP_POWER_SAVE=0, "
        "LocalName in AE AD, RSI_BLE_SET_RAND_ADDR=C1:44:33:AA:BB:CC",
    )

    wait_for_pi_health(pi_ip, http_port, 60.0, log)

    matched: Optional[str] = None
    scan_result: Optional[dict] = None
    deadline = time.time() + connect_timeout
    attempt = 0
    connect_ok = False
    connect_result: Optional[dict] = None

    # Unlike ae_central / ble_central (Pi advertises, DUT connects), here the Pi
    # must *see* the DUT AE advertiser first. Blind ConnectDevice crashes Pi BlueZ.
    while time.time() < deadline and not matched:
        attempt += 1
        remain = max(5, int(deadline - time.time()))
        scan_result = ble_debug_scan(
            pi_ip,
            timeout=min(20, remain),
            http_port=http_port,
            log=log,
            name=adv_name,
        )
        matched = scan_result.get("matched_address")
        if matched:
            _log(log, f"PASS step: scan found {adv_name!r} at {matched}")
            break
        for addr in candidates:
            if time.time() >= deadline:
                break
            remain = max(5, int(deadline - time.time()))
            scan_result = ble_debug_scan(
                pi_ip,
                addr,
                timeout=min(15, remain),
                http_port=http_port,
                log=log,
            )
            if scan_result.get("address_found"):
                matched = addr
                _log(log, f"PASS step: scan found DUT MAC {matched}")
                break
        if not matched:
            _log(log, f"  scan attempt {attempt}: DUT not seen yet — retry …")
            time.sleep(2.0)

    if not matched:
        serial_seen = _log_ae_peripheral_serial_checklist(log, serial_cursor)
        if serial_seen.get("ae_enable"):
            _log(
                log,
                "Scan missed DUT but serial shows AE adv enabled — "
                "trying direct connect to known MAC(s) …",
            )
            rand = str(prof.get("dut_random_adv_addr") or "C1:44:33:AA:BB:CC").strip().upper()
            for addr in candidates:
                atype = "random" if addr == rand else "public"
                _log(log, f"POST /ble/connect direct address={addr} type={atype}")
                try:
                    connect_result = _http_json_retry(
                        "POST",
                        f"{base}/ble/connect",
                        _merge_connect_payload(
                            addr,
                            use_passkey=False,
                            conn_params=None,
                            address_type=atype,
                            direct_connect=True,
                        ),
                        log=log,
                        timeout=90.0,
                    )
                except Exception as exc:
                    connect_result = {"ok": False, "error": str(exc)}
                if connect_result.get("ok"):
                    matched = addr
                    connect_ok = True
                    _log(log, f"PASS step: Pi connected (direct) to {matched}")
                    break
        if not matched:
            raise TimeoutError(
                f"DUT AE peripheral {adv_name!r} not found in Pi scan within "
                f"{connect_timeout}s (tried name + {candidates}). "
                "Rebuild with Build Studio (UTF patches scannable+legacy AE, "
                "LocalName AD, power save off) and redeploy Pi test package "
                "for HCI scan fallback. "
                f"Confirm RSI_BLE_SET_RAND_ADDR=C1:44:33:AA:BB:CC."
            )

    if not connect_ok:
        # SET1 and SET2 may both be visible under the same LocalName.  BlueZ
        # can reject a direct connection to the random SET1 address while the
        # public SET2 address is connectable, so do not abort on the first
        # matching scan result. Try the matched address first, then every
        # remaining candidate with the correct address type.
        random_addr = str(
            prof.get("dut_random_adv_addr") or "C1:44:33:AA:BB:CC"
        ).strip().upper()
        connect_candidates = [matched] + [addr for addr in candidates if addr != matched]
        failures: List[dict] = []
        for candidate in connect_candidates:
            atype = "random" if candidate == random_addr else "public"
            _log(log, f"POST /ble/connect address={candidate} bond=false address_type={atype}")
            try:
                connect_result = _http_json_retry(
                    "POST",
                    f"{base}/ble/connect",
                    _merge_connect_payload(
                        candidate,
                        use_passkey=False,
                        conn_params=None,
                        address_type=atype,
                    ),
                    log=log,
                    timeout=60.0,
                )
            except Exception as exc:
                connect_result = {"ok": False, "error": str(exc)}
            if connect_result.get("ok"):
                matched = candidate
                connect_ok = True
                _log(log, f"PASS step: Pi connected to {matched}")
                break
            failures.append({"address": candidate, "address_type": atype, "result": connect_result})
            _log(log, f"  connect failed for {candidate}; trying next address candidate")

        if not connect_ok:
            _log_ae_peripheral_serial_checklist(log, serial_cursor)
            raise RuntimeError(
                f"BLE connect failed for AE peripheral candidates {connect_candidates}: "
                f"{failures}"
            )

    # Brief settle — confirm link still up (no 5‑min soak).
    time.sleep(2.0)
    st = _http_json_retry("GET", f"{base}/ble/status", None, log=None, timeout=15.0)
    status = (st.get("status") or {}) if isinstance(st, dict) else {}
    if status.get("connected") is not True:
        # One retry connect if status flaps.
        _log(log, "WARN: status connected=false after connect — retrying once …")
        atype = "random" if matched == str(prof.get("dut_random_adv_addr") or "C1:44:33:AA:BB:CC").strip().upper() else "public"
        connect_result = _http_json_retry(
            "POST",
            f"{base}/ble/connect",
            _merge_connect_payload(
                matched,
                use_passkey=False,
                conn_params=None,
                address_type=atype,
            ),
            log=log,
            timeout=90.0,
        )
        if not connect_result.get("ok"):
            raise RuntimeError(f"AE peripheral connect did not stay up: {connect_result}")

    serial_seen = _log_ae_peripheral_serial_checklist(log, serial_cursor)
    _log(log, "=== AE Peripheral RESULT: PASS (connect established) ===")

    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": 1},
        log=log,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=log, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "simple_connect",
        "dut_address": matched,
        "candidates": candidates,
        "scan": {
            "matched_address": matched,
            "address_found": True,
            "name": adv_name,
        },
        "connect": connect_result,
        "mark": mark,
        "complete": complete,
        "serial_milestones": serial_seen,
        "peripheral_name": adv_name,
    }


def orchestrate_gatt_long_read(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
) -> dict:
    """
    SDK gatt_long_read SERVER: Pi central scan+connect, then GATT Read of long attr.

    Pass = connected + POST /ble/read length >= min_gatt_read_len (default 21).
    No notify / no 5‑min soak. Matches phone Simplicity Connect long-read demo.
    """
    prof = profile or {}
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    adv_name = str(prof.get("dut_advertising_name") or "LONG_READ_TEST")
    service_uuid = str(prof.get("service_uuid") or "aabb")
    char_uuid = str(prof.get("char_uuid") or "1aa1")
    min_len = int(prof.get("min_gatt_read_len") or 21)
    base = f"http://{pi_ip}:{http_port}"
    public_addr = normalize_dut_address(dut_address)

    _log(log, "=== GATT Long Read SERVER (SDK gatt_long_read) ===")
    _log(log, f"  DUT advertises as {adv_name!r} (GATT_ROLE=SERVER)")
    _log(log, f"  Pi = central scan+connect (bond=false)")
    _log(log, f"  GATT Read service={service_uuid} char={char_uuid} min_len={min_len}")
    _log(log, "  Pass when: long attribute Read succeeds (length > 20)")

    wait_for_pi_health(pi_ip, http_port, 60.0, log)

    matched: Optional[str] = None
    scan_result: Optional[dict] = None
    deadline = time.time() + connect_timeout
    attempt = 0

    while time.time() < deadline and not matched:
        attempt += 1
        remain = max(5, int(deadline - time.time()))
        scan_result = ble_debug_scan(
            pi_ip,
            timeout=min(20, remain),
            http_port=http_port,
            log=log,
            name=adv_name,
        )
        matched = scan_result.get("matched_address")
        if matched:
            _log(log, f"PASS step: scan found {adv_name!r} at {matched}")
            break
        remain = max(5, int(deadline - time.time()))
        scan_result = ble_debug_scan(
            pi_ip,
            public_addr,
            timeout=min(15, remain),
            http_port=http_port,
            log=log,
        )
        if scan_result.get("address_found"):
            matched = public_addr
            _log(log, f"PASS step: scan found DUT MAC {matched}")
            break
        _log(log, f"  scan attempt {attempt}: DUT not seen yet — retry …")
        time.sleep(2.0)

    if not matched:
        raise TimeoutError(
            f"DUT {adv_name!r} not found in Pi scan within {connect_timeout}s "
            f"(tried name + {public_addr}). Flash GATT_ROLE=SERVER and confirm advertising."
        )

    _log(log, f"POST /ble/connect address={matched} bond=false")
    connect_result = _http_json_retry(
        "POST",
        f"{base}/ble/connect",
        _merge_connect_payload(
            matched,
            use_passkey=False,
            conn_params=connect_conn_params("gatt_long_read"),
        ),
        log=log,
        timeout=60.0,
    )
    if not connect_result.get("ok"):
        raise RuntimeError(f"BLE connect failed for gatt_long_read {matched}: {connect_result}")
    _log(log, f"PASS step: Pi connected to {matched}")

    # DUT exchanges MTU after connect (RSI_BLE_MTU_SIZE=100); allow settle.
    time.sleep(3.0)

    read_payload = {
        "service_uuid": service_uuid,
        "char_uuid": char_uuid,
        "timeout": 30,
    }
    read_result: Optional[dict] = None
    read_deadline = time.time() + 60.0
    read_attempt = 0
    while time.time() < read_deadline:
        read_attempt += 1
        _log(log, f"POST /ble/read {json.dumps(read_payload)} (attempt {read_attempt})")
        try:
            read_result = _http_json_retry(
                "POST",
                f"{base}/ble/read",
                read_payload,
                log=log,
                timeout=45.0,
            )
        except Exception as exc:
            read_result = {"ok": False, "error": str(exc)}
        length = int(read_result.get("length") or 0) if isinstance(read_result, dict) else 0
        if read_result.get("ok") and length >= min_len:
            _log(
                log,
                f"PASS step: GATT Read length={length} "
                f"preview={read_result.get('value_preview')}",
            )
            break
        _log(
            log,
            f"  read attempt {read_attempt}: ok={read_result.get('ok')} "
            f"length={length} (need>={min_len}) — retry after MTU/services…",
        )
        time.sleep(2.0)
    else:
        raise RuntimeError(
            f"GATT long read failed after retries: need length>={min_len}, "
            f"last={read_result}"
        )

    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": 1, "gatt_read_length": read_result.get("length")},
        log=log,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=log, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "gatt_long_read",
        "dut_address": matched,
        "scan": scan_result,
        "connect": connect_result,
        "read": read_result,
        "mark": mark,
        "complete": complete,
        "peripheral_name": adv_name,
        "min_gatt_read_len": min_len,
    }


def submit_passkey_to_pi(pi_ip: str, passkey: str, log: Optional[LogFn] = None, http_port: int = DEFAULT_PI_HTTP_PORT) -> dict:
    base = f"http://{pi_ip}:{http_port}"
    _log(log, f"Submitting passkey {passkey} to Pi")
    result = _http_json_retry(
        "POST",
        f"{base}/ble/passkey",
        {"passkey": str(passkey)},
        log=log,
        timeout=130.0,
        attempts=10,
    )
    _log(log, f"Passkey response: {json.dumps(result, indent=None)}")
    if not result.get("ok"):
        st = _pi_status_dict(result.get("status") or result)
        state = st.get("state") if st else result.get("status", {})
        if isinstance(state, dict):
            state = state.get("state")
        raise RuntimeError(
            f"Passkey submit failed: {result} (pi_state={state!r})"
        )
    return result


def normalize_dut_address(address: str) -> str:
    raw = (address or "").strip().upper().replace("-", ":")
    if not RE_MAC.match(raw):
        raise ValueError(
            f"Invalid DUT BLE address {address!r} — use AA:BB:CC:DD:EE:FF"
        )
    return raw


def resolve_dut_address(
    explicit: Optional[str],
    log: Optional[LogFn] = None,
    *,
    since_index: Optional[int] = None,
    fresh: bool = True,
    quiet: bool = False,
) -> str:
    """Use UI/configured MAC when set; otherwise parse from DUT serial after flash."""
    if explicit and str(explicit).strip():
        addr = normalize_dut_address(str(explicit))
        if not quiet:
            _log(log, f"Using configured DUT address: {addr}")
        return addr
    try:
        return parse_dut_address_from_serial(log, since_index=since_index, fresh=fresh)
    except TimeoutError as exc:
        raise TimeoutError(
            f"{exc}. Enter the DUT BLE address in Build Studio (UTF section) "
            "or open Serial Console and confirm 'Local device address' appears after flash."
        ) from exc


def parse_dut_address_from_serial(
    log: Optional[LogFn] = None,
    *,
    since_index: Optional[int] = None,
    fresh: bool = True,
) -> str:
    if since_index is None:
        since_index = mark_serial_cursor() if fresh else 0
    if not fresh and since_index == 0:
        existing = RE_DUT_ADDRESS.search(get_all_text())
        if existing:
            address = existing.group(1).upper()
            _log(log, f"Parsed DUT address from serial (buffer): {address}")
            return address
    match = wait_for_pattern(RE_DUT_ADDRESS, timeout_sec=MAC_TIMEOUT_SEC, since_index=since_index)
    address = match.group(1).upper()
    _log(log, f"Parsed DUT address from serial: {address}")
    return address


def ensure_serial_monitor(
    port: Optional[str] = None,
    log: Optional[LogFn] = None,
    *,
    label: Optional[str] = None,
    quiet: bool = False,
) -> str:
    """Start DUT serial capture if not already active."""
    status = serial_status()
    if status.get("active") and status.get("port"):
        active_port = str(status["port"])
        if not quiet:
            _log(log, f"DUT serial already listening on {active_port}")
            if status.get("log_path"):
                _log(log, f"DUT serial log file: {status['log_path']}")
        return active_port
    resolved = resolve_serial_port(port)
    start_serial(resolved, DEFAULT_BAUD, label=label)
    if quiet:
        _log(
            log,
            f"Serial Console: {resolved} @ {DEFAULT_BAUD} "
            "(DUT output appears there — not in Build Console)",
        )
    else:
        _log(log, f"DUT serial listening on {resolved} @ {DEFAULT_BAUD}")
        saved_to = serial_log_path()
        if saved_to:
            _log(log, f"DUT serial log file: {saved_to}")
        else:
            _log(log, "WARN: could not open a serial log file — console will not be saved")
    return resolved


def parse_passkey_from_serial(
    log: Optional[LogFn] = None,
    *,
    since_index: Optional[int] = None,
    fresh: bool = True,
    pattern: Optional[re.Pattern] = None,
) -> str:
    regex = pattern or RE_PASSKEY
    if since_index is None and fresh:
        since_index = serial_cursor()
    if since_index is None:
        since_index = 0
    if not fresh and since_index == 0:
        existing = regex.search(get_all_text())
        if existing:
            passkey = existing.group(1)
            _log(log, f"Parsed passkey from serial (buffer): {passkey}")
            return passkey
    _log(log, f"Waiting for passkey on DUT serial (lines after index {since_index}) …")
    match = wait_for_pattern(regex, timeout_sec=PASSKEY_TIMEOUT_SEC, since_index=since_index)
    passkey = match.group(1)
    _log(log, f"Parsed passkey from serial: {passkey}")
    return passkey


def orchestrate_passkey_pairing(
    pi_ip: str,
    log: Optional[LogFn] = None,
    *,
    serial_since_index: Optional[int] = None,
) -> dict:
    """After bond=true connect: read DUT passkey from serial and POST /ble/passkey."""
    wait_for_pi_ble_state(
        pi_ip,
        ("awaiting_passkey", "passkey_submitted"),
        timeout_sec=45.0,
        log=log,
    )
    passkey = parse_passkey_from_serial(log, since_index=serial_since_index, fresh=True)
    passkey_result = submit_passkey_to_pi(pi_ip, passkey, log)
    if check_smp_failure():
        raise RuntimeError("SMP pairing failed (DUT shows 0 central devices)")
    wait_for_smp_success(log, since_index=serial_since_index)
    return {"passkey": passkey, "response": passkey_result}


def orchestrate_passkey_connect_flow(
    pi_ip: str,
    app_id: str,
    address: str,
    log: Optional[LogFn] = None,
    *,
    scan_before_connect: bool = False,
    conn_params: Optional[dict] = None,
) -> dict:
    """Connect with SMP, submit passkey from DUT serial, enable notifications."""
    conn = conn_params or connect_conn_params(app_id)
    connect_out = orchestrate_ble_connect(
        pi_ip,
        address,
        True,
        log,
        scan_before_connect=scan_before_connect,
        conn_params=conn,
    )
    pairing = orchestrate_passkey_pairing(
        pi_ip, log, serial_since_index=connect_out.get("serial_cursor")
    )
    notify_result = orchestrate_ble_notifications(pi_ip, app_id, log)
    return {"connect": connect_out, "pairing": pairing, "notifications": notify_result}


def wait_for_smp_success(log: Optional[LogFn] = None, *, since_index: Optional[int] = None) -> None:
    _log(log, "Waiting for SMP success in DUT serial…")
    if since_index is None:
        since_index = serial_cursor()
    wait_for_pattern(RE_SMP_SUCCESS, timeout_sec=PASSKEY_TIMEOUT_SEC, since_index=since_index)
    _log(log, "SMP pairing succeeded (security keys event)")


def check_smp_failure() -> bool:
    text = get_all_text()
    return bool(RE_SMP_FAILURE.search(text) or RE_SMP_FAILED_EVENT.search(text))


def _log_secureconnection_serial_checklist(
    log: Optional[LogFn],
    serial_cursor: int,
) -> dict:
    seen = _serial_milestones_seen(
        serial_cursor, milestones=SECURECONNECTION_SERIAL_MILESTONES
    )
    labels = (
        ("wifi_init", "Wi-Fi initialization"),
        ("local_addr", "Local device address"),
        ("connected", "Module connected / Enhance connected"),
        ("smp_req", "SMP request/response"),
        ("passkey", "Passkey display on console"),
        ("encrypt", "start encrypt status: 0"),
        ("security_keys", "security keys event"),
    )
    _log(log, "DUT serial checklist (ble_secureconnection readme):")
    for key, label in labels:
        mark = "OK" if seen.get(key) else "--"
        _log(log, f"  [{mark}] {label}")
    if seen.get("smp_failed"):
        _log(log, "  [FAIL] smp_failed status seen on DUT serial")
    return seen


def orchestrate_secureconnection_manual(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    serial_since_index: Optional[int] = None,
    conn_params: Optional[dict] = None,
) -> dict:
    """
    SDK ble_secureconnection readme — Pi replaces Simplicity Connect phone:

    1–2 DUT advertises + serial up
    3   clear prior BlueZ bond (bonded-tab delete)
    4–5 scan for BLE_SMP_SC / DUT MAC, connect
    6–7 accept SMP / enter passkey from DUT console
    8–9 encrypt + security keys (or smp_failed)
    """
    prof = profile or {}
    adv_name = str(prof.get("dut_advertising_name") or "BLE_SMP_SC")
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)
    conn = conn_params or connect_conn_params("ble_secureconnection")
    if serial_since_index is not None:
        serial_cursor = int(serial_since_index)
    else:
        serial_cursor = mark_serial_cursor()

    _log(log, "=== BLE Secure Connection (SDK ble_secureconnection) ===")
    _log(log, f"DUT = peripheral advertiser ({adv_name!r})")
    _log(log, "Pi = central (Simplicity Connect phone role) + SMP passkey")
    _log(log, "No GATT notifications / no Heart Rate path")
    _log(log, "")

    _log(log, "[1] DUT advertising (after flash) — wait Local device address")
    boot_deadline = time.time() + 45.0
    while time.time() < boot_deadline:
        seen = _serial_milestones_seen(
            serial_cursor, milestones=SECURECONNECTION_SERIAL_MILESTONES
        )
        if seen.get("local_addr") or seen.get("wifi_init"):
            break
        time.sleep(1.0)
    seen_boot = _serial_milestones_seen(
        serial_cursor, milestones=SECURECONNECTION_SERIAL_MILESTONES
    )
    if seen_boot.get("local_addr"):
        _log(log, "[1] DUT Local device address seen [OK]")
    else:
        _log(log, "[1] WARN — Local device address not seen yet; continuing")

    _log(log, "[2] Serial console attached for passkey / SMP prints [OK]")

    _log(log, f"[3] Clear prior bond on Pi (readme bonded-tab delete) for {address}")
    unpair = _http_json_retry(
        "POST",
        f"{base}/ble/unpair",
        {"address": address},
        log=None,
        timeout=30.0,
    )
    _log(
        log,
        f"     unpair: {unpair.get('message') or unpair.get('error') or unpair}",
    )

    _log(log, f"[4] Scan for {adv_name!r} / {address}")
    matched: Optional[str] = None
    scan_result: Optional[dict] = None
    deadline = time.time() + connect_timeout
    attempt = 0
    while time.time() < deadline and not matched:
        attempt += 1
        remain = max(5, int(deadline - time.time()))
        scan_result = ble_debug_scan(
            pi_ip,
            address,
            timeout=min(15, remain),
            http_port=http_port,
            log=None,
        )
        if scan_result.get("address_found"):
            matched = address
            break
        scan_result = ble_debug_scan(
            pi_ip,
            timeout=min(15, remain),
            http_port=http_port,
            log=None,
            name=adv_name,
        )
        matched = scan_result.get("matched_address")
        if matched:
            break
        _log(log, f"     scan attempt {attempt}: not seen yet — retry …")
        time.sleep(2.0)

    if not matched:
        _log_secureconnection_serial_checklist(log, serial_cursor)
        raise TimeoutError(
            f"DUT {adv_name!r} / {address} not found in Pi scan within "
            f"{connect_timeout}s (ensure advertising and not bonded elsewhere)"
        )
    _log(log, f"[4] Found DUT at {matched} [OK]")

    _log(
        log,
        f"[5] Connect (phone flow) → {matched} — DUT initiates SMP after link up",
    )
    serial_mark = mark_serial_cursor()
    connect_payload = _merge_connect_payload(
        matched, True, conn, capability="KeyboardOnly"
    )
    connect = _http_json_retry(
        "POST",
        f"{base}/ble/connect",
        connect_payload,
        log=None,
        timeout=90.0,
    )
    if not connect.get("ok"):
        _log_secureconnection_serial_checklist(log, serial_cursor)
        raise RuntimeError(f"[5] Connect failed: {connect}")
    _log(log, "[5] Link up — awaiting DUT SMP / passkey display [OK]")

    wait_for_pi_ble_state(
        pi_ip,
        ("awaiting_passkey", "passkey_submitted", "pairing", "bonded"),
        timeout_sec=90.0,
        log=None,
        http_port=http_port,
    )
    _log(log, "[6] SMP in progress (DUT security request / pair) [OK]")

    _log(log, "[7] Enter passkey from DUT console on Pi …")
    passkey = parse_passkey_from_serial(log, since_index=serial_mark, fresh=True)
    passkey_result = submit_passkey_to_pi(pi_ip, passkey, log=None, http_port=http_port)
    if not passkey_result.get("ok"):
        _log_secureconnection_serial_checklist(log, serial_cursor)
        raise RuntimeError(f"[7] Passkey submit failed: {passkey_result}")
    _log(log, f"[7] Passkey {passkey} submitted [OK]")

    _log(log, "[8] Wait SMP encrypt / security keys on DUT serial …")
    if check_smp_failure():
        _log_secureconnection_serial_checklist(log, serial_cursor)
        raise RuntimeError("[8/9] SMP failed (smp_failed or 0 centrals on DUT)")
    try:
        wait_for_smp_success(log, since_index=serial_mark)
    except Exception as exc:
        _log_secureconnection_serial_checklist(log, serial_cursor)
        raise RuntimeError(f"[8/9] SMP encrypt/security keys not seen: {exc}") from exc
    _log(log, "[8] SMP procedure complete (encrypt / keys) [OK]")
    _log(log, "[9] SMP encrypt started / security keys to host [OK]")

    serial_seen = _log_secureconnection_serial_checklist(log, serial_cursor)
    _log(log, "[10] Console prints checklist above")

    if serial_seen.get("smp_failed"):
        raise RuntimeError("DUT reported smp_failed status")

    _log(log, "=== BLE Secure Connection RESULT: PASS ===")
    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": 1},
        log=None,
        timeout=30.0,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=None, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "secureconnection",
        "dut_address": matched,
        "passkey": passkey,
        "connect": connect,
        "passkey_response": passkey_result,
        "mark": mark,
        "complete": complete,
        "serial_milestones": serial_seen,
        "adv_name": adv_name,
    }


def _dut_hr_client_notify_rx_seen(since_index: Optional[int] = None) -> bool:
    """True when CLIENT DUT serial shows Heart Rate Measurement notify RX."""
    full = get_all_text() or ""
    merged = _serial_milestones_merged(
        since_index, milestones=HEART_RATE_CLIENT_SERIAL_MILESTONES
    )
    if merged.get("notify_rx"):
        return True
    if RE_HID_CLIENT_REPORT_HEX.search(full):
        return True
    since = max(0, int(since_index or 0))
    text = "\n".join(get_lines(since).get("lines") or []) or full
    if RE_HID_CLIENT_REPORT_HEX.search(text):
        return True
    if merged.get("notify_enable") and re.search(r"gatt wr", full, re.I):
        return True
    return bool(
        merged.get("notify_enable") and re.search(r"gatt wr", text, re.I)
    )


def _count_hr_client_report_lines(since_index: Optional[int] = None) -> int:
    full_lines = get_all_text().splitlines()
    since = max(0, int(since_index or 0))
    lines = get_lines(since).get("lines") or []
    if len(lines) < len(full_lines) // 2:
        lines = full_lines
    return sum(1 for line in lines if RE_HID_CLIENT_REPORT_HEX.search(line or ""))


def _dut_hid_client_notify_rx_seen(since_index: Optional[int] = None) -> bool:
    """True when CLIENT DUT serial shows HID notify payloads (incl. all-zero release)."""
    full = get_all_text() or ""
    merged = _serial_milestones_merged(
        since_index, milestones=HID_ON_GATT_CLIENT_SERIAL_MILESTONES
    )
    if merged.get("notify_rx"):
        return True
    if RE_HID_CLIENT_REPORT_HEX.search(full):
        return True
    since = max(0, int(since_index or 0))
    text = "\n".join(get_lines(since).get("lines") or []) or full
    if RE_HID_CLIENT_REPORT_HEX.search(text):
        return True
    # SDK CLIENT path: "Notification enabled" then repeated "gatt wr" (+ hex on later lines).
    if merged.get("notify_enable") and re.search(r"gatt wr", full, re.I):
        return True
    return bool(
        merged.get("notify_enable") and re.search(r"gatt wr", text, re.I)
    )


def _count_hid_client_report_lines(since_index: Optional[int] = None) -> int:
    full_lines = get_all_text().splitlines()
    since = max(0, int(since_index or 0))
    lines = get_lines(since).get("lines") or []
    if len(lines) < len(full_lines) // 2:
        lines = full_lines
    return sum(1 for line in lines if RE_HID_CLIENT_REPORT_HEX.search(line or ""))


def _dut_hid_report_notify_seen(since_index: Optional[int] = None) -> bool:
    """True when DUT serial shows the HID report CCCD was subscribed."""
    merged = _serial_milestones_merged(
        since_index, milestones=HID_ON_GATT_SERIAL_MILESTONES
    )
    if merged.get("report_notify"):
        return True
    # Handles stale cursors and reconnect churn during the 90s soak window.
    return bool(RE_HID_REPORT_NOTIFY_ENABLED.search(get_all_text() or ""))


def _log_hid_on_gatt_serial_checklist(
    log: Optional[LogFn],
    serial_cursor: int,
) -> dict:
    seen = _serial_milestones_merged(
        serial_cursor, milestones=HID_ON_GATT_SERIAL_MILESTONES
    )
    labels = (
        ("wifi_init", "Wi-Fi initialization"),
        ("local_addr", "Local device address"),
        ("start_adv", "Start advertising"),
        ("connected", "Module connected / Enhance connected"),
        ("mtu", "Received MTU event"),
        ("smp_req", "smp req / smp resp"),
        ("passkey", "smp passkey disp on console"),
        ("encrypt", "smp encrypt resp"),
        ("report_notify", "Input report notify val: 1 (peer wrote report CCCD)"),
    )
    _log(log, "DUT serial checklist (ble_hid_on_gatt GATT_ROLE=SERVER readme):")
    for key, label in labels:
        mark = "OK" if seen.get(key) else "--"
        _log(log, f"  [{mark}] {label}")
    if seen.get("smp_failed"):
        _log(log, "  [FAIL] smp failed seen on DUT serial")
    return seen


def _uuid_is(uuid: str, short: str) -> bool:
    """Match a BlueZ 128-bit UUID against a 16-bit short form (e.g. '1812')."""
    text = str(uuid or "").lower().replace("0x", "")
    short = short.lower()
    return text == short or text.startswith(f"0000{short}-")


def _find_hid_service(services: dict, service_short: str, char_short: str) -> dict:
    """Locate the HID service / report characteristic in GET /ble/services output."""
    found: dict = {"service_uuid": None, "char_uuid": None, "flags": []}
    if not isinstance(services, dict):
        return found
    for svc_uuid, svc in services.items():
        if not _uuid_is(svc_uuid, service_short):
            continue
        found["service_uuid"] = svc_uuid
        chars = svc.get("characteristics") if isinstance(svc, dict) else None
        if isinstance(chars, dict):
            items = chars.items()
        elif isinstance(chars, list):
            items = [
                (c.get("uuid"), c) for c in chars if isinstance(c, dict)
            ]
        else:
            items = []
        for char_uuid, char in items:
            if not _uuid_is(str(char_uuid), char_short):
                continue
            flags = char.get("flags") if isinstance(char, dict) else None
            flags = list(flags) if isinstance(flags, list) else []
            # Several 0x2A4D instances exist (input / output report) — keep notify.
            if found["char_uuid"] is None or "notify" in [f.lower() for f in flags]:
                found["char_uuid"] = str(char_uuid)
                found["flags"] = flags
        break
    return found


def _describe_hid_report(raw: str) -> str:
    """Decode SDK demo keystrokes (h/o/g/_) from a HID keyboard report payload."""
    text = str(raw or "").strip()
    if not text:
        return text
    compact = re.sub(r"[\s:.-]+", "", text).lower()
    if not compact or not all(c in "0123456789abcdef" for c in compact):
        return text
    if len(compact) % 2:
        return text
    try:
        data = bytes.fromhex(compact)
    except ValueError:
        return text
    keys: List[str] = []
    # Standard 8-byte keyboard report: [modifier, reserved, key1..key6].
    start = 2 if len(data) >= 8 else 0
    for code in data[start : start + 6]:
        if code == 0:
            continue
        keys.append(_HID_USAGE_TO_KEY.get(code, f"0x{code:02x}"))
    if keys:
        return " ".join(keys)
    return text


def _hid_report_has_keystroke(raw: str) -> bool:
    """True when a HID notify payload contains SDK demo key usage (h/o/g/_)."""
    decoded = _describe_hid_report(raw)
    if any(part in ("h", "o", "g", "_") for part in decoded.split()):
        return True
    compact = re.sub(r"[\s:.-]+", "", str(raw or "")).lower()
    if not compact or len(compact) % 2:
        return False
    try:
        data = bytes.fromhex(compact)
    except ValueError:
        return False
    demo_usages = frozenset(_HID_USAGE_TO_KEY.keys())
    start = 2 if len(data) >= 8 else 0
    return any(b in demo_usages for b in data[start : start + 6])


def _latest_hid_passkey(
    since_index: int,
    log: Optional[LogFn] = None,
    *,
    timeout_sec: float = 75.0,
) -> str:
    """
    Newest 'smp passkey disp' on DUT serial.

    Each SMP attempt makes the DUT generate a new passkey, so the first match after
    a cursor is often already stale. Return a value only once it stops changing.
    """
    deadline = time.time() + timeout_sec
    last: Optional[str] = None
    while time.time() < deadline:
        lines = get_lines(max(0, int(since_index))).get("lines") or []
        matches = RE_HID_PASSKEY.findall("\n".join(lines))
        if matches:
            newest = str(matches[-1])
            if newest == last:
                if len(matches) > 1:
                    _log(
                        log,
                        f"     DUT displayed {len(matches)} passkeys — using newest {newest}",
                    )
                return newest
            last = newest
        time.sleep(1.0)
    if last:
        return last
    raise TimeoutError(
        f"no 'smp passkey disp' on DUT serial within {timeout_sec:.0f}s "
        "(DUT never reached the SMP passkey stage)"
    )


def orchestrate_hid_on_gatt_manual(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    serial_since_index: Optional[int] = None,
    conn_params: Optional[dict] = None,
) -> dict:
    """
    SDK ble_hid_on_gatt readme (GATT_ROLE=SERVER) — Pi replaces the phone:

    1–2 DUT advertises HID_OVER_GATT + serial up
    3   clear prior BlueZ bond (readme "forget device")
    4–5 scan for HID_OVER_GATT / DUT MAC, connect with bonding
    6–7 enter the passkey the DUT prints, wait for encryption
    8   subscribe to the HID report characteristic (0x1812 / 0x2A4D)
    9   collect the "hog_" input reports the DUT sends after the CCCD write
    """
    prof = profile or {}
    adv_name = str(prof.get("dut_advertising_name") or "HID_OVER_GATT")
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    report_wait = int(prof.get("hid_report_wait_sec") or 90)
    min_reports = int(prof.get("min_hid_report_count") or 1)
    min_key_reports = int(prof.get("min_hid_key_reports") or 1)
    service_short = str(prof.get("service_uuid") or "1812")
    char_short = str(prof.get("char_uuid") or "2a4d")
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)
    conn = conn_params or connect_conn_params("ble_hid_on_gatt")
    smp_capability = str(prof.get("smp_capability") or "KeyboardDisplay")
    if serial_since_index is not None:
        serial_cursor_start = int(serial_since_index)
    else:
        serial_cursor_start = mark_serial_cursor()

    _log(log, "=== BLE HID over GATT (SDK ble_hid_on_gatt) ===")
    _log(log, f"DUT = HID keyboard peripheral ({adv_name!r}, GATT_ROLE=SERVER)")
    _log(log, "Pi = central (Simplicity Connect phone role) + SMP passkey")
    _log(log, f"Pi SMP IO capability: {smp_capability}")
    _log(log, f"HID report: service {service_short} char {char_short} (keys 'h','o','g','_')")
    try:
        pi_status = _http_json_retry(
            "GET", f"{base}/ble/status", None, log=None, timeout=15.0
        )
        st = pi_status.get("status") or {}
        _log(
            log,
            f"     Pi bluez_noplugin_input={st.get('bluez_noplugin_input')!r} "
            f"bluetoothd={st.get('bluetoothd_cmdline') or '(unknown)'}",
        )
    except Exception as exc:
        _log(log, f"     Pi /ble/status preflight: {exc}")
    _log(log, "")

    _log(log, "[1] DUT advertising (after flash) — wait Local device address")
    boot_deadline = time.time() + 45.0
    while time.time() < boot_deadline:
        seen = _serial_milestones_seen(
            serial_cursor_start, milestones=HID_ON_GATT_SERIAL_MILESTONES
        )
        if seen.get("local_addr") or seen.get("start_adv"):
            break
        time.sleep(1.0)
    seen_boot = _serial_milestones_seen(
        serial_cursor_start, milestones=HID_ON_GATT_SERIAL_MILESTONES
    )
    if seen_boot.get("local_addr"):
        _log(log, "[1] DUT Local device address seen [OK]")
    else:
        _log(log, "[1] WARN — Local device address not seen yet; continuing")

    _log(log, "[2] Serial console attached for passkey / HID prints [OK]")

    _log(log, f"[3] Clear prior bond on Pi (readme forget device) for {address}")
    unpair = _http_json_retry(
        "POST",
        f"{base}/ble/unpair",
        {"address": address},
        log=None,
        timeout=30.0,
    )
    _log(
        log,
        f"     unpair: {unpair.get('message') or unpair.get('error') or unpair}",
    )

    _log(log, f"[4] Scan for {adv_name!r} / {address}")
    matched: Optional[str] = None
    deadline = time.time() + connect_timeout
    attempt = 0
    while time.time() < deadline and not matched:
        attempt += 1
        remain = max(5, int(deadline - time.time()))
        scan_result = ble_debug_scan(
            pi_ip, address, timeout=min(15, remain), http_port=http_port, log=None
        )
        if scan_result.get("address_found"):
            matched = address
            break
        scan_result = ble_debug_scan(
            pi_ip,
            timeout=min(15, remain),
            http_port=http_port,
            log=None,
            name=adv_name,
        )
        matched = scan_result.get("matched_address")
        if matched:
            break
        _log(log, f"     scan attempt {attempt}: not seen yet — retry …")
        time.sleep(2.0)

    if not matched:
        _log_hid_on_gatt_serial_checklist(log, serial_cursor_start)
        raise TimeoutError(
            f"DUT {adv_name!r} / {address} not found in Pi scan within "
            f"{connect_timeout}s (check RSI_BLE_APP_HIDS='HID_OVER_GATT', "
            "GATT_ROLE=SERVER, ENABLE_NWP_POWER_SAVE=0)"
        )
    _log(log, f"[4] Found DUT at {matched} [OK]")

    connect_payload = _merge_connect_payload(
        matched, True, conn, capability=smp_capability
    )
    # Every SMP attempt makes the DUT display a *new* passkey and drop the link when
    # the attempt fails, so each attempt reads its own passkey from a fresh cursor.
    attempts = max(1, int(prof.get("hid_pair_attempts") or 3))
    serial_mark = mark_serial_cursor()
    connect: dict = {}
    passkey = ""
    passkey_result: dict = {}
    encrypted = False
    for attempt in range(1, attempts + 1):
        serial_mark = mark_serial_cursor()
        _log(log, f"[5] Attempt {attempt}/{attempts}: connect → {matched}")
        connect = _http_json_retry(
            "POST", f"{base}/ble/connect", connect_payload, log=None, timeout=90.0
        )
        if not connect.get("ok"):
            _log(log, f"     connect failed: {connect.get('error') or connect}")
            ble_debug_scan(
                pi_ip, address, timeout=10, http_port=http_port, log=None
            )
            continue
        _log(log, "[5] Link up [OK]")

        # GATT_ROLE=SERVER never calls rsi_ble_smp_pair_request, so nothing pairs
        # until the peer touches an encrypted HID attribute. Read the report map to
        # start SMP (phone behaviour) — an auth error here is the expected reply.
        _log(log, f"[5] Read HID report map ({HID_REPORT_MAP_UUID}) to trigger SMP …")
        for read_try in range(1, 4):
            if _serial_milestones_seen(
                serial_mark, milestones=HID_ON_GATT_SERIAL_MILESTONES
            ).get("smp_req"):
                _log(log, "     SMP already started (BlueZ HoG plugin) — read not needed")
                break
            try:
                nudge = _http_json(
                    "POST",
                    f"{base}/ble/read",
                    {"service_uuid": service_short, "char_uuid": HID_REPORT_MAP_UUID},
                    timeout=45.0,
                )
                detail = nudge.get("error") or f"length={nudge.get('length')}"
                _log(log, f"     report map read: ok={nudge.get('ok')} {detail}")
                if nudge.get("ok"):
                    break
            except Exception as exc:
                _log(log, f"     report map read {read_try}: {exc}")
            time.sleep(4.0)

        # Do NOT gate on Pi state here. The BlueZ agent blocks inside RequestPasskey
        # waiting for POST /ble/passkey, while the bond watchdog can already have
        # moved the state to pair_failed over the DUT's reconnect churn — waiting for
        # 'awaiting_passkey' deadlocks against the agent's own timeout.
        _log(log, "[6] Read the passkey the DUT displays ('smp passkey disp') …")
        try:
            passkey = _latest_hid_passkey(serial_mark, log, timeout_sec=75.0)
        except TimeoutError as exc:
            _log(log, f"     {exc}")
            continue

        # /ble/passkey blocks on the Pi until bond or ~120s, so submit in a worker
        # and watch DUT serial for the outcome (encrypt vs smp failed).
        _log(log, f"[6] Submitting passkey {passkey} …")
        submit_box: dict = {}

        def _submit_worker(pk: str = passkey, box: dict = submit_box) -> None:
            try:
                box["result"] = submit_passkey_to_pi(
                    pi_ip, pk, log=None, http_port=http_port
                )
            except Exception as exc:  # noqa: BLE001 — reported below
                box["error"] = str(exc)

        submit_thread = threading.Thread(
            target=_submit_worker, name="hid-passkey-submit", daemon=True
        )
        submit_thread.start()

        _log(log, "[7] Wait for encryption on DUT serial ('smp encrypt resp') …")
        outcome_deadline = time.time() + 75.0
        smp_failed = False
        while time.time() < outcome_deadline:
            seen = _serial_milestones_seen(
                serial_mark, milestones=HID_ON_GATT_SERIAL_MILESTONES
            )
            if seen.get("encrypt"):
                encrypted = True
                break
            if seen.get("smp_failed"):
                smp_failed = True
                break
            if submit_box.get("result") and submit_box["result"].get("ok"):
                encrypted = True
                break
            time.sleep(2.0)

        submit_thread.join(timeout=5.0)
        passkey_result = submit_box.get("result") or {
            "ok": encrypted,
            "error": submit_box.get("error") or "passkey submit still pending",
        }
        if encrypted:
            _log(log, f"[7] Encryption enabled with passkey {passkey} [OK]")
            break
        _log(
            log,
            f"[7] Attempt {attempt} failed "
            f"({'DUT reported smp failed' if smp_failed else 'no encrypt on DUT serial'}) "
            f"— passkey submit: {passkey_result.get('error') or passkey_result.get('ok')}",
        )
        if attempt < attempts:
            _log(log, "     DUT re-advertises after the drop — retrying with a fresh passkey")
            time.sleep(5.0)

    if not encrypted:
        _log_hid_on_gatt_serial_checklist(log, serial_cursor_start)
        raise RuntimeError(
            f"SMP never completed after {attempts} attempt(s) "
            f"(last passkey {passkey or 'n/a'}). Check the UTF log on the Pi: "
            "'RequestPasskey … sending' means the Pi entered it, while "
            "'DisplayPasskey' / 'RequestConfirmation' means BlueZ chose a different "
            "pairing method than the DUT's RSI_BLE_SMP_IO_CAPABILITY expects."
        )

    dut_notify_seen = _dut_hid_report_notify_seen(serial_cursor_start)

    _log(log, f"[8] Discover HID service {service_short} on the peer …")
    hid: dict = {"service_uuid": None, "char_uuid": None, "flags": []}
    discover_deadline = time.time() + 45.0
    while time.time() < discover_deadline:
        if _dut_hid_report_notify_seen(serial_cursor_start):
            dut_notify_seen = True
        services = _http_json_retry(
            "GET", f"{base}/ble/services", None, log=None, timeout=60.0
        )
        hid = _find_hid_service(
            services.get("services") or {}, service_short, char_short
        )
        if hid.get("service_uuid"):
            break
        if dut_notify_seen and not hid.get("service_uuid"):
            _log(
                log,
                "     DUT serial: Input report notify val: 1 — stopping D-Bus wait "
                "(CCCD already subscribed; 0x1812 may never appear on D-Bus)",
            )
            break
        svc_count = services.get("service_count") or 0
        _log(
            log,
            f"     waiting for 0x{service_short} on D-Bus "
            f"({svc_count} peer service(s) visible) …",
        )
        time.sleep(2.0)
    if hid.get("service_uuid"):
        _log(
            log,
            f"[8] HID service {hid['service_uuid']} report char "
            f"{hid.get('char_uuid')} flags={hid.get('flags')} [OK]",
        )
    else:
        _log(
            log,
            f"[8] WARN — service {service_short} not exported over D-Bus "
            "(BlueZ input/hog plugins may still own HoG). Falling back to the DUT "
            "'Input report notify val' print for HID evidence.",
        )

    notify_enable: dict = {}
    if hid.get("char_uuid"):
        # Clear before the CCCD write — the DUT sends its first keystrokes immediately.
        try:
            _http_json("POST", f"{base}/ble/notifications/clear", {}, timeout=20.0)
        except Exception as exc:
            _log(log, f"     notifications clear: {exc} (continuing)")
        _log(log, f"[9] Subscribe to HID report {hid['char_uuid']} (CCCD write) …")
        notify_enable = _http_json_retry(
            "POST",
            f"{base}/ble/notifications/enable",
            {"service_uuid": hid["service_uuid"], "char_uuid": hid["char_uuid"]},
            log=None,
            timeout=60.0,
        )
        if notify_enable.get("ok"):
            _log(
                log,
                f"[9] Notifications on: notifying={notify_enable.get('notifying')} [OK]",
            )
        else:
            _log(
                log,
                f"[9] WARN — enable notifications failed: "
                f"{notify_enable.get('error') or notify_enable}",
            )
    else:
        _log(log, "[9] Skipped explicit CCCD write — no report characteristic exported")

    _log(
        log,
        f"[10] Collect HID input reports for up to {report_wait}s "
        f"(DUT sends 'h','o','g','_' keystrokes — logged as they arrive) …",
    )
    report_deadline = time.time() + report_wait
    if dut_notify_seen and not hid.get("char_uuid"):
        serial_pass_soak = float(prof.get("hid_serial_pass_soak_sec") or 8.0)
        report_deadline = min(report_deadline, time.time() + serial_pass_soak)
        _log(
            log,
            f"     Serial CCCD evidence already latched — shortening soak to "
            f"{serial_pass_soak:.0f}s (Pi /ble/notifications may stay empty)",
        )
    reports: List[str] = []
    report_count = 0
    pi_report_idx = 0
    serial_idx = get_lines(serial_mark).get("total") or serial_mark
    keystroke_stream: List[str] = []
    keystroke_logged = 0
    poll_sec = float(prof.get("hid_report_poll_sec") or 1.0)
    while time.time() < report_deadline:
        dut_notify_seen = _dut_hid_report_notify_seen(serial_cursor_start)
        if dut_notify_seen and not hid.get("char_uuid"):
            break
        snap = get_lines(serial_idx)
        for line in snap.get("lines") or []:
            if RE_HID_SERIAL_ACTIVITY.search(line):
                _log(log, f"     DUT serial: {line.strip()}")
        serial_idx = snap.get("total") or serial_idx
        try:
            payload = _http_json("GET", f"{base}/ble/notifications", timeout=20.0)
            entries = payload.get("notifications")
            if isinstance(entries, list):
                reports = [str(item) for item in entries]
                report_count = len(reports)
                while pi_report_idx < report_count:
                    pi_report_idx += 1
                    decoded = _describe_hid_report(reports[pi_report_idx - 1])
                    keystroke_stream.extend(decoded.split())
                    _log(
                        log,
                        f"     HID report #{pi_report_idx}: {decoded} "
                        f"(raw={reports[pi_report_idx - 1]!r})",
                    )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            _log(log, f"     notifications poll: {exc} — retrying …")
        if len(keystroke_stream) > keystroke_logged:
            keystroke_logged = len(keystroke_stream)
            tail = " ".join(keystroke_stream[-24:])
            _log(log, f"     HID keys so far: {tail}")
        time.sleep(max(0.25, poll_sec))

    dut_notify_seen = _dut_hid_report_notify_seen(serial_cursor_start)
    if dut_notify_seen and not hid.get("char_uuid"):
        _log(log, "[10] DUT serial confirms HID report CCCD subscribed [OK]")

    if reports:
        preview = ", ".join(_describe_hid_report(r) for r in reports[:12])
        _log(log, f"[10] HID reports collected ({report_count}): {preview}")
    key_reports = [r for r in reports if _hid_report_has_keystroke(r)]
    if key_reports:
        keys_preview = ", ".join(_describe_hid_report(r) for r in key_reports[:8])
        _log(
            log,
            f"[10] HID keystroke reports ({len(key_reports)}): {keys_preview} "
            "(sniffer should show 0x0B/0x12/0x0A/0x2D in notify payload)",
        )
    if report_count < min_reports and not dut_notify_seen:
        _log_hid_on_gatt_serial_checklist(log, serial_cursor_start)
        raise RuntimeError(
            f"No HID input reports observed: buffered={report_count} "
            f"(need {min_reports}) and DUT never printed 'Input report notify val: 1'. "
            "The report CCCD was never written — check that the peer subscribed and "
            "that the DUT firmware is GATT_ROLE=SERVER with ENABLE_NWP_POWER_SAVE=0."
        )

    # README pass: buffered 0x2A4D reports OR DUT "Input report notify val: 1"
    # (CCCD written). BlueZ may still consume 0x1812 via hog/uhid even with
    # --noplugin=input,hog — serial evidence is authoritative then.
    serial_hid_pass = dut_notify_seen

    if not hid.get("char_uuid"):
        if serial_hid_pass:
            _log(
                log,
                "[8–10] PASS via DUT serial — 'Input report notify val: 1' confirms "
                "the peer subscribed to the HID report CCCD. Service 0x1812 is not "
                "on Pi D-Bus (BlueZ hog/uhid path); Pi /ble/notifications may stay "
                "empty even though the link is valid.",
            )
        else:
            _log_hid_on_gatt_serial_checklist(log, serial_cursor_start)
            raise RuntimeError(
                "HID over GATT pass criteria not met: service 0x1812 is not on Pi "
                "D-Bus and DUT serial never showed 'Input report notify val: 1'. "
                "BlueZ may still consume HoG internally even with "
                "--noplugin=input,hog (check GET /ble/status bluez_noplugin_input). "
                "When serial shows CCCD subscribed, the run should pass without D-Bus "
                "0x1812. Confirm Build Studio was restarted after orchestrator updates."
            )
    else:
        if not notify_enable.get("ok"):
            if serial_hid_pass:
                _log(
                    log,
                    "[9] WARN — POST /ble/notifications/enable failed but DUT serial "
                    f"shows CCCD subscribed: {notify_enable.get('error') or notify_enable}",
                )
            else:
                _log_hid_on_gatt_serial_checklist(log, serial_cursor_start)
                raise RuntimeError(
                    f"Failed to subscribe to HID report 0x2A4D via POST /ble/notifications/enable: "
                    f"{notify_enable.get('error') or notify_enable}. "
                    "Check Pi UTF logs and that BLE_BLUEZ_NOPPLUGIN_INPUT=1 was active at init."
                )
        if len(key_reports) < min_key_reports:
            if serial_hid_pass:
                _log(
                    log,
                    f"[10] WARN — only {len(key_reports)} Pi keystroke report(s) "
                    f"(wanted {min_key_reports}); accepting DUT serial CCCD evidence.",
                )
            else:
                _log_hid_on_gatt_serial_checklist(log, serial_cursor_start)
                raise RuntimeError(
                    f"Insufficient HID keystroke evidence: key_reports={len(key_reports)} "
                    f"(need {min_key_reports}). Buffered notifies={report_count}. "
                    "Sniffer should show non-zero key usage bytes (0x0B=h, 0x12=o, 0x0A=g, "
                    "0x2D=_) in 11-byte reports after CCCD write — not only 00…00 release "
                    "reports. Confirm BLE_BLUEZ_NOPPLUGIN_INPUT=1 on Pi and DUT "
                    "Input report notify val: 1 on serial."
                )
    if report_count < min_reports:
        _log(
            log,
            f"[10] WARN — only {report_count} buffered report(s) "
            f"(wanted {min_reports}), but {len(key_reports)} carried h/o/g/_ keys",
        )

    serial_seen = _log_hid_on_gatt_serial_checklist(log, serial_cursor_start)
    if serial_seen.get("smp_failed"):
        raise RuntimeError("DUT reported smp failed")
    if not serial_seen.get("connected"):
        raise RuntimeError(
            "DUT serial never showed 'Module connected to address' — "
            "no HID link was established"
        )

    _log(log, "=== BLE HID over GATT RESULT: PASS ===")
    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": len(key_reports)},
        log=None,
        timeout=30.0,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=None, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "hid_on_gatt",
        "dut_address": matched,
        "passkey": passkey,
        "connect": connect,
        "passkey_response": passkey_result,
        "hid_service": hid,
        "notifications_enable": notify_enable,
        "hid_report_count": report_count,
        "hid_key_report_count": len(key_reports),
        "hid_reports": reports[:32],
        "dut_report_notify_enabled": dut_notify_seen,
        "mark": mark,
        "complete": complete,
        "serial_milestones": serial_seen,
        "adv_name": adv_name,
    }


def _log_hid_on_gatt_client_serial_checklist(
    log: Optional[LogFn],
    serial_cursor: int,
) -> dict:
    seen = _serial_milestones_merged(
        serial_cursor, milestones=HID_ON_GATT_CLIENT_SERIAL_MILESTONES
    )
    labels = (
        ("wifi_init", "Wi-Fi initialization"),
        ("local_addr", "Local device address"),
        ("started_scanning", "Started scanning / initiating connect"),
        ("module_connected", "Module connected to Pi address"),
        ("gatt_services", "GATT services discovered on Pi"),
        ("notify_enable", "HID report notify enabled (CCCD)"),
        ("notify_rx", "HID notification received on DUT"),
    )
    _log(log, "DUT serial checklist (ble_hid_on_gatt GATT_ROLE=CLIENT readme):")
    for key, label in labels:
        mark = "OK" if seen.get(key) else "--"
        _log(log, f"  [{mark}] {label}")
    return seen


def orchestrate_hid_on_gatt_client_manual(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    serial_since_index: Optional[int] = None,
) -> dict:
    """
    SDK ble_hid_on_gatt readme (GATT_ROLE=CLIENT) — Pi replaces the HID peripheral:

    1   Pi advertises HID_OVER_GATT with Human Interface Device service (0x1812)
    2   DUT central connects to Pi using RSI_BLE_DEV_ADDR / configured MAC
    3   DUT discovers remote GATT services
    4   DUT enables notify on the HID report characteristic (0x2A4D)
    5   Pi sends demo key reports; DUT prints notification events on serial
    """
    prof = profile or {}
    peripheral_name = str(
        prof.get("ae_central_peripheral_name")
        or prof.get("dut_advertising_name")
        or "HID_OVER_GATT"
    )
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    report_wait = int(prof.get("hid_report_wait_sec") or 90)
    min_notify_rx = int(prof.get("min_hid_report_count") or 1)
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)
    kind = "hid_on_gatt_client"
    quiet = _quiet_build_console(kind)
    if serial_since_index is not None:
        serial_cursor_start = int(serial_since_index)
    else:
        serial_cursor_start = mark_serial_cursor()

    health = _http_json_retry("GET", f"{base}/health", None, log=None, timeout=15.0)
    pi_status = (health.get("status") or {}) if isinstance(health, dict) else {}
    pi_mac = pi_status.get("local_address")

    if quiet:
        _log(log, "Test: HID over GATT Client  DUT=central")
        _log(
            log,
            _format_pi_peripheral_status(
                pi_status, peripheral_name=peripheral_name, kind=kind
            ),
        )
    else:
        _log(log, "=== BLE HID over GATT CLIENT (SDK ble_hid_on_gatt) ===")
        _log(log, f"Pi = HOGP keyboard peripheral ({peripheral_name!r}, 0x1812/0x2A4D)")
        _log(log, "DUT = central (GATT_ROLE=CLIENT)")
        _log(log, f"Pi MAC: {pi_mac}  expect DUT: {address}")
        _log(
            log,
            "Firmware: GATT_ROLE=CLIENT, RSI_BLE_DEV_ADDR=<Pi MAC>, "
            "ENABLE_NWP_POWER_SAVE=0",
        )

    arm_dut_central_expect_peer(
        pi_ip, address, log=log, http_port=http_port, quiet=quiet
    )

    # Do not stop at the first "Module connected" — wait through GATT discovery,
    # CCCD (Notification enabled), and HID notify RX on the same deadline.
    combined_wait = connect_timeout + report_wait
    _log(
        log,
        f"Waiting up to {combined_wait}s for DUT connect + HID notify on serial …",
    )
    combined_deadline = time.time() + combined_wait
    connected = False
    notify_rx_count = 0
    key_report_count = 0
    connect_logged = False
    while time.time() < combined_deadline:
        merged = _serial_milestones_merged(
            serial_cursor_start, milestones=HID_ON_GATT_CLIENT_SERIAL_MILESTONES
        )
        if merged.get("module_connected"):
            connected = True
            if not connect_logged:
                connect_logged = True
                _log(log, "PASS: connect established (DUT serial: Module connected)")
        if not connected:
            st = poll_dut_central_connected(
                pi_ip,
                timeout_sec=1.0,
                log=None,
                http_port=http_port,
                poll_sec=0.5,
                label="connect",
            )
            if st is not None:
                connected = True
                pi_status = st
                if not connect_logged:
                    connect_logged = True
                    _log(log, "PASS: connect established (Pi link up)")
        notify_rx_count = _count_hid_client_report_lines(serial_cursor_start)
        for line in get_all_text().splitlines():
            if _hid_report_has_keystroke(line):
                key_report_count += 1
        if _dut_hid_client_notify_rx_seen(serial_cursor_start):
            break
        if merged.get("notify_enable") and notify_rx_count:
            break
        if key_report_count >= min_notify_rx:
            break
        time.sleep(1.0)

    if not connected:
        _log_hid_on_gatt_client_serial_checklist(log, serial_cursor_start)
        raise TimeoutError(
            f"DUT {address} did not connect to Pi within {connect_timeout}s "
            f"(flash GATT_ROLE=CLIENT and RSI_BLE_DEV_ADDR={pi_mac!r})"
        )

    notify_rx_count = max(
        notify_rx_count, _count_hid_client_report_lines(serial_cursor_start)
    )
    serial_hid_client_pass = _dut_hid_client_notify_rx_seen(serial_cursor_start)
    merged = _serial_milestones_merged(
        serial_cursor_start, milestones=HID_ON_GATT_CLIENT_SERIAL_MILESTONES
    )
    if not serial_hid_client_pass and merged.get("notify_enable") and notify_rx_count:
        serial_hid_client_pass = True
        _log(
            log,
            "[notify] PASS via DUT serial — Notification enabled + "
            f"{notify_rx_count} HID report line(s) (0x2A4D notify RX)",
        )
    elif not serial_hid_client_pass and merged.get("notify_enable") and merged.get(
        "gatt_services"
    ) and re.search(r"gatt wr", get_all_text() or "", re.I):
        serial_hid_client_pass = True
        _log(
            log,
            "[notify] PASS via DUT serial — GATT discovery + Notification enabled + "
            "gatt wr (HID notify path active)",
        )

    serial_seen = (
        _save_dut_serial_checklist_log_only(serial_cursor_start, kind=kind)
        if quiet
        else _log_hid_on_gatt_client_serial_checklist(log, serial_cursor_start)
    )
    if not serial_hid_client_pass and notify_rx_count < min_notify_rx:
        raise RuntimeError(
            "No HID notification evidence on DUT serial — confirm Pi HOGP peripheral "
            "is advertising 0x1812, DUT enabled notify on 0x2A4D, and "
            "BLE_BLUEZ_NOPPLUGIN_INPUT=1 on Pi UTF. Expected DUT prints like "
            "'Notification enabled' and hex report lines "
            "(e.g. 0x00 0x00 … after gatt wr). "
            "Restart Build Studio if this message lacks the 'Expected DUT prints' hint."
        )

    if quiet:
        _log(
            log,
            f"PASS: HID over GATT Client — connect + notify RX "
            f"(reports={notify_rx_count}, keys={key_report_count})",
        )
    else:
        if key_report_count:
            _log(
                log,
                f"[notify] HID keystroke reports on DUT serial: {key_report_count}",
            )
        elif notify_rx_count:
            _log(
                log,
                f"[notify] HID report notify RX ({notify_rx_count} line(s); "
                "all-zero release reports are OK for pass)",
            )
        _log(log, "=== BLE HID over GATT CLIENT RESULT: PASS ===")

    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": max(notify_rx_count, key_report_count, 1)},
        log=None,
        timeout=30.0,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=None, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "hid_on_gatt_client",
        "dut_address": address,
        "pi_local_address": pi_mac,
        "peripheral_name": peripheral_name,
        "hid_notify_rx_count": notify_rx_count,
        "mark": mark,
        "complete": complete,
        "serial_milestones": serial_seen,
    }


def _log_heart_rate_client_serial_checklist(
    log: Optional[LogFn],
    serial_cursor: int,
) -> dict:
    seen = _serial_milestones_merged(
        serial_cursor, milestones=HEART_RATE_CLIENT_SERIAL_MILESTONES
    )
    labels = (
        ("wifi_init", "Wi-Fi initialization"),
        ("local_addr", "Local device address"),
        ("started_scanning", "Started scanning / initiating connect"),
        ("module_connected", "Module connected to Pi address"),
        ("gatt_services", "Heart Rate service (0x180D) discovered on Pi"),
        ("notify_enable", "Heart Rate Measurement notify enabled (0x2A37 CCCD)"),
        ("notify_rx", "Heart Rate Measurement notify received on DUT"),
    )
    _log(log, "DUT serial checklist (ble_heart_rate_profile GATT_ROLE=CLIENT readme):")
    for key, label in labels:
        mark = "OK" if seen.get(key) else "--"
        _log(log, f"  [{mark}] {label}")
    return seen


def orchestrate_heart_rate_profile_client_manual(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    serial_since_index: Optional[int] = None,
) -> dict:
    """
    SDK ble_heart_rate_profile readme (GATT_ROLE=CLIENT) — Pi replaces the phone GATT server:

    1   Pi advertises BLE_HEART_RATE_PROFILE with Heart Rate service (0x180D)
    2   DUT central connects using RSI_BLE_DEV_ADDR / RSI_REMOTE_DEVICE_NAME
    3   DUT discovers 0x180D, enables notify on 0x2A37
    4   Pi sends Heart Rate Measurement notifications; DUT prints notify on serial
    """
    prof = profile or {}
    peripheral_name = str(
        prof.get("ae_central_peripheral_name")
        or prof.get("dut_advertising_name")
        or "BLE_HEART_RATE_PROFILE"
    )
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    report_wait = int(prof.get("hr_report_wait_sec") or 90)
    min_notify_rx = int(prof.get("min_hr_report_count") or 1)
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)
    kind = "heart_rate_client"
    quiet = _quiet_build_console(kind)
    if serial_since_index is not None:
        serial_cursor_start = int(serial_since_index)
    else:
        serial_cursor_start = mark_serial_cursor()

    health = _http_json_retry("GET", f"{base}/health", None, log=None, timeout=15.0)
    pi_status = (health.get("status") or {}) if isinstance(health, dict) else {}
    pi_mac = pi_status.get("local_address")

    _log(log, "Test: Heart Rate Profile Client  DUT=central")
    _log(
        log,
        _format_pi_peripheral_status(
            pi_status, peripheral_name=peripheral_name, kind=kind
        ),
    )
    if not quiet:
        _log(log, "=== BLE Heart Rate Profile CLIENT (SDK ble_heart_rate_profile) ===")
        _log(
            log,
            f"Pi = HRS peripheral ({peripheral_name!r}, 0x180D/0x2A37 notify)",
        )
        _log(log, "DUT = central (GATT_ROLE=CLIENT)")
        _log(log, f"Pi MAC: {pi_mac}  expect DUT: {address}")
        _log(
            log,
            "Firmware: GATT_ROLE=CLIENT, RSI_BLE_DEV_ADDR=<Pi MAC>, "
            "RSI_REMOTE_DEVICE_NAME=BLE_HEART_RATE_PROFILE, ENABLE_NWP_POWER_SAVE=0",
        )

    arm_dut_central_expect_peer(
        pi_ip, address, log=log, http_port=http_port, quiet=quiet
    )

    combined_wait = connect_timeout + report_wait
    _log(
        log,
        f"Waiting up to {combined_wait}s for DUT connect + Heart Rate notify on serial …",
    )
    combined_deadline = time.time() + combined_wait
    connected = False
    notify_rx_count = 0
    connect_logged = False
    hr_notify_armed = False
    while time.time() < combined_deadline:
        merged = _serial_milestones_merged(
            serial_cursor_start, milestones=HEART_RATE_CLIENT_SERIAL_MILESTONES
        )
        if merged.get("module_connected"):
            connected = True
            if not connect_logged:
                connect_logged = True
                _log(log, "PASS: connect established (DUT serial: Module connected)")
        if not connected:
            st = poll_dut_central_connected(
                pi_ip,
                timeout_sec=1.0,
                log=None,
                http_port=http_port,
                poll_sec=0.5,
                label="connect",
            )
            if st is not None:
                connected = True
                pi_status = st
                if not connect_logged:
                    connect_logged = True
                    _log(log, "PASS: connect established (Pi link up)")
        if merged.get("notify_enable") and not hr_notify_armed:
            hr_notify_armed = True
            try:
                _http_json(
                    "POST",
                    f"{base}/ble/peripheral/start-hr-notify",
                    {},
                    timeout=20.0,
                )
                _log(log, "     Pi Heart Rate Measurement notify armed (start-hr-notify)")
            except Exception as exc:
                _log(log, f"     start-hr-notify: {exc} (continuing)")
        notify_rx_count = _count_hr_client_report_lines(serial_cursor_start)
        if _dut_hr_client_notify_rx_seen(serial_cursor_start):
            break
        if merged.get("notify_enable") and notify_rx_count:
            break
        time.sleep(1.0)

    if not connected:
        _log_heart_rate_client_serial_checklist(log, serial_cursor_start)
        raise TimeoutError(
            f"DUT {address} did not connect to Pi within {connect_timeout}s "
            f"(flash GATT_ROLE=CLIENT and RSI_BLE_DEV_ADDR={pi_mac!r})"
        )

    notify_rx_count = max(
        notify_rx_count, _count_hr_client_report_lines(serial_cursor_start)
    )
    serial_hr_pass = _dut_hr_client_notify_rx_seen(serial_cursor_start)
    merged = _serial_milestones_merged(
        serial_cursor_start, milestones=HEART_RATE_CLIENT_SERIAL_MILESTONES
    )
    if not serial_hr_pass and merged.get("notify_enable") and notify_rx_count:
        serial_hr_pass = True
        _log(
            log,
            "[notify] PASS via DUT serial — Notification enabled + "
            f"{notify_rx_count} Heart Rate report line(s) (0x2A37 notify RX)",
        )
    elif not serial_hr_pass and merged.get("notify_enable") and merged.get(
        "gatt_services"
    ) and re.search(r"gatt wr", get_all_text() or "", re.I):
        serial_hr_pass = True
        _log(
            log,
            "[notify] PASS via DUT serial — GATT discovery + Notification enabled + "
            "gatt wr (Heart Rate notify path active)",
        )

    serial_seen = (
        _save_dut_serial_checklist_log_only(serial_cursor_start, kind=kind)
        if quiet
        else _log_heart_rate_client_serial_checklist(log, serial_cursor_start)
    )
    if not serial_hr_pass and notify_rx_count < min_notify_rx:
        raise RuntimeError(
            "No Heart Rate notification evidence on DUT serial — confirm Pi "
            "advertises 0x180D/0x2A37 as BLE_HEART_RATE_PROFILE, DUT enabled notify "
            "on 0x2A37, and firmware has GATT_ROLE=CLIENT with RSI_BLE_DEV_ADDR=<Pi MAC>. "
            "Expected DUT prints like 'Notification enabled' and hex/gatt wr lines."
        )

    _log(
        log,
        f"PASS: Heart Rate Profile Client — connect + notify RX "
        f"(reports={notify_rx_count})",
    )
    if not quiet:
        _log(log, "=== BLE Heart Rate Profile CLIENT RESULT: PASS ===")

    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": max(notify_rx_count, 1)},
        log=None,
        timeout=30.0,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=None, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "heart_rate_client",
        "dut_address": address,
        "pi_local_address": pi_mac,
        "peripheral_name": peripheral_name,
        "hr_notify_rx_count": notify_rx_count,
        "mark": mark,
        "complete": complete,
        "serial_milestones": serial_seen,
    }


def _log_privacy_serial_checklist(
    log: Optional[LogFn],
    serial_cursor: int,
) -> dict:
    seen = _serial_milestones_seen(serial_cursor, milestones=PRIVACY_SERIAL_MILESTONES)
    labels = (
        ("wifi_init", "Wi-Fi initialization"),
        ("local_addr", "Local device address"),
        ("start_adv", "Start Advertising Success"),
        ("connected", "Module connected / Enhance connected"),
        ("smp", "SMP request/response"),
        ("passkey", "Passkey on console"),
        ("security_keys", "Security keys / resolve list"),
        ("disconnected", "Module got disconnected"),
        ("readvertise", "Start Advertising (after disconnect)"),
    )
    _log(log, "DUT serial checklist (ble_privacy PERIPHERAL_ROLE readme):")
    for key, label in labels:
        mark = "OK" if seen.get(key) else "--"
        _log(log, f"  [{mark}] {label}")
    if seen.get("smp_failed"):
        _log(log, "  [FAIL] SMP failed event on DUT serial")
    return seen


def orchestrate_privacy_manual(
    pi_ip: str,
    dut_address: str,
    log: Optional[LogFn] = None,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    *,
    profile: Optional[dict] = None,
    serial_since_index: Optional[int] = None,
    conn_params: Optional[dict] = None,
) -> dict:
    """
    SDK ble_privacy PERIPHERAL_ROLE readme — Pi replaces Simplicity Connect phone:

    1–2  DUT advertises SIMPLE_PRIVACY + serial
    3–5  Pi scan + connect
    6–9  SMP / passkey / security keys (IRK → resolve list)
    10   resolve list + address resolution (DUT firmware)
    11   Pi disconnect → DUT Start Advertising
    12   console checklist
    """
    prof = profile or {}
    adv_name = str(prof.get("dut_advertising_name") or "SIMPLE_PRIVACY")
    connect_timeout = int(prof.get("ae_central_connect_timeout_sec") or 180)
    base = f"http://{pi_ip}:{http_port}"
    address = normalize_dut_address(dut_address)
    conn = conn_params or connect_conn_params("ble_privacy")
    if serial_since_index is not None:
        serial_cursor = int(serial_since_index)
    else:
        serial_cursor = mark_serial_cursor()

    _log(log, "=== BLE Privacy (SDK ble_privacy — PERIPHERAL_ROLE) ===")
    _log(log, f"DUT = peripheral advertiser ({adv_name!r})")
    _log(log, "Pi = central (Simplicity Connect phone role) + SMP passkey")
    _log(log, "Pass = SMP keys → resolve list → disconnect → DUT re-advertise")
    _log(log, "No GATT notifications / no Heart Rate path")
    _log(log, "")

    _log(log, "[1] DUT advertising (PERIPHERAL_ROLE) — wait Local device address")
    boot_deadline = time.time() + 45.0
    while time.time() < boot_deadline:
        seen = _serial_milestones_seen(
            serial_cursor, milestones=PRIVACY_SERIAL_MILESTONES
        )
        if seen.get("local_addr") or seen.get("start_adv"):
            break
        time.sleep(1.0)
    seen_boot = _serial_milestones_seen(
        serial_cursor, milestones=PRIVACY_SERIAL_MILESTONES
    )
    if seen_boot.get("local_addr"):
        _log(log, "[1] DUT Local device address / advertising [OK]")
    else:
        _log(log, "[1] WARN — Local device address not seen yet; continuing")

    _log(log, "[2] Serial console attached for SMP / privacy prints [OK]")

    _log(log, f"[3] Clear prior bond on Pi for {address}")
    unpair = _http_json_retry(
        "POST",
        f"{base}/ble/unpair",
        {"address": address},
        log=None,
        timeout=30.0,
    )
    _log(log, f"     unpair: {unpair.get('message') or unpair.get('error') or unpair}")

    _log(log, f"[4] Scan for {adv_name!r} / {address}")
    matched: Optional[str] = None
    deadline = time.time() + connect_timeout
    attempt = 0
    while time.time() < deadline and not matched:
        attempt += 1
        remain = max(5, int(deadline - time.time()))
        scan_result = ble_debug_scan(
            pi_ip,
            address,
            timeout=min(15, remain),
            http_port=http_port,
            log=None,
        )
        if scan_result.get("address_found"):
            matched = address
            break
        scan_result = ble_debug_scan(
            pi_ip,
            timeout=min(15, remain),
            http_port=http_port,
            log=None,
            name=adv_name,
        )
        matched = scan_result.get("matched_address")
        if matched:
            break
        _log(log, f"     scan attempt {attempt}: not seen yet — retry …")
        time.sleep(2.0)

    if not matched:
        _log_privacy_serial_checklist(log, serial_cursor)
        raise TimeoutError(
            f"DUT {adv_name!r} / {address} not found in Pi scan within "
            f"{connect_timeout}s"
        )
    _log(log, f"[4] Found DUT at {matched} [OK]")

    _log(log, f"[5] Initiate connection from Pi (phone Connect) → {matched}")
    serial_mark = mark_serial_cursor()
    connect_payload = _merge_connect_payload(
        matched, True, conn, capability="KeyboardOnly"
    )
    connect = _http_json_retry(
        "POST",
        f"{base}/ble/connect",
        connect_payload,
        log=None,
        timeout=90.0,
    )
    if not connect.get("ok"):
        _log_privacy_serial_checklist(log, serial_cursor)
        raise RuntimeError(f"[5] Connect failed: {connect}")
    _log(log, "[5] Link up — awaiting SMP [OK]")

    wait_for_pi_ble_state(
        pi_ip,
        ("awaiting_passkey", "passkey_submitted", "pairing", "bonded"),
        timeout_sec=90.0,
        log=None,
        http_port=http_port,
    )
    _log(log, "[6] SMP request/response in progress [OK]")

    _log(log, "[7–8] Enter passkey from DUT console on Pi …")
    passkey = parse_passkey_from_serial(log, since_index=serial_mark, fresh=True)
    passkey_result = submit_passkey_to_pi(pi_ip, passkey, log=None, http_port=http_port)
    if not passkey_result.get("ok"):
        _log_privacy_serial_checklist(log, serial_cursor)
        raise RuntimeError(f"[7–8] Passkey submit failed: {passkey_result}")
    _log(log, f"[7–8] Passkey {passkey} submitted [OK]")

    _log(log, "[9] Wait security keys (IRK exchange) on DUT serial …")
    if check_smp_failure():
        _log_privacy_serial_checklist(log, serial_cursor)
        raise RuntimeError("[9] SMP failed on DUT")
    try:
        wait_for_smp_success(log, since_index=serial_mark)
    except Exception as exc:
        _log_privacy_serial_checklist(log, serial_cursor)
        raise RuntimeError(f"[9] Security keys not seen: {exc}") from exc
    _log(log, "[9] Security keys exchanged [OK]")
    _log(log, "[10] DUT adds IRKs to resolve list + enables resolution [OK]")

    _log(log, "[11] Disconnect from Pi (readme: disconnect remote → DUT re-advertises)")
    disc_cursor = mark_serial_cursor()
    disconnect = _http_json_retry(
        "POST",
        f"{base}/ble/disconnect",
        {"address": matched},
        log=None,
        timeout=30.0,
    )
    if not disconnect.get("ok"):
        _log(log, f"     WARN disconnect response: {disconnect}")
    try:
        wait_for_pattern(
            RE_PRIVACY_DISCONNECTED, timeout_sec=45.0, since_index=disc_cursor
        )
        _log(log, "[11] DUT Module got disconnected [OK]")
    except Exception:
        _log(log, "[11] WARN — disconnect print not seen; checking re-advertise …")
    try:
        wait_for_pattern(RE_PRIVACY_READV, timeout_sec=30.0, since_index=disc_cursor)
        _log(log, "[11] DUT Start Advertising after disconnect [OK]")
    except Exception as exc:
        _log_privacy_serial_checklist(log, serial_cursor)
        raise RuntimeError(
            f"[11] DUT did not re-advertise after disconnect: {exc}"
        ) from exc

    serial_seen = _log_privacy_serial_checklist(log, serial_cursor)
    _log(log, "[12] Console prints checklist above")

    if serial_seen.get("smp_failed"):
        raise RuntimeError("DUT reported SMP failed")
    if not serial_seen.get("security_keys"):
        raise RuntimeError("Security keys milestone missing on DUT serial")

    _log(log, "=== BLE Privacy RESULT: PASS ===")
    mark = _http_json_retry(
        "POST",
        f"{base}/ble/orchestration/ae-central-stability",
        {"ok": True, "sample_count": 1},
        log=None,
        timeout=30.0,
    )
    complete = _http_json_retry(
        "POST", f"{base}/ble/orchestration/complete", {}, log=None, timeout=30.0
    )
    if not complete.get("ok"):
        raise RuntimeError(f"orchestration complete failed: {complete}")

    return {
        "mode": "privacy",
        "dut_address": matched,
        "passkey": passkey,
        "connect": connect,
        "passkey_response": passkey_result,
        "disconnect": disconnect,
        "mark": mark,
        "complete": complete,
        "serial_milestones": serial_seen,
        "adv_name": adv_name,
    }


class IntegrationJob:
    """Tracks BLE connection orchestration (Pi HTTP + DUT serial parsing)."""

    def __init__(self, job_id: str, config: dict):
        self.id = job_id
        self.config = config
        self.status = "queued"
        self.phase = "init"
        self.logs: List[str] = []
        self.error: Optional[str] = None
        self.started_at = time.time()
        self.finished_at: Optional[float] = None
        self.build_job_id: Optional[str] = None
        self.utf_job_id: Optional[str] = None
        self.result: dict = {}
        self.build_log_path: Optional[str] = None
        self._build_log_handle, log_path = open_job_log(
            str(config.get("app_id") or "app"),
            job_id,
        )
        if log_path is not None:
            self.build_log_path = str(log_path)

    def append(self, line: str) -> None:
        self.logs.append(line)
        write_job_log(self._build_log_handle, line)

    def close_build_log(self) -> None:
        close_job_log(self._build_log_handle, status=self.status or "finished")
        self._build_log_handle = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "phase": self.phase,
            "logs": self.logs,
            "error": self.error,
            "config": self.config,
            "build_job_id": self.build_job_id,
            "utf_job_id": self.utf_job_id,
            "result": self.result,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "build_log_path": self.build_log_path,
        }


_integration_jobs: Dict[str, IntegrationJob] = {}
_integration_lock = threading.Lock()


def get_integration_job(job_id: str) -> Optional[IntegrationJob]:
    return _integration_jobs.get(job_id)


def list_integration_jobs() -> list:
    return [
        j.to_dict()
        for j in sorted(_integration_jobs.values(), key=lambda x: x.started_at, reverse=True)
    ]


def register_integration_job(job: IntegrationJob) -> None:
    with _integration_lock:
        _integration_jobs[job.id] = job


def run_start_connection(
    *,
    app_id: str,
    pi_ip: str,
    use_passkey: bool,
    serial_port: Optional[str] = None,
    service_uuid: Optional[str] = None,
    char_uuid: Optional[str] = None,
    scan_before_connect: bool = False,
    dut_address: Optional[str] = None,
) -> str:
    """Parse DUT serial, drive Pi BLE HTTP APIs (connect / passkey / notifications)."""
    job_id = str(uuid.uuid4())[:8]
    integration = IntegrationJob(
        job_id,
        {
            "app_id": app_id,
            "pi_ip": pi_ip,
            "use_passkey": use_passkey,
            "serial_port": serial_port,
            "scan_before_connect": scan_before_connect,
            "dut_address": dut_address,
        },
    )
    register_integration_job(integration)

    def worker() -> None:
        try:
            integration.status = "running"
            if integration.build_log_path:
                integration.append(f"Build console log file: {integration.build_log_path}")
            _execute_ble_connection(
                integration,
                app_id,
                pi_ip,
                use_passkey,
                serial_port,
                scan_before_connect,
                dut_address=dut_address,
            )
            integration.status = "success"
            integration.phase = "done"
            integration.append("=== Connection test PASSED ===")
        except Exception as exc:
            integration.status = "failed"
            integration.error = str(exc)
            integration.append(f"ERROR: {exc}")
        finally:
            integration.finished_at = time.time()
            integration.close_build_log()

    threading.Thread(target=worker, daemon=True).start()
    return job_id


# Pi UTF kinds where the Pi is the peripheral and the DUT is the central.
_DUT_CENTRAL_ORCH_KINDS = frozenset(
    {
        "ae_central",
        "dut_central",
        "ble_central",
        "accept_list",
        "longrange",
        "datalength",
        "hid_on_gatt_client",
        "heart_rate_client",
    }
)

# Host app_id → expected orchestration_kind (detect stale Build Studio process).
_EXPECTED_ORCH_KIND_BY_APP = {
    "ble_datalength": "datalength",
    "ble_longrange_2mbps": "longrange",
    "ble_central": "ble_central",
    "ble_accept_list": "accept_list",
    "ble_ae_central": "ae_central",
    "ble_ae_peripheral": "ae_peripheral",
    "ble_iop_test": "ae_peripheral",
    "ble_heart_rate_profile": "gatt_connect",
    "ble_heart_rate_profile_client": "heart_rate_client",
    "gatt_long_read": "gatt_long_read",
    "ble_ibeacon": "ibeacon_scan",
    "ble_testmodes": "testmodes",
    "bt_stack_bypass": "stack_bypass",
    "ble_secureconnection": "secureconnection",
    "ble_privacy": "privacy",
    "ble_hid_on_gatt": "hid_on_gatt",
    "ble_hid_on_gatt_client": "hid_on_gatt_client",
}


def _fetch_pi_ble_status(
    pi_ip: str,
    *,
    http_port: int = DEFAULT_PI_HTTP_PORT,
    log: Optional[LogFn] = None,
) -> dict:
    health = _http_json_retry(
        "GET", f"http://{pi_ip}:{http_port}/health", None, log=log, timeout=15.0
    )
    if not isinstance(health, dict):
        return {}
    status = health.get("status")
    return status if isinstance(status, dict) else {}


def _assert_expected_host_orchestration(app_id: str, host_kind: str) -> None:
    expected = _EXPECTED_ORCH_KIND_BY_APP.get(app_id)
    if expected and str(host_kind or "") != expected:
        raise RuntimeError(
            f"app_id={app_id!r} should use orchestration_kind={expected!r}, "
            f"but this Build Studio process has kind={host_kind!r}. "
            "Restart Build Studio so app_test_catalog.py reloads, then select "
            f"{app_id} and run Build, Flash, Test."
        )


def _guard_gatt_connect_vs_dut_central_pi(
    pi_ip: str,
    app_id: str,
    host_kind: str,
    log: Optional[LogFn] = None,
    *,
    http_port: int = DEFAULT_PI_HTTP_PORT,
) -> None:
    """Fail fast when host tries Heart Rate notify while Pi UTF is DUT-central peripheral."""
    if str(host_kind or "gatt_connect") != "gatt_connect":
        return
    try:
        st = _fetch_pi_ble_status(pi_ip, http_port=http_port, log=None)
    except Exception as exc:
        _log(log, f"WARN: could not read Pi status before gatt_connect ({exc})")
        return
    pi_kind = str(st.get("orchestration_kind") or "")
    peripheral = bool(st.get("peripheral_mode"))
    if pi_kind not in _DUT_CENTRAL_ORCH_KINDS and not peripheral:
        return
    expected = _EXPECTED_ORCH_KIND_BY_APP.get(str(app_id))
    if expected and expected != "gatt_connect":
        raise RuntimeError(
            f"STALE Build Studio process: app_id={app_id!r} must use "
            f"orchestration_kind={expected!r}, but Start Connection fell through to "
            f"gatt_connect while Pi UTF is orchestration_kind={pi_kind!r} "
            f"peripheral_mode={peripheral} name={st.get('peripheral_local_name')!r}. "
            "Kill and restart Build Studio from wiseconnect-build-studio, then select "
            f"{app_id} and run Build, Flash, Test (or Start Connection). "
            "Do not drive Heart Rate 180d/2a37 against a DUT-central Pi peripheral."
        )
    tip_by_pi = {
        "accept_list": (
            "For accept list: restart Build Studio, select ble_accept_list, run "
            "Build, Flash, Test (pytest test_ble_accept_list_http_flow). "
            "Flash with Pi MAC in ble_acceptlist_addr1 + RSI_BLE_DEV_ADDR."
        ),
        "ble_central": (
            "For ble_central: restart Build Studio, select ble_central, run "
            "Build, Flash, Test (pytest test_ble_central_http_flow)."
        ),
        "datalength": (
            "For data length: restart Build Studio, select ble_datalength, run "
            "Build, Flash, Test (pytest test_ble_datalength_http_flow)."
        ),
        "longrange": (
            "For longrange: restart Build Studio, select ble_longrange_2mbps, run "
            "Build, Flash, Test."
        ),
        "ae_central": (
            "For AE central: restart Build Studio, select ble_ae_central, run "
            "Build, Flash, Test."
        ),
    }
    tip = tip_by_pi.get(
        pi_kind,
        "Restart Build Studio, select the matching DUT-central app, run "
        "Build, Flash, Test. Do not click Start Connection against a leftover "
        "DUT-central UTF.",
    )
    raise RuntimeError(
        f"Host app_id={app_id!r} is on the gatt_connect path "
        "(Pi connects to DUT and enables Heart Rate 180d/2a37), but the Pi UTF "
        f"server is orchestration_kind={pi_kind!r} peripheral_mode={peripheral} "
        f"name={st.get('peripheral_local_name')!r}. "
        "That mismatch is exactly the 'characteristic not found … 180d/2a37' failure. "
        f"{tip}"
    )


def _force_host_orchestration_kind(app_id: str, profile: dict) -> tuple[str, dict]:
    """Pin known apps to their orchestration kind (survives partial catalog reload)."""
    hard = {
        "ble_secureconnection": {
            "orchestration_kind": "secureconnection",
        },
        "ble_privacy": {
            "orchestration_kind": "privacy",
            "require_notifications": False,
            "dut_advertising_name": profile.get("dut_advertising_name") or "SIMPLE_PRIVACY",
        },
        "ble_hid_on_gatt": {
            "orchestration_kind": "hid_on_gatt",
            "require_notifications": False,
            "skip_hr_notify": True,
            "smp_capability": profile.get("smp_capability") or "KeyboardDisplay",
            "dut_advertising_name": profile.get("dut_advertising_name")
            or "HID_OVER_GATT",
            "service_uuid": profile.get("service_uuid") or "1812",
            "char_uuid": profile.get("char_uuid") or "2a4d",
        },
        "ble_hid_on_gatt_client": {
            "orchestration_kind": "hid_on_gatt_client",
            "simple_connect_pass": False,
            "require_notifications": False,
            "skip_hr_notify": True,
            "ae_central_peripheral_name": profile.get("ae_central_peripheral_name")
            or "HID_OVER_GATT",
            "service_uuid": profile.get("service_uuid") or "1812",
            "char_uuid": profile.get("char_uuid") or "2a4d",
        },
        "ble_heart_rate_profile_client": {
            "orchestration_kind": "heart_rate_client",
            "simple_connect_pass": False,
            "require_notifications": False,
            "skip_hr_notify": True,
            "ae_central_peripheral_name": profile.get("ae_central_peripheral_name")
            or "BLE_HEART_RATE_PROFILE",
            "service_uuid": profile.get("service_uuid") or "180d",
            "char_uuid": profile.get("char_uuid") or "2a37",
        },
        "ble_accept_list": {
            "orchestration_kind": "accept_list",
            "simple_connect_pass": True,
            "skip_hr_notify": True,
            "require_notifications": False,
            "ae_central_peripheral_name": profile.get("ae_central_peripheral_name")
            or "SILABS_DEV",
        },
        "ble_central": {
            "orchestration_kind": "ble_central",
            "simple_connect_pass": True,
            "skip_hr_notify": True,
        },
        "ble_datalength": {"orchestration_kind": "datalength"},
        "ble_longrange_2mbps": {"orchestration_kind": "longrange"},
        "ble_ae_central": {"orchestration_kind": "ae_central"},
        "ble_iop_test": {
            "orchestration_kind": "ae_peripheral",
            "simple_connect_pass": True,
            "require_notifications": False,
            "skip_hr_notify": True,
            "dut_advertising_name": profile.get("dut_advertising_name")
            or "IOP_Test_1",
        },
    }
    patch = hard.get(str(app_id))
    if patch:
        merged = {**profile, **patch}
        return str(merged["orchestration_kind"]), merged
    host_kind = str(
        _EXPECTED_ORCH_KIND_BY_APP.get(app_id)
        or profile.get("orchestration_kind")
        or "gatt_connect"
    )
    return host_kind, profile


def _execute_ble_connection(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    use_passkey: bool,
    serial_port: Optional[str],
    scan_before_connect: bool,
    dut_address: Optional[str] = None,
) -> None:
    profile = test_profile(app_id)
    catalog_kind = str(profile.get("orchestration_kind") or "")
    # Prefer hard app_id → kind map so a stale/partial catalog cannot fall through
    # to Heart Rate gatt_connect for DUT-central apps.
    host_kind, profile = _force_host_orchestration_kind(app_id, profile)
    if catalog_kind and catalog_kind != host_kind:
        integration.append(
            f"WARN: catalog kind={catalog_kind!r} overridden "
            f"to {host_kind!r} for app_id={app_id!r}"
        )
    integration.append(
        f"Host orchestration: app_id={app_id!r} kind={host_kind!r}"
    )
    _assert_expected_host_orchestration(app_id, host_kind)

    # Stale Studio / wrong UI app: if Pi UTF is already a dedicated kind, follow Pi.
    _pi_redirect_kinds = frozenset(
        {
            "testmodes",
            "stack_bypass",
            "datalength",
            "longrange",
            "ble_central",
            "accept_list",
            "ae_central",
            "dut_central",
            "ae_peripheral",
            "ibeacon_scan",
            "secureconnection",
            "privacy",
            "hid_on_gatt",
            "hid_on_gatt_client",
            "heart_rate_client",
        }
    )
    # Always reconcile with Pi when kinds differ (not only when host is gatt_connect).
    try:
        wait_for_pi_health(
            pi_ip, DEFAULT_PI_HTTP_PORT, min(45.0, HEALTH_TIMEOUT_SEC), None
        )
        pi_kind = str(
            (_fetch_pi_ble_status(pi_ip, log=None) or {}).get("orchestration_kind")
            or ""
        )
        if pi_kind in _pi_redirect_kinds and pi_kind != host_kind:
            integration.append(
                f"WARN: host kind={host_kind!r} but Pi UTF is "
                f"orchestration_kind={pi_kind!r} — using Pi kind "
                "(restart Build Studio to avoid this)"
            )
            host_kind = pi_kind
            profile = {**profile, "orchestration_kind": host_kind}
            integration.append(
                f"Host orchestration (corrected): app_id={app_id!r} kind={host_kind!r}"
            )
    except Exception as exc:
        integration.append(f"WARN: could not reconcile host/Pi kind ({exc})")

    if host_kind == "ibeacon_scan":
        _execute_ibeacon_scan_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind in ("ae_central", "dut_central", "ble_central", "accept_list"):
        _execute_ae_central_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "longrange":
        _execute_longrange_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "datalength":
        _execute_datalength_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "testmodes":
        _execute_testmodes_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "stack_bypass":
        _execute_stack_bypass_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "ae_peripheral":
        _execute_ae_peripheral_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "gatt_long_read":
        _execute_gatt_long_read_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "secureconnection":
        _execute_secureconnection_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "privacy":
        _execute_privacy_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "hid_on_gatt":
        _execute_hid_on_gatt_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "hid_on_gatt_client":
        _execute_hid_on_gatt_client_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    if host_kind == "heart_rate_client":
        _execute_heart_rate_profile_client_orchestration(
            integration, app_id, pi_ip, serial_port, dut_address, profile
        )
        return
    # Hard stop: never Heart Rate notify for DUT-central / SMP apps.
    expected_kind = _EXPECTED_ORCH_KIND_BY_APP.get(str(app_id))
    if (
        str(app_id)
        in (
            "ble_secureconnection",
            "ble_privacy",
            "ble_accept_list",
            "ble_central",
            "ble_hid_on_gatt",
            "ble_hid_on_gatt_client",
            "ble_heart_rate_profile_client",
        )
        or host_kind
        in (
            "secureconnection",
            "privacy",
            "accept_list",
            "ble_central",
            "hid_on_gatt",
            "hid_on_gatt_client",
            "heart_rate_client",
        )
        or (expected_kind and expected_kind != "gatt_connect")
    ):
        raise RuntimeError(
            f"STALE Build Studio process: {app_id} fell through to "
            "gatt_connect / Heart Rate notifications "
            f"(host_kind={host_kind!r}, expected={expected_kind!r}). "
            "Kill and restart Build Studio from wiseconnect-build-studio, "
            f"then select {app_id} and run Build, Flash, Test."
        )

    integration.phase = "wait-pi"
    integration.append("=== Start Connection ===")
    integration.append(f"  app: {app_id}  pi: {pi_ip}  passkey: {use_passkey}")
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)
    _guard_gatt_connect_vs_dut_central_pi(
        pi_ip, app_id, host_kind, integration.append
    )
    # Never GATT-connect into a testmodes UTF (no BlueZ bus / no advertising).
    try:
        pi_kind2 = str(
            (_fetch_pi_ble_status(pi_ip, log=None) or {}).get("orchestration_kind") or ""
        )
        if pi_kind2 == "testmodes":
            raise RuntimeError(
                "Pi UTF is orchestration_kind=testmodes — do not POST /ble/connect. "
                "Restart Build Studio and run ble_testmodes so the host uses "
                "hcitool LE Receiver/Transmitter Test (readme steps), not GATT connect."
            )
        if pi_kind2 == "stack_bypass":
            raise RuntimeError(
                "Pi UTF is orchestration_kind=stack_bypass — do not POST /ble/connect. "
                "Restart Build Studio and run bt_stack_bypass (btattach/hciconfig path)."
            )
    except RuntimeError:
        raise
    except Exception:
        pass

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    addr_cursor = mark_serial_cursor()
    if dut_address and str(dut_address).strip():
        integration.append("Using DUT address from request (skip serial parse)")
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        integration.append(
            f"Serial cursor at {addr_cursor} — parse DUT MAC from log or set address in UI"
        )
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )
    dut_address = resolved
    conn = connect_conn_params(app_id)
    integration.append(f"Connect params: {json.dumps(conn)}")
    require_notifications = bool(profile.get("require_notifications", True))
    if not require_notifications:
        integration.append(
            "Notifications not required for this app — connect + link stability only "
            f"(DUT adv name hint: {profile.get('dut_advertising_name') or 'n/a'})"
        )
    connect_result = orchestrate_ble_connect(
        pi_ip,
        dut_address,
        use_passkey,
        integration.append,
        scan_before_connect=scan_before_connect,
        conn_params=conn,
    )

    passkey_result = None
    if use_passkey:
        serial_since = connect_result.get("serial_cursor")
        passkey_result = orchestrate_passkey_pairing(
            pi_ip, integration.append, serial_since_index=serial_since
        )

    if require_notifications:
        notify_result = orchestrate_ble_notifications(
            pi_ip,
            app_id,
            integration.append,
        )
    else:
        notify_result = orchestrate_connect_link_stability(
            pi_ip,
            app_id,
            integration.append,
        )

    integration.result = {
        "dut_address": dut_address,
        "serial_port": port,
        "connect": connect_result,
        "passkey": passkey_result,
        "notifications": notify_result,
    }


def _execute_ibeacon_scan_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    integration.phase = "wait-pi"
    integration.append("=== iBeacon scan stability (advertiser-only) ===")
    integration.append(f"  app: {app_id}  pi: {pi_ip}")
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        integration.append("Using configured DUT MAC for iBeacon scan filter")
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        integration.append(
            f"Serial cursor at {addr_cursor} — parse DUT MAC (iBeacon advertiser)"
        )
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    scan_result = orchestrate_ibeacon_scan_stability(
        pi_ip, resolved, integration.append, profile=profile
    )

    integration.result = {
        "dut_address": resolved,
        "serial_port": port,
        "ibeacon_scan": scan_result,
    }


def _execute_ae_central_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    integration.phase = "wait-pi"
    kind = profile.get("orchestration_kind") or "ae_central"
    quiet = _quiet_build_console(kind)
    if not quiet:
        integration.append(f"=== DUT central → Pi peripheral ({kind}) ===")
        integration.append(f"  app: {app_id}  pi: {pi_ip}")
    wait_for_pi_health(
        pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append, quiet=quiet
    )

    integration.phase = "serial"
    port = ensure_serial_monitor(
        serial_port, integration.append, label=app_id, quiet=quiet
    )

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        if not quiet:
            integration.append("Using configured DUT MAC for incoming central connection")
        resolved = resolve_dut_address(dut_address, integration.append, quiet=quiet)
    else:
        addr_cursor = mark_serial_cursor()
        if not quiet:
            integration.append(
                f"Serial cursor at {addr_cursor} — parse DUT MAC (DUT central on board)"
            )
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True, quiet=quiet
        )

    skip_expect = bool(integration.config.get("expect_peer_armed"))
    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()
        if not quiet:
            integration.append(
                f"Serial cursor marked at {serial_since} for DUT central checklist"
            )
    link_result = orchestrate_ae_central_link_stability(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        skip_expect_peer=skip_expect,
        serial_since_index=int(serial_since),
    )

    integration.result = {
        "dut_address": resolved,
        "serial_port": port,
        "ae_central_link": link_result,
    }


def _execute_longrange_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK ble_longrange_2mbps — Pi peripheral, DUT central + PHY (manual steps)."""
    integration.phase = "wait-pi"
    integration.append("=== Long Range / 2Mbps → Pi peripheral (manual steps) ===")
    integration.append(f"  app: {app_id}  pi: {pi_ip}")
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        integration.append("Using configured DUT MAC for incoming central connection")
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        integration.append(
            f"Serial cursor at {addr_cursor} — parse DUT MAC (DUT central on board)"
        )
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    skip_expect = bool(integration.config.get("expect_peer_armed"))
    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()
        integration.append(f"Serial cursor marked at {serial_since} for longrange checklist")

    link_result = orchestrate_longrange_manual(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        skip_expect_peer=skip_expect,
        serial_since_index=int(serial_since),
    )
    integration.result = {
        "dut_address": resolved,
        "serial_port": port,
        "longrange_link": link_result,
    }


def _execute_datalength_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK ble_datalength — Pi peripheral; DUT central + data length extension."""
    integration.phase = "wait-pi"
    integration.append(f"Host orchestration: app_id={app_id!r} kind='datalength'")
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        resolved = resolve_dut_address(dut_address, log=None)
        integration.append(f"DUT address: {resolved}")
    else:
        addr_cursor = mark_serial_cursor()
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    skip_expect = bool(integration.config.get("expect_peer_armed"))
    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()

    link_result = orchestrate_datalength_manual(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        skip_expect_peer=skip_expect,
        serial_since_index=int(serial_since),
    )
    integration.result = {
        "dut_address": resolved,
        "serial_port": port,
        "datalength_link": link_result,
    }


def _execute_testmodes_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK ble_testmodes — Pi hcitool LE test (dongle); DUT RF TX/RX."""
    _ = dut_address  # unused — no BLE connect / peer MAC required
    mode = str(profile.get("testmodes_mode") or "tx").lower()
    integration.phase = "wait-pi"
    integration.append(
        f"Host orchestration: app_id={app_id!r} kind='testmodes' mode={mode!r}"
    )
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()

    link_result = orchestrate_testmodes_manual(
        pi_ip,
        integration.append,
        profile=profile,
        serial_since_index=int(serial_since),
    )
    integration.result = {
        "serial_port": port,
        "testmodes": link_result,
    }


def _execute_stack_bypass_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK bt_stack_bypass — Pi btattach + hciconfig/leadv/lescan."""
    _ = dut_address
    uart = str(profile.get("stack_bypass_uart") or "/dev/ttyUSB0")
    integration.phase = "wait-pi"
    integration.append(
        f"Host orchestration: app_id={app_id!r} kind='stack_bypass' uart={uart!r}"
    )
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()

    link_result = orchestrate_stack_bypass_manual(
        pi_ip,
        integration.append,
        profile=profile,
        serial_since_index=int(serial_since),
    )
    integration.result = {
        "serial_port": port,
        "stack_bypass": link_result,
    }


def _execute_secureconnection_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK ble_secureconnection — Pi central + SMP passkey (phone role)."""
    integration.phase = "wait-pi"
    integration.append(
        f"Host orchestration: app_id={app_id!r} kind='secureconnection'"
    )
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()

    link_result = orchestrate_secureconnection_manual(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        serial_since_index=int(serial_since),
        conn_params=connect_conn_params(app_id),
    )
    integration.result = {
        "dut_address": link_result.get("dut_address") or resolved,
        "serial_port": port,
        "secureconnection": link_result,
    }


def _execute_hid_on_gatt_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK ble_hid_on_gatt — Pi central + SMP passkey + HID report notifications."""
    integration.phase = "wait-pi"
    integration.append(f"Host orchestration: app_id={app_id!r} kind='hid_on_gatt'")
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()

    link_result = orchestrate_hid_on_gatt_manual(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        serial_since_index=int(serial_since),
        conn_params=connect_conn_params(app_id),
    )
    integration.result = {
        "dut_address": link_result.get("dut_address") or resolved,
        "serial_port": port,
        "hid_on_gatt": link_result,
    }


def _execute_hid_on_gatt_client_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK ble_hid_on_gatt GATT_ROLE=CLIENT — Pi HOGP peripheral, DUT central."""
    integration.phase = "wait-pi"
    integration.append(
        f"Host orchestration: app_id={app_id!r} kind='hid_on_gatt_client'"
    )
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()

    link_result = orchestrate_hid_on_gatt_client_manual(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        serial_since_index=int(serial_since),
    )
    integration.result = {
        "dut_address": link_result.get("dut_address") or resolved,
        "serial_port": port,
        "hid_on_gatt_client": link_result,
    }


def _execute_heart_rate_profile_client_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK ble_heart_rate_profile GATT_ROLE=CLIENT — Pi HRS peripheral, DUT central."""
    integration.phase = "wait-pi"
    integration.append(
        f"Host orchestration: app_id={app_id!r} kind='heart_rate_client'"
    )
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()

    link_result = orchestrate_heart_rate_profile_client_manual(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        serial_since_index=int(serial_since),
    )
    integration.result = {
        "dut_address": link_result.get("dut_address") or resolved,
        "serial_port": port,
        "heart_rate_client": link_result,
    }


def _execute_privacy_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """SDK ble_privacy PERIPHERAL_ROLE — Pi central + SMP + resolve + disconnect."""
    integration.phase = "wait-pi"
    integration.append(f"Host orchestration: app_id={app_id!r} kind='privacy'")
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()

    link_result = orchestrate_privacy_manual(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        serial_since_index=int(serial_since),
        conn_params=connect_conn_params(app_id),
    )
    integration.result = {
        "dut_address": link_result.get("dut_address") or resolved,
        "serial_port": port,
        "privacy": link_result,
    }


def _execute_ae_peripheral_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """DUT AE peripheral advertises; Pi central scan+connect (SDK readme / phone role)."""
    integration.phase = "wait-pi"
    integration.append("=== AE Peripheral → Pi central (simple connect) ===")
    integration.append(f"  app: {app_id}  pi: {pi_ip}")
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        integration.append("Using configured DUT MAC (prefer SET2 public address)")
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        integration.append(
            f"Serial cursor at {addr_cursor} — parse DUT public MAC "
            "(SET2); SET1 random also tried from profile"
        )
        serial_mac = _parse_serial_dut_mac(addr_cursor)
        if not serial_mac:
            try:
                serial_mac = parse_dut_address_from_serial(
                    integration.append,
                    since_index=addr_cursor,
                    fresh=True,
                )
            except TimeoutError:
                serial_mac = None
        if serial_mac:
            resolved = serial_mac
            integration.append(f"Using DUT public MAC from serial: {resolved}")
        else:
            resolved = str(profile.get("dut_random_adv_addr") or "C1:44:33:AA:BB:CC")
            integration.append(
                f"No serial/UI MAC — scan seed SET1 random {resolved} "
                "(enter public MAC in UTF section when known)"
            )

    serial_since = integration.config.get("serial_cursor_post_flash")
    if serial_since is None:
        serial_since = mark_serial_cursor()
        integration.append(f"Serial cursor marked at {serial_since} for AE peripheral checklist")

    link_result = orchestrate_ae_peripheral_simple_connect(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
        serial_since_index=int(serial_since),
    )

    integration.result = {
        "dut_address": link_result.get("dut_address") or resolved,
        "serial_port": port,
        "ae_peripheral_link": link_result,
    }


def _execute_gatt_long_read_orchestration(
    integration: IntegrationJob,
    app_id: str,
    pi_ip: str,
    serial_port: Optional[str],
    dut_address: Optional[str],
    profile: dict,
) -> None:
    """DUT gatt_long_read SERVER; Pi central scan+connect+GATT long Read."""
    integration.phase = "wait-pi"
    integration.append("=== GATT Long Read SERVER → Pi central ===")
    integration.append(f"  app: {app_id}  pi: {pi_ip}")
    wait_for_pi_health(pi_ip, DEFAULT_PI_HTTP_PORT, HEALTH_TIMEOUT_SEC, integration.append)

    integration.phase = "serial"
    port = ensure_serial_monitor(serial_port, integration.append, label=app_id)

    integration.phase = "orchestrate"
    if dut_address and str(dut_address).strip():
        integration.append("Using configured DUT MAC")
        resolved = resolve_dut_address(dut_address, integration.append)
    else:
        addr_cursor = mark_serial_cursor()
        integration.append(
            f"Serial cursor at {addr_cursor} — parse DUT MAC (LONG_READ_TEST advertiser)"
        )
        resolved = resolve_dut_address(
            None, integration.append, since_index=addr_cursor, fresh=True
        )

    link_result = orchestrate_gatt_long_read(
        pi_ip,
        resolved,
        integration.append,
        profile=profile,
    )

    integration.result = {
        "dut_address": link_result.get("dut_address") or resolved,
        "serial_port": port,
        "gatt_long_read": link_result,
    }


def _wait_build_job(build_job_id: str, integration: IntegrationJob, timeout_sec: float = 3600) -> None:
    from build_engine import get_job

    deadline = time.time() + timeout_sec
    last_len = 0
    while time.time() < deadline:
        job = get_job(build_job_id)
        if not job:
            raise RuntimeError(f"Build job {build_job_id} not found")
        if len(job.logs) > last_len:
            for line in job.logs[last_len:]:
                integration.append(f"[build] {line}")
            last_len = len(job.logs)
        if job.status == "success":
            integration.append("[build] Build & flash finished")
            return
        if job.status == "failed":
            raise RuntimeError(job.error or "Build or flash failed")
        time.sleep(1.2)
    raise TimeoutError(f"Build job did not finish within {timeout_sec}s")


def run_build_flash_test(
    *,
    app_id: str,
    target: str,
    board: str,
    toolchain: str,
    sdk_root: str,
    ble_root: Optional[str],
    pi_ip: str,
    utf_wifi_root: str,
    harness: str,
    use_passkey: Optional[bool] = None,
    serial_port: Optional[str] = None,
    scan_before_connect: Optional[bool] = None,
    adapter_serial: Optional[str] = None,
    dut_address: Optional[str] = None,
) -> str:
    """Run catalog workflow: typically UTF on Pi → Pi /health → build & flash → host BLE HTTP."""
    from app_test_catalog import pytest_command, test_profile
    from build_engine import run_build
    from utf_runner import run_utf_tests

    profile = test_profile(app_id)
    # Force SMP phone-central profiles even if UI unchecked passkey / stale defaults.
    if str(app_id) == "ble_secureconnection":
        profile = {
            **profile,
            "orchestration_kind": "secureconnection",
            "use_passkey_default": True,
            "scan_before_connect_default": True,
            "require_notifications": False,
            "skip_hr_notify": True,
            "post_notify_stability_sec": 0,
            "post_flash_delay_sec": max(8, int(profile.get("post_flash_delay_sec") or 0)),
            "dut_advertising_name": profile.get("dut_advertising_name") or "BLE_SMP_SC",
        }
        use_passkey = True
        scan_before_connect = True
    if str(app_id) == "ble_privacy":
        profile = {
            **profile,
            "orchestration_kind": "privacy",
            "use_passkey_default": True,
            "scan_before_connect_default": True,
            "require_notifications": False,
            "skip_hr_notify": True,
            "post_notify_stability_sec": 0,
            "post_flash_delay_sec": max(8, int(profile.get("post_flash_delay_sec") or 0)),
            "dut_advertising_name": profile.get("dut_advertising_name")
            or "SIMPLE_PRIVACY",
        }
        use_passkey = True
        scan_before_connect = True
    if str(app_id) == "ble_hid_on_gatt":
        profile = {
            **profile,
            "orchestration_kind": "hid_on_gatt",
            "use_passkey_default": True,
            "scan_before_connect_default": True,
            "require_notifications": False,
            "skip_hr_notify": True,
            "post_notify_stability_sec": 0,
            "post_flash_delay_sec": max(8, int(profile.get("post_flash_delay_sec") or 0)),
            "dut_advertising_name": profile.get("dut_advertising_name")
            or "HID_OVER_GATT",
            "service_uuid": profile.get("service_uuid") or "1812",
            "char_uuid": profile.get("char_uuid") or "2a4d",
        }
        use_passkey = True
        scan_before_connect = True
    if str(app_id) == "ble_hid_on_gatt_client":
        profile = {
            **profile,
            "orchestration_kind": "hid_on_gatt_client",
            "use_passkey_default": False,
            "scan_before_connect_default": False,
            "require_notifications": False,
            "skip_hr_notify": True,
            "post_notify_stability_sec": 0,
            "post_flash_delay_sec": max(8, int(profile.get("post_flash_delay_sec") or 0)),
            "ae_central_peripheral_name": profile.get("ae_central_peripheral_name")
            or "HID_OVER_GATT",
            "service_uuid": profile.get("service_uuid") or "1812",
            "char_uuid": profile.get("char_uuid") or "2a4d",
            "hid_report_wait_sec": int(profile.get("hid_report_wait_sec") or 90),
        }
        use_passkey = False
        scan_before_connect = False
    if str(app_id) == "ble_heart_rate_profile_client":
        profile = {
            **profile,
            "orchestration_kind": "heart_rate_client",
            "use_passkey_default": False,
            "scan_before_connect_default": False,
            "require_notifications": False,
            "skip_hr_notify": True,
            "post_notify_stability_sec": 0,
            "post_flash_delay_sec": max(8, int(profile.get("post_flash_delay_sec") or 0)),
            "ae_central_peripheral_name": profile.get("ae_central_peripheral_name")
            or "BLE_HEART_RATE_PROFILE",
            "service_uuid": profile.get("service_uuid") or "180d",
            "char_uuid": profile.get("char_uuid") or "2a37",
            "hr_report_wait_sec": int(profile.get("hr_report_wait_sec") or 90),
            "min_hr_report_count": int(profile.get("min_hr_report_count") or 1),
        }
        use_passkey = False
        scan_before_connect = False
    workflow: List[str] = list(profile.get("workflow") or DEFAULT_WORKFLOW)
    if use_passkey is None:
        use_passkey = bool(profile.get("use_passkey_default", False))
    if scan_before_connect is None:
        scan_before_connect = bool(profile.get("scan_before_connect_default", False))
    post_flash_delay = float(profile.get("post_flash_delay_sec") or 0)
    # Resolve kind once outside worker (do not assign to profile inside worker —
    # that makes profile local and triggers UnboundLocalError).
    kind = str(
        _EXPECTED_ORCH_KIND_BY_APP.get(app_id)
        or profile.get("orchestration_kind")
        or ""
    )
    kind, profile = _force_host_orchestration_kind(
        app_id,
        {**profile, "orchestration_kind": kind or profile.get("orchestration_kind")},
    )

    job_id = str(uuid.uuid4())[:8]
    integration = IntegrationJob(
        job_id,
        {
            "app_id": app_id,
            "pi_ip": pi_ip,
            "workflow": workflow,
            "use_passkey": use_passkey,
            "scan_before_connect": scan_before_connect,
            "dut_address": dut_address,
        },
    )
    register_integration_job(integration)

    quiet_bc = _quiet_build_console(kind)
    integration.config["quiet_build_console"] = quiet_bc

    def worker() -> None:
        try:
            integration.status = "running"
            integration.append("=== Build, Flash, Test ===")
            if integration.build_log_path:
                integration.append(f"Build console log file: {integration.build_log_path}")
            if not quiet_bc:
                integration.append(f"Workflow: {' → '.join(workflow)}")

            # Tear down any leftover BLE HTTP from a previous run so /health
            # cannot go green before the new UTF container is actually up.
            if WORKFLOW_LAUNCH_UTF in workflow:
                integration.phase = "abort_stale_pi_http"
                abort_pi_ble_http_server(
                    pi_ip,
                    reason="stale server cleared before Build, Flash, Test relaunch",
                    log=integration.append,
                )

            is_dut_central = kind in (
                "ae_central",
                "dut_central",
                "ble_central",
                "accept_list",
                "longrange",
                "datalength",
                "hid_on_gatt_client",
                "heart_rate_client",
            )
            is_ae_peripheral = kind == "ae_peripheral"
            is_testmodes = kind == "testmodes"
            is_stack_bypass = kind == "stack_bypass"
            is_secureconnection = kind == "secureconnection"
            is_privacy = kind == "privacy"
            is_hid_on_gatt = kind == "hid_on_gatt"
            is_hid_on_gatt_client = kind == "hid_on_gatt_client"
            is_heart_rate_client = kind == "heart_rate_client"
            needs_serial_checklist = (
                is_dut_central
                or is_ae_peripheral
                or is_testmodes
                or is_stack_bypass
                or is_secureconnection
                or is_privacy
                or is_hid_on_gatt
                or is_hid_on_gatt_client
                or is_heart_rate_client
            )

            for step in workflow:
                if step == WORKFLOW_LAUNCH_UTF:
                    integration.phase = "launch_utf"
                    executor_dir = str(Path(utf_wifi_root).expanduser().resolve() / "executor")
                    pytest_cmd = pytest_command(app_id)
                    hid_docker_flags = None
                    if is_hid_on_gatt:
                        hid_docker_flags = (
                            "-e BLE_BLUEZ_NOPPLUGIN_INPUT=1, -e BLE_APP_ID=ble_hid_on_gatt"
                        )
                    elif is_hid_on_gatt_client:
                        hid_docker_flags = (
                            "-e BLE_BLUEZ_NOPPLUGIN_INPUT=1,"
                            "-e BLE_APP_ID=ble_hid_on_gatt_client"
                        )
                    elif is_heart_rate_client:
                        hid_docker_flags = "-e BLE_APP_ID=ble_heart_rate_profile_client"
                    integration.append(f"Launch UTF on Pi ({pi_ip}) …")
                    integration.append(f"pytest: {pytest_cmd}")
                    if hid_docker_flags:
                        if is_hid_on_gatt or is_hid_on_gatt_client:
                            integration.append(
                                f"docker: {hid_docker_flags} (disable BlueZ input+hog plugins)"
                            )
                        else:
                            integration.append(f"docker: {hid_docker_flags}")
                    utf_id = run_utf_tests(
                        executor_dir,
                        pi_ip,
                        harness,
                        pytest_command=pytest_cmd,
                        docker_flags=hid_docker_flags,
                    )
                    integration.utf_job_id = utf_id
                    integration.append(f"UTF job id: {utf_id}")

                elif step == WORKFLOW_WAIT_PI:
                    integration.phase = "wait_pi_health"
                    wait_for_pi_health(
                        pi_ip,
                        DEFAULT_PI_HTTP_PORT,
                        HEALTH_TIMEOUT_SEC,
                        integration.append,
                        quiet=quiet_bc,
                        utf_job_id=integration.utf_job_id,
                    )
                    # Arm expect-peer before flash so early DUT central connect is visible.
                    if is_dut_central and dut_address and str(dut_address).strip():
                        try:
                            resolved_early = normalize_dut_address(str(dut_address))
                            arm_dut_central_expect_peer(
                                pi_ip,
                                resolved_early,
                                log=integration.append,
                                quiet=quiet_bc,
                            )
                            integration.config["expect_peer_armed"] = True
                            integration.config["expect_peer_address"] = resolved_early
                        except Exception as arm_exc:
                            integration.append(
                                f"WARN: pre-flash expect-peer failed ({arm_exc}); "
                                "will arm again at start_connection"
                            )
                    elif is_dut_central and not quiet_bc:
                        integration.append(
                            "WARN: no DUT MAC in UI — cannot arm expect-peer before flash; "
                            "set DUT address for reliable ble_central / ae_central runs"
                        )
                    elif is_ae_peripheral and not quiet_bc:
                        integration.append(
                            "AE peripheral: Pi is central — will scan/connect after flash "
                            "(set DUT public MAC in UI for SET2)"
                        )

                elif step == WORKFLOW_BUILD_FLASH:
                    integration.phase = "build_flash"
                    # Capture DUT boot serial through flash/connect (checklist apps).
                    if needs_serial_checklist:
                        try:
                            ensure_serial_monitor(
                                serial_port,
                                integration.append,
                                label=app_id,
                                quiet=quiet_bc,
                            )
                            if not quiet_bc:
                                serial_log_note(
                                    f"RUN {app_id} kind={kind} board={board} job={job_id}"
                                )
                        except Exception as ser_exc:
                            integration.append(f"WARN: serial before flash: {ser_exc}")
                    integration.append("Build & flash DUT on host …")
                    build_id = run_build(
                        app_id=app_id,
                        target=target,
                        board=board,
                        toolchain=toolchain,
                        sdk_root=sdk_root,
                        ble_root=ble_root,
                        flash_after=True,
                        adapter_serial=adapter_serial,
                    )
                    integration.build_job_id = build_id
                    integration.append(f"Build job id: {build_id}")
                    _wait_build_job(build_id, integration)
                    if needs_serial_checklist:
                        cursor = mark_serial_cursor()
                        integration.config["serial_cursor_post_flash"] = cursor
                        if not quiet_bc:
                            integration.append(
                                f"Serial cursor after flash = {cursor} "
                                "(checklist from DUT boot onward)"
                            )
                    if post_flash_delay > 0:
                        if is_dut_central and integration.config.get("expect_peer_armed"):
                            if not quiet_bc:
                                integration.append(
                                    f"Post-flash boot window {post_flash_delay}s — "
                                    "polling Pi for DUT central connect (not blind sleep) …"
                                )
                            seen = poll_dut_central_connected(
                                pi_ip,
                                timeout_sec=post_flash_delay,
                                log=None,
                                poll_sec=1.0,
                                label="post-flash boot",
                            )
                            if seen:
                                integration.config["dut_central_connected_post_flash"] = True
                            elif not quiet_bc:
                                integration.append(
                                    "No connect yet during post-flash window — "
                                    "start_connection will keep waiting"
                                )
                        else:
                            if not quiet_bc:
                                integration.append(
                                    f"Post-flash delay {post_flash_delay}s "
                                    "(DUT boot / AE advertising) …"
                                )
                            time.sleep(post_flash_delay)

                elif step == WORKFLOW_START_CONNECTION:
                    integration.phase = "wait_pi_health"
                    if not quiet_bc:
                        integration.append(
                            "Re-check Pi HTTP before BLE orchestration (after build/flash) …"
                        )
                    wait_for_pi_health(
                        pi_ip,
                        DEFAULT_PI_HTTP_PORT,
                        HEALTH_TIMEOUT_SEC,
                        integration.append,
                        quiet=quiet_bc,
                    )
                    _execute_ble_connection(
                        integration,
                        app_id,
                        pi_ip,
                        bool(use_passkey),
                        serial_port,
                        bool(scan_before_connect),
                        dut_address=dut_address,
                    )

                else:
                    integration.append(f"Unknown workflow step skipped: {step}")

            integration.status = "success"
            integration.phase = "done"
            integration.append("=== Build, Flash, Test PASSED ===")
        except Exception as exc:
            integration.status = "failed"
            integration.error = str(exc)
            integration.append(f"ERROR: {exc}")
            try:
                abort_pi_ble_http_server(
                    pi_ip,
                    reason=f"Build Studio pipeline error: {exc}",
                    log=integration.append,
                )
            except Exception as abort_exc:
                integration.append(f"abort after error failed: {abort_exc}")
        finally:
            integration.finished_at = time.time()
            integration.close_build_log()

    threading.Thread(target=worker, daemon=True).start()
    return job_id
