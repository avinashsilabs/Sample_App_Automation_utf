"""DUT serial readme checklists — ordered milestone lines for manual testers."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from serial_monitor import get_lines

# (key, regex, readme label when line not found)
ChecklistRow = Tuple[str, re.Pattern[str], str]

SERIAL_NOISE_RE = re.compile(
    r"^(event_engine_thread_priority|Thread priority order is correct|"
    r"Keep module in to |Module is in power save|start_scanning status:|"
    r"Connect status:|Initiating connect cancel|BLE connect cancel|"
    r"Restarted Scanning|\s*$|\x01+$)",
    re.I,
)

APP_ID_TO_CHECKLIST_KIND: Dict[str, str] = {
    "ble_datalength": "datalength",
    "ble_longrange_2mbps": "longrange",
    "ble_central": "ble_central",
    "ble_accept_list": "accept_list",
    "ble_ae_central": "ae_central",
    "ble_hid_on_gatt_client": "hid_on_gatt_client",
    "ble_heart_rate_profile_client": "heart_rate_client",
}

DATALENGTH_ROWS: Tuple[ChecklistRow, ...] = (
    ("wifi_init", re.compile(r"Wi-Fi Initialization Success", re.I), "Wi-Fi Initialization Success"),
    ("local_addr", re.compile(r"Local device address", re.I), "Local device address …"),
    ("started_scanning", re.compile(r"Started scanning", re.I), "Started scanning"),
    ("adv_event", re.compile(r"In Advertising Event", re.I), "In Advertising Event"),
    (
        "module_connected",
        re.compile(
            r"Module connected to address|Enhance connected|Remote device connected",
            re.I,
        ),
        "Module connected to address : <Pi MAC>",
    ),
    ("mtu_event", re.compile(r"In MTU event", re.I), "In MTU event"),
    (
        "set_data_len",
        re.compile(r"set data length|rsi_ble_set_data_len|Setting data length", re.I),
        "Setting data length (TX_LEN=… TX_TIME=…)",
    ),
    (
        "data_length_change",
        re.compile(r"In event length change event|data length change event", re.I),
        "In event length change event",
    ),
)

BLE_CENTRAL_ROWS: Tuple[ChecklistRow, ...] = (
    ("wifi_init", re.compile(r"Wi-Fi Initialization Success", re.I), "Wi-Fi Initialization Success"),
    ("local_addr", re.compile(r"Local device address", re.I), "Local device address …"),
    ("started_scanning", re.compile(r"Started scanning", re.I), "Started scanning"),
    ("adv_event", re.compile(r"In Advertising Event", re.I), "In Advertising Event"),
    (
        "module_connected",
        re.compile(r"Module connected to address", re.I),
        "Module connected to address : <Pi MAC>",
    ),
)

AE_CENTRAL_ROWS: Tuple[ChecklistRow, ...] = (
    ("wifi_init", re.compile(r"Wi-Fi Initialization Success", re.I), "Wi-Fi Initialization Success"),
    ("local_addr", re.compile(r"Local device address", re.I), "Local device address …"),
    ("scan_params", re.compile(r"set ae scan params success", re.I), "set ae scan params success"),
    ("scan_enable", re.compile(r"set ae scan enable success", re.I), "set ae scan enable success"),
    ("ae_report", re.compile(r"ae report rec for", re.I), "ae report rec for <Pi MAC>"),
    ("initiating_connect", re.compile(r"Initiating connect command", re.I), "Initiating connect command"),
    (
        "remote_connected",
        re.compile(r"Remote device connected", re.I),
        "Remote device connected <Pi MAC>",
    ),
)

ACCEPT_LIST_ROWS: Tuple[ChecklistRow, ...] = (
    ("wifi_init", re.compile(r"Wi-Fi Initialization Success", re.I), "Wi-Fi Initialization Success"),
    ("local_addr", re.compile(r"Local device address", re.I), "Local device address …"),
    ("ble_start_scan", re.compile(r"BLE start scanning", re.I), "BLE start scanning"),
    (
        "remote_name",
        re.compile(r"BLE remote device name to connect to", re.I),
        "BLE remote device name to connect to : SILABS_DEV",
    ),
    ("adv_event", re.compile(r"In Advertising Event", re.I), "In Advertising Event"),
    (
        "module_connected",
        re.compile(r"Module connected to address", re.I),
        "Module connected to address : <Pi MAC>",
    ),
)

LONGRANGE_ROWS: Tuple[ChecklistRow, ...] = (
    ("wifi_init", re.compile(r"Wi-Fi Initialization Success", re.I), "Wi-Fi Initialization Success"),
    ("local_addr", re.compile(r"Local device address", re.I), "Local device address …"),
    (
        "module_connected",
        re.compile(r"Module connected to address", re.I),
        "Module connected to address : <Pi MAC>",
    ),
    ("phy_skip", re.compile(r"Skipping PHY update", re.I), "Skipping PHY update (Pi peer)"),
    ("phy_complete", re.compile(r"Phy rate update complete", re.I), "Phy rate update complete"),
    (
        "phy_2mbps",
        re.compile(r"PHY data rate is updated to 2Mbps", re.I),
        "PHY data rate is updated to 2Mbps",
    ),
)

HID_ON_GATT_CLIENT_ROWS: Tuple[ChecklistRow, ...] = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I), "Wi-Fi Initialization Success"),
    ("local_addr", re.compile(r"Local device address", re.I), "Local device address …"),
    (
        "started_scanning",
        re.compile(
            r"Start(?:ed|ing)? scanning|Initiating connect|In Advertising Event",
            re.I,
        ),
        "Started scanning / initiating connect",
    ),
    (
        "module_connected",
        re.compile(
            r"Module connected to address|Enhance connected|Remote device connected",
            re.I,
        ),
        "Module connected to address : <Pi MAC>",
    ),
    (
        "gatt_services",
        re.compile(
            r"GATT services|services discovered|get_profile_async|get_char_services|"
            r"Character services|Handle range|rsi_ble_get_profile",
            re.I,
        ),
        "GATT services discovered on Pi",
    ),
    (
        "notify_enable",
        re.compile(
            r"notify enable|Notification enabled|enable notify|Input report notify|CCCD|"
            r"set_att_cmd_async",
            re.I,
        ),
        "HID report notify enabled",
    ),
    (
        "notify_rx",
        re.compile(
            r"In notify event|GATT notification|Input report notify val|report notify|"
            r"0x[0-9a-f]{2}(?:\s+0x[0-9a-f]{2}){3,7}|gatt wr",
            re.I,
        ),
        "HID notification received",
    ),
)

HEART_RATE_CLIENT_ROWS: Tuple[ChecklistRow, ...] = (
    ("wifi_init", re.compile(r"Wi-Fi [Ii]nitialization", re.I), "Wi-Fi Initialization Success"),
    ("local_addr", re.compile(r"Local device address", re.I), "Local device address …"),
    (
        "started_scanning",
        re.compile(
            r"Start(?:ed|ing)? scanning|Initiating connect|In Advertising Event",
            re.I,
        ),
        "Started scanning / initiating connect",
    ),
    (
        "module_connected",
        re.compile(
            r"Module connected to address|Enhance connected|Remote device connected",
            re.I,
        ),
        "Module connected to address : <Pi MAC>",
    ),
    (
        "gatt_services",
        re.compile(
            r"GATT services|services discovered|get_profile_async|get_char_services|"
            r"Character services|heart rate|0x180[dD]|Handle range|rsi_ble_get_profile",
            re.I,
        ),
        "Heart Rate service (0x180D) discovered on Pi",
    ),
    (
        "notify_enable",
        re.compile(
            r"notify enable|Notification enabled|enable notify|CCCD|set_att_cmd_async",
            re.I,
        ),
        "Heart Rate Measurement notify enabled",
    ),
    (
        "notify_rx",
        re.compile(
            r"In notify event|GATT notification|Heart[_ ]Rate|heart rate measurement|"
            r"0x[0-9a-f]{2}(?:\s+0x[0-9a-f]{2}){0,7}|gatt wr",
            re.I,
        ),
        "Heart Rate Measurement notify received",
    ),
)

CHECKLIST_BY_KIND: Dict[str, Tuple[ChecklistRow, ...]] = {
    "datalength": DATALENGTH_ROWS,
    "ble_central": BLE_CENTRAL_ROWS,
    "dut_central": BLE_CENTRAL_ROWS,
    "accept_list": ACCEPT_LIST_ROWS,
    "longrange": LONGRANGE_ROWS,
    "ae_central": AE_CENTRAL_ROWS,
    "hid_on_gatt_client": HID_ON_GATT_CLIENT_ROWS,
    "heart_rate_client": HEART_RATE_CLIENT_ROWS,
}


def resolve_checklist_kind(
    app_id: Optional[str] = None, kind: Optional[str] = None
) -> Optional[str]:
    if kind and kind in CHECKLIST_BY_KIND:
        return kind
    if app_id:
        return APP_ID_TO_CHECKLIST_KIND.get(str(app_id))
    return None


def milestones_seen(since_index: int = 0, *, kind: str) -> Dict[str, bool]:
    rows = CHECKLIST_BY_KIND.get(kind)
    if not rows:
        return {}
    text = "\n".join(get_lines(max(0, int(since_index))).get("lines") or [])
    return {key: bool(pat.search(text)) for key, pat, _label in rows}


def extract_checklist_lines(since_index: int = 0, *, kind: str) -> List[str]:
    """First matching DUT serial line per readme step, in order."""
    rows = CHECKLIST_BY_KIND.get(kind)
    if not rows:
        return []
    lines = get_lines(max(0, int(since_index))).get("lines") or []
    out: List[str] = []
    for _key, pat, label in rows:
        matched = None
        for line in lines:
            if pat.search(line or ""):
                matched = line.strip()
                break
        out.append(matched if matched else f"[--] {label}")
    return out


def filter_noise_lines(lines: List[str]) -> List[str]:
    cleaned: List[str] = []
    for line in lines:
        text = (line or "").strip()
        if not text or SERIAL_NOISE_RE.search(text):
            continue
        cleaned.append(text)
    return cleaned


def format_checklist_block(
    since_index: int = 0,
    *,
    kind: str,
    title: Optional[str] = None,
) -> str:
    header = title or f"DUT serial checklist ({kind})"
    body = extract_checklist_lines(since_index, kind=kind)
    seen = milestones_seen(since_index, kind=kind)
    ok = sum(1 for v in seen.values() if v)
    total = len(seen)
    return "\n".join(
        [header, ""] + body + ["", f"({ok}/{total} readme milestones seen in capture window)"]
    )
