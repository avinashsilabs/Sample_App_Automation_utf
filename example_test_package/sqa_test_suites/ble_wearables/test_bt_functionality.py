"""
=============================================================================
test_bt_functionality.py: Bluetooth Classic (BT) Functionality Test Suite
=============================================================================

Overview
--------
    This module contains automated test cases for validating Bluetooth Classic
    (BR/EDR) functionality on the DUT (Device Under Test). The tests focus on
    standalone BT Classic operations including inquiry, paging, pairing,
    A2DP/HFP/AVRCP profile connections, audio streaming, and power-saving
    modes — without concurrent BLE traffic.

    Each test case independently establishes a BT Classic link between the
    DUT (RT595 + RS9116) and a remote BT peer (Raspberry Pi or commercial
    headset/speaker), exercises the targeted feature, and verifies expected
    behavior via UART log inspection and HCI event monitoring.

Test Categories
---------------
    1. Discovery & Connection
        - BT Inquiry (active / passive)
        - BT Paging as Initiator / Acceptor
        - Connection / Reconnection stability

    2. Pairing & Security
        - SSP (Secure Simple Pairing) - Just Works
        - SSP - Numeric Comparison
        - SSP - Passkey Entry
        - Link key generation, save and reuse
        - BR/EDR encryption (AES-CCM)

    3. Audio Profiles
        - A2DP Source / Sink streaming
        - AVRCP play / pause / forward / rewind / volume control
        - HFP voice call (SCO/eSCO)
        - Codec negotiation (SBC, AAC, mSBC, CVSD)

    4. Power Management
        - Sniff mode entry / exit
        - Role switch (Master <-> Slave)

    5. Stress & Stability
        - Long-duration streaming (20+ minutes)
        - Multiple pair / unpair cycles
        - Disconnect / reconnect loop
        - Audio quality under weak RSSI conditions

Dependencies
------------
    - pytest                          : Test runner
    - utf_core                        : Test framework + RPC layer
    - utf.interfaces.bluetooth.bluez  : BlueZ D-Bus wrapper for Raspi peer
    - Raspberry Pi (running BlueZ)    : BT Classic peer device
    - RT595 + RS9116 DUT              : Device under test

=============================================================================
Author : Sivaramakrishna Sivalenka
=============================================================================
"""

import time
import random
import pytest
import os
import datetime
import subprocess

import string
from datetime import timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple



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
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from utf.interfaces.bluetooth.nrf_blatann import (
    NRFBLEIoCapabilities
)

from test_ble_a2dp import BtsnoopCaptureManager


# =============================================================================
# GLOBAL VARIABLES AND CONSTANTS
# =============================================================================

connect_status_container = {}
local_dut_address = None

# =============================================================================
# LOGGER
# =============================================================================
def logger():
    return get_logger(__name__)

# =============================================================================
# HELPER FUNCTIONS
# ============================================================================= 
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
    start_index=None
):
    flags = re.IGNORECASE if case_insensitive else 0
    if isinstance(patterns, (str, bytes)):
        patterns = [patterns]
    compiled = [re.compile(p, flags) for p in patterns] if regex else [
        (p.lower() if case_insensitive else p) for p in patterns
    ]
    bus = dut.interfaces.wifi.bus
    if start_index is None:
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

def serial_expect_multi(dut, patterns, timeout=30, baseline=False, **kwargs):
    mode = kwargs.get("mode", "all")
    result = serial_wait_multi(dut, patterns, timeout=timeout, baseline=baseline, **kwargs)
    if mode == "all":
        missing = [p for p in patterns if p not in result]
        assert not missing, f"Missing patterns: {missing}"
    else:
        assert result, f"No pattern from list found within {timeout}s"
    return result


SDP_PROFILE_UUIDS = {
    0x110D: "A2DP (Advanced Audio Distribution)",
    0x110E: "AVRCP (A/V Remote Control)",
    0x111E: "HFP (Handsfree)",
}
_SDP_PROFILE_BLOCK_RE = re.compile(
    r"Attribute:\s*Bluetooth Profile Descriptor List\s*\(0x0009\)"
    r"(?P<body>.*?)(?=^\s*Attribute:|^[<>=@!])",
    re.S | re.M,
)
_SDP_UUID_LINE_RE = re.compile(r"^\s*(?P<name>.+?)\s*\(0x0*(?P<uuid>[0-9A-Fa-f]{1,8})\)\s*$")
_SDP_VER_LINE_RE = re.compile(r"^\s*0x(?P<ver>[0-9A-Fa-f]{4})\s*$")

def parse_profile_versions_in_btmon(bt_mon_log_path: str) -> dict:
    """
    Parse SDP 'Bluetooth Profile Descriptor List' attributes from a btmon text log
    and return {profile_uuid: "major.minor"}.
    Example btmon lines:
        Attribute: Bluetooth Profile Descriptor List (0x0009) [len 2]
          Sequence (6) with 6 bytes [8 extra bits] len 8
            UUID (3) with 2 bytes [0 extra bits] len 3
              Advanced Audio Distribution (0x110d)
            Unsigned Integer (1) with 2 bytes [0 extra bits] len 3
              0x0104
    """
    assert os.path.isfile(bt_mon_log_path), f"btmon log not found: {bt_mon_log_path}"
    with open(bt_mon_log_path, "r", errors="ignore") as f:
        text = f.read()
    versions = {}
    for block in _SDP_PROFILE_BLOCK_RE.finditer(text):
        pending = None
        for line in block.group("body").splitlines():
            m_u = _SDP_UUID_LINE_RE.match(line)
            if m_u:
                pending = int(m_u.group("uuid"), 16)
                continue
            m_v = _SDP_VER_LINE_RE.match(line)
            if m_v and pending is not None:
                raw = int(m_v.group("ver"), 16)
                versions[pending] = f"{raw >> 8}.{raw & 0xFF}"
                pending = None
    logger().info(
        "  SDP profile versions: "
        + ", ".join(
            f"{SDP_PROFILE_UUIDS.get(u, hex(u))}={v}" for u, v in sorted(versions.items())
        )
    )
    return versions


def verify_a2dp_avrcp_sdp_versions_in_btmon(bt_mon_log_path: str) -> dict:
    """
    Parse A2DP and AVRCP profile versions from the SDP
    Profile Descriptor List in the btmon log.
    """

    versions = parse_profile_versions_in_btmon(bt_mon_log_path)

    a2dp_version = versions.get(0x110D)
    avrcp_version = versions.get(0x110E)

    assert a2dp_version, (
        f"No A2DP (0x110D) profile version found in "
        f"{bt_mon_log_path}. "
        f"Found: {[(hex(k), v) for k, v in versions.items()]}"
    )

    assert avrcp_version, (
        f"No AVRCP (0x110E) profile version found in "
        f"{bt_mon_log_path}. "
        f"Found: {[(hex(k), v) for k, v in versions.items()]}"
    )

    logger().info(
        f"[PASS] A2DP SDP version: {a2dp_version}, "
        f"AVRCP SDP version: {avrcp_version}"
    )

    return {
        "a2dp": a2dp_version,
        "avrcp": avrcp_version,
    }


PTYPE_2DH3 = "0x3206"
PTYPE_2DH5 = "0x2306"
PTYPE_3DH3 = "0x3106"
PTYPE_3DH5 = "0x1306"


#---------------------------------------------------------------------------
# AVDTP stats pkts count extraction
#---------------------------------------------------------------------------

def get_3dh3t_tx_count(avdtp_stats: str) -> int:
    """
    Extract 3dh3t TX packet count from an AVDTP stats block.

    Example:
        3dh3t:200,r:0

    Returns:
        TX packet count
    """

    match = re.search(
        r"3dh3t:(\d+),r:(\d+)",
        avdtp_stats,
        re.IGNORECASE,
    )

    assert match, (
        "3dh3t statistics not found in AVDTP stats block"
    )

    return int(match.group(1))


# AVDTP signal name -> id (btmon text)
AVDTP_SIGNALS = {
    "Discover": 0x01,
    "GetCapabilities": 0x02,
    "SetConfiguration": 0x03,
    "GetConfiguration": 0x04,
    "Reconfigure": 0x05,
    "Open": 0x06,
    "Start": 0x07,
    "Close": 0x08,
    "Suspend": 0x09,
    "Abort": 0x0A,
    "SecurityControl": 0x0B,
    "GetAllCapabilities": 0x0C,
    "DelayReport": 0x0D,
}

import re

# Maps packet-type constant value to host-serial stats counter key
PTYPE_TO_STAT_KEY = {
    PTYPE_2DH3: "2dh3t",
    PTYPE_2DH5: "2dh5t",
    PTYPE_3DH3: "3dh3t",
    PTYPE_3DH5: "3dh5t",
}

_PKT_PAIR_RE = re.compile(r"(?P<name>(?:dm|dh|2dh|3dh)[135])t:(?P<t>\d+),r:(?P<r>\d+)", re.I)
_CLK_RE = re.compile(r"Clk:(0x[0-9A-Fa-f]+|\d+),TxP:(\d+),TxN:(\d+),RxP:(\d+),RxN:(\d+)", re.I)
_CRC_RE = re.compile(r"CRC:(\d+),Retry:(\d+),Hdr:(\d+),Seq:(\d+)", re.I)
_AVDTP_ERR_RE = re.compile(r"AVDTP err:(\d+),sent:(\d+)", re.I)
_AVDTP_PER_RE = re.compile(r"AVDTP PER:(\d+)", re.I)
_AVDTP_TX_RE = re.compile(r"AVDTP TX:(\d+),ACK:(\d+)", re.I)
_ACK_BINS_RE = re.compile(r"ACK\s+<10:(\d+),20:(\d+),30:(\d+),40:(\d+),50:(\d+),60:(\d+),70:(\d+),80:(\d+),90:(\d+),100:(\d+),>100:(\d+)", re.I)

def get_latest_avdtp_stats_block(ble_dut, start_index=0):
    """
    Returns the latest complete host-serial stats block as a string.
    Block start: 'Clk:...'
    Block end  : 'AVDTP TX:...,ACK:...'
    """
    bus = ble_dut.interfaces.wifi.bus
    log = bus.get_input_log()

    lines = []
    for _, raw in log[start_index:]:
        try:
            lines.append(raw.decode(errors="ignore"))
        except Exception:
            lines.append(str(raw))

    latest = None
    i = 0
    while i < len(lines):
        if "Clk:" in lines[i] and "TxP:" in lines[i]:
            j = i
            while j < len(lines):
                if "AVDTP TX:" in lines[j]:
                    latest = "\n".join(lines[i:j + 1])
                    i = j
                    break
                j += 1
        i += 1

    assert latest, "No complete AVDTP stats block found in host serial log"
    return latest

def parse_avdtp_stats_block(block_text):
    """
    Parses one block like:
      Clk..., TxP...
      dm*/dh*/2dh*/3dh* lines
      CRC...
      ACK bins...
      AVDTP err...
      AVDTP PER...
      AVDTP TX...
    """
    out = {
        "clk": None,
        "link": {},
        "pkt": {},
        "pkt_retry": {},
        "crc": {},
        "ack_bins": {},
        "avdtp": {},
        "raw": block_text,
    }

    m = _CLK_RE.search(block_text)
    if m:
        clk_raw = m.group(1)
        out["clk"] = int(clk_raw, 16) if clk_raw.lower().startswith("0x") else int(clk_raw)
        out["link"] = {
            "TxP": int(m.group(2)),
            "TxN": int(m.group(3)),
            "RxP": int(m.group(4)),
            "RxN": int(m.group(5)),
        }

    for pm in _PKT_PAIR_RE.finditer(block_text):
        name = pm.group("name").lower()      # dm1 / 2dh3 / 3dh5
        out["pkt"][f"{name}t"] = int(pm.group("t"))
        out["pkt_retry"][f"{name}r"] = int(pm.group("r"))

    m = _CRC_RE.search(block_text)
    if m:
        out["crc"] = {
            "CRC": int(m.group(1)),
            "Retry": int(m.group(2)),
            "Hdr": int(m.group(3)),
            "Seq": int(m.group(4)),
        }

    m = _ACK_BINS_RE.search(block_text)
    if m:
        keys = ["<10", "20", "30", "40", "50", "60", "70", "80", "90", "100", ">100"]
        out["ack_bins"] = {k: int(v) for k, v in zip(keys, m.groups())}

    m = _AVDTP_ERR_RE.search(block_text)
    if m:
        out["avdtp"]["err"] = int(m.group(1))
        out["avdtp"]["sent"] = int(m.group(2))

    m = _AVDTP_PER_RE.search(block_text)
    if m:
        out["avdtp"]["per"] = int(m.group(1))

    m = _AVDTP_TX_RE.search(block_text)
    if m:
        out["avdtp"]["tx"] = int(m.group(1))
        out["avdtp"]["ack"] = int(m.group(2))

    return out

def assert_a2dp_streaming_active(ble_dut, start_index=0):
    """
    Verify that A2DP audio packets are being transmitted
    during the streaming period.

    Expected:
        3dh3t > 0
    """

    avdtp_stats = get_latest_avdtp_stats_block(
        ble_dut,
        start_index=start_index,
    )

    logger().info(
        "Latest AVDTP stats during A2DP streaming:\n%s",
        avdtp_stats,
    )

    match = re.search(
        r"3dh3t:\s*(\d+)",
        avdtp_stats,
        re.IGNORECASE,
    )

    assert match, (
        "3dh3t statistics not found in AVDTP stats"
    )

    tx_count = int(match.group(1))

    logger().info(
        "3dh3t TX count during A2DP streaming: %d",
        tx_count,
    )

    assert tx_count > 0, (
        "A2DP audio data is not being transmitted during streaming. "
        f"Expected 3dh3t > 0, observed 3dh3t: {tx_count}"
    )

    logger().info(
        "PASS: A2DP audio data is being transmitted during streaming "
        f"(3dh3t: {tx_count})"
    )

    return True

# ---------------------------------------------------------------------------
# Packet type stats assertions for A2DP / AVDTP
# ---------------------------------------------------------------------------

def assert_packet_type_stats(stats, expected_ptype, min_packets=50):
    """
    Example: if expected_ptype = PTYPE_3DH3, expects stats['pkt']['3dh3t'] >= min_packets.
    """
    key = PTYPE_TO_STAT_KEY.get(expected_ptype)
    assert key, f"Unsupported expected_ptype: {expected_ptype}"

    count = int(stats.get("pkt", {}).get(key, 0))
    assert count >= min_packets, (
        f"Expected {key} >= {min_packets}, got {count}. "
        f"pkt counters: {stats.get('pkt', {})}"
    )

    # Optional quality gates
    per = stats.get("avdtp", {}).get("per")
    if per is not None:
        assert per == 0, f"AVDTP PER expected 0, got {per}"

    logger().info(f"[PASS] Packet stats match: {key}={count}, AVDTP={stats.get('avdtp', {})}")
    return count

def verify_a2dp_media_transmission(avdtp_stats):
    """
    Verify that A2DP media packets were transmitted.

    Expected during streaming:
        3dh3t > 0
        AVDTP TX > 0
    """

    pkt_match = re.search(
        r"3dh3t:(\d+),r:(\d+)",
        avdtp_stats,
        re.IGNORECASE
    )

    assert pkt_match, (
        "3dh3t statistics not found in AVDTP stats block"
    )

    tx_3dh3t = int(pkt_match.group(1))

    tx_match = re.search(
        r"AVDTP TX:(\d+),ACK:(\d+)",
        avdtp_stats,
        re.IGNORECASE
    )

    assert tx_match, (
        "AVDTP TX statistics not found in AVDTP stats block"
    )

    avdtp_tx = int(tx_match.group(1))

    logger().info(
        f"A2DP media statistics: "
        f"3dh3t:{tx_3dh3t}, AVDTP TX:{avdtp_tx}"
    )

    assert tx_3dh3t > 0, (
        f"A2DP media transmission failed: "
        f"3dh3t:{tx_3dh3t}. Expected > 0"
    )

    assert avdtp_tx > 0, (
        f"A2DP media transmission failed: "
        f"AVDTP TX:{avdtp_tx}. Expected > 0"
    )

    logger().info(
        "[PASS] A2DP media packets are being transmitted"
    )
    return True


def verify_avdtp_cmd_rsp_in_btmon(
    bt_mon_log_path: str,
    signal: str = "Open",
    signal_id: int = None,
    require_accept: bool = True,
    min_pairs: int = 1,
):
    """
    Parse btmon text log and verify AVDTP <signal> Command has a matching
    Response (same label / transaction).

    Example lines:
      AVDTP: Open (0x06) Command (0x00) type 0x00 label 6 nosp 0
      AVDTP: Open (0x06) Response Accept (0x02) type 0x00 label 6 nosp 0

    Raises AssertionError if fewer than min_pairs matched pairs are found.
    Returns list of dicts: {label, signal, response_kind}.
    """
    assert os.path.isfile(bt_mon_log_path), f"btmon log not found: {bt_mon_log_path}"

    sig_name = signal.strip()
    sid = signal_id if signal_id is not None else AVDTP_SIGNALS.get(sig_name)
    assert sid is not None, f"Unknown AVDTP signal '{sig_name}' — pass signal_id="

    # Simpler / more reliable line regex:
    line_re = re.compile(
        r"AVDTP:\s*(?P<name>\w+)\s*\((?P<sid>0x[0-9A-Fa-f]+|\d+)\)\s*"
        r"(?P<kind>Command|Response(?:\s+Accept|\s+Reject|\s+General Reject)?)\s*"
        r"\((?P<mtype>0x[0-9A-Fa-f]+|\d+)\)"
        r".*?\blabel\s+(?P<label>\d+)",
        re.IGNORECASE,
    )

    with open(bt_mon_log_path, "r", errors="ignore") as f:
        text = f.read()

    pending = {}   # label -> True (command seen)
    pairs = []

    for m in line_re.finditer(text):
        name = m.group("name")
        sid_val = int(m.group("sid"), 0)
        kind = re.sub(r"\s+", " ", m.group("kind")).strip().title()
        label = m.group("label")

        if name.lower() != sig_name.lower() or sid_val != sid:
            continue

        if kind == "Command":
            pending[label] = True
            logger().info(f"  AVDTP {sig_name} Command  label={label}")
        elif kind.startswith("Response"):
            if label not in pending:
                logger().warning(
                    f"  AVDTP {sig_name} {kind} label={label} with no prior Command"
                )
                continue
            is_accept = "Accept" in kind or m.group("mtype").lower() in ("0x02", "2")
            is_reject = "Reject" in kind
            if require_accept and not is_accept:
                raise AssertionError(
                    f"AVDTP {sig_name} label={label} got '{kind}', expected Response Accept"
                )
            pending.pop(label, None)
            pairs.append({"label": label, "signal": sig_name, "response": kind})
            logger().info(f"  AVDTP {sig_name} {kind} label={label}  [PAIR OK]")

    unmatched = sorted(pending.keys())
    assert not unmatched, (
        f"AVDTP {sig_name} Command(s) with no Response: labels {unmatched}"
    )
    assert len(pairs) >= min_pairs, (
        f"Expected >= {min_pairs} AVDTP {sig_name} Command/Response pair(s) in "
        f"{bt_mon_log_path}, found {len(pairs)}"
    )
    logger().info(
        f"[PASS] AVDTP {sig_name} (0x{sid:02X}): {len(pairs)} Command/Response pair(s)"
    )
    return pairs

def avrcp_pause_play_cycle(
    ble_dut,
    bt_client,
    local_dut_address,
    pause_hold_sec=5,
    require_status=True,
    cycle_id=1,
):
    """
    One AVRCP Pause -> hold -> Play cycle.

    Does NOT assert pause/play command/passthrough events.
    With require_status=True, asserts playback status PAUSED then PLAYING
    from DUT serial (RegisterNotification), using start_index so each cycle
    only sees new lines.
    """
    bus = ble_dut.interfaces.wifi.bus

    # ----- PAUSE -----
    logger().info(f"\n--- AVRCP cycle {cycle_id}: PAUSE ---")
    t_pause = time.time()
    base_idx = len(bus.get_input_log())
    bt_client.interfaces.bluetooth.bt_media_player.pause(local_dut_address)

    if require_status:
        serial_expect_multi(
            ble_dut,
            [r"playback changed event:\s*PAUSED|\bPAUSED\b"],
            timeout=10,
            poll_interval=0.5,
            regex=True,
            case_insensitive=True,
            mode="any",
            start_index=base_idx,
        )
        logger().info(f"  [PASS] Cycle {cycle_id}: status PAUSED")

    remaining = pause_hold_sec - (time.time() - t_pause)
    if remaining > 0:
        logger().info(f"  Holding PAUSED {remaining:.1f}s (cycle {cycle_id})")
        time.sleep(remaining)

    gap = time.time() - t_pause
    assert gap >= pause_hold_sec, (
        f"Cycle {cycle_id}: Pause→Play gap {gap:.1f}s < required {pause_hold_sec}s"
    )

    # ----- PLAY -----
    logger().info(f"--- AVRCP cycle {cycle_id}: PLAY ---")
    base_idx = len(bus.get_input_log())
    bt_client.interfaces.bluetooth.bt_media_player.play(local_dut_address)

    if require_status:
        serial_expect_multi(
            ble_dut,
            [
                r"playback changed event:\s*PLAYING",
                r"A2DP audio"
            ],
            timeout=10,
            poll_interval=0.5,
            regex=True,
            case_insensitive=True,
            mode="any",
            start_index=base_idx,
        )
        logger().info(f"  [PASS] Cycle {cycle_id}: status PLAYING")
        

    time.sleep(1)  # settle before next cycle


# ============================================================================
# Audio capture helper class to manage btsnoop capture on the Raspberry Pi
# peer device
# ============================================================================
def start_btsnoop_capture(test_case_name: str, timestamp, output_dir: str = "reports") -> BtsnoopCaptureManager:
    """
    Create a BtsnoopCaptureManager, start btmon binary capture, and verify it
    is running. The caller passes `timestamp` so the btsnoop filename matches
    the test's other artifacts (btmon log, wav, etc.).
    Caller is responsible for stopping it (try/finally with manager.stop_capture()).
    """
    btsnoop_filename = f"{test_case_name}_{timestamp}_btsnoop.log"
    btsnoop_manager = BtsnoopCaptureManager(output_dir=output_dir)
    logger().info("Starting btsnoop binary capture...")
    btsnoop_file = btsnoop_manager.start_capture(filename=btsnoop_filename)
    assert btsnoop_file is not None, (
        "btsnoop/btmon capture failed to start (start_capture returned None). "
        "Check that 'btmon' is installed and sudo permissions are available on the Raspi."
    )
    assert (
        btsnoop_manager.btmon_process is not None
        and btsnoop_manager.btmon_process.poll() is None
    ), "btmon process terminated unexpectedly right after start; btsnoop capture is not running."
    return btsnoop_manager, btsnoop_file

# # TMTP per AVRCP: TG must respond within 1000 ms
# AVRCP_TMTP_MS = 1000
def verify_avrcp_response_timing(btsnoop_file: str, tmtp_ms: int = AVRCP_TMTP_MS):
    """
    Parse the captured btsnoop air log with tshark and verify that the TG (DUT)
    generated a response within TMTP for:
      - NOTIFY commands  (RegisterNotification, PDU 0x31) -> INTERIM (0xF)
      - STATUS commands  (GetCapabilities,     PDU 0x10) -> STABLE  (0xC)
    Raises AssertionError if any response exceeds tmtp_ms (or if no command/response
    pairs are found).
    """
    cmd = [
        "tshark", "-r", btsnoop_file,
        "-Y", "btavrcp",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "btavctp.transaction",
        "-e", "btavctp.cr",        # 0 = command, 1 = response
        "-e", "btavrcp.ctype",     # cmd: 0x1 STATUS, 0x3 NOTIFY ; rsp: 0xF INTERIM, 0xC STABLE
        "-e", "btavrcp.pdu_id",    # 0x10 GetCapabilities, 0x31 RegisterNotification
        "-E", "separator=,",
    ]
    logger().info(f"Analyzing AVRCP timing from air log: {btsnoop_file}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"tshark failed: {proc.stderr.strip()}"
    # Buffer outstanding commands keyed by transaction label
    pending = {}      # txn -> (epoch, pdu_id, kind)
    results = []      # (kind, txn, delta_ms)
    for line in proc.stdout.splitlines():
        parts = line.split(",")
        if len(parts) < 5:
            continue
        t_str, txn, cr, ctype, pdu = (p.strip() for p in parts[:5])
        if not t_str or not txn:
            continue
        try:
            epoch = float(t_str)
            ctype_i = int(ctype, 16) if ctype.startswith("0x") else (int(ctype) if ctype else -1)
            pdu_i = int(pdu, 16) if pdu.startswith("0x") else (int(pdu) if pdu else -1)
        except ValueError:
            continue
        if cr == "0":  # command
            if pdu_i == 0x31 and ctype_i == 0x3:
                pending[txn] = (epoch, pdu_i, "NOTIFY/RegisterNotification")
            elif pdu_i == 0x10 and ctype_i == 0x1:
                pending[txn] = (epoch, pdu_i, "STATUS/GetCapabilities")
        elif cr == "1":  # response
            if txn in pending:
                start, pdu_i0, kind = pending.pop(txn)
                # interim (0xF) for NOTIFY, stable (0xC) for STATUS
                if (kind.startswith("NOTIFY") and ctype_i == 0xF) or \
                   (kind.startswith("STATUS") and ctype_i in (0xC, 0x9)):
                    delta_ms = (epoch - start) * 1000.0
                    results.append((kind, txn, delta_ms))
                    logger().info(f"  {kind} (txn {txn}): response in {delta_ms:.1f} ms")
    assert results, (
        "No AVRCP NOTIFY/STATUS command-response pairs found in the air log. "
        "Check that streaming/AVRCP actually ran and that tshark can read the btsnoop."
    )
    violations = [(k, t, d) for (k, t, d) in results if d > tmtp_ms]
    assert not violations, (
        f"AVRCP response(s) exceeded TMTP ({tmtp_ms} ms): "
        + "; ".join(f"{k} txn {t} took {d:.1f} ms" for k, t, d in violations)
    )
    logger().info(f"[PASS] All {len(results)} AVRCP responses within TMTP ({tmtp_ms} ms)")


# Two DUT serial forms report a headset-initiated absolute volume change:
#
#  1) CT-side notify (only while EVENT_VOLUME_CHANGED registration is live):
#       Absolute Volume: 74 (0x5f)          -> exact raw value in hex
#  2) TG-side SetAbsoluteVolume callback (always fires):
#       rsi_bt_on_avrcp_set_abs_vol_event- bt_str_conn_bd_addr: <addr>, Vol: 74
#     -> percentage only, where pct = raw * 100 / 0x7f
ABS_VOL_RE = r"(?i)Absolute\s+Volume:.*?\(\s*0x([0-9A-Fa-f]{1,2})\s*\)"
SET_ABS_VOL_PCT_RE = r"(?i)set_abs_vol_event-.*?\bVol:\s*(\d{1,3})"


def serial_log_index(ble_dut) -> int:
    """Current length of the DUT serial input log (use as a scan start marker)."""
    return len(ble_dut.interfaces.wifi.bus.get_input_log())


def _abs_vol_pct(raw: int) -> int:
    """Firmware conversion: abs_vol_per = (abs_vol * 100) / 0x7f (integer div)."""
    return (raw * 100) // 0x7F


def expect_abs_volume(
    ble_dut,
    expected: int,
    start_index: int,
    timeout: int = 15,
    poll_interval: float = 0.5,
) -> int:
    """
    Assert the DUT reports AVRCP absolute volume == `expected` (raw 0..127) in
    serial output that arrived after `start_index`.

    Accepts either the hex 'Absolute Volume: <pct> (0x..)' line or the
    percentage-only 'set_abs_vol_event- ... Vol: <pct>' line.

    NOTE: serial log timestamps are perf_counter_ns deltas, not epoch seconds,
    so the log is windowed by index rather than by time.
    """
    bus = ble_dut.interfaces.wifi.bus
    hex_pat = re.compile(ABS_VOL_RE)
    pct_pat = re.compile(SET_ABS_VOL_PCT_RE)
    expected_pct = _abs_vol_pct(expected)

    deadline = time.time() + timeout
    got_raw = None
    got_pct = None

    while time.time() < deadline and got_raw is None and got_pct is None:
        for _ts, chunk in bus.get_input_log()[start_index:]:
            line = chunk.decode(errors="ignore")
            m = hex_pat.search(line)
            if m:
                got_raw = int(m.group(1), 16)
                continue
            m = pct_pat.search(line)
            if m:
                got_pct = int(m.group(1))
        if got_raw is None and got_pct is None:
            time.sleep(poll_interval)

    if got_raw is not None:
        assert 0 <= got_raw <= 127, (
            f"Parsed volume {got_raw} outside AVRCP range 0..127"
        )
        assert got_raw == expected, (
            f"Absolute volume {got_raw} (0x{got_raw:02x}) != expected {expected}"
        )
        logger().info(f"[PASS] Absolute volume == {got_raw} (0x{got_raw:02x})")
        return got_raw

    assert got_pct is not None, (
        f"No absolute volume report in DUT serial after log index {start_index} "
        f"(waited {timeout}s). Expected either 'Absolute Volume: <pct> (0x..)' "
        "or 'set_abs_vol_event- ... Vol: <pct>'. Check btmon for "
        "AVRCP SetAbsoluteVolume from the headset."
    )
    assert got_pct == expected_pct, (
        f"Reported volume {got_pct}% != expected {expected_pct}% "
        f"(raw {expected}, 0x{expected:02x})"
    )
    logger().info(
        f"[PASS] Absolute volume {got_pct}% matches raw {expected} "
        f"(0x{expected:02x}) - verified via set_abs_vol_event percentage"
    )
    return expected

# =============================================================================
# TEST SETUP AND CLEANUP FUNCTIONS
# =============================================================================

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_verify_bt_paging_process_C553518(ble_dut, bt_client, ble_sniffer):
    """
    Verify BT Paging process initiated by DUT and verify peer address in logs
    TC: C553518

    """

    time.sleep(20)  # Allow DUT to stabilize after reset

    test_case_name = "BT_Paging_Process_C553518"
    time_stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")    

    logger().info("\n\n==== Test: BT Paging Process Verification ====\n\n")

    btsnoop_manager, btsnoop_file = start_btsnoop_capture(test_case_name, time_stamp)

    bt_mon_log_file_name = f"reports/C553518_BT_Paging_{time_stamp}.log"

    local_dut_address = None
    bt_peer_address = None
    
    with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):

        try:

            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_func_{test_case_name}_{time_stamp}")
            logger().info("Frontline sniffer: initialized and capture started")
            time.sleep(10)

            # ---------------------------------------------------------------------
            # 1) Get local DUT and BT peer addresses
            # ---------------------------------------------------------------------
            local_dut_address = ble_dut.interfaces.bluetooth.get_local_address()
            logger().info(f"Local DUT Address      : {local_dut_address}")

            # ---------------------------------------------------------------------
            # 2) Make bt_client discoverable (A2DP sink)
            # ---------------------------------------------------------------------
            logger().info("\n**** Configure Raspberry Pi as A2DP sink (discoverable) ****\n")
            pin_code = "0000"
            bt_peer_address = bt_client.interfaces.bluetooth.start_a2dp_sink_with_bluez(
                bt_dut_address=local_dut_address, pin_code=pin_code
            )
            time.sleep(5)

            logger().info(" select audio data src for a2dp")
            ble_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 30 seconds")
            time.sleep(30)

            ble_dut.interfaces.wifi.bt_connect(bt_peer_address)
            time.sleep(1) # Wait for bt paging

            assert_check(ble_dut, "Initiated Paging")
            logger().info(" BT paging process initiated successfully")

            elapsed_time = 0
            max_wait_time = 5  # seconds
            while elapsed_time < max_wait_time:
                elapsed_time += 1                
                time.sleep(1)  # Wait before retrying


            # verify paging logs in OTA - manually
            try:
                assert_check(ble_dut, "on conn paging")
                logger().info(" BT paging process confirmed in serial log")
            except AssertionError:
                logger().error(" on conn paging not found in serial log")
                raise

            try:
                #time.sleep(10) # Wait for paging to complete
                expected = bt_peer_address.strip().upper()
                assert_check(ble_dut, f"conn paging: BD Address: {expected}")
                logger().info(f" conn paging: BD Address: {expected} found in serial log")
                time.sleep(1) # Wait for paging to complete
                assert_check(ble_dut, f"page done")
                logger().info(" page done found in serial log")

            except AssertionError:
                logger().error(f" conn paging: BD Address: {expected} not found in serial log")
                raise

            time.sleep(5)

            # Use assert_check which searches ENTIRE log
            connect_status = assert_check(ble_dut, "a2dp conn ok")
            time.sleep(10) # Wait for connection to complete
            logger().info(f" BT Classic connection status: {connect_status}")

            
        except Exception as e:
            logger().error(f"Exception during BT Paging test: {e}")
            raise

        finally:
            logger().info("Cleaning up BT connections and stopping captures")

            try:
                if bt_peer_address:
                    ble_dut.interfaces.wifi.bt_disconnect(bt_peer_address)
                    time.sleep(2)  # Wait for disconnection to complete
            except Exception as e:
                logger().warning(f"bt_disconnect cleanup warning: {e}")

            try:
                btsnoop_file = btsnoop_manager.stop_capture()
                logger().info(f"btsnoop capture stopped. File saved at: {btsnoop_file}")
            except Exception as e:
                logger().warning(f"stop_capture cleanup warning: {e}")

            time.sleep(10)
            try:
                ble_sniffer.interfaces.sniffer.stop_capture()
                logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
            except Exception as sniffer_err:
                logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

            try:
                bt_adapter_path = bt_client.interfaces.bluetooth.adapter_path
                get_bus = bt_client.interfaces.bluetooth.bus
                bt_client.interfaces.bluetooth.bluez_adapter.remove_device(
                    bus=get_bus, adapter_path=bt_adapter_path, dev_addr=local_dut_address
                )
                time.sleep(3)
            except Exception as e:
                logger().warning(f"remove_device cleanup warning: {e}")

            try:
                bt_client.interfaces.bluetooth.close()
                time.sleep(5)
            except Exception as e:
                logger().warning(f"bt_client close cleanup warning: {e}")

            logger().info("=" * 70)
            logger().info("   OUTPUT FILES")
            logger().info("=" * 70)
            logger().info(f"   btmon log:      {bt_mon_log_file_name}")
            logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
            logger().info("=" * 70)

  

    logger().info("\n\n==== Test Completed: BT Paging and Connection Verification ====\n\n")


@pytest.mark.ble_sniffer("frontline_sniffer")
def test_bt_sdp_features_C553523(ble_dut, bt_client, ble_sniffer): 
    """
    Verify BT SDP features of DUT by parsing supported features from OTA logs
    TC: C553523
    """

    time.sleep(20)  # Allow DUT to stabilize after reset

    test_case_name = "BT_SDP_Features_C553523"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    logger().info("\n\n==== Test: BT SDP Features Verification ====\n\n")

    btsnoop_manager, btsnoop_file = start_btsnoop_capture(test_case_name, timestamp)

    bt_mon_log_file_name = f"reports/{test_case_name}_{timestamp}.log"

    bt_peer_address = None
    local_dut_address = None
    
    with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
        try:

            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_func_{test_case_name}")
            logger().info("Frontline sniffer: initialized and capture started")
            time.sleep(10)

            # ---------------------------------------------------------------------
            # 1) Get local DUT and BT peer addresses
            # ---------------------------------------------------------------------
            local_dut_address = ble_dut.interfaces.bluetooth.get_local_address()
            logger().info(f"Local DUT Address      : {local_dut_address}")

            # ---------------------------------------------------------------------
            # 2) Make bt_client discoverable (A2DP sink)
            # ---------------------------------------------------------------------    
            logger().info("\n**** Configure Raspberry Pi as A2DP sink (discoverable) ****\n")
            pin_code = "0000"
            bt_peer_address = bt_client.interfaces.bluetooth.start_a2dp_sink_with_bluez(
                bt_dut_address=local_dut_address, pin_code=pin_code
            )
            logger().info(f"BT peer address (Raspberry Pi): {bt_peer_address}")
            time.sleep(3)

            logger().info(" select audio data src for a2dp")
            ble_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 30 seconds")
            time.sleep(30)

            # ---------------------------------------------------------------------
            # 3) Initiate bt connection from DUT to bt_client
            # ---------------------------------------------------------------------
            logger().info("Initiating BT connection from DUT to bt_client...")
            ble_dut.interfaces.wifi.bt_connect(bt_peer_address)

            #Wait for pairing (LINK_KEY)
            try:
                serial_expect_multi(
                    ble_dut,
                    [r"saved key:"],
                    timeout=40,
                    poll_interval=0.5,
                    regex=False,                   
                    case_insensitive=True
                )
                logger().info(" BT pairing completed (SAVED_LINK_KEY received)")
            except AssertionError as e:
                logger().error(f" BT pairing failed - SAVED_LINK_KEY not found: {e}")
                raise


            time.sleep(10) # Wait for connection to stabilize

            connect_status_bt = bt_client.interfaces.bluetooth.get_bt_connection_status(local_dut_address)
            assert connect_status_bt, "BT Classic connection disconnected during monitoring"
            logger().info(f"connect_status_bt: {connect_status_bt}")

            # To be verified sdp features from OTA logs
            logger().info("Verify SDP features from OTA logs...")

        except Exception as e:
            logger().error(f"Exception during BT SDP features test: {e}")
            raise

        finally:
            logger().info("Cleaning up BT connections and stopping captures")

            try:
                if bt_peer_address:
                    ble_dut.interfaces.wifi.bt_disconnect(bt_peer_address)
                    time.sleep(2)  # Wait for disconnection to complete
            except Exception as e:
                logger().warning(f"bt_disconnect cleanup warning: {e}")

            try:
                btsnoop_file = btsnoop_manager.stop_capture()
                logger().info(f"btsnoop capture stopped. File saved at: {btsnoop_file}")
            except Exception as e:
                logger().warning(f"stop_capture cleanup warning: {e}")

            time.sleep(10)
            try:
                ble_sniffer.interfaces.sniffer.stop_capture()
                logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
            except Exception as sniffer_err:
                logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

            try:
                logger().info(f"Removing bonded DUT ({local_dut_address}) from bt_client")
                bt_adapter_path = bt_client.interfaces.bluetooth.adapter_path
                get_bus = bt_client.interfaces.bluetooth.bus
                bt_client.interfaces.bluetooth.bluez_adapter.remove_device(
                    bus=get_bus, adapter_path=bt_adapter_path, dev_addr=local_dut_address
                )

                logger().info(f"PASS: Successfully removed bonded DUT " f"({local_dut_address}) from bt_client")

                time.sleep(3)
            except Exception as e:
                logger().warning(f"remove_device cleanup warning: {e}")

            try:
                bt_client.interfaces.bluetooth.close()
                time.sleep(5)
            except Exception as e:
                logger().warning(f"bt_client close cleanup warning: {e}")


    logger().info("\n\n==== Test Completed: BT SDP Features Verification ====\n\n")

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_bt_verify_bt_connection_without_streaming_C553526(ble_dut, bt_client, ble_sniffer):
    """
    Verify BT connection establishment and disconnection without streaming and verify logs in OTA
    TC: C553526

    """

    time.sleep(20)  # Allow DUT to stabilize after reset

    test_case_name = "BT_Connection_Without_Streaming_C553526"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"

    btsnoop_manager, btsnoop_file = start_btsnoop_capture(test_case_name, timestamp)

    logger().info("\n\n==== Test: BT Connection without Streaming ====\n\n")

    bt_mon_log_file_name = f"reports/{test_case_name}_{timestamp}.log"

    bt_peer_address = None
    local_dut_address = None

    with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
        try:

            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_func_{test_case_name}_{timestamp}")
            logger().info("Frontline sniffer: initialized and capture started")
            time.sleep(10)

            # ---------------------------------------------------------------------
            # 1) Get local DUT and BT peer addresses
            # ---------------------------------------------------------------------
            local_dut_address = ble_dut.interfaces.bluetooth.get_local_address()
            logger().info(f"Local DUT Address      : {local_dut_address}")

            # ---------------------------------------------------------------------
            # 2) Make bt_client discoverable (A2DP sink)
            # ---------------------------------------------------------------------    
            logger().info("\n**** Configure Raspberry Pi as A2DP sink (discoverable) ****\n")
            pin_code = "0000"
            bt_peer_address = bt_client.interfaces.bluetooth.start_a2dp_sink_with_bluez(
                bt_dut_address=local_dut_address, pin_code=pin_code
            )
            logger().info(f"BT peer address (Raspberry Pi): {bt_peer_address}")
            time.sleep(3)  

            logger().info(" select audio data src for a2dp")
            ble_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 30 seconds")
            time.sleep(30)
            
            ble_dut.interfaces.wifi.bt_connect(bt_peer_address)
            # Wait for pairing (LINK_KEY)
            try:
                serial_expect_multi(
                    ble_dut,
                    [r"saved key:"],
                    timeout=40,
                    poll_interval=0.5,
                    regex=False,                   
                    case_insensitive=True
                )
                logger().info(" BT pairing completed (SAVED_LINK_KEY received)")
            except AssertionError as e:
                logger().error(f" BT pairing failed - SAVED_LINK_KEY not found: {e}")
                raise

            # Use assert_check which searches ENTIRE log
            connect_status = assert_check(ble_dut, "a2dp conn ok")
            if connect_status:
                logger().info(" BT Classic connection established successfully")
            else:
                logger().error(" BT Classic connection failed - assert_check returned False")
                raise AssertionError("BT Classic A2DP connection verification failed")        

            
            time.sleep(2) # Wait for connection to stabilize

            logger().info("\n--- Step 1: Send AVRCP PAUSE command from Headset ---")
            bt_client.interfaces.bluetooth.bt_media_player.pause(local_dut_address)
            time.sleep(2)  # Allow command to process

            logger().info(
                "Verifying A2DP audio transmission stopped after PAUSE"
            )


            base_idx = len(
                ble_dut.interfaces.wifi.bus.get_input_log()
            )

            elapsed_time = 0
            elapsed_time_period = 5
            wait_avdtp_stats_period = 30
            while elapsed_time < wait_avdtp_stats_period:
                time.sleep(elapsed_time_period)
                elapsed_time += elapsed_time_period
                logger().info(f"Elapsed time: {elapsed_time} seconds")
                logger().info(f"Remaining time: {wait_avdtp_stats_period - elapsed_time} seconds")



            avdtp_stats = get_latest_avdtp_stats_block(ble_dut, start_index=base_idx)

            logger().info(
                "AVDTP statistics after PAUSE:\n%s",
                avdtp_stats,
            )

            match = re.search(
                r"3dh3t:\s*(\d+)",
                avdtp_stats,
                re.IGNORECASE,
            )

            assert match, (
                "3dh3t statistics not found"
            )

            tx_count = int(match.group(1))

            assert tx_count == 0, (
                f"A2DP audio packets are still being transferred after PAUSE. "
                f"Observed 3dh3t: {tx_count}"
            )

            logger().info(
                "PASS: No A2DP audio packets transferred"
                "(3dh3t: 0)"
            )

            start_time = time.time()

            while time.time() - start_time < 60:  # Monitor connection for 60 seconds
                connect_status_bt = bt_client.interfaces.bluetooth.get_bt_connection_status(local_dut_address)
                assert connect_status_bt, "BT Classic connection disconnected during monitoring"
                time.sleep(5)

            logger().info("BT connection remained stable for 60 seconds without streaming")

        except Exception as e:
            logger().error(f"Exception during BT connection without streaming test: {e}")
            raise

        finally:
            logger().info("Cleaning up BT connections and stopping captures")

            try:
                btsnoop_file = btsnoop_manager.stop_capture()
                logger().info(f"BTSnoop file saved: {btsnoop_file}")
            except Exception as e:
                logger().warning(f"stop_capture cleanup warning: {e}")

            time.sleep(10)
            try:
                ble_sniffer.interfaces.sniffer.stop_capture()
                logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
            except Exception as sniffer_err:
                logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

            logger().info("=" * 70)
            logger().info("   OUTPUT FILES")
            logger().info("=" * 70)
            logger().info(f"   btmon log:      {bt_mon_log_file_name}")
            #logger().info(f"   Audio WAV:      {capture_file_path}")
            logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
            logger().info("=" * 70)        

            # To be verified disconnection logs in OTA - manually
            try:
                if bt_peer_address:
                    ble_dut.interfaces.wifi.bt_disconnect(bt_peer_address)
                    time.sleep(2)  # Wait for disconnection to complete
            except Exception as e:
                logger().warning(f"bt_disconnect cleanup warning: {e}")

            try:
                logger().info(f"Removing bonded DUT ({local_dut_address}) from bt_client")
                bt_adapter_path = bt_client.interfaces.bluetooth.adapter_path
                get_bus = bt_client.interfaces.bluetooth.bus
                bt_client.interfaces.bluetooth.bluez_adapter.remove_device(
                    bus=get_bus, adapter_path=bt_adapter_path, dev_addr=local_dut_address)

                logger().info(f"PASS: Successfully removed bonded DUT " f"({local_dut_address}) from bt_client")
                time.sleep(3)
            except Exception as e:
                logger().warning(f"remove_device cleanup warning: {e}")

            try:
                bt_client.interfaces.bluetooth.close()
                time.sleep(5)
            except Exception as e:
                logger().warning(f"bt_client close cleanup warning: {e}")

    logger().info("\n\n==== Test Completed: BT Connection without Streaming ====\n\n")

@pytest.mark.ble_sniffer("frontline_sniffer")
def test_bt_a2dp_connection_streaming_C553527(ble_dut, bt_client, ble_sniffer):
    """
    Verify BT A2DP connection and streaming from DUT to bt_client and verify logs in OTA
    TC: C553527

    """

    time.sleep(20)  # Allow DUT to stabilize after reset
    wait_duration = int(os.environ.get("AUDIO_CAPTURE_DURATION", "300"))

    test_case_name = "BT_A2DP_Connection_Streaming_C553527"

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_file_path = f"./reports/{test_case_name}_audio_{timestamp}.wav"
    #btsnoop_filename = f"{test_case_name}_{timestamp}.btsnoop"

    logger().info("\n\n==== Test: BT A2DP Connection and Streaming ====\n\n")

    btsnoop_manager, btsnoop_file = start_btsnoop_capture(test_case_name, timestamp)

    bt_mon_log_file_name = f"reports/{test_case_name}_{timestamp}.log"

    bt_peer_address = None
    local_dut_address = None

    with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
        
        try:

            ble_sniffer.interfaces.sniffer.init_sniffer()
            ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"btc_func_{test_case_name}_{timestamp}")
            logger().info("Frontline sniffer: initialized and capture started")
            time.sleep(10)

            # ---------------------------------------------------------------------
            # 1) Get local DUT and BT peer addresses
            # ---------------------------------------------------------------------
            local_dut_address = ble_dut.interfaces.bluetooth.get_local_address()
            logger().info(f"Local DUT Address      : {local_dut_address}")

            # ---------------------------------------------------------------------
            # 2) Make bt_client discoverable (A2DP sink)
            # ---------------------------------------------------------------------    
            logger().info("\n**** Configure Raspberry Pi as A2DP sink (discoverable) ****\n")
            pin_code = "0000"
            bt_peer_address = bt_client.interfaces.bluetooth.start_a2dp_sink_with_bluez(
                bt_dut_address=local_dut_address, pin_code=pin_code
            )
            logger().info(f"BT peer address (Raspberry Pi): {bt_peer_address}")
            time.sleep(5)

            logger().info(" select audio data src for a2dp")
            ble_dut.interfaces.wifi.a2dp_audio_data_src_selection()
            logger().info(" Delay started of 30 seconds")
            time.sleep(30)

            logger().info("Initiating BT connection from DUT to bt_client...")
            ble_dut.interfaces.wifi.bt_connect(bt_peer_address)

            # Wait for pairing (LINK_KEY)
            try:
                serial_expect_multi(
                    ble_dut,
                    [r"saved key:"],
                    timeout=40,
                    poll_interval=0.5,
                    regex=False,                   
                    case_insensitive=True
                )
                logger().info(" BT pairing completed (SAVED_LINK_KEY received)")
            except AssertionError as e:
                logger().error(f" BT pairing failed - SAVED_LINK_KEY not found: {e}")
                raise

            # Use assert_check which searches ENTIRE log
            connect_status = assert_check(ble_dut, "a2dp conn ok")
            if connect_status:
                logger().info(" BT Classic connection established successfully")
            else:
                logger().error(" BT Classic connection failed - assert_check returned False")
                raise AssertionError("BT Classic A2DP connection verification failed")
            
            time.sleep(5) # Wait for connection to stabilize

            assert_check(ble_dut, "avrcp conn")

            # call streaming code here to start streaming from DUT to bt_client
            logger().info("Starting A2DP streaming from DUT to bt_client...")

            assert_check(ble_dut, "A2DP audio")
            logger().info("[PASS] A2DP audio check - streaming")

            # Start audio capture
            bt_client.interfaces.bluetooth.bt_service.start_capturing_audio(capture_file_path)
            logger().info(f"Audio capture started: {capture_file_path}")

            base_idx = len(ble_dut.interfaces.wifi.bus.get_input_log())

            # Wait for connection and audio streaming
            logger().info(f"Waiting {wait_duration} seconds for connection and audio...")
            logger().info("")

            elapsed_time = 0
            elapsed_time_period = 5
            check_avdtp_stats_period = 30
            while elapsed_time < check_avdtp_stats_period:                
                time.sleep(elapsed_time_period)
                elapsed_time += elapsed_time_period
                logger().info(f"Elapsed time: {elapsed_time} seconds")
                logger().info(f"Remaining time: {check_avdtp_stats_period - elapsed_time} seconds")

            assert_a2dp_streaming_active(ble_dut, start_index=base_idx)
            logger().info("A2DP streaming is active - verified from avdtp stats")

            elapsed_time = 0
            elapsed_time_period = 5
            while elapsed_time < wait_duration:                
                time.sleep(elapsed_time_period)
                elapsed_time += elapsed_time_period
                logger().info(f"Elapsed time: {elapsed_time} seconds")
                logger().info(f"Remaining time: {wait_duration - elapsed_time} seconds")

            # Check audio file
            try:
                captured_audio_size = bt_client.interfaces.bluetooth.bt_service.read_file_size(capture_file_path)
                logger().info(f"Captured audio size: {captured_audio_size} bytes")
            except Exception as e:
                logger().warning(f"Could not read audio file: {e}")

        except Exception as e:
            logger().error(f"Exception occurred during BT A2DP connection and streaming test: {e}")
            raise

        finally:
            # To be verified streaming logs in OTA - manually

            try:
                btsnoop_file = btsnoop_manager.stop_capture()
                logger().info(f"BTSnoop file saved: {btsnoop_file}")
            except Exception as e:
                logger().warning(f"stop_capture cleanup warning: {e}")

            time.sleep(10)
            try:
                ble_sniffer.interfaces.sniffer.stop_capture()
                logger().info(f"Frontline capture saved: {ble_sniffer.interfaces.sniffer.local_capture_files}")
            except Exception as sniffer_err:
                logger().warning(f"Frontline sniffer stop_capture error (non-fatal): {sniffer_err}")

            logger().info("=" * 70)
            logger().info("   OUTPUT FILES")
            logger().info("=" * 70)
            logger().info(f"   btmon log:      {bt_mon_log_file_name}")
            logger().info(f"   Audio WAV:      {capture_file_path}")
            logger().info(f"   btsnoop binary: {btsnoop_file or 'N/A'}")
            logger().info("=" * 70)

            try:
                if bt_peer_address:
                    ble_dut.interfaces.wifi.bt_disconnect(bt_peer_address)
                    time.sleep(2)  # Wait for disconnection to complete
            except Exception as e:
                logger().warning(f"bt_disconnect cleanup warning: {e}")

            try:
                logger().info(f"Removing bonded DUT ({local_dut_address}) from bt_client")
                bt_adapter_path = bt_client.interfaces.bluetooth.adapter_path
                get_bus = bt_client.interfaces.bluetooth.bus
                bt_client.interfaces.bluetooth.bluez_adapter.remove_device(
                    bus=get_bus, 
                    adapter_path=bt_adapter_path, 
                    dev_addr=local_dut_address
                )
                time.sleep(3)
            except Exception as e:
                logger().warning(f"remove_device cleanup warning: {e}")

            try:
                bt_client.interfaces.bluetooth.close()
                time.sleep(5)
            except Exception as e:
                logger().warning(f"bt_client close cleanup warning: {e}")

    logger().info("\n\n==== Test Completed: BT A2DP Connection and Streaming ====\n\n")





