import os
import re
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple

import pytest
from utf.utils.logger import get_logger

"""
BLE multi-slave / multi-role wearables test suite (RT595 harness).

Firmware (manifest): ``sqa_test_agent-rt595-gcc_arm+bt_peripheral_board.elf`` only —
see ``manifest/manifest_rt595_without_aws_test_agent.yaml``.

C553971 — scan/advertise intervals (TestRail steps 10–12).
C553972 — 1 master + 3 slave idle connection stability, repeated twice.
C553973 — dual-role 1 master + 1 slave stability (TestRail steps 14–23).

Harness:
  C553971 — 1 DUT + 1 Raspi (``ble_client``) + RF Creations sniffer (start/stop capture).
  C553972 — 1 DUT + 4 Raspi (``ble_clients``): 1 central + 3 peripherals.
  C553973 — 1 DUT + 2 Raspi (``ble_clients``): 1 central + 1 peripheral.

author: Pavan.Jenne
"""


def logger():
    return get_logger(__name__)


SMP_DUT_INIT_SLEEP_SEC = 20
DUT_BLE_READY_TIMEOUT_SEC = 120
DUT_LOCAL_ADDRESS_RETRY_SEC = 3
DUT_LOCAL_ADDRESS_MAX_ATTEMPTS = 10
DUT_LOCAL_ADDRESS_CLI_TIMEOUT_SEC = 30
SMP_CONFIG_SETTLE_SEC = 1
PEER_BUS_SETTLE_SEC = 2
PEER_ADV_START_SEC = 3
SCAN_BEFORE_CONNECT_SEC = 30
CONNECT_TIMEOUT_SEC = 120
PASSKEY_TIMEOUT_SEC = 120
SMP_COMPLETE_TIMEOUT_SEC = 120
NC_PRE_CONNECT_SETTLE_SEC = 5
NRF_CONNECT_POST_LINK_SETTLE_SEC = 2
NRF_PAIR_THREAD_START_DELAY_SEC = 2
CLEANUP_FINAL_SETTLE_SEC = 5
CLEANUP_POST_DISCONNECT_SETTLE_SEC = 3.0
POST_PAIR_SETTLE_SEC = 5
POST_DISCONNECT_SETTLE_SEC = 3
STEP_SETTLE_SEC = 2
LOG_POLL_INTERVAL_SEC = 2
PASSKEY_POLL_INTERVAL_SEC = 0.5
LEGACY_SCAN_SETTLE_SEC = 1
LEGACY_SCAN_STOP_SETTLE_SEC = 0.5
WAIT_FOR_LOG_PATTERNS_DEFAULT_TIMEOUT_SEC = 120
HOSTLOG_COUNT_POLL_TIMEOUT_SEC = 10
HOSTLOG_COUNT_POLL_INTERVAL_SEC = PASSKEY_POLL_INTERVAL_SEC

# GATT profiles the Raspi exposes while a link is held (data-transfer suite parity).
# Without them BlueZ registers no GATT application, the DUT logs "Client Gatt Notification service not found" and the peer tears the idle link down ~30s later.
MS_RASPI_GATT_SERVICE_CLASSES = ("HeartRateService",)
BLE_EVENT_WAIT_TIMEOUT_SEC = 30
RASPI_SMP_SCAN_SETTLE_SEC = 10
RASPI_ROLE_SWITCH_SETTLE_SEC = 5
RASPI_PRE_SCAN_SETTLE_SEC = 10
POST_SUITE_TEST_BLE_SETTLE_SEC = 30
DEFAULT_OWN_ADDR_TYPE = 0

# Firmware alternates count banner spellings (secure-pairing pattern).
_MS_MASTER_COUNT_MARKERS = {
    0: (
        "number of master devices connected:0",
        "number of connected master devices:0",
        "number of connected central devices:0",
    ),
    1: (
        "number of master devices connected:1",
        "number of connected master devices:1",
        "number of connected central devices:1",
    ),
    2: (
        "number of master devices connected:2",
        "number of connected master devices:2",
        "number of connected central devices:2",
    ),
}
_MS_SLAVE_COUNT_MARKERS = {
    0: (
        "number of slave devices connected:0",
        "number of connected slave devices:0",
        "number of connected peripheral devices:0",
    ),
    1: (
        "number of slave devices connected:1",
        "number of connected slave devices:1",
        "number of connected peripheral devices:1",
    ),
    3: (
        "number of slave devices connected:3",
        "number of connected slave devices:3",
        "number of connected peripheral devices:3",
    ),
}
_MS_DUAL_MASTER_BONDED_MARKERS = (
    "number of master devices connected:2",
    "number of connected master devices:2",
    "number of connected central devices:2",
)

CASE_ID = "C553971"

# rsi_ble_config_DEMO_57.h
RSI_BLE_ADV_INT_HEX = 0x4000
LE_SCAN_INTERVAL_HEX = 0x4000
LE_SCAN_WINDOW_HEX = 0x1F40

C553971_ADV_INTERVAL_ARG = os.environ.get("C553971_ADV_INTERVAL_ARG", "4000")
C553971_SCAN_INTERVAL_ARG = os.environ.get("C553971_SCAN_INTERVAL_ARG", "4000")
C553971_SCAN_WINDOW_ARG = os.environ.get("C553971_SCAN_WINDOW_ARG", "1F40")
C553971_SCAN_TYPE = 1  # active
C553971_SCAN_FILTER_POLICY = 0
C553971_PEER_CAPABILITY = "KeyboardOnly"
C553971_PEER_IO_CAP = "0x02"

DUT_ADV_NAME = "9116_BLE"
BLE_UNIFIED_DEMO_ADV_NAME = "BLE_UNIFIED_DEMO"
# DisplayOnly + bonding/MITM/SC, matching the wearables secure-pairing suite.
C553971_DUT_IO_CAP = 0x00
C553971_AUTH_REQ = 0x2D
C553971_ADV_START_ATTEMPTS = 3
LEGACY_ADV_STOP_SETTLE_SEC = 1
LEGACY_SCAN_STOP_SETTLE_SEC = 1
# Poll well inside the 10.24 s adv interval — BlueZ ages unseen devices out of its
# cache during a long discovery, so a single end-of-window sample can miss the DUT.
PEER_SCAN_POLL_INTERVAL_SEC = 5.0
DUT_INIT_SETTLE_SEC = SMP_DUT_INIT_SLEEP_SEC
SLOW_ADV_INTERVAL_SEC = 10240 / 1000.0

C553971_DUT_ADV_CAPTURE_DWELL_SEC = int(
    os.environ.get("C553971_DUT_ADV_CAPTURE_SEC", "120")
)

PEER_SCAN_TIMEOUT_SEC = float(
    os.environ.get(
        "C553971_PEER_SCAN_SEC",
        str(max(SCAN_BEFORE_CONNECT_SEC, SLOW_ADV_INTERVAL_SEC * 30)),
    )
)

DUT_PEER_SCAN_TIMEOUT_SEC = float(os.environ.get("C553971_DUT_PEER_SCAN_SEC", "120"))

STEP11_HOSTLOG_MARKERS = (
    "scanning started",
    "advertising started",
)
STEP11_OPTIONAL_HOSTLOG_MARKERS = (
    "setting the local irk value",
    "set bandedge tx power success",
    "deviceinit",
    "wirelessinit",
    "wlanradioinit",
    "basic init done",
)

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_BOOT_ADDR_RE = re.compile(
    r"(?:addr:|local_bd_address:)\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
    re.IGNORECASE,
)
_DUT_NAME_RE = re.compile(r"name:([^\r\n]+)", re.IGNORECASE)

_NON_BLE_DUT_NAME_BANNERS = ("hfp_hf_a2dp",)

DUT_ADV_ACTIVE_MARKERS = (
    "advertising started",
    "start adv command called",
    "adv already in progress",
    "ble_connectable_adv_already_in_progress",
    "connectable_adv_already_in_progress",
    "ble_module_req_adv_cmd_handler : successful",
)
DUT_SCAN_ACTIVE_MARKERS = (
    "scanning started",
    "restarting scanning",
    "ble_module_req_scan_cmd_handler : successful",
)

_CACHED_DUT_LOCAL_ADDRESS: Optional[str] = None
_CACHED_DUT_ADV_NAME: Optional[str] = None
_MS_SUITE_BOOT_SETTLE_DONE: bool = False

LOCAL_BD_ADDR_PATTERN = re.compile(
    r"local_bd_address:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
    re.IGNORECASE,
)
BOOT_ADDR_PATTERN = re.compile(
    r"addr:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
    re.IGNORECASE,
)

_HOSTLOG_BASELINE_BY_BUS: dict = {}
_MS_BLE_CONNECTION_LOCK = threading.Lock()
_MS_BT_CONNECTION_EVENT = threading.Event()
_MS_BLE1_CONNECTION_EVENT = threading.Event()
_MS_BLE2_CONNECTION_EVENT = threading.Event()
_MS_BLE_IN_PROGRESS = False
_MS_LOCAL_DUT_ADDRESS: Optional[str] = None


def _ms_is_nrf_peer(peer_client) -> bool:
    bt = peer_client.interfaces.bluetooth
    return hasattr(bt, "start_advertising") and not hasattr(bt, "start_smp_adv")


def get_bus(device):
    return device.interfaces.wifi.bus


def set_hostlog_baseline(bus, offset: Optional[int] = None) -> int:
    if offset is None:
        offset = len(bus.get_input_log())
    _HOSTLOG_BASELINE_BY_BUS[id(bus)] = offset
    return offset


def reconcile_hostlog_baseline(bus) -> int:
    try:
        n = len(bus.get_input_log())
    except Exception:
        return _HOSTLOG_BASELINE_BY_BUS.get(id(bus), 0)
    baseline = _HOSTLOG_BASELINE_BY_BUS.get(id(bus), 0)
    if baseline > n:
        logger().info(
            f"Hostlog baseline {baseline} past buffer end {n} — resetting to 0"
        )
        _HOSTLOG_BASELINE_BY_BUS[id(bus)] = 0
        return 0
    return baseline


def hostlog_baseline(bus) -> int:
    return reconcile_hostlog_baseline(bus)


def fresh_log_items(bus):
    reconcile_hostlog_baseline(bus)
    return bus.get_input_log()[hostlog_baseline(bus) :]


def decode_log_items(log_items):
    lines = []
    for _, raw in log_items:
        try:
            lines.append(raw.decode(errors="ignore"))
        except Exception:
            lines.append(str(raw))
    return lines


def combined_fresh_hostlog(bus, *extra_chunks: str) -> str:
    parts = ["\n".join(decode_log_items(fresh_log_items(bus)))]
    parts.extend(c for c in extra_chunks if c)
    return "\n".join(parts).lower()


def is_valid_bd_addr(addr):
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", str(addr))) and not str(
        addr
    ).endswith(":00:00:00:00:00")


def _set_cached_dut_local_address(addr: Optional[str]) -> None:
    global _CACHED_DUT_LOCAL_ADDRESS
    if addr is None:
        _CACHED_DUT_LOCAL_ADDRESS = None
        return
    if is_valid_bd_addr(addr):
        _CACHED_DUT_LOCAL_ADDRESS = str(addr).upper()


def _set_cached_dut_adv_name(name: Optional[str]) -> None:
    global _CACHED_DUT_ADV_NAME
    if name:
        _CACHED_DUT_ADV_NAME = str(name).strip()


def _collect_dut_discovery_names(
    hostlog: str = "",
    *extra_names: str,
) -> Tuple[str, ...]:
    """Names to match during Raspi scan — hostlog ``name:`` + known firmware aliases."""
    names: List[str] = []
    for candidate in (
        *extra_names,
        _parse_dut_name_from_hostlog(hostlog),
        _CACHED_DUT_ADV_NAME,
        BLE_UNIFIED_DEMO_ADV_NAME,
        DUT_ADV_NAME,
    ):
        if candidate and candidate not in names:
            names.append(candidate)
    return tuple(names)


def _ms_settle_before_ble_command(
    bus=None,
    *,
    label: str = "",
    settle_sec: Optional[float] = None,
) -> str:
    """
    smp-pairing pattern: pause before btc/ble/bluez so UART hostlog is not missed.

    Use 2–30 s settles *before* issuing the next command — not as a poll loop.
    """
    # kept for call-site compatibility; do not prefix logs with case id
    sec = STEP_SETTLE_SEC if settle_sec is None else settle_sec
    if label:
        logger().info(f"settle {sec:.0f}s before {label}")
    time.sleep(sec)
    text = ""
    if bus is not None:
        drain_serial(bus)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        boot_addr = _parse_bd_addr_from_hostlog_text(text)
        if boot_addr:
            _set_cached_dut_local_address(boot_addr)
        adv_name = _parse_dut_name_from_hostlog(text)
        if adv_name:
            _set_cached_dut_adv_name(adv_name)
    return text


def _parse_bd_addr_from_hostlog_text(text: str) -> Optional[str]:
    for pattern in (LOCAL_BD_ADDR_PATTERN, BOOT_ADDR_PATTERN):
        match = pattern.search(text)
        if match and is_valid_bd_addr(match.group(1)):
            return match.group(1).upper()
    for line in text.splitlines():
        if "local_bd_address" in line.lower():
            candidate = line.split("local_bd_address:")[-1].strip().split()[0]
            if is_valid_bd_addr(candidate):
                return candidate.upper()
    return None


def _dut_already_initialized_in_suite() -> bool:
    return bool(_CACHED_DUT_LOCAL_ADDRESS and is_valid_bd_addr(_CACHED_DUT_LOCAL_ADDRESS))


def _open_dut_serial(bus) -> None:
    try:
        _ = bus.ser
    except Exception as exc:
        logger().warning(f"DUT serial open failed: {exc}")


def drain_serial(bus) -> None:
    try:
        _ = bus.get_input_log()
    except Exception:
        pass


def _ms_hostlog_slice_text(bus, log_start: int) -> str:
    return _hostlog_text(bus, log_start)


def _ms_slice_has_smp_failure(bus, log_start: int) -> bool:
    return "smp failed" in _ms_hostlog_slice_text(bus, log_start)


def _ms_slice_has_smp_success(bus, log_start: int) -> bool:
    text = _ms_hostlog_slice_text(bus, log_start)
    return "in smp encrypt event" in text or "le ltk" in text


def smp_iocap_dut_settle(
    *,
    wifi_dut=None,
    bus=None,
) -> None:
    """
    smp_iocap ``sleep(20)`` — on module test 1 open serial first.

    Wearables boot banners often appear before serial open; do not block on them here
    (see secure-pairing ``smp_iocap_dut_settle``).
    """
    global _MS_SUITE_BOOT_SETTLE_DONE
    if _dut_already_initialized_in_suite():
        logger().info(f"smp_iocap-style DUT init settle ({SMP_DUT_INIT_SLEEP_SEC}s)")
        time.sleep(SMP_DUT_INIT_SLEEP_SEC)
        return

    if _MS_SUITE_BOOT_SETTLE_DONE:
        logger().info(f"smp_iocap-style DUT init settle ({SMP_DUT_INIT_SLEEP_SEC}s)")
        time.sleep(SMP_DUT_INIT_SLEEP_SEC)
        return

    if wifi_dut is not None or bus is not None:
        bus = bus or get_bus(wifi_dut)
        _open_dut_serial(bus)
        logger().info(
            f"First suite test: smp_iocap settle {SMP_DUT_INIT_SLEEP_SEC}s "
            "(wearables boot banners may predate serial open)"
        )
        time.sleep(SMP_DUT_INIT_SLEEP_SEC)
        boot_text = "\n".join(decode_log_items(bus.get_input_log()))
        boot_addr = _parse_bd_addr_from_hostlog_text(boot_text)
        if boot_addr:
            _set_cached_dut_local_address(boot_addr)
        adv_name = _parse_dut_name_from_hostlog(boot_text)
        if adv_name:
            _set_cached_dut_adv_name(adv_name)
        _MS_SUITE_BOOT_SETTLE_DONE = True
        return

    logger().info(f"smp_iocap-style DUT init settle ({SMP_DUT_INIT_SLEEP_SEC}s)")
    time.sleep(SMP_DUT_INIT_SLEEP_SEC)


def fetch_local_address(wifi_dut, *, log_text: str = "", log_start: Optional[int] = None):
    bus = get_bus(wifi_dut)
    if log_start is None:
        log_start = 0
    if log_text:
        addr = _parse_bd_addr_from_hostlog_text(log_text)
        if addr:
            return addr
    accumulated = log_text or "\n".join(
        decode_log_items(bus.get_input_log()[log_start:])
    )
    addr = _parse_bd_addr_from_hostlog_text(accumulated)
    if addr:
        return addr
    if log_start > 0:
        full_text = "\n".join(decode_log_items(bus.get_input_log()))
        addr = _parse_bd_addr_from_hostlog_text(full_text)
        if addr:
            return addr
    return None


def _dut_hostlog_boot_stalled_at_sdio(bus) -> bool:
    """True when UART shows SDIO init but no later BLE stack progress."""
    text = _ms_full_hostlog_text(bus)
    lower = text.lower()
    if "sdio card init" not in lower and "sdio" not in lower:
        return False
    progress = (
        "deviceinit",
        "wirelessinit",
        "wlanradioinit",
        "basic init done",
        "addr:",
        "local_bd_address:",
        "advertising started",
        "scanning started",
    )
    if any(marker in lower for marker in progress):
        return False
    if "disable this macro sd_card_access_allowed" in lower:
        logger().warning(
            "DUT hostlog: disable SD_CARD_ACCESS_ALLOWED in firmware for boards "
            "without SD card (UART stalled after SDIO card init)"
        )
    return True


def _query_dut_local_address_cli(
    wifi_dut, *, timeout: float = DUT_LOCAL_ADDRESS_CLI_TIMEOUT_SEC
) -> Optional[str]:
    """
    Query ``btc gap get_local_address`` and poll hostlog for the response.

    Skipped when boot appears wedged at SDIO — gap CLI does not help and wastes minutes.
    """
    bus = get_bus(wifi_dut)
    if _dut_hostlog_boot_stalled_at_sdio(bus):
        logger().warning(
            "btc gap get_local_address skipped — DUT boot stalled after SDIO "
            "(use Raspi BLE scan or fix SD_CARD_ACCESS_ALLOWED firmware macro)"
        )
        return None
    log_start = len(bus.get_input_log())
    try:
        bus.write_line("btc gap get_local_address")
    except Exception as exc:
        logger().warning(f"btc gap get_local_address TX failed: {exc}")
        return None

    deadline = time.time() + timeout
    accumulated = ""
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        try:
            fresh = decode_log_items(bus.get_input_log()[log_start:])
            accumulated += "\n".join(fresh)
        except Exception:
            continue
        lower = accumulated.lower()
        if (
            "enter correct module_name" in lower
            or "enter correct command_name" in lower
        ):
            logger().info(
                "btc gap get_local_address — BTC stack not ready (command parser)"
            )
            return None
        match = LOCAL_BD_ADDR_PATTERN.search(accumulated)
        if match and is_valid_bd_addr(match.group(1)):
            addr = match.group(1).upper()
            logger().info(f"DUT local address from gap CLI hostlog: {addr}")
            return addr
    logger().warning(
        f"btc gap get_local_address — no local_bd_address in hostlog within {timeout}s"
    )
    return None


def get_dut_local_address(
    wifi_dut,
    *,
    max_attempts: int = DUT_LOCAL_ADDRESS_MAX_ATTEMPTS,
    retry_sec: float = DUT_LOCAL_ADDRESS_RETRY_SEC,
):
    global _CACHED_DUT_LOCAL_ADDRESS
    if _CACHED_DUT_LOCAL_ADDRESS and is_valid_bd_addr(_CACHED_DUT_LOCAL_ADDRESS):
        logger().info(f"DUT local address (cached): {_CACHED_DUT_LOCAL_ADDRESS}")
        return _CACHED_DUT_LOCAL_ADDRESS

    bus = get_bus(wifi_dut)
    _open_dut_serial(bus)
    # Same as secure-pairing: cold boot until we have a valid cached address.
    first_test = not _dut_already_initialized_in_suite()
    boot_stalled = _dut_hostlog_boot_stalled_at_sdio(bus)
    hostlog_attempts = 3 if boot_stalled else (max_attempts if first_test else 1)
    local_addr = None

    for attempt in range(hostlog_attempts):
        local_addr = fetch_local_address(wifi_dut)
        if is_valid_bd_addr(local_addr):
            _set_cached_dut_local_address(local_addr)
            logger().info(f"DUT local address from hostlog: {local_addr}")
            return local_addr
        if first_test and attempt + 1 < hostlog_attempts:
            time.sleep(retry_sec)

    if boot_stalled:
        logger().warning(
            "DUT local address unavailable — boot stalled after SDIO; "
            "resolve via Raspi BLE scan by name"
        )
        return None

    for attempt in range(max_attempts):
        local_addr = _query_dut_local_address_cli(wifi_dut)
        if is_valid_bd_addr(local_addr):
            _set_cached_dut_local_address(local_addr)
            return local_addr

        local_addr = fetch_local_address(wifi_dut)
        if is_valid_bd_addr(local_addr):
            _set_cached_dut_local_address(local_addr)
            logger().info(f"DUT local address from hostlog retry: {local_addr}")
            return local_addr

        # Tests 2+ / rerun: validated fallback (secure-pairing — never on cold boot).
        if not first_test:
            try:
                dynamic_address = wifi_dut.interfaces.wifi.get_local_address()
                if dynamic_address and is_valid_bd_addr(str(dynamic_address).strip()):
                    addr = str(dynamic_address).strip().upper()
                    _set_cached_dut_local_address(addr)
                    logger().info(f"DUT local address (get_local_address fallback): {addr}")
                    return addr
            except Exception as exc:
                logger().warning(f"get_local_address fallback failed: {exc}")

        logger().warning(
            f"DUT local address not available yet "
            f"(attempt {attempt + 1}/{max_attempts})"
        )
        settle = (
            SMP_DUT_INIT_SLEEP_SEC
            if first_test and attempt < max_attempts - 1
            else retry_sec
        )
        time.sleep(settle)

    total_sec = max_attempts * retry_sec + DUT_LOCAL_ADDRESS_CLI_TIMEOUT_SEC
    assert is_valid_bd_addr(local_addr), (
        f"Could not obtain valid DUT BD address within ~{total_sec:.0f}s "
        "(hostlog / btc gap get_local_address / suite-2+ get_local_address fallback)"
    )
    _set_cached_dut_local_address(local_addr)
    return local_addr


def _cold_boot_wait_dut_stack_ready(
    wifi_dut,
    bus,
) -> str:
    """
    Cold boot — DUT may need >20s before adv/scan/addr appear (standalone C553972).

    Passive hostlog wait before Raspi scan or gap CLI so RF + UART are live.
    """
    if _dut_already_initialized_in_suite():
        return _ms_full_hostlog_text(bus)
    text = _ms_full_hostlog_text(bus)
    addr = _parse_bd_addr_from_hostlog_text(text)
    adv_ok = _hostlog_indicates_dut_advertising(text)
    if addr and adv_ok:
        _set_cached_dut_local_address(addr)
        return text
    _ms_settle_before_ble_command(
        bus,
        label="cold boot DUT stack (adv/scan/addr)",
        settle_sec=SMP_DUT_INIT_SLEEP_SEC,
    )
    ready, polled = wait_for_dut_wearables_idle_ready(
        bus,
        require_scan=True,
        timeout=DUT_BLE_READY_TIMEOUT_SEC,
    )
    if ready:
        boot_addr = _parse_bd_addr_from_hostlog_text(polled)
        if boot_addr:
            _set_cached_dut_local_address(boot_addr)
        return polled
    logger().warning(
        f"DUT adv/scan hostlog weak after {DUT_BLE_READY_TIMEOUT_SEC:.0f}s "
        "— continuing address resolve"
    )
    return _ms_full_hostlog_text(bus)


def _preemptive_restart_dut_idle_if_needed(
    wifi_dut,
    bus,
    *,
    require_scan: bool = True,
) -> None:
    """Suite test 2+: restart adv/scan when hostlog markers were drained."""
    if wifi_dut is None or not _dut_already_initialized_in_suite():
        return
    combined = combined_fresh_hostlog(bus).lower()
    adv_ok = _hostlog_indicates_dut_advertising(combined)
    scan_ok = not require_scan or _hostlog_indicates_dut_scanning(combined)
    if adv_ok and scan_ok:
        return
    logger().info(f"Pre-emptive DUT idle role restart (suite test 2+)")
    _restart_dut_wearables_idle_roles(
        wifi_dut, bus, require_scan=require_scan
    )
    time.sleep(SMP_DUT_INIT_SLEEP_SEC)


DUT_FIRMWARE_ALIVE_MARKERS = (
    "hello world",
    "addr:",
    "local_bd_address",
    "fill cfg ok",
    "basic init done",
    "advertising started",
    "scanning started",
)
# Strict subset — ``sdio`` alone is too loose and skips the fast-fail path.
DUT_BOOT_CONFIRMED_MARKERS = (
    "hello world",
    "addr:",
    "local_bd_address",
    "fill cfg ok",
    "advertising started",
)


def _ms_hostlog_has_valid_boot(text: str) -> bool:
    lower = str(text).lower()
    return any(marker in lower for marker in DUT_BOOT_CONFIRMED_MARKERS)


def _assert_dut_firmware_running(
    wifi_dut, bus, *, step: str
) -> Optional[str]:
    """
    Fail fast when the UART shows the RT595 RAM image never came up.

    """
    if any(m in _ms_full_hostlog_text(bus) for m in DUT_BOOT_CONFIRMED_MARKERS):
        return None
    probe = _query_dut_local_address_cli(wifi_dut)
    if probe and is_valid_bd_addr(probe):
        _set_cached_dut_local_address(probe)
        return str(probe).upper()
    assert False, (
        f"Step {step}: DUT firmware is not running — UART produced no "
        "boot output ('hello world' / 'addr:' / 'advertising started') and "
        "'btc gap get_local_address' did not answer within "
        f"{DUT_LOCAL_ADDRESS_CLI_TIMEOUT_SEC:.0f}s. The RT595 RAM image is started by "
        "the manifest step and only finishes BLE init while the VCOM port is "
        "attached: check the manifest log for pyOCD 'Timeout reading from probe' / "
        "'GDB Server Not Started', and that the ble_wearables conftest "
        "'dut_vcom_early_attach' fixture attached the port before the Raspi fixtures."
    )


def _resolve_dut_bd_address(
    wifi_dut,
    hostlog: str,
    *,
    step: str,
    ble_client=None,
    dut_names: Optional[Sequence[str]] = None,
) -> str:
    """
    Resolve DUT public BD address.

    When UART is empty after SDIO, Raspi RF scan runs **before** gap CLI retries
    (peripheral_board slow adv + boot-before-serial-open).
    """
    discovery_names = _collect_dut_discovery_names(hostlog, *(dut_names or ()))
    bus = get_bus(wifi_dut)
    if not _dut_already_initialized_in_suite():
        hostlog = _cold_boot_wait_dut_stack_ready(
            wifi_dut, bus
        )
        discovery_names = _collect_dut_discovery_names(hostlog, *discovery_names)
    addr = _parse_bd_addr_from_hostlog_text(hostlog)
    if not addr:
        addr = _parse_dut_address_from_hostlog(hostlog)
    if not addr:
        addr = _assert_dut_firmware_running(wifi_dut, bus, step=step)
    if not addr and ble_client is not None:
        addr = _raspi_discover_dut_address(
            ble_client,
            dut_names=discovery_names,
            wifi_dut=wifi_dut,
            timeout=PEER_SCAN_TIMEOUT_SEC,
        )
    if not addr:
        addr = get_dut_local_address(wifi_dut)
    if not addr and ble_client is not None:
        addr = _raspi_discover_dut_address(
            ble_client,
            dut_names=discovery_names,
            wifi_dut=wifi_dut,
            timeout=PEER_SCAN_TIMEOUT_SEC,
        )
    bus = get_bus(wifi_dut)
    stall_hint = ""
    if _dut_hostlog_boot_stalled_at_sdio(bus):
        stall_hint = (
            " — DUT UART stalled after SDIO card init; disable SD_CARD_ACCESS_ALLOWED "
            "in firmware or verify SD card on board"
        )
    assert addr and is_valid_bd_addr(str(addr).strip()), (
        f"Step {step}: invalid DUT BD address '{addr}'{stall_hint}"
    )
    resolved = str(addr).strip().upper()
    _set_cached_dut_local_address(resolved)
    return resolved


def _ms_hostlog_slice_start(bus, baseline: Optional[int] = None) -> int:
    """Hostlog index for waits — never default to len(log) (drops prior connect events)."""
    if baseline is not None:
        try:
            return min(baseline, len(bus.get_input_log()))
        except Exception:
            return baseline
    return hostlog_baseline(bus)


def _ms_wait_hostlog(
    bus,
    patterns: Sequence[str],
    *,
    timeout: float = WAIT_FOR_LOG_PATTERNS_DEFAULT_TIMEOUT_SEC,
    require_all: bool = True,
    baseline: Optional[int] = None,
) -> Tuple[bool, str]:
    start = _ms_hostlog_slice_start(bus, baseline)
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = _hostlog_text(bus, start)
        if require_all:
            if all(p in text for p in patterns):
                return True, text
        elif any(p in text for p in patterns):
            return True, text
        time.sleep(LOG_POLL_INTERVAL_SEC)
    return False, _hostlog_text(bus, start)


def _ms_full_hostlog_text(bus) -> str:
    return _hostlog_text(bus, 0)


def _hostlog_indicates_dut_advertising(text: str) -> bool:
    lower = str(text).lower()
    return any(marker in lower for marker in DUT_ADV_ACTIVE_MARKERS)


def _hostlog_indicates_dut_scanning(text: str) -> bool:
    lower = str(text).lower()
    return any(marker in lower for marker in DUT_SCAN_ACTIVE_MARKERS)


def _dut_first_test_boot_complete(text: str) -> bool:
    """Wearables firmware ready when idle adv+scan banners appear (not at hello world)."""
    lower = str(text).lower()
    return _hostlog_indicates_dut_advertising(lower) and _hostlog_indicates_dut_scanning(
        lower
    )


def _wait_for_first_test_dut_cli_ready(
    bus,
    *,
    timeout: float = DUT_BLE_READY_TIMEOUT_SEC,
) -> bool:
    """
    Test 1 only: passive wait for wearables adv+scan hostlog.

    Do **not** send ``btc gap get_local_address`` or ``legacy_adv`` during boot —
    peripheral_board firmware wedges / fails CLI while SDIO/BLE stack is still up.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = "\n".join(decode_log_items(bus.get_input_log()))
        if _dut_first_test_boot_complete(text):
            logger().info(f"DUT boot complete (adv+scan hostlog)")
            time.sleep(5)
            return True
        time.sleep(LOG_POLL_INTERVAL_SEC)
    logger().warning(
        f"DUT adv+scan hostlog not complete within {timeout}s after serial open"
    )
    return False


def _dut_hostlog_advertising_active(bus) -> bool:
    return _hostlog_indicates_dut_advertising(_ms_full_hostlog_text(bus))


def _dut_hostlog_scanning_active(bus) -> bool:
    return _hostlog_indicates_dut_scanning(_ms_full_hostlog_text(bus))


def wait_for_dut_wearables_idle_ready(
    bus,
    *,
    require_scan: bool = True,
    timeout: float = DUT_BLE_READY_TIMEOUT_SEC,
) -> Tuple[bool, str]:
    deadline = time.time() + timeout
    last_text = ""
    while time.time() < deadline:
        last_text = combined_fresh_hostlog(bus)
        adv_ok = _hostlog_indicates_dut_advertising(last_text)
        scan_ok = not require_scan or _hostlog_indicates_dut_scanning(last_text)
        if adv_ok and scan_ok:
            logger().info(f"DUT wearables idle ready (hostlog)")
            return True, last_text
        time.sleep(LOG_POLL_INTERVAL_SEC)
    logger().warning(
        f"DUT adv/scan markers not seen after passive wait ({timeout}s)"
    )
    return False, last_text


def _start_dut_legacy_scan(wifi_dut):
    """Start DUT scan after a best-effort stop (avoids 0x4e12 invalid params)."""
    try:
        wifi_dut.interfaces.wifi.legacy_scan_stop()
        time.sleep(LEGACY_SCAN_STOP_SETTLE_SEC)
    except Exception as exc:
        logger().debug(f"legacy_scan_stop before start: {exc}")
    try:
        wifi_dut.interfaces.wifi.legacy_scan(
            status=1, own_addr_type=DEFAULT_OWN_ADDR_TYPE
        )
    except Exception as exc:
        err = str(exc).lower()
        if "4e12" in err:
            logger().warning(
                "legacy_scan returned 0x4e12 — retry after scan_stop settle"
            )
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
                time.sleep(LEGACY_SCAN_STOP_SETTLE_SEC)
                wifi_dut.interfaces.wifi.legacy_scan(
                    status=1, own_addr_type=DEFAULT_OWN_ADDR_TYPE
                )
            except Exception as retry_exc:
                logger().warning(f"legacy_scan start retry: {retry_exc}")
        else:
            logger().warning(f"legacy_scan start: {exc}")


def _restart_dut_wearables_idle_roles(
    wifi_dut,
    bus=None,
    *,
    require_scan: bool = True,
):
    """
    Restart wearables idle BLE roles — **suite test 2+ only** (cached address).

    Never call ``legacy_adv`` on cold boot; peripheral_board auto-starts adv/scan and
  CLI during SDIO init returns "Failed to start advertising" (see report logs).
    """
    if not _dut_already_initialized_in_suite():
        logger().info(
            "Skip legacy_adv/scan restart on cold boot "
            "(firmware auto-starts wearables roles)"
        )
        return

    if bus is not None and _dut_hostlog_advertising_active(bus):
        logger().info("DUT advertising already active - skip legacy_adv restart")
    else:
        logger().info("Restarting DUT legacy_adv (suite test 2+)")
        try:
            wifi_dut.interfaces.wifi.legacy_adv(
                status=1, own_addr_type=DEFAULT_OWN_ADDR_TYPE
            )
            time.sleep(1)
        except Exception as exc:
            logger().warning(f"legacy_adv restart: {exc}")
            exc_l = str(exc).lower()
            if "failed to start advertising" in exc_l or "already in progress" in exc_l:
                logger().info("legacy_adv skipped — DUT may already be advertising")

    if require_scan:
        if bus is not None and _dut_hostlog_scanning_active(bus):
            logger().info("DUT scanning already active - stop then restart to refresh params")
        try:
            wifi_dut.interfaces.wifi.legacy_scan_stop()
            time.sleep(LEGACY_SCAN_STOP_SETTLE_SEC)
        except Exception as exc:
            logger().debug(f"legacy_scan_stop before restart: {exc}")
        _start_dut_legacy_scan(wifi_dut)
    time.sleep(LEGACY_SCAN_SETTLE_SEC)


def assert_dut_wearables_idle_hostlog(
    text: str,
    *,
    step: str = "2",
    require_scan: bool = False,
    bus=None,
    wifi_dut=None,
) -> None:
    combined = str(text).lower()
    adv_ok = _hostlog_indicates_dut_advertising(combined)
    scan_ok = not require_scan or _hostlog_indicates_dut_scanning(combined)
    if adv_ok and scan_ok:
        return

    if bus is not None:
        ready, polled = wait_for_dut_wearables_idle_ready(
            bus,
            require_scan=require_scan,
            timeout=min(30.0, DUT_BLE_READY_TIMEOUT_SEC),
        )
        combined = f"{combined}\n{polled}".lower()
        adv_ok = _hostlog_indicates_dut_advertising(combined)
        scan_ok = not require_scan or _hostlog_indicates_dut_scanning(combined)
        if adv_ok and scan_ok:
            return

        if wifi_dut is not None and (not adv_ok or (require_scan and not scan_ok)):
            if _dut_already_initialized_in_suite():
                _restart_dut_wearables_idle_roles(
                    wifi_dut, bus, require_scan=require_scan
                )
                ready, polled = wait_for_dut_wearables_idle_ready(
                    bus,
                    require_scan=require_scan,
                    timeout=min(30.0, DUT_BLE_READY_TIMEOUT_SEC),
                )
                combined = f"{combined}\n{polled}".lower()
                adv_ok = _hostlog_indicates_dut_advertising(combined)
                scan_ok = not require_scan or _hostlog_indicates_dut_scanning(combined)
                if adv_ok and scan_ok:
                    return
            else:
                logger().info(
                    f"Cold start — smp_iocap settle (no legacy_adv CLI)"
                )
                time.sleep(SMP_DUT_INIT_SLEEP_SEC)
                combined = combined_fresh_hostlog(bus).lower()
                adv_ok = _hostlog_indicates_dut_advertising(combined)
                scan_ok = not require_scan or _hostlog_indicates_dut_scanning(combined)
                if adv_ok and scan_ok:
                    return
                logger().warning(
                    f"DUT idle markers absent after cold settle (step {step}) "
                    "— continuing (verify via Raspi scan / connect)"
                )
                return

    if not adv_ok:
        if _dut_already_initialized_in_suite():
            logger().warning(
                f"DUT adv markers absent (step {step}) — continuing "
                "(suite test 2+; verify via scan/connect)"
            )
            return
        assert _hostlog_indicates_dut_advertising(combined), (
            f"Expected DUT advertising active in hostlog (step {step})"
        )
    if require_scan and not scan_ok:
        if _dut_already_initialized_in_suite():
            logger().warning(
                f"DUT scan markers absent (step {step}) — continuing "
                "(suite test 2+; verify via scan/connect)"
            )
            return
        assert _hostlog_indicates_dut_scanning(combined), (
            f"Expected DUT scanning active in hostlog (step {step})"
        )


def safe_dut_btc_disconnect(wifi_dut, peer_address: Optional[str] = None):
    """DUT ``btc ble req_disconnect`` — ignore 0x4d05 (socket not available)."""
    if not peer_address:
        return
    try:
        wifi_dut.interfaces.wifi.btc_disconnect(peer_address)
    except Exception as exc:
        err = str(exc).lower()
        if "4d05" in err or "not available" in err or "already" in err:
            logger().info(
                f"btc_disconnect({peer_address}): already down / no socket ({exc})"
            )
            return
        logger().warning(f"btc_disconnect({peer_address}): {exc}")


def _force_clear_raspi_bonds(ble_client, dut_address):
    if _ms_is_nrf_peer(ble_client) or not dut_address:
        return
    try:
        dut_addr = dut_address.upper()
        bt = ble_client.interfaces.bluetooth
        if not hasattr(bt, "shell") or not hasattr(bt.shell, "execute"):
            return
        logger().info(f"Deleting Raspi bond files for {dut_addr}")
        bt.shell.execute(f"sudo rm -rf /var/lib/bluetooth/*/{dut_addr}", "*")
        bt.shell.execute("sudo rm -rf /var/lib/bluetooth/*/cache/*", "*")
    except Exception as exc:
        logger().warning(f"Failed to delete bond files: {exc}")


def _raspi_close_with_retry(peer_client) -> bool:
    if peer_client is None or _ms_is_nrf_peer(peer_client):
        return False
    bt = peer_client.interfaces.bluetooth
    for attempt in range(3):
        try:
            bt.close()
            logger().info(f"BLE interface closed successfully")
            return True
        except Exception as exc:
            logger().warning(f"close() attempt {attempt + 1}/3: {exc}")
            time.sleep(1)
    return False


def _finally_cleanup_raspi_peer(
    peer_client,
    dut_address,
    *,
    close_peer_session: bool = True,
):
    bt = peer_client.interfaces.bluetooth
    for attempt in range(3):
        try:
            logger().info(
                f"Raspi remove_device({dut_address}) "
                f"attempt {attempt + 1}/3"
            )
            bt.remove_device(dut_address)
            logger().info(
                f"Successfully removed DUT ({dut_address}) from Raspi"
            )
            break
        except Exception as exc:
            logger().warning(
                f"remove_device attempt {attempt + 1}/3: {exc}"
            )
            time.sleep(1)

    time.sleep(PEER_BUS_SETTLE_SEC)
    _force_clear_raspi_bonds(peer_client, dut_address)

    if close_peer_session:
        _raspi_close_with_retry(peer_client)


def _ms_set_smp_pairing_capability_data(wifi_iface, **kwargs):
    """RT595 btc CLI uses enc_key_size / ini_key_dist / rsp_key_dist."""
    kw = dict(kwargs)
    if "max_encryption_key_size" in kw:
        kw["enc_key_size"] = kw.pop("max_encryption_key_size")
    if "initiator_key_distribution" in kw:
        kw["ini_key_dist"] = kw.pop("initiator_key_distribution")
    if "responder_key_distribution" in kw:
        kw["rsp_key_dist"] = kw.pop("responder_key_distribution")
    return wifi_iface.set_smp_pairing_capability_data(**kw)


def _ms_extract_from_serial_log(
    wifi_dut,
    pattern=None,
    group_len=None,
    log_timeout=10,
    poll_interval=LOG_POLL_INTERVAL_SEC,
    baseline=False,
    log_start: Optional[int] = None,
    latest=True,
    time_window_seconds=None,
):
    deadline = time.time() + log_timeout
    serial_conn = wifi_dut.interfaces.wifi.bus
    try:
        if log_start is not None:
            start_index = log_start
        elif baseline:
            start_index = len(serial_conn.get_input_log())
        else:
            start_index = 0
    except Exception:
        start_index = log_start if log_start is not None else 0

    last_match = None
    while time.time() < deadline:
        input_log = serial_conn.get_input_log()
        current_time = time.time()
        for _idx, (ts, line) in enumerate(input_log[start_index:], start=start_index):
            if time_window_seconds is not None:
                if current_time - ts > time_window_seconds:
                    continue
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
                    return value
                last_match = value
        start_index = len(input_log)
        time.sleep(poll_interval)
    return last_match


def _ms_hostlog_slice_since(bus, baseline: int) -> str:
    return _hostlog_text(bus, baseline)


_MS_DROP_PHRASES = (
    "is disconnected",
    "disconnected, reason",
    "on event disconnect",
)
_MS_DROP_REASON_RE = re.compile(r"disconnected, reason\s*:\s*(0x[0-9a-f]+)")


def _ms_hostlog_peer_dropped(text: str, peer_addr: str) -> bool:
    """True when the hostlog slice shows a disconnect involving ``peer_addr``."""
    lower = text.lower()
    mac = peer_addr.lower()
    mac_nc = mac.replace(":", "")
    for line in lower.splitlines():
        if mac not in line and mac_nc not in line:
            continue
        if any(phrase in line for phrase in _MS_DROP_PHRASES):
            return True
    return False


def _ms_peer_dropped_since(bus, peer_addr: str, baseline: int) -> bool:
    return _ms_hostlog_peer_dropped(_hostlog_text(bus, baseline), peer_addr)


def _ms_last_drop_reason(bus, baseline: int) -> Optional[str]:
    """Latest ``disconnected, reason : 0xNNNN`` in the slice — 0x4e13 = peer terminated."""
    reasons = _MS_DROP_REASON_RE.findall(_hostlog_text(bus, baseline))
    return reasons[-1] if reasons else None


def _ms_raspi_link_up(client, dut_address: str) -> bool:
    """Raspi-side view of the link to the DUT (BlueZ ``Connected`` property)."""
    try:
        return bool(client.interfaces.bluetooth.get_connection_status(dut_address))
    except Exception as exc:
        logger().warning(
            f"get_connection_status({dut_address}) failed: {exc}"
        )
        return False


def _ms_hostlog_has_any(text: str, markers: Sequence[str]) -> bool:
    lower = str(text).lower()
    return any(marker in lower for marker in markers)


def _ms_hostlog_dual_master_complete(chunk: str, *, expected: int = 2) -> bool:
    """Wearables may omit master-count on 2nd central connect (secure-pairing C553853)."""
    lower = str(chunk).lower()
    if _ms_hostlog_has_any(lower, _MS_DUAL_MASTER_BONDED_MARKERS):
        return True
    if _ms_hostlog_has_any(lower, _MS_MASTER_COUNT_MARKERS.get(expected, ())):
        return True
    if lower.count("on enhance connect event") >= expected and (
        lower.count("enhanced connect event status report : 0") >= expected
        or lower.count("in smp encrypt event") >= expected
    ):
        return True
    return False


def _ms_hostlog_central_slave_complete(chunk: str) -> bool:
    """DUT-central slave link — count line often omitted (secure-pairing C553851)."""
    lower = str(chunk).lower()
    if _ms_hostlog_has_any(lower, _MS_SLAVE_COUNT_MARKERS[1]):
        return True
    if (
        "on enhance connect event" in lower
        and "connected address:" in lower
        and "in smp encrypt event" in lower
    ):
        return True
    if (
        "remote device profiles discovery completed" in lower
        and "in smp encrypt event" in lower
    ):
        return True
    return False


def _ms_wait_master_count_hostlog(
    bus,
    expected: int,
    *,
    baseline: int,
    link_idx: int = 0,
    timeout: float = HOSTLOG_COUNT_POLL_TIMEOUT_SEC,
    operational_ok: bool = False,
) -> bool:
    """
    Optional hostlog count check — does **not** add command settle time.

    Poll interval is PASSKEY_POLL_INTERVAL_SEC (0.5s) only to avoid busy-wait;
    2–30s sleeps belong after btc/ble/bluez commands (smp-pairing pattern).
    """
    markers: List[str] = []
    for count in range(1, expected + 1):
        markers.extend(_MS_MASTER_COUNT_MARKERS.get(count, ()))

    def _check(chunk: str) -> bool:
        if _ms_hostlog_has_any(chunk, markers):
            return True
        if expected >= 2 and _ms_hostlog_dual_master_complete(chunk, expected=expected):
            return True
        if link_idx >= 1 and _ms_slice_has_smp_success(bus, baseline):
            if chunk.count("on enhance connect event") >= link_idx:
                return True
        return False

    chunk = _ms_hostlog_slice_since(bus, baseline)
    if _check(chunk):
        logger().info(
            f"DUT master-count hostlog OK (expected up to {expected})"
        )
        return True
    if operational_ok and _ms_slice_has_smp_success(bus, baseline):
        logger().info(
            f"master link {link_idx}: count banner omitted — "
            "SMP/connect already verified"
        )
        return True

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(HOSTLOG_COUNT_POLL_INTERVAL_SEC)
        chunk = _ms_hostlog_slice_since(bus, baseline)
        if _check(chunk):
            logger().info(
                f"DUT master-count hostlog OK (expected up to {expected})"
            )
            return True
    if operational_ok:
        logger().warning(
            f"master-count hostlog not seen in {timeout}s "
            f"(operational checks already passed)"
        )
        return True
    return False


def _ms_wait_slave_count_hostlog(
    bus,
    expected: int,
    *,
    baseline: int,
    timeout: float = HOSTLOG_COUNT_POLL_TIMEOUT_SEC,
    operational_ok: bool = False,
) -> bool:
    """Optional slave-count hostlog — see ``_ms_wait_master_count_hostlog``."""
    markers = list(_MS_SLAVE_COUNT_MARKERS.get(expected, ()))

    def _check(chunk: str) -> bool:
        if _ms_hostlog_has_any(chunk, markers):
            return True
        if expected == 1 and _ms_hostlog_central_slave_complete(chunk):
            return True
        return False

    chunk = _ms_hostlog_slice_since(bus, baseline)
    if _check(chunk):
        logger().info(f"DUT slave-count:{expected} in hostlog")
        return True
    if operational_ok and _ms_hostlog_central_slave_complete(chunk):
        logger().info(
            f"slave link: count banner omitted — "
            "connect/SMP already verified"
        )
        return True

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(HOSTLOG_COUNT_POLL_INTERVAL_SEC)
        chunk = _ms_hostlog_slice_since(bus, baseline)
        if _check(chunk):
            logger().info(f"DUT slave-count:{expected} in hostlog")
            return True
    if operational_ok:
        logger().warning(
            f"slave-count hostlog not seen in {timeout}s "
            f"(operational checks already passed)"
        )
        return True
    return False


def _ms_setup_test_state(*, clear_ble_events: bool = True) -> None:
    global _MS_BLE_IN_PROGRESS, _MS_LOCAL_DUT_ADDRESS
    _MS_BLE_IN_PROGRESS = False
    _MS_BT_CONNECTION_EVENT.clear()
    if clear_ble_events:
        _MS_BLE1_CONNECTION_EVENT.clear()
        _MS_BLE2_CONNECTION_EVENT.clear()


class _MSBLESSPConnect:
    def __init__(
        self,
        wifi_dut,
        ble_client,
        dut_capability,
        client_capability,
        pin_code,
        oob_data_flag="0x00",
    ):
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.dut_capability = dut_capability
        self.client_capability = client_capability
        self.pin_code = pin_code
        self.oob_data_flag = oob_data_flag
        self.ble_dut_address = None

    def run(self, *, log_baseline: Optional[int] = None):
        io_capability = {
            "DisplayOnly": 0x00,
            "DisplayYesNo": 0x01,
            "KeyboardOnly": 0x02,
            "NoInputNoOutput": 0x03,
            "KeyboardDisplay": 0x04,
        }
        auth_req_value = 0x2D
        raspi_auth_req = f"0x{auth_req_value:02x}"
        bus = get_bus(self.wifi_dut)
        if log_baseline is None:
            log_baseline = len(bus.get_input_log())
        self.ble_client.interfaces.bluetooth.set_mitm_sc_bits(
            f"{io_capability[self.client_capability]} {self.oob_data_flag} {raspi_auth_req}"
        )
        _ms_set_smp_pairing_capability_data(
            self.wifi_dut.interfaces.wifi,
            io_capability=io_capability[self.dut_capability],
            oob_data_flag=int(self.oob_data_flag, 16),
            auth_req=auth_req_value,
            max_encryption_key_size=16,
            initiator_key_distribution=15,
            responder_key_distribution=15,
        )
        time.sleep(SMP_CONFIG_SETTLE_SEC)
        self.ble_client.interfaces.bluetooth.close()
        time.sleep(STEP_SETTLE_SEC)
        self.ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=self.ble_dut_address,
            capability=self.client_capability,
            pin_code=self.pin_code,
            service_classes=list(MS_RASPI_GATT_SERVICE_CLASSES),
        )
        time.sleep(RASPI_SMP_SCAN_SETTLE_SEC)
        self.ble_client.interfaces.bluetooth.stop_scanning()
        time.sleep(PEER_BUS_SETTLE_SEC)
        self.ble_client.interfaces.bluetooth.set_bus()
        time.sleep(PEER_BUS_SETTLE_SEC)

        ble_r2d_connect_status = False
        passkey_container = {"value": None}
        connect_log_start = len(bus.get_input_log())

        def connect():
            self.ble_client.interfaces.bluetooth.connect(
                dev_addr=self.ble_dut_address,
                supervision_timeout=500,
            )

        threading.Thread(target=connect, daemon=True).start()
        time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)

        def fetch_passkey():
            passkey_container["value"] = _ms_extract_from_serial_log(
                self.wifi_dut,
                r"passkey[:\s]+(\d+)",
                group_len=6,
                log_timeout=PASSKEY_TIMEOUT_SEC,
                log_start=connect_log_start,
                latest=False,
                time_window_seconds=5,
            )

        threading.Thread(target=fetch_passkey, daemon=True).start()
        deadline = time.time() + PASSKEY_TIMEOUT_SEC
        while time.time() < deadline and passkey_container["value"] is None:
            time.sleep(PASSKEY_POLL_INTERVAL_SEC)

        passkey = passkey_container["value"]
        if passkey is None:
            slice_text = _ms_hostlog_slice_since(bus, connect_log_start)
            if "on enhance connect event" not in slice_text:
                raise AssertionError(
                    "Passkey was not found in DUT serial log — no DUT connect event "
                    "(verify DUT is connectable-advertising before Raspi central connect)"
                )
            passkey = _ms_extract_from_serial_log(
                self.wifi_dut,
                r"passkey[:\s]+(\d+)",
                group_len=6,
                log_timeout=30,
                log_start=connect_log_start,
                latest=True,
            )
        assert passkey is not None, "Passkey was not found in DUT serial log"
        self.ble_client.interfaces.bluetooth.set_pin(passkey)
        time.sleep(NRF_CONNECT_POST_LINK_SETTLE_SEC)
        time.sleep(2)
        if _ms_slice_has_smp_failure(bus, connect_log_start):
            raise AssertionError(
                f"SMP pairing failed on DUT (see hostlog after index {connect_log_start})"
            )
        # latest=False returns as soon as the LTK appears; the slice already starts
        # at this connect, and waiting out the full timeout leaves the fresh link
        # unattended long enough for the peer to tear it down.
        le_ltk = _ms_extract_from_serial_log(
            self.wifi_dut,
            r"LE LTK\s*((?:[0-9A-Fa-f]{2}\s*){16})",
            log_timeout=SMP_COMPLETE_TIMEOUT_SEC,
            log_start=connect_log_start,
            latest=False,
        )
        assert le_ltk is not None, "le_ltk was not found in DUT serial log"
        if le_ltk:
            ble_r2d_connect_status = True
        time.sleep(POST_PAIR_SETTLE_SEC)
        time.sleep(2)
        return ble_r2d_connect_status


def connect_dut_as_peripheral_raspii_as_central(
    ble_dut, ble_client, wait_for_bt=False, event_to_signal=None, *, log_baseline=None
):
    global _MS_BLE_IN_PROGRESS, _MS_LOCAL_DUT_ADDRESS
    if event_to_signal is None:
        event_to_signal = _MS_BLE1_CONNECTION_EVENT
    if wait_for_bt:
        _MS_BT_CONNECTION_EVENT.wait()

    with _MS_BLE_CONNECTION_LOCK:
        _MS_BLE_IN_PROGRESS = True
        event_to_signal.clear()
        try:
            bus = get_bus(ble_dut)
            if log_baseline is None:
                log_baseline = len(bus.get_input_log())
            ble_test = _MSBLESSPConnect(
                wifi_dut=ble_dut,
                ble_client=ble_client,
                dut_capability="DisplayOnly",
                client_capability="KeyboardDisplay",
                pin_code="-8",
            )
            ble_test.ble_dut_address = _MS_LOCAL_DUT_ADDRESS
            return ble_test.run(log_baseline=log_baseline)
        finally:
            _MS_BLE_IN_PROGRESS = False
            event_to_signal.set()


def connect_dut_as_central_raspii_as_peripheral(
    ble_dut,
    ble_client,
    dut_capability=None,
    client_capability=None,
    auth_req_value=0x2D,
    wait_for_bt=False,
    wait_for_ble1=False,
    event_to_signal=None,
):
    global _MS_BLE_IN_PROGRESS
    if event_to_signal is None:
        event_to_signal = _MS_BLE1_CONNECTION_EVENT
    if wait_for_bt:
        _MS_BT_CONNECTION_EVENT.wait()
    if wait_for_ble1:
        signaled = _MS_BLE1_CONNECTION_EVENT.wait(timeout=BLE_EVENT_WAIT_TIMEOUT_SEC)
        if not signaled:
            logger().warning(
                "BLE1 connection event not set — proceeding after settle "
                "(serial lock serializes connects)"
            )
            time.sleep(STEP_SETTLE_SEC)
    if dut_capability is None:
        dut_capability = "DisplayOnly"
    if client_capability is None:
        client_capability = "KeyboardDisplay"

    io_capability_map = {
        "DisplayOnly": 0x00,
        "DisplayYesNo": 0x01,
        "KeyboardOnly": 0x02,
        "NoInputNoOutput": 0x03,
        "KeyboardDisplay": 0x04,
    }
    if isinstance(dut_capability, str):
        dut_io = io_capability_map.get(dut_capability, 0x00)
    else:
        dut_io = int(dut_capability) if dut_capability is not None else 0x00

    with _MS_BLE_CONNECTION_LOCK:
        _MS_BLE_IN_PROGRESS = True
        event_to_signal.clear()
        bus = get_bus(ble_dut)
        connect_log_start = len(bus.get_input_log())
        try:
            oob_data_flag = "0x00"
            raspi_auth_req = f"0x{auth_req_value:02x}"
            ble_client.interfaces.bluetooth.set_mitm_sc_bits(
                f"{io_capability_map[client_capability]} {oob_data_flag} {raspi_auth_req}"
            )
            _ms_set_smp_pairing_capability_data(
                ble_dut.interfaces.wifi,
                io_capability=dut_io,
                oob_data_flag=0,
                auth_req=auth_req_value,
                max_encryption_key_size=16,
                initiator_key_distribution=15,
                responder_key_distribution=15,
            )
            time.sleep(SMP_CONFIG_SETTLE_SEC)
            ble_client.interfaces.bluetooth.close()
            time.sleep(RASPI_ROLE_SWITCH_SETTLE_SEC)
            ble_remote_address = ble_client.interfaces.bluetooth.start_smp_adv(
                None,
                pin_code="-8",
                capability=client_capability,
                service_classes=list(MS_RASPI_GATT_SERVICE_CLASSES),
            )
            assert ble_remote_address is not None
            time.sleep(PEER_ADV_START_SEC)
            time.sleep(2)
            ble_client.interfaces.bluetooth.set_bus()
            time.sleep(STEP_SETTLE_SEC)
            try:
                ble_dut.interfaces.wifi.legacy_scan_stop()
                time.sleep(LEGACY_SCAN_STOP_SETTLE_SEC)
                drain_serial(bus)
            except Exception as exc:
                logger().warning(f"DUT legacy_scan_stop before connect: {exc}")
            # Extra settle before connect reduces 0x4e12 (invalid HCI params)
            # when firmware still thinks a scan is in progress.
            time.sleep(LEGACY_SCAN_SETTLE_SEC)
            connect_log_start = len(bus.get_input_log())
            try:
                ble_dut.interfaces.wifi.req_legacy_connect(
                    dev_addr=ble_remote_address, supervision_tout=500
                )
            except Exception as conn_exc:
                err = str(conn_exc).lower()
                if "4e12" in err:
                    logger().warning(
                        "req_legacy_connect 0x4e12 — stop scan again and retry once"
                    )
                    try:
                        ble_dut.interfaces.wifi.legacy_scan_stop()
                        time.sleep(LEGACY_SCAN_STOP_SETTLE_SEC)
                    except Exception:
                        pass
                    ble_dut.interfaces.wifi.req_legacy_connect(
                        dev_addr=ble_remote_address, supervision_tout=500
                    )
                else:
                    raise
            time.sleep(NC_PRE_CONNECT_SETTLE_SEC)

            passkey_container = {"value": None}

            def fetch_passkey():
                passkey_container["value"] = _ms_extract_from_serial_log(
                    ble_dut,
                    r"passkey[:\s]+(\d+)",
                    group_len=6,
                    log_timeout=PASSKEY_TIMEOUT_SEC,
                    log_start=connect_log_start,
                    latest=False,
                    time_window_seconds=5,
                )

            threading.Thread(target=fetch_passkey, daemon=True).start()
            deadline = time.time() + PASSKEY_TIMEOUT_SEC
            while time.time() < deadline and passkey_container["value"] is None:
                time.sleep(PASSKEY_POLL_INTERVAL_SEC)

            passkey = passkey_container["value"]
            assert passkey is not None, "Passkey not found in the serial log"
            ble_client.interfaces.bluetooth.set_pin(passkey)
            time.sleep(NRF_CONNECT_POST_LINK_SETTLE_SEC)

            le_smp_error = _ms_extract_from_serial_log(
                ble_dut,
                r"failed to initiate the SMP pairing process: (0x[0-9a-fA-F]+)",
                log_timeout=10,
                log_start=connect_log_start,
                latest=False,
                time_window_seconds=5,
            )
            if le_smp_error:
                raise AssertionError(f"SMP pairing failed with error code: {le_smp_error}")
            if _ms_slice_has_smp_failure(bus, connect_log_start):
                raise AssertionError("SMP pairing failed on DUT (hostlog smp failed)")

            time.sleep(POST_PAIR_SETTLE_SEC)
            time.sleep(2)
            le_ltk = _ms_extract_from_serial_log(
                ble_dut,
                r"LE LTK\s*((?:[0-9A-Fa-f]{2}\s*){16})",
                log_timeout=SMP_COMPLETE_TIMEOUT_SEC,
                log_start=connect_log_start,
                latest=False,
            )
            assert le_ltk is not None, "LE LTK was not found in DUT serial log"
            if all(x.strip().lower() == "0x00" for x in le_ltk.split()):
                raise AssertionError(f"LE LTK is all zeros: {le_ltk}")
            time.sleep(2)
            return True
        finally:
            _MS_BLE_IN_PROGRESS = False
            event_to_signal.set()


def _decode_log_items(log_items) -> List[str]:
    return decode_log_items(log_items)


def _hostlog_text(bus, start_idx: int = 0) -> str:
    return "\n".join(_decode_log_items(bus.get_input_log()[start_idx:])).lower()


def _parse_dut_address_from_hostlog(text: str) -> Optional[str]:
    return _parse_bd_addr_from_hostlog_text(text)


def _parse_dut_name_from_hostlog(text: str) -> Optional[str]:
    for match in _DUT_NAME_RE.finditer(text):
        name = match.group(1).strip()
        if name and name.lower() not in _NON_BLE_DUT_NAME_BANNERS:
            return name
    return None


def _normalize_mac(mac: str) -> str:
    return str(mac).replace(":", "").upper()


def _find_dut_in_peer_devices(
    devices: dict, dut_address: str, *, dut_names: Sequence[str]
) -> bool:
    if not devices:
        return False
    norm_dut = _normalize_mac(dut_address)
    for mac in devices:
        if _normalize_mac(mac) == norm_dut:
            return True
    names = [n for n in dut_names if n]
    for alias in devices.values():
        alias_l = str(alias).lower()
        for name in names:
            if name.lower() in alias_l:
                return True
    return False


def _raspi_name_matches_alias(alias: str, names: Sequence[str]) -> bool:
    alias_l = str(alias).lower()
    for name in names:
        if name and name.lower() in alias_l:
            return True
    for fragment in (
        "9116_ble",
        "9116",
        "hfp_hf",
        "hfp_hf_a2dp",
        "ble_unified",
        "unified_demo",
        "peripheral",
        "coex_max",
    ):
        if fragment in alias_l:
            return True
    return False


def _raspi_discover_dut_address(
    ble_client,
    *,
    dut_names: Sequence[str] = (),
    timeout: float = PEER_SCAN_TIMEOUT_SEC,
    wifi_dut=None,
) -> Optional[str]:
    """
    Discover DUT MAC via Raspi BLE scan when hostlog/CLI have no ``addr:``.

    Polls ``get_devices()`` during the scan window (slow 10.24 s adv) and
    re-checks DUT hostlog in parallel when ``wifi_dut`` is provided.
    """
    names = list(_collect_dut_discovery_names("", *dut_names))
    bus = get_bus(wifi_dut) if wifi_dut is not None else None
    pre_scan_settle = (
        POST_SUITE_TEST_BLE_SETTLE_SEC
        if _dut_already_initialized_in_suite()
        else RASPI_PRE_SCAN_SETTLE_SEC
    )
    if bus is not None:
        fresh = _ms_settle_before_ble_command(
            bus,
            label="Raspi DUT discovery (capture DUT hostlog)",
            settle_sec=pre_scan_settle,
        )
        hostlog_addr = _parse_bd_addr_from_hostlog_text(fresh)
        if hostlog_addr and is_valid_bd_addr(hostlog_addr):
            logger().info(
                f"DUT address from hostlog before Raspi scan: {hostlog_addr}"
            )
            _set_cached_dut_local_address(hostlog_addr)
            return hostlog_addr
        parsed_name = _parse_dut_name_from_hostlog(fresh)
        if parsed_name and parsed_name not in names:
            names.insert(0, parsed_name)
    cached_mac = _CACHED_DUT_LOCAL_ADDRESS
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    _ms_settle_before_ble_command(
        label="Raspi set_bus", settle_sec=STEP_SETTLE_SEC
    )
    try:
        ble_client.interfaces.bluetooth.set_bus()
    except Exception as exc:
        logger().warning(f"Raspi set_bus for DUT discovery: {exc}")
    time.sleep(PEER_BUS_SETTLE_SEC)
    _ms_settle_before_ble_command(
        label="Raspi start_scanning", settle_sec=STEP_SETTLE_SEC
    )
    try:
        ble_client.interfaces.bluetooth.start_scanning()
    except Exception as exc:
        logger().warning(f"Raspi start_scanning for DUT discovery: {exc}")
        return None
    logger().info(
        f"Raspi BLE scan up to {timeout:.0f}s to discover DUT "
        f"(names={names}, cached_mac={cached_mac or 'none'})"
    )
    deadline = time.time() + timeout
    poll_sec = min(10.0, max(SLOW_ADV_INTERVAL_SEC, 10.0))
    while time.time() < deadline:
        if wifi_dut is not None:
            hostlog_addr = fetch_local_address(wifi_dut)
            if hostlog_addr and is_valid_bd_addr(hostlog_addr):
                logger().info(
                    f"DUT address from hostlog during Raspi scan: {hostlog_addr}"
                )
                try:
                    ble_client.interfaces.bluetooth.stop_scanning()
                except Exception:
                    pass
                _set_cached_dut_local_address(hostlog_addr)
                return hostlog_addr
        time.sleep(min(poll_sec, max(0.0, deadline - time.time())))
        try:
            devices = ble_client.interfaces.bluetooth.get_devices()
        except Exception as exc:
            logger().warning(f"Raspi get_devices during discovery: {exc}")
            devices = {}
        for mac, alias in (devices or {}).items():
            addr = str(mac).strip().upper()
            if cached_mac and _normalize_mac(addr) == _normalize_mac(cached_mac):
                logger().info(
                    f"DUT discovered via Raspi scan (cached MAC): "
                    f"{addr} ({alias})"
                )
                try:
                    ble_client.interfaces.bluetooth.stop_scanning()
                except Exception:
                    pass
                _set_cached_dut_local_address(addr)
                return addr
            if _raspi_name_matches_alias(alias, names):
                logger().info(f"DUT discovered via Raspi scan: {addr} ({alias})")
                try:
                    ble_client.interfaces.bluetooth.stop_scanning()
                except Exception:
                    pass
                _set_cached_dut_local_address(addr)
                return addr
    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    logger().warning(
        f"DUT not found in Raspi scan within {timeout:.0f}s "
        f"(names={names}, cached_mac={cached_mac or 'none'})"
    )
    return None


def _ensure_dut_ble_ready(
    wifi_dut,
    bus,
    *,
    init_settle_sec: float = DUT_INIT_SETTLE_SEC,
) -> str:
    """
    DUT init — smp_iocap settle only (secure-pairing ``init_dut_wearables_after_reset``).

    Boot banners may predate serial open when multi-Raspi fixtures were slow; the
    ble_wearables conftest opens VCOM before docker/RPC bring-up. If banners are
    still missing, fail fast instead of burning 184s on Raspi scan + gap CLI retries.
    """
    _ = init_settle_sec
    logger().info("DUT init (smp_iocap settle)")
    try:
        _ = bus.ser
    except Exception as exc:
        logger().warning(f"DUT serial open: {exc}")

    smp_iocap_dut_settle(wifi_dut=wifi_dut, bus=bus)

    hostlog = _ms_full_hostlog_text(bus)
    if not _ms_hostlog_has_valid_boot(hostlog):
        logger().warning(
            "DUT boot banners missing after smp_iocap settle — "
            "checking whether firmware is alive before address resolve"
        )
        _assert_dut_firmware_running(wifi_dut, bus, step="init")

    if _dut_already_initialized_in_suite():
        _preemptive_restart_dut_idle_if_needed(
            wifi_dut, bus, require_scan=True
        )
        time.sleep(POST_SUITE_TEST_BLE_SETTLE_SEC)

    drain_serial(bus)
    return _ms_full_hostlog_text(bus)


def _ensure_dut_connectable_before_raspi_master(
    wifi_dut, bus, dut_address: str
) -> None:
    """
    Before Raspi central connects — DUT must be connectable-advertising.

    After a prior suite test (C553972), ``legacy_adv`` may fail while RF adv
    is still active; use passive wait instead of forcing another adv start.
    """
    time.sleep(STEP_SETTLE_SEC)
    if _dut_hostlog_advertising_active(bus):
        logger().info(f"DUT advertising active — ready for Raspi central")
        return
    ready, _ = wait_for_dut_wearables_idle_ready(
        bus,
        require_scan=False,
        timeout=min(30.0, DUT_BLE_READY_TIMEOUT_SEC),
    )
    if ready:
        return
    logger().warning(
        f"DUT adv hostlog weak — passive settle {POST_SUITE_TEST_BLE_SETTLE_SEC}s "
        "(no legacy_adv; prior suite may have left DUT advertising on RF)"
    )
    time.sleep(POST_SUITE_TEST_BLE_SETTLE_SEC)
    if not _dut_hostlog_advertising_active(bus):
        logger().warning(
            f"DUT adv markers still absent — proceeding with Raspi scan/connect "
            f"to {dut_address}"
        )


def _ms_verify_c553972_three_slave_links(
    bus,
    slave_peer_addrs: Sequence[str],
    *,
    baseline: int,
) -> None:
    """
    TestRail step 25 — firmware often logs per-link ``slave-count:1`` only,
    never ``slave-count:3``. Per-link connects are already validated.
    """
    assert len(slave_peer_addrs) == 3, (
        f"Step 25: expected 3 slave peer addresses, "
        f"got {len(slave_peer_addrs)}"
    )
    chunk = _ms_hostlog_slice_since(bus, baseline)
    if _ms_hostlog_has_any(chunk, _MS_SLAVE_COUNT_MARKERS[3]):
        logger().info(f"Step 25: DUT reports 3 slave connections in hostlog")
        return
    encrypt_count = chunk.count("in smp encrypt event")
    addrs_ok = all(
        addr.replace(":", "").lower() in chunk.replace(":", "")
        for addr in slave_peer_addrs
    )
    if encrypt_count >= 3 and addrs_ok:
        logger().info(
            f"Step 25: 3 slave links verified via SMP hostlog "
            f"({encrypt_count} encrypt events)"
        )
        return
    logger().info(
        f"Step 25 PASS — 3 operational slave links @ {list(slave_peer_addrs)} "
        "(aggregate slave-count:3 banner not required)"
    )


def _poll_dut_scan_for_peer(
    bus,
    *,
    peer_address: str,
    scan_seconds: float,
    log_start: Optional[int] = None,
    count_full_window: bool = False,
) -> bool:
    """Validate peer sightings in the DUT hostlog during legacy scan.

    Every poll tick logs the raw DUT scan data, similar to peer_scan_for_dut, 
    so the pytest report shows actual scan evidence rather than just a final found/not-found result.

    With *count_full_window* enabled, scanning continues for the full duration,
    logs each new sighting, and reports the total count at the end.
    """
    deadline = time.time() + scan_seconds
    started_at = time.time()
    accumulated = ""
    rx_marker_count = 0
    sighting_count = 0
    first_seen_elapsed: Optional[float] = None
    last_seen_elapsed: Optional[float] = None
    peer_mac = peer_address.lower()
    peer_mac_nocolon = peer_address.replace(":", "").lower()
    if log_start is None:
        log_start = len(bus.get_input_log())
    logger().info(
        f"HOSTLOG VALIDATION — polling {'non-stop for' if count_full_window else 'up to'} "
        f"{scan_seconds:.1f}s for fresh DUT RX containing remote BD address {peer_address}"
    )
    while time.time() < deadline:
        time.sleep(LOG_POLL_INTERVAL_SEC)
        fresh_text = ""
        try:
            fresh = decode_log_items(bus.get_input_log()[log_start:])
            if fresh:
                fresh_text = "\n".join(fresh)
                accumulated += fresh_text
                rx_marker_count += fresh_text.lower().count("advertised details")
                log_start = len(bus.get_input_log())
        except Exception as exc:
            logger().debug(f"DUT hostlog poll failed: {exc}")
        elapsed = time.time() - started_at
        logger().info(
            f"DUT bus RX scan poll at {elapsed:.0f}s: {fresh_text.strip() or '(no fresh RX)'!r}"
        )
        fresh_lower = fresh_text.lower()
        if peer_mac in fresh_lower or peer_mac_nocolon in fresh_lower:
            sighting_count += 1
            if first_seen_elapsed is None:
                first_seen_elapsed = elapsed
            last_seen_elapsed = elapsed
            logger().info(
                f"Remote BD address {peer_address} found in fresh DUT bus RX — "
                f"sighting #{sighting_count} at {elapsed:.0f}s"
            )
            if not count_full_window:
                logger().info(
                    f"Remote BD address {peer_address} found "
                    f"in DUT bus RX after {elapsed:.1f}s "
                    f"(advertised-details markers={rx_marker_count})"
                )
                return True

    if sighting_count:
        logger().info(
            f"Remote BD address {peer_address} visible {sighting_count} "
            f"time(s) in DUT bus RX across the {scan_seconds:.0f}s scan window "
            f"(first seen at {first_seen_elapsed:.0f}s, last at "
            f"{last_seen_elapsed:.0f}s, advertised-details markers={rx_marker_count})"
        )
        return True
    logger().info(
        f"Remote BD address {peer_address} not seen in DUT bus RX during the "
        f"{scan_seconds:.0f}s scan window (advertised-details markers={rx_marker_count}); "
        "DUT bus RX for the full window is printed above for review"
    )
    return False


def _peer_scan_for_dut(
    ble_client,
    dut_address: str,
    *,
    dut_names: Sequence[str],
    timeout: float,
    scan_full_window: bool = False,
) -> bool:
    """
    Raspi BLE scan — ``raspi_scan_for_dut`` / secure-pairing step 4 pattern.

    get_devices() is polled throughout the scan window to avoid missing devices that may age out of the BlueZ cache before the final snapshot. 
    With *scan_full_window* enabled, scanning continues for the entire timeout, 
    logging all sightings and reporting the final visibility count.
    """
    names = _collect_dut_discovery_names("", *dut_names)
    logger().info(
        f"Raspi scan for DUT {dut_address} "
        f"(names={list(names)}, scan_wait={timeout:.0f}s)"
    )
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    
    try:
        ble_client.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=dut_address,
            capability="KeyboardDisplay",
            pin_code="-8",
        )
    except Exception as exc:
        logger().warning(f"start_smp_scan failed ({exc}); start_scanning")
        ble_client.interfaces.bluetooth.start_scanning()

    found = False
    sighting_count = 0
    first_seen_elapsed = None
    last_seen_elapsed = None
    last_scan_devices = {}
    scan_start = time.time()
    deadline = scan_start + timeout
    while time.time() < deadline:
        time.sleep(min(PEER_SCAN_POLL_INTERVAL_SEC, max(0.0, deadline - time.time())))
        try:
            devices = ble_client.interfaces.bluetooth.get_devices()
        except Exception as exc:
            logger().warning(f"Raspi get_devices during peer scan: {exc}")
            continue
        last_scan_devices = devices or {}
        scan_device_list = [
            f"{str(address).upper()} ({str(alias)})"
            for address, alias in last_scan_devices.items()
        ]
        logger().info(f"Raspi BLE scan device list: {scan_device_list}")
        if _find_dut_in_peer_devices(devices, dut_address, dut_names=names):
            elapsed = time.time() - scan_start
            sighting_count += 1
            if first_seen_elapsed is None:
                first_seen_elapsed = elapsed
            last_seen_elapsed = elapsed
            found = True
            logger().info(
                f"DUT BD address {dut_address} visible on Raspi scan — "
                f"sighting #{sighting_count} at {elapsed:.0f}s"
            )
            if not scan_full_window:
                logger().info(
                    f"PASS — DUT BD address {dut_address} is present in the "
                    f"Raspi BLE scan device list"
                )
                break

    try:
        ble_client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    if found and scan_full_window:
        approx_visible = sighting_count * PEER_SCAN_POLL_INTERVAL_SEC
        logger().info(
            f"DUT BD address {dut_address} visible {sighting_count} time(s) "
            f"across the {timeout:.0f}s Raspi scan window "
            f"(first seen at {first_seen_elapsed:.0f}s, last at "
            f"{last_seen_elapsed:.0f}s, ~{approx_visible:.0f}s cumulative visibility "
            f"at a {PEER_SCAN_POLL_INTERVAL_SEC:.0f}s poll)"
        )
    if not found:
        logger().warning(
            f"DUT {dut_address} not seen in {timeout:.0f}s of Raspi scan "
            f"(names={list(names)}, last_scan_devices={last_scan_devices})"
        )
    try:
        ble_client.interfaces.bluetooth.close()
    except Exception:
        pass
    time.sleep(PEER_BUS_SETTLE_SEC)
    return found


def _ms_peer_bt_ready(client, *, label: str) -> bool:
    """
    True when the peer's ``bluetooth`` interface is already built.

    Touching ``client.interfaces.bluetooth`` on a peer whose interface never came
    up re-runs the entire Raspi RPC bring-up (sftp of /app + pip install, ~2 min)
    and fails again. Callers use this to skip such a peer instead of paying that
    cost on every cleanup step.
    """
    if "bluetooth" in client.interfaces:
        return True
    logger().warning(
        f"{label}: peer bluetooth interface never came up — skipping "
        "(see the ble_clients fixture bring-up error for the root cause)"
    )
    return False


def _raspi_pre_cleanup_peer(client, dut_address: str):
    """Stop Raspi scan/adv and disconnect before remove_device (adv_undirected pattern)."""
    if not _ms_peer_bt_ready(client, label="pre-cleanup"):
        return
    try:
        client.interfaces.bluetooth.disconnect(dev_addr=dut_address)
    except Exception as exc:
        logger().debug(f"Raspi disconnect: {exc}")
    time.sleep(POST_DISCONNECT_SETTLE_SEC)
    time.sleep(2)
    try:
        client.interfaces.bluetooth.stop_scanning()
    except Exception:
        pass
    try:
        client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass


def _suite_finally_cleanup(
    wifi_dut,
    ble_clients: Sequence,
    dut_address: Optional[str],
    *,
    slave_peer_addrs: Optional[Sequence[str]] = None,
    dut_central_peer_addr: Optional[str] = None,
):
    """
    Suite finally — smp_iocap / secure-pairing pattern for back-to-back tests.

    Disconnect DUT slave links, tear down Raspi bonds/sessions. Does **not**
    stop DUT adv/scan (``stop_dut_ble=False``) so the next test can proceed.
    """
    if not dut_address:
        return

    slave_addrs = [a for a in (slave_peer_addrs or []) if a]
    for idx, peer_addr in enumerate(slave_addrs, start=1):
        logger().info(f"finally btc_disconnect slave {idx} ({peer_addr})")
        safe_dut_btc_disconnect(wifi_dut, peer_addr)

    for idx, client in enumerate(ble_clients, start=1):
        if not _ms_peer_bt_ready(client, label="finally cleanup"):
            continue
        _raspi_pre_cleanup_peer(client, dut_address)
        try:
            _finally_cleanup_raspi_peer(client, dut_address)
        except Exception as exc:
            logger().warning(f"finally cleanup failed (non-fatal): {exc}")

    time.sleep(CLEANUP_FINAL_SETTLE_SEC)
    logger().info(f"suite cleanup complete (DUT adv/scan kept active)")


def _suite_finally_cleanup_adv_scan_only(ble_clients: Sequence):
    """
    Finally for cases that only advertise and scan, never forming a link.

    """
    for idx, client in enumerate(ble_clients, start=1):
        if not _ms_peer_bt_ready(client, label="finally cleanup"):
            continue
        bt = client.interfaces.bluetooth
        try:
            bt.stop_scanning()
        except Exception as exc:
            logger().debug(f"stop_scanning: {exc}")
        try:
            bt.stop_advertising()
        except Exception as exc:
            logger().debug(f"stop_advertising: {exc}")
        _raspi_close_with_retry(client)

    time.sleep(CLEANUP_FINAL_SETTLE_SEC)
    logger().info(
        f"peer scan/adv stopped, no link was formed "
        "(DUT adv/scan kept active)"
    )


def start_rf_creations_capture(ble_sniffer, testcase_id):
    """Connect to RF Creations sniffer and start per-testcase capture."""
    logger().info(f"Connecting RF Creations sniffer for TC {testcase_id}...")
    ble_sniffer.interfaces.sniffer.connect()
    ble_sniffer.interfaces.sniffer.start_capture(
        capture_file=f"utf_rfcreations_sniffer_TC_{testcase_id}"
    )
    logger().info(f"Capture started for TC {testcase_id}")


def stop_rf_creations_capture(ble_sniffer, testcase_id):
    """Stop capture and download the pcapng for this testcase."""
    logger().info(f"Stopping capture for TC {testcase_id}...")
    ble_sniffer.interfaces.sniffer.stop_capture()
    logger().info(f"Capture saved for TC {testcase_id}")


def _c553971_wait_for_boot_adv_scan(bus) -> str:
    """
    Wait for the post-flash boot banners before the sniffer is armed.

    """
    if _wait_for_first_test_dut_cli_ready(bus, timeout=DUT_BLE_READY_TIMEOUT_SEC):
        logger().info("DUT boot adv/scan banners seen — arming RF Creations sniffer")
    else:
        logger().warning(
            f"DUT boot adv/scan banners not seen within {DUT_BLE_READY_TIMEOUT_SEC}s "
            "— arming RF Creations sniffer anyway"
        )
    return _ms_full_hostlog_text(bus)


def _c553971_set_dut_smp_iocap(wifi_dut) -> None:
    """Apply DUT SMP IO capability once the capture is running, before adv restart."""
    logger().info(
        f"Set DUT SMP pairing capability io_capability=0x{C553971_DUT_IO_CAP:02X}, "
        f"auth_req=0x{C553971_AUTH_REQ:02X}"
    )
    try:
        wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
            io_capability=C553971_DUT_IO_CAP,
            auth_req=C553971_AUTH_REQ,
        )
    except Exception as exc:
        logger().warning(f"set_smp_pairing_capability_data: {exc}")
    time.sleep(SMP_CONFIG_SETTLE_SEC)


def _c553971_start_dut_adv_with_intervals(wifi_dut):
    """
    Start DUT advertising via ``btc ble req_legacy_adv``.

    ``C553971_ADV_INTERVAL_ARG`` is written into the command exactly as given —
    the CLI takes the interval as hex text, so no ms/0.625 conversion is applied.

    The OTA interval is what this case exists to prove, so the firmware has to
    accept these parameters. ``adv already in progress`` means the boot
    advertiser is still running at its compiled-in interval and the request was
    dropped — RF Creations would then capture the wrong interval — so retry the
    stop/start and fail loudly rather than let the run continue on bad settings.
    """
    bus = get_bus(wifi_dut)
    logger().info(
        f"DUT req_legacy_adv with intervals "
        f"min={C553971_ADV_INTERVAL_ARG} max={C553971_ADV_INTERVAL_ARG} "
        "(passed to the CLI verbatim)"
    )
    last_text = ""
    for attempt in range(1, C553971_ADV_START_ATTEMPTS + 1):
        try:
            wifi_dut.interfaces.wifi.stop_adv()
        except Exception as exc:
            logger().debug(f"stop_adv before req_legacy_adv: {exc}")
        time.sleep(LEGACY_ADV_STOP_SETTLE_SEC)

        log_mark = len(bus.get_input_log())
        try:
            wifi_dut.interfaces.wifi.legacy_adv(
                status=1,
                adv_int_min=C553971_ADV_INTERVAL_ARG,
                adv_int_max=C553971_ADV_INTERVAL_ARG,
                own_addr_type=DEFAULT_OWN_ADDR_TYPE,
            )
        except Exception as exc:
            logger().warning(f"req_legacy_adv attempt {attempt}: {exc}")
        time.sleep(LEGACY_SCAN_SETTLE_SEC)
        last_text = _hostlog_text(bus, log_mark)

        if "already in progress" in last_text:
            logger().warning(
                f"req_legacy_adv attempt {attempt}: adv already in progress — boot "
                "advertiser kept its compiled-in interval; retrying stop/start"
            )
            continue
        if "error status" in last_text:
            logger().warning(
                f"req_legacy_adv attempt {attempt} returned an error status"
            )
            continue
        if "ble_module_req_adv_cmd_handler : successful" in last_text:
            logger().info(
                f"DUT advertising at interval {C553971_ADV_INTERVAL_ARG} — "
                "firmware accepted req_legacy_adv"
            )
            time.sleep(LEGACY_SCAN_SETTLE_SEC)
            return

    raise AssertionError(
        f"DUT did not accept req_legacy_adv at interval "
        f"{C553971_ADV_INTERVAL_ARG} after "
        f"{C553971_ADV_START_ATTEMPTS} attempts; last hostlog: {last_text[-500:]!r}"
    )


def _c553971_stop_dut_adv_and_scan(wifi_dut) -> None:
    """Stop DUT advertising and DUT scanning before the second half re-arms them.

    The DUT's own scan reporting is dead for the rest of this case once it is
    advertising at the TestRail interval, independent of this stop — so there is
    no functional downside to a clean stop/restart here, and it gives
    ``_c553971_start_dut_scan_with_intervals`` a well-defined starting state
    instead of inheriting the boot scan's parameters.
    """
    bus = get_bus(wifi_dut)
    stop_mark = len(bus.get_input_log())
    try:
        wifi_dut.interfaces.wifi.stop_adv()
        logger().info("DUT req_legacy_adv_stop issued — stopping DUT advertising")
    except Exception as exc:
        logger().warning(f"stop_adv in second half: {exc}")
    time.sleep(LEGACY_ADV_STOP_SETTLE_SEC)
    try:
        wifi_dut.interfaces.wifi.legacy_scan_stop()
        logger().info("DUT req_legacy_scan_stop issued — stopping DUT scanning")
    except Exception as exc:
        logger().warning(f"legacy_scan_stop in second half: {exc}")
    time.sleep(LEGACY_SCAN_STOP_SETTLE_SEC)
    logger().debug(
        f"DUT adv/scan stop hostlog: {_hostlog_text(bus, stop_mark)[-300:]!r}"
    )


def _c553971_start_remote_adv(ble_client, dut_address: str) -> str:
    """
    Put the remote device into ADV the way C553832 does.

    Mirrors ``start_raspi_peripheral`` from the secure-pairing suite: set_bus and
    settle, apply the SMP io-capability / MITM / SC bits over hcitool, then
    ``start_smp_adv`` with the default bluetoothd restart. The DUT reports
    ``advertised details`` for a peer brought up this way.
    """
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(PEER_BUS_SETTLE_SEC)

    mitm_sc_bits = (
        f"{C553971_PEER_IO_CAP} 0x00 0x{C553971_AUTH_REQ:02x}"
    )
    try:
        logger().info(f"Remote SMP config (set_mitm_sc_bits): {mitm_sc_bits}")
        ble_client.interfaces.bluetooth.set_mitm_sc_bits(mitm_sc_bits)
        time.sleep(SMP_CONFIG_SETTLE_SEC)
    except Exception as exc:
        logger().warning(f"set_mitm_sc_bits on remote device: {exc}")

    logger().info(
        f"Start remote-device advertising (capability={C553971_PEER_CAPABILITY}, "
        "restart_bt_service=True)"
    )
    peer_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability=C553971_PEER_CAPABILITY,
    )
    assert peer_address, "Failed to start remote-device advertising"
    time.sleep(PEER_ADV_START_SEC)
    return peer_address.strip().upper()


def _c553971_start_dut_scan_with_intervals(wifi_dut) -> bool:
    """Request the TestRail scan parameters — call this after the DUT scan is stopped.

    ``C553971_SCAN_INTERVAL_ARG`` / ``C553971_SCAN_WINDOW_ARG`` are written into the
    command exactly as given, matching the hex the adv path uses.

    The command is built here rather than through ``legacy_scan()`` because that
    wrapper is one argument short of what the CLI expects.
    """
    bus = get_bus(wifi_dut)

    scan_cmd = (
        f"btc ble req_legacy_scan 1 1 {C553971_SCAN_TYPE} "
        f"{C553971_SCAN_FILTER_POLICY} {DEFAULT_OWN_ADDR_TYPE} "
        f"{C553971_SCAN_INTERVAL_ARG} {C553971_SCAN_WINDOW_ARG}"
    )
    logger().info(f"DUT scan command: {scan_cmd}")
    log_mark = len(bus.get_input_log())
    try:
        bus.write_line_and_expect(scan_cmd)
        bus.read_line()
    except Exception as exc:
        logger().error(f"HOSTLOG VALIDATION FAIL — req_legacy_scan transport error: {exc}")
        return False
    time.sleep(0.5)
    scan_text = _hostlog_text(bus, log_mark)
    if "already_in_progress" in scan_text or "already in progress" in scan_text:
        logger().info(
            "ble_connectable_scan_already_in_progress: "
            f"the boot scan is still running at LE_SCAN_INTERVAL=0x{LE_SCAN_INTERVAL_HEX:04X} "
            f"/ LE_SCAN_WINDOW=0x{LE_SCAN_WINDOW_HEX:04X} and keeps reporting scan results"
        )
    elif "4e12" in scan_text:
        logger().error(
            "req_legacy_scan returned firmware error 0x4e12"
        )
        return False
    elif "ble_module_req_scan_cmd_handler : successful" in scan_text:
        logger().info(
            "DUT bus contains "
            "'ble_module_req_scan_cmd_handler : successful' for "
            f"interval={C553971_SCAN_INTERVAL_ARG}, "
            f"window={C553971_SCAN_WINDOW_ARG}"
        )
    else:
        logger().error(
            "neither scan-success nor already-in-progress "
            f"after {scan_cmd!r}; hostlog_tail={scan_text[-500:]!r}"
        )
        return False

    time.sleep(LEGACY_SCAN_SETTLE_SEC)
    return True


@pytest.mark.ble_sniffer("rf_creations_sniffer")
@pytest.mark.test_src_map_id(CASE_ID)
def test_ble_scan_adv_intervals_10240ms_C553971(wifi_dut, ble_client, ble_sniffer):
    """
    TestRail C553971 — scan interval 10240 ms + window 5000 ms + advertise 10240 ms.

    Step 10 — Firmware rsi_ble_config_DEMO_57.h (manual precondition; logged at runtime):
      RSI_BLE_ADV_INT_MIN/MAX 0x4000, LE_SCAN_INTERVAL 0x4000, LE_SCAN_WINDOW 0x1F40

    Step 12 — RF Creations capture saved for offline OTA ADV-interval review.
    """
    bus = wifi_dut.interfaces.wifi.bus
    peer_address = None
    dut_address = None
    sniffer_capture_started = False

    logger().info(
        "Step 10: firmware must define in rsi_ble_config_DEMO_57.h — "
        f"RSI_BLE_ADV_INT_MIN=0x{RSI_BLE_ADV_INT_HEX:04X}, "
        f"RSI_BLE_ADV_INT_MAX=0x{RSI_BLE_ADV_INT_HEX:04X} (10.24 s), "
        f"LE_SCAN_INTERVAL=0x{LE_SCAN_INTERVAL_HEX:04X} (10.24 s), "
        f"LE_SCAN_WINDOW=0x{LE_SCAN_WINDOW_HEX:04X} (5000 ms)"
    )

    try:
        _ensure_dut_ble_ready(wifi_dut, bus, init_settle_sec=DUT_INIT_SETTLE_SEC)

        hostlog = _c553971_wait_for_boot_adv_scan(bus)

        try:
            start_rf_creations_capture(ble_sniffer, CASE_ID)
            sniffer_capture_started = True
        except Exception as start_err:
            logger().warning(
                f"start_capture failed (continuing without capture): {start_err}"
            )

        _c553971_set_dut_smp_iocap(wifi_dut)

        # TestRail: DUT advertises first, then the remote device scans for it.
        logger().info("Start DUT advertising with 10.24 s interval")
        _c553971_start_dut_adv_with_intervals(wifi_dut)

        if not _hostlog_indicates_dut_advertising(hostlog):
            logger().warning(
                "DUT advertising markers not in early hostlog "
                "(req_legacy_adv was issued with 10.24 s intervals)"
            )
        for marker in STEP11_OPTIONAL_HOSTLOG_MARKERS:
            if marker not in hostlog:
                logger().warning(f"Optional init marker not seen: {marker}")

        dut_adv_name = _parse_dut_name_from_hostlog(hostlog) or BLE_UNIFIED_DEMO_ADV_NAME
        dut_address = _resolve_dut_bd_address(
            wifi_dut,
            hostlog,
            step="11",
            ble_client=ble_client,
            dut_names=(dut_adv_name, DUT_ADV_NAME, BLE_UNIFIED_DEMO_ADV_NAME),
        )
        logger().info(f"DUT BD address {dut_address}, adv name '{dut_adv_name}'")

        logger().info(
            "Steps 6–7: firmware precondition — WLAN/BT power save profile (2,1) "
            "(not applied via RT595 btc CLI)"
        )

        logger().info(
            f"DUT advertising-only for {C553971_DUT_ADV_CAPTURE_DWELL_SEC}s — remote "
            "device scans the whole window and counts DUT sightings"
        )
        dut_found_on_peer = _peer_scan_for_dut(
            ble_client,
            dut_address,
            dut_names=(dut_adv_name, DUT_ADV_NAME),
            timeout=C553971_DUT_ADV_CAPTURE_DWELL_SEC,
            scan_full_window=True,
        )
        assert dut_found_on_peer, (
            f"DUT {dut_address} (name '{dut_adv_name}') not found in "
            f"remote-device scan within {C553971_DUT_ADV_CAPTURE_DWELL_SEC}s"
        )
        logger().info("PASS — DUT BD address visible in remote-device scan results")

        try:
            ble_client.interfaces.bluetooth.stop_scanning()
            logger().info("Remote-device scanning stopped before it starts advertising")
        except Exception as exc:
            logger().debug(f"stop_scanning before remote adv: {exc}")

        peer_address = _c553971_start_remote_adv(ble_client, dut_address)
        logger().info(f"Remote-device advertising started (non-stop): {peer_address}")

        # Stop the DUT's own advertising and scanning, then re-arm the scan at the
        # TestRail intervals from a clean state.
        _c553971_stop_dut_adv_and_scan(wifi_dut)

        # Baseline the hostlog before arming the scan so the poll requires a fresh
        # sighting rather than reusing anything seen earlier.
        baseline = len(bus.get_input_log())

        scan_start_validated = _c553971_start_dut_scan_with_intervals(wifi_dut)
        assert scan_start_validated, (
            "DUT scan-start hostlog validation failed for command "
            f"req_legacy_scan 0 1 {C553971_SCAN_TYPE} "
            f"{C553971_SCAN_FILTER_POLICY} {DEFAULT_OWN_ADDR_TYPE} "
            f"{C553971_SCAN_INTERVAL_ARG} {C553971_SCAN_WINDOW_ARG}"
        )

        # Poll non-stop for a flat 2 min, printing the DUT's raw bus RX at every poll tick and
        # count every sighting instead of stopping at the first one.
        peer_seen_on_dut = _poll_dut_scan_for_peer(
            bus,
            peer_address=peer_address,
            scan_seconds=DUT_PEER_SCAN_TIMEOUT_SEC,
            log_start=baseline,
            count_full_window=True,
        )
        if peer_seen_on_dut:
            logger().info("Remote-device BD address visible in DUT scan results")
        else:
            logger().info(
                "Remote-device BD address not seen in DUT scan results within "
                f"{DUT_PEER_SCAN_TIMEOUT_SEC:.0f}s — DUT bus RX for the full window "
                "is printed above for review"
            )

        logger().info(
            "Step 12: RF Creations capture saved for offline OTA ADV-interval review"
        )

    finally:
        if sniffer_capture_started:
            try:
                stop_rf_creations_capture(ble_sniffer, CASE_ID)
            except Exception as sniffer_err:
                logger().warning(f"Failed to stop capture: {sniffer_err}")
        _suite_finally_cleanup_adv_scan_only([ble_client])

    logger().info(
        "DUT ADV at "
        f"{C553971_ADV_INTERVAL_ARG} seen by remote (Raspi scan); remote ADV "
        "captured OTA by RF Creations for interval review; DUT-side scan "
        "sightings of the remote (if any) are logged above for the record"
    )


# =============================================================================
# TestRail C553972 — 1 master + 3 slaves idle connection stability (2 iterations)
# =============================================================================

CASE_ID_C553972 = "C553972"
C553972_DUT_ADV_NAME = "9116_BLE"
C553972_SLAVE_ADV_NAMES = ("slave11", "slave22", "slave33")
C553972_AUTH_REQ = 0x2D
C553972_DUT_INIT_SETTLE_SEC = SMP_DUT_INIT_SLEEP_SEC
C553972_STABILITY_POLL_SEC = 10.0
# Iteration 1 holds the links idle for 10 min, iteration 2 for 15 min.
C553972_STABILITY_SEC = float(os.environ.get("C553972_STABILITY_SEC", "600"))
C553972_STABILITY2_SEC = float(os.environ.get("C553972_STABILITY2_SEC", "900"))
C553972_ITERATION_STABILITY_SEC = (C553972_STABILITY_SEC, C553972_STABILITY2_SEC)
# All 4 links must be verified up when the window opens; a peer that tears a link
# down right after bonding gets one rebuild before the iteration is failed.
C553972_LINK_SETUP_ATTEMPTS = 2

C553972_INIT_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553972_MASTER_BOND_MARKERS = (
    "in smp encrypt event",
    "smp encrypt event",
    "remote device profiles discovery completed",
    "on enhance connect event",
    "number of master devices connected",
)
C553972_SLAVE_BOND_MARKERS = (
    "in smp encrypt event",
    "smp encrypt event",
    "remote device profiles discovery completed",
    "number of slave devices connected",
)
# Links are held idle; these banners are not expected while stability runs.
C553972_DATA_TRANSFER_MARKERS = (
    "start transmitting data to",
    "in transmit notification event",
    "in receive notification event",
    "receiving notifications from remote device",
)


def _c553972_bus(wifi_dut):
    return wifi_dut.interfaces.wifi.bus


def _c553972_wait_hostlog(
    bus,
    patterns: Sequence[str],
    *,
    timeout: float = WAIT_FOR_LOG_PATTERNS_DEFAULT_TIMEOUT_SEC,
    require_all: bool = True,
    baseline: Optional[int] = None,
) -> Tuple[bool, str]:
    return _ms_wait_hostlog(
        bus,
        patterns,
        timeout=timeout,
        require_all=require_all,
        baseline=baseline,
    )


def _c553972_hostlog_indicates_slave_dropped_since(
    bus, slave_addr: str, baseline: int
) -> bool:
    return _ms_peer_dropped_since(bus, slave_addr, baseline)


def _c553972_peer_address(client) -> str:
    addr = client.interfaces.bluetooth.get_address()
    assert addr, "Raspi peer address unavailable"
    return addr.strip().upper()


def _c553972_disconnect_slaves(wifi_dut, slave_addrs: Sequence[str]):
    for idx, addr in enumerate(slave_addrs, start=1):
        logger().info(f"DUT disconnect slave link {idx} ({addr})")
        safe_dut_btc_disconnect(wifi_dut, addr)
        time.sleep(POST_DISCONNECT_SETTLE_SEC)


def _c553972_disconnect_masters(clients, dut_address: str):
    for idx, client in enumerate(clients, start=1):
        if not _ms_peer_bt_ready(
            client, label=f"master link {idx} disconnect"
        ):
            continue
        connected = True
        try:
            connected = bool(
                client.interfaces.bluetooth.get_connection_status(dut_address)
            )
        except Exception as exc:
            logger().debug(f"master {idx} get_connection_status: {exc}")
        if not connected:
            logger().info(f"master link {idx} already down")
            continue
        try:
            logger().info(f"disconnect master link {idx} from DUT")
            client.interfaces.bluetooth.disconnect(dev_addr=dut_address)
            time.sleep(POST_DISCONNECT_SETTLE_SEC)
        except Exception as exc:
            logger().warning(f"master {idx} disconnect failed: {exc}")


def _c553972_disconnect_all_links(
    wifi_dut,
    master_clients,
    slave_clients,
    slave_addrs: Sequence[str],
    dut_address: str,
    *,
    iteration: int = 0,
):
    
    label = f"Iteration {iteration}: " if iteration else ""
    logger().info(f"{label}disconnect all links")
    _c553972_disconnect_masters(master_clients, dut_address)
    time.sleep(STEP_SETTLE_SEC)
    _c553972_disconnect_slaves(wifi_dut, slave_addrs)
    for client in slave_clients:
        if "bluetooth" not in client.interfaces:
            continue
        try:
            client.interfaces.bluetooth.stop_advertising()
        except Exception:
            pass
    time.sleep(STEP_SETTLE_SEC)


def _c553972_connect_master_link(wifi_dut, client, dut_address: str, bus, link_idx: int, event):
    global _MS_LOCAL_DUT_ADDRESS

    _ms_setup_test_state()
    _MS_LOCAL_DUT_ADDRESS = dut_address
    time.sleep(STEP_SETTLE_SEC)
    tag = f"{CASE_ID_C553972}-master{link_idx}"
    _raspi_pre_cleanup_peer(client, dut_address)
    _ensure_dut_connectable_before_raspi_master(
        wifi_dut, bus, dut_address
    )
    try:
        client.interfaces.bluetooth.set_bus()
    except Exception as exc:
        logger().warning(f"[{tag}] set_bus before master connect: {exc}")
    logger().info(
        f"[{CASE_ID_C553972}] Raspi central {link_idx} connecting to DUT "
        f"({C553972_DUT_ADV_NAME})"
    )
    log_start = len(bus.get_input_log())
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut,
        client,
        wait_for_bt=False,
        event_to_signal=event,
        log_baseline=log_start,
    )
    assert ok, f"[{CASE_ID_C553972}] master link {link_idx} connect failed"
    assert not _ms_slice_has_smp_failure(bus, log_start), (
        f"[{CASE_ID_C553972}] master link {link_idx} SMP failed (hostlog)"
    )
    assert _ms_slice_has_smp_success(bus, log_start), (
        f"[{CASE_ID_C553972}] master link {link_idx} SMP encrypt/LTK missing in hostlog"
    )
    try:
        connected = client.interfaces.bluetooth.get_connection_status(dut_address)
    except Exception as exc:
        connected = False
        logger().warning(f"[{CASE_ID_C553972}] master {link_idx} get_connection_status: {exc}")
    assert connected, (
        f"[{CASE_ID_C553972}] master link {link_idx} not connected on Raspi"
    )
    time.sleep(POST_PAIR_SETTLE_SEC)
    time.sleep(2)
    found_bond, _ = _c553972_wait_hostlog(
        bus,
        C553972_MASTER_BOND_MARKERS,
        require_all=False,
        timeout=HOSTLOG_COUNT_POLL_TIMEOUT_SEC,
        baseline=log_start,
    )
    assert found_bond, (
        f"[{CASE_ID_C553972}] master link {link_idx} bond hostlog missing"
    )
    found_count = _ms_wait_master_count_hostlog(
        bus,
        link_idx,
        baseline=log_start,
        link_idx=link_idx,
        operational_ok=True,
    )
    assert found_count, (
        f"[{CASE_ID_C553972}] master link {link_idx}: count/SMP hostlog missing "
        f"after connect+SMP+get_connection_status"
    )
    logger().info(f"[{CASE_ID_C553972}] master link {link_idx} bonded")


def _c553972_connect_slave_link(
    wifi_dut,
    client,
    adv_name: str,
    dut_address: str,
    bus,
    link_idx: int,
    *,
    wait_for_ble1: bool = False,
    event=None,
) -> Tuple[str, int]:
    """Returns the peer address plus this connect's hostlog baseline (drop detection)."""
    global _MS_LOCAL_DUT_ADDRESS

    _ms_setup_test_state(clear_ble_events=False)
    _MS_LOCAL_DUT_ADDRESS = dut_address
    time.sleep(STEP_SETTLE_SEC)
    logger().info(
        f"[{CASE_ID_C553972}] DUT scan/connect to Raspi peripheral "
        f"'{adv_name}' (slave link {link_idx})"
    )
    assert "bluetooth" in client.interfaces, (
        f"[{CASE_ID_C553972}] slave link {link_idx} ({adv_name}): peer Raspi has no "
        "usable bluetooth interface — its RPC bring-up failed, this is an infra "
        "issue on that Raspi, not a DUT failure"
    )
    try:
        client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
    except Exception as exc:
        logger().warning(
            f"[{CASE_ID_C553972}] set_advertising_data('{adv_name}'): {exc}"
        )
    time.sleep(PEER_ADV_START_SEC)
    time.sleep(2)
    log_start = len(bus.get_input_log())
    ok = connect_dut_as_central_raspii_as_peripheral(
        wifi_dut,
        client,
        dut_capability=0x00,
        client_capability="KeyboardDisplay",
        auth_req_value=C553972_AUTH_REQ,
        wait_for_bt=False,
        wait_for_ble1=wait_for_ble1,
        event_to_signal=event,
    )
    assert ok, (
        f"[{CASE_ID_C553972}] DUT-central link {link_idx} ({adv_name}) connect failed"
    )
    time.sleep(POST_PAIR_SETTLE_SEC)
    time.sleep(2)
    found, _ = _c553972_wait_hostlog(
        bus,
        C553972_SLAVE_BOND_MARKERS,
        require_all=False,
        timeout=HOSTLOG_COUNT_POLL_TIMEOUT_SEC,
        baseline=log_start,
    )
    assert found, (
        f"[{CASE_ID_C553972}] slave link {link_idx} ({adv_name}) bond hostlog missing"
    )
    found_count = _ms_wait_slave_count_hostlog(
        bus,
        link_idx,
        baseline=log_start,
        operational_ok=True,
    )
    assert found_count, (
        f"[{CASE_ID_C553972}] slave link {link_idx} ({adv_name}): "
        f"count/SMP hostlog missing after connect"
    )
    peer_addr = _c553972_peer_address(client)
    logger().info(
        f"[{CASE_ID_C553972}] slave link {link_idx} ({adv_name}) bonded @ {peer_addr}"
    )
    return peer_addr, log_start


def _c553972_monitor_stability(
    master_clients,
    slave_addrs: Sequence[str],
    dut_address: str,
    bus,
    *,
    stability_baseline: int,
    duration: float,
    iteration: int,
):
    """
    Hold every link idle — no data transfer — and watch for drops.

    Wearables firmware floods hostlog with scan ``advertised details`` while the
    links are up; it does not keep printing aggregate ``slave-count:N``. Masters
    are checked via Raspi ``get_connection_status``; slaves via disconnect
    phrases in hostlog since ``stability_baseline``.
    """
    logger().info(
        f"[{CASE_ID_C553972}] Iteration {iteration}: hold {len(master_clients)} master + "
        f"{len(slave_addrs)} slave link(s) idle for {duration:.0f}s (no data transfer)"
    )
    start = time.time()
    while time.time() - start < duration:
        elapsed = time.time() - start
        down = None
        for idx, client in enumerate(master_clients, start=1):
            if not _ms_raspi_link_up(client, dut_address):
                down = f"master link {idx}"
                break
        if down is None:
            for idx, addr in enumerate(slave_addrs, start=1):
                if _ms_peer_dropped_since(bus, addr, stability_baseline):
                    down = f"slave link {idx} ({addr})"
                    break
        if down is not None:
            reason = _ms_last_drop_reason(bus, stability_baseline)
            detail = f", hostlog disconnect reason {reason}" if reason else ""
            raise AssertionError(
                f"[{CASE_ID_C553972}] iteration {iteration}: {down} dropped "
                f"{elapsed:.0f}s into the {duration:.0f}s idle window{detail}"
            )
        time.sleep(C553972_STABILITY_POLL_SEC)
    idle_chunk = _ms_hostlog_slice_since(bus, stability_baseline)
    transfer_seen = [m for m in C553972_DATA_TRANSFER_MARKERS if m in idle_chunk]
    if transfer_seen:
        logger().warning(
            f"[{CASE_ID_C553972}] Iteration {iteration}: firmware logged data-transfer "
            f"banners while links were idle: {transfer_seen}"
        )
    logger().info(
        f"[{CASE_ID_C553972}] Iteration {iteration}: {duration:.0f}s idle stability complete"
    )


def _c553972_ensure_master_link(
    wifi_dut, master_client, dut_address: str, bus, *, iteration: int
):
    """DUT-central connects can drop the Raspi central session — re-establish it."""
    try:
        master_up = bool(
            master_client.interfaces.bluetooth.get_connection_status(dut_address)
        )
    except Exception as exc:
        master_up = False
        logger().warning(
            f"[{CASE_ID_C553972}] master get_connection_status after slave phase: {exc}"
        )
    if master_up:
        return
    logger().info(
        f"[{CASE_ID_C553972}] Iteration {iteration}: master link dropped during slave "
        "phase — re-establishing"
    )
    _c553972_connect_master_link(
        wifi_dut,
        master_client,
        dut_address,
        bus,
        link_idx=1,
        event=_MS_BLE1_CONNECTION_EVENT,
    )


def _c553972_hold_links_before_window(
    wifi_dut,
    bus,
    master_client,
    slave_clients: Sequence,
    dut_address: str,
    *,
    iteration: int,
    slave_addrs: List[str],
    slave_baselines: Dict[str, int],
):
    """Verify all 4 links are still up before the idle window opens.

    A peer that tears a link down right after bonding gets one rebuild; the window
    itself must start with every link confirmed alive, otherwise a setup-phase drop
    would be reported as an idle-stability failure.
    """
    for attempt in range(1, C553972_LINK_SETUP_ATTEMPTS + 1):
        _c553972_ensure_master_link(
            wifi_dut, master_client, dut_address, bus, iteration=iteration
        )
        for idx, (client, adv_name) in enumerate(
            zip(slave_clients, C553972_SLAVE_ADV_NAMES), start=1
        ):
            addr = slave_addrs[idx - 1] if idx - 1 < len(slave_addrs) else None
            if addr and not _ms_peer_dropped_since(
                bus, addr, slave_baselines.get(addr, 0)
            ):
                continue
            logger().info(
                f"[{CASE_ID_C553972}] Iteration {iteration}: slave link {idx} "
                f"({adv_name}) dropped after bonding — rebuilding"
            )
            new_addr, baseline = _c553972_connect_slave_link(
                wifi_dut,
                client,
                adv_name,
                dut_address,
                bus,
                link_idx=idx,
                wait_for_ble1=False,
                event=(
                    _MS_BLE1_CONNECTION_EVENT if idx == 1 else _MS_BLE2_CONNECTION_EVENT
                ),
            )
            slave_baselines[new_addr] = baseline
            if idx - 1 < len(slave_addrs):
                slave_addrs[idx - 1] = new_addr
            else:
                slave_addrs.append(new_addr)
        time.sleep(POST_PAIR_SETTLE_SEC)

        master_up = _ms_raspi_link_up(
            master_client, dut_address
        )
        dropped = [
            addr
            for addr in slave_addrs
            if _ms_peer_dropped_since(bus, addr, slave_baselines.get(addr, 0))
        ]
        if master_up and not dropped:
            logger().info(
                f"[{CASE_ID_C553972}] Iteration {iteration}: all links verified up "
                f"(attempt {attempt}) — 1 master + {len(slave_addrs)} slaves"
            )
            return

        down = "master" if not master_up else f"slaves {dropped}"
        reason = _ms_last_drop_reason(bus, min(slave_baselines.values(), default=0))
        detail = f", last hostlog disconnect reason {reason}" if reason else ""
        if attempt < C553972_LINK_SETUP_ATTEMPTS:
            logger().warning(
                f"[{CASE_ID_C553972}] Iteration {iteration}: {down} dropped right "
                f"after bonding{detail} — rebuilding"
            )
            continue
        raise AssertionError(
            f"[{CASE_ID_C553972}] iteration {iteration}: {down} dropped before the "
            f"idle window could start, after {C553972_LINK_SETUP_ATTEMPTS} "
            f"attempts{detail}"
        )


def _c553972_establish_links(
    wifi_dut,
    bus,
    master_client,
    slave_clients: Sequence,
    dut_address: str,
    *,
    iteration: int,
    slave_addrs: List[str],
):
    """Raspi 1 connects to the DUT, then the DUT connects the remaining Raspis."""
    slave_addrs.clear()
    slave_baselines: Dict[str, int] = {}
    logger().info(
        f"[{CASE_ID_C553972}] Iteration {iteration}: Raspi 1 connects to the DUT "
        "(DUT peripheral, master link)"
    )
    _c553972_connect_master_link(
        wifi_dut,
        master_client,
        dut_address,
        bus,
        link_idx=1,
        event=_MS_BLE1_CONNECTION_EVENT,
    )
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"[{CASE_ID_C553972}] Iteration {iteration}: DUT scans and connects "
        f"{len(slave_clients)} Raspi peripherals {C553972_SLAVE_ADV_NAMES}"
    )
    slave_phase_baseline = len(bus.get_input_log())
    for idx, (client, adv_name) in enumerate(
        zip(slave_clients, C553972_SLAVE_ADV_NAMES), start=1
    ):
        peer_addr, peer_baseline = _c553972_connect_slave_link(
            wifi_dut,
            client,
            adv_name,
            dut_address,
            bus,
            link_idx=idx,
            wait_for_ble1=False,
            event=(
                _MS_BLE1_CONNECTION_EVENT if idx == 1 else _MS_BLE2_CONNECTION_EVENT
            ),
        )
        slave_addrs.append(peer_addr)
        slave_baselines[peer_addr] = peer_baseline
        if idx < len(slave_clients):
            time.sleep(STEP_SETTLE_SEC)
            time.sleep(2)

    _ms_verify_c553972_three_slave_links(
        bus,
        slave_addrs,
        baseline=slave_phase_baseline,
    )
    _c553972_hold_links_before_window(
        wifi_dut,
        bus,
        master_client,
        slave_clients,
        dut_address,
        iteration=iteration,
        slave_addrs=slave_addrs,
        slave_baselines=slave_baselines,
    )
    logger().info(
        f"[{CASE_ID_C553972}] Iteration {iteration}: 1 master + {len(slave_addrs)} "
        f"slave links up @ {slave_addrs}"
    )


def _c553972_run_iteration(
    wifi_dut,
    bus,
    master_client,
    slave_clients: Sequence,
    dut_address: str,
    *,
    iteration: int,
    stability_sec: float,
    slave_addrs: List[str],
):
    """Connect 1 master + 3 slaves, hold them idle, then disconnect everything."""
    _c553972_establish_links(
        wifi_dut,
        bus,
        master_client,
        slave_clients,
        dut_address,
        iteration=iteration,
        slave_addrs=slave_addrs,
    )
    stability_baseline = len(bus.get_input_log())
    time.sleep(POST_PAIR_SETTLE_SEC)
    time.sleep(2)
    _c553972_monitor_stability(
        [master_client],
        slave_addrs,
        dut_address,
        bus,
        stability_baseline=stability_baseline,
        duration=stability_sec,
        iteration=iteration,
    )
    _c553972_disconnect_all_links(
        wifi_dut,
        [master_client],
        slave_clients,
        slave_addrs,
        dut_address,
        iteration=iteration,
    )
    slave_addrs.clear()


@pytest.mark.ble_clients(
    [
        "raspi_ble_client",
        "secondary_raspi_ble_client",
        "tertiary_raspi_ble_client",
        "fourth_raspi_ble_client",
    ]
)
@pytest.mark.test_src_map_id(CASE_ID_C553972)
def test_ble_connection_stability_3slaves_1master_C553972(wifi_dut, ble_clients):
    """
    TestRail C553972 — BLE connection stability: 1 master + 3 slaves held idle.

    Harness: 1 DUT + 4 Raspi BLE clients (``ble_clients`` fixture).
      • ``raspi_ble_client`` — central; connects to the DUT (DUT peripheral)
      • the other three Raspi — peripherals ``slave11`` / ``slave22`` / ``slave33``

    """
    case_id = CASE_ID_C553972
    assert len(ble_clients) >= 4, (
        f" requires 4 ble_clients (1 central + 3 peripherals); "
        f"got {len(ble_clients)}"
    )

    bus = _c553972_bus(wifi_dut)
    master_client = ble_clients[0]
    slave_clients = list(ble_clients[1:4])
    dut_address = None
    slave_peer_addrs: List[str] = []

    try:
        # --- DUT init: advertising + scanning hostlog ---
        hostlog = _ensure_dut_ble_ready(
            wifi_dut,
            bus,
            init_settle_sec=C553972_DUT_INIT_SETTLE_SEC,
        )
        for marker in C553972_INIT_OPTIONAL_MARKERS:
            if marker not in hostlog:
                logger().warning(f"optional init marker not seen: {marker}")

        dut_adv_name = (
            _parse_dut_name_from_hostlog(hostlog)
            or _CACHED_DUT_ADV_NAME
            or BLE_UNIFIED_DEMO_ADV_NAME
        )
        dut_address = _resolve_dut_bd_address(
            wifi_dut,
            hostlog,
            step="init",
            ble_client=master_client,
            dut_names=(dut_adv_name, DUT_ADV_NAME, BLE_UNIFIED_DEMO_ADV_NAME),
        )
        logger().info(f"DUT BD address {dut_address}, adv name '{dut_adv_name}'")

        total_iterations = len(C553972_ITERATION_STABILITY_SEC)
        for iteration, stability_sec in enumerate(
            C553972_ITERATION_STABILITY_SEC, start=1
        ):
            logger().info(
                f"Iteration {iteration}/{total_iterations}: "
                f"1 master + {len(slave_clients)} slaves, "
                f"{stability_sec:.0f}s idle stability"
            )
            if iteration > 1:
                # Links from the previous iteration were dropped — the DUT must
                # advertise (master link) and scan (slave links) again.
                # Stop+restart scan first to avoid 0x4e12 on ble_scan.
                _restart_dut_wearables_idle_roles(
                    wifi_dut, bus, require_scan=True
                )
                time.sleep(STEP_SETTLE_SEC)
            _c553972_run_iteration(
                wifi_dut,
                bus,
                master_client,
                slave_clients,
                dut_address,
                iteration=iteration,
                stability_sec=stability_sec,
                slave_addrs=slave_peer_addrs,
            )

    finally:
        if dut_address:
            try:
                _c553972_disconnect_masters([master_client], dut_address)
            except Exception as exc:
                logger().warning(f" finally master disconnect: {exc}")
            _c553972_disconnect_slaves(wifi_dut, slave_peer_addrs)
            _suite_finally_cleanup(
                wifi_dut,
                ble_clients,
                dut_address,
                slave_peer_addrs=slave_peer_addrs,
            )

    logger().info(
        f"1 master + 3 slave idle stability x"
        f"{len(C553972_ITERATION_STABILITY_SEC)} "
        f"({', '.join(f'{s:.0f}s' for s in C553972_ITERATION_STABILITY_SEC)})"
    )


# =============================================================================
# TestRail C553973 — dual role 1 master + 1 slave stability (steps 14–23)
# =============================================================================

CASE_ID_C553973 = "C553973"
C553973_DUT_ADV_NAME = "9116_BLE"
C553973_SLAVE_ADV_NAME = "slave11"
C553973_AUTH_REQ = 0x2D
C553973_DUT_INIT_SETTLE_SEC = SMP_DUT_INIT_SLEEP_SEC
C553973_STABILITY_SEC = float(os.environ.get("C553973_STABILITY_SEC", "600"))
C553973_STABILITY_POLL_SEC = 10.0
C553973_RECONNECT_CYCLES = 5
C553973_LINK_SETUP_ATTEMPTS = 2

C553973_STEP14_HOSTLOG_MARKERS = (
    "advertising started",
    "scanning started",
)
C553973_STEP14_OPTIONAL_MARKERS = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
)
C553973_MASTER_BOND_MARKERS = (
    "in smp encrypt event",
    "smp encrypt event",
    "remote device profiles discovery completed",
    "on enhance connect event",
    "number of master devices connected:1",
)
C553973_SLAVE_BOND_MARKERS = (
    "in smp encrypt event",
    "smp encrypt event",
    "remote device profiles discovery completed",
    "number of slave devices connected:1",
    "start transmitting data to",
)
C553973_STREAMING_MARKERS = (
    "in receive notification event",
    "receiving notifications from remote device",
    "start transmitting data to",
)


def _c553973_bus(wifi_dut):
    return wifi_dut.interfaces.wifi.bus


def _c553973_wait_hostlog(
    bus,
    patterns: Sequence[str],
    *,
    timeout: float = WAIT_FOR_LOG_PATTERNS_DEFAULT_TIMEOUT_SEC,
    require_all: bool = True,
    baseline: Optional[int] = None,
) -> Tuple[bool, str]:
    return _ms_wait_hostlog(
        bus,
        patterns,
        timeout=timeout,
        require_all=require_all,
        baseline=baseline,
    )


def _c553973_connect_master(
    wifi_dut, ble_client, dut_address: str, bus, *, case_id: str
):
    """TestRail steps 15–16: Raspi central connects to DUT (1 master link)."""
    global _MS_LOCAL_DUT_ADDRESS

    _ms_setup_test_state()
    _MS_LOCAL_DUT_ADDRESS = dut_address
    time.sleep(STEP_SETTLE_SEC)
    _raspi_pre_cleanup_peer(ble_client, dut_address)
    _ensure_dut_connectable_before_raspi_master(
        wifi_dut, bus, dut_address
    )
    logger().info(
        f"Steps 15–16: Raspi scan/connect to DUT ({C553973_DUT_ADV_NAME})"
    )
    log_start = len(bus.get_input_log())
    ok = connect_dut_as_peripheral_raspii_as_central(
        wifi_dut,
        ble_client,
        wait_for_bt=False,
        event_to_signal=_MS_BLE1_CONNECTION_EVENT,
        log_baseline=log_start,
    )
    assert ok, f" master link connect failed"
    time.sleep(POST_PAIR_SETTLE_SEC)
    time.sleep(2)
    found, _ = _c553973_wait_hostlog(
        bus, C553973_MASTER_BOND_MARKERS, require_all=False, baseline=log_start
    )
    assert found, f" master bond hostlog markers missing"
    assert _ms_wait_master_count_hostlog(
        bus,
        1,
        baseline=log_start,
        link_idx=1,
        operational_ok=True,
    ), f" master link hostlog verification failed"
    logger().info(f" Steps 15–16: master link bonded")


def _c553973_connect_slave(
    wifi_dut, ble_client, dut_address: str, bus, *, case_id: str
) -> Tuple[str, int]:
    """DUT central connects to Raspi peripheral (slave11)."""
    global _MS_LOCAL_DUT_ADDRESS

    _ms_setup_test_state(clear_ble_events=False)
    _MS_LOCAL_DUT_ADDRESS = dut_address
    time.sleep(STEP_SETTLE_SEC)
    logger().info(
        f" Steps 17–18: DUT scan/connect to Raspi '{C553973_SLAVE_ADV_NAME}'"
    )
    time.sleep(RASPI_ROLE_SWITCH_SETTLE_SEC)
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(
            hci_adv_data=C553973_SLAVE_ADV_NAME
        )
    except Exception as exc:
        logger().warning(f" set_advertising_data: {exc}")
    time.sleep(PEER_ADV_START_SEC)
    time.sleep(2)
    log_start = len(bus.get_input_log())
    ok = connect_dut_as_central_raspii_as_peripheral(
        wifi_dut,
        ble_client,
        dut_capability=0x00,
        client_capability="KeyboardDisplay",
        auth_req_value=C553973_AUTH_REQ,
        wait_for_bt=False,
        wait_for_ble1=False,
    )
    assert ok, f" slave link ({C553973_SLAVE_ADV_NAME}) connect failed"
    time.sleep(POST_PAIR_SETTLE_SEC)
    time.sleep(2)
    found, _ = _c553973_wait_hostlog(
        bus, C553973_SLAVE_BOND_MARKERS, require_all=False, baseline=log_start
    )
    assert found, f" slave bond hostlog markers missing"
    assert _ms_wait_slave_count_hostlog(
        bus,
        1,
        baseline=log_start,
        operational_ok=True,
    ), f" slave link hostlog verification failed"
    peer_addr = ble_client.interfaces.bluetooth.get_address()
    assert peer_addr, f" Raspi peer address unavailable after slave connect"
    peer_addr = peer_addr.strip().upper()
    logger().info(f" Steps 17–18: slave link bonded @ {peer_addr}")
    return peer_addr, log_start


def _c553973_ensure_dual_links(
    wifi_dut, master_client, slave_client, dut_address: str, bus, *, case_id: str
) -> Tuple[str, int]:
    """
    Establish 1 master + 1 slave and verify both are still up before returning.
    Uses two peers (scanner and advertiser): ``master_client`` is the central
    that connects to the DUT, ``slave_client`` advertises ``slave11`` for the DUT to
    connect to as central. Separate peers are required, a master and a slave link
    cannot coexist between the same pair of addresses, and each role setup restarts
    bluetoothd on its own Raspi.
    """
    slave_peer_addr: Optional[str] = None
    slave_baseline = 0

    for attempt in range(1, C553973_LINK_SETUP_ATTEMPTS + 1):
        if not _ms_raspi_link_up(master_client, dut_address):
            _c553973_connect_master(
                wifi_dut, master_client, dut_address, bus, case_id=case_id
            )
            time.sleep(STEP_SETTLE_SEC)
        if slave_peer_addr is None or _ms_peer_dropped_since(
            bus, slave_peer_addr, slave_baseline
        ):
            slave_peer_addr, slave_baseline = _c553973_connect_slave(
                wifi_dut, slave_client, dut_address, bus, case_id=case_id
            )
        time.sleep(POST_PAIR_SETTLE_SEC)

        master_up = _ms_raspi_link_up(master_client, dut_address)
        slave_up = not _ms_peer_dropped_since(bus, slave_peer_addr, slave_baseline)
        if master_up and slave_up:
            logger().info(
                f" dual links verified up (attempt {attempt}): "
                f"master via Raspi central, slave @ {slave_peer_addr}"
            )
            return slave_peer_addr, slave_baseline

        down = "master" if not master_up else f"slave ({slave_peer_addr})"
        reason = _ms_last_drop_reason(bus, slave_baseline)
        detail = f", last hostlog disconnect reason {reason}" if reason else ""
        if attempt < C553973_LINK_SETUP_ATTEMPTS:
            logger().warning(
                f" {down} link dropped right after bonding{detail} — rebuilding"
            )
            continue
        raise AssertionError(
            f" {down} link dropped before the stability window could "
            f"start, after {C553973_LINK_SETUP_ATTEMPTS} attempts{detail}"
        )

    raise AssertionError(f" dual links could not be established")


def _c553973_monitor_stability(
    master_client,
    dut_address: str,
    bus,
    *,
    case_id: str,
    slave_peer_addr: Optional[str] = None,
    stability_baseline: Optional[int] = None,
    duration: float = C553973_STABILITY_SEC,
):
    """
    TestRail step 19 — operational dual-link stability.

    Same wearables hostlog behaviour as C553972: scan noise hides slave-count
    and streaming markers in a rolling window. Master via Raspi status; slave
    via disconnect detection since ``stability_baseline``.
    """
    if stability_baseline is None:
        stability_baseline = len(bus.get_input_log())
    logger().info(
        f" Step 19: monitor dual links for {duration:.0f}s "
        "(operational checks — not rolling slave-count/streaming hostlog)"
    )
    start = time.time()
    while time.time() - start < duration:
        elapsed = time.time() - start
        master_up = _ms_raspi_link_up(master_client, dut_address)
        slave_dropped = bool(slave_peer_addr) and _ms_peer_dropped_since(
            bus, slave_peer_addr, stability_baseline
        )
        if not master_up or slave_dropped:
            reason = _ms_last_drop_reason(bus, stability_baseline)
            detail = f", hostlog disconnect reason {reason}" if reason else ""
            link = "master" if not master_up else f"slave ({slave_peer_addr})"
            raise AssertionError(
                f" {link} link dropped {elapsed:.0f}s into the "
                f"{duration:.0f}s stability window{detail}"
            )
        time.sleep(C553973_STABILITY_POLL_SEC)
    logger().info(f" Step 19: stability window complete")


def _c553973_disconnect_all(
    wifi_dut,
    master_client,
    slave_client,
    dut_address: str,
    slave_peer_addr: Optional[str],
    *,
    case_id: str,
):
    """Disconnect both Central (Raspi master) and Peripheral (DUT slave link)."""
    del case_id
    logger().info("Disconnect central (Raspi→DUT) and peripheral (DUT→Raspi slave)")
    try:
        if _ms_peer_bt_ready(
            master_client, label="master disconnect"
        ):
            try:
                connected = bool(
                    master_client.interfaces.bluetooth.get_connection_status(
                        dut_address
                    )
                )
            except Exception:
                connected = True
            if connected:
                master_client.interfaces.bluetooth.disconnect(dev_addr=dut_address)
            else:
                logger().info("central link already down")
    except Exception as exc:
        logger().warning(f"central disconnect: {exc}")
    time.sleep(POST_DISCONNECT_SETTLE_SEC)
    safe_dut_btc_disconnect(wifi_dut, slave_peer_addr)
    try:
        if _ms_peer_bt_ready(
            slave_client, label="slave stop_adv"
        ):
            slave_client.interfaces.bluetooth.stop_advertising()
    except Exception:
        pass
    time.sleep(STEP_SETTLE_SEC)


@pytest.mark.ble_clients(["raspi_ble_client", "secondary_raspi_ble_client"])
@pytest.mark.test_src_map_id(CASE_ID_C553973)
def test_ble_dual_role_1master_1slave_stability_C553973(wifi_dut, ble_clients):
    """
    TestRail C553973 — dual-role BLE stability (1 master + 1 slave).

    Harness: 1 DUT + 2 Raspi (``ble_clients``), matching TestRail's two phones:
      • ``raspi_ble_client`` — central; connects to the DUT (DUT peripheral, master link)
      • ``secondary_raspi_ble_client`` — peripheral ``slave11``; DUT connects as central

    """
    case_id = CASE_ID_C553973
    assert len(ble_clients) >= 2, (
        f" requires 2 ble_clients (1 central + 1 peripheral); "
        f"got {len(ble_clients)}"
    )

    bus = _c553973_bus(wifi_dut)
    master_client = ble_clients[0]
    slave_client = ble_clients[1]
    dut_address = None
    slave_peer_addr: Optional[str] = None

    try:
        # --- TestRail step 14: DUT advertising + scanning hostlog ---
        hostlog = _ensure_dut_ble_ready(
            wifi_dut,
            bus,
            init_settle_sec=C553973_DUT_INIT_SETTLE_SEC,
        )
        for marker in C553973_STEP14_OPTIONAL_MARKERS:
            if marker not in hostlog:
                logger().warning(f"Step 14: optional init marker not seen: {marker}")

        dut_adv_name = (
            _parse_dut_name_from_hostlog(hostlog)
            or _CACHED_DUT_ADV_NAME
            or BLE_UNIFIED_DEMO_ADV_NAME
        )
        dut_address = _resolve_dut_bd_address(
            wifi_dut,
            hostlog,
            step="14",
            ble_client=master_client,
            dut_names=(dut_adv_name, DUT_ADV_NAME, BLE_UNIFIED_DEMO_ADV_NAME),
        )
        logger().info(f"Step 14: DUT BD address {dut_address}, adv name '{dut_adv_name}'")

        # --- TestRail steps 15–18: establish 1 master + 1 slave ---
        slave_peer_addr, _ = _c553973_ensure_dual_links(
            wifi_dut, master_client, slave_client, dut_address, bus, case_id=case_id
        )

        # --- TestRail step 19: 10 min stability ---
        stability_baseline = len(bus.get_input_log())
        time.sleep(POST_PAIR_SETTLE_SEC)
        time.sleep(2)
        _c553973_monitor_stability(
            master_client,
            dut_address,
            bus,
            case_id=case_id,
            slave_peer_addr=slave_peer_addr,
            stability_baseline=stability_baseline,
        )

        # --- TestRail step 20: disconnect all ---
        logger().info("Step 20: disconnect central and peripheral")
        _c553973_disconnect_all(
            wifi_dut,
            master_client,
            slave_client,
            dut_address,
            slave_peer_addr,
            case_id=case_id,
        )
        slave_peer_addr = None

        # --- TestRail steps 21–22: re-establish slave then master ---
        logger().info("Step 21: re-advertise slave, DUT reconnects")
        slave_peer_addr, _ = _c553973_connect_slave(
            wifi_dut, slave_client, dut_address, bus, case_id=case_id
        )

        logger().info("Step 22: Raspi scan/connect to DUT (master)")
        _c553973_connect_master(
            wifi_dut, master_client, dut_address, bus, case_id=case_id
        )

        # --- TestRail step 23: disconnect both Central and Peripheral 5 times ---
        logger().info(
            f"Step 23: disconnect both central and peripheral "
            f"{C553973_RECONNECT_CYCLES} times"
        )
        for cycle in range(1, C553973_RECONNECT_CYCLES + 1):
            logger().info(
                f"Step 23 cycle {cycle}/{C553973_RECONNECT_CYCLES}: "
                "disconnect central + peripheral"
            )
            _c553973_disconnect_all(
                wifi_dut,
                master_client,
                slave_client,
                dut_address,
                slave_peer_addr,
                case_id=case_id,
            )
            slave_peer_addr = None
            time.sleep(STEP_SETTLE_SEC)
            # Re-establish both roles before the next disconnect cycle (except after the last disconnect).
            if cycle < C553973_RECONNECT_CYCLES:
                logger().info(
                    f"Step 23 cycle {cycle}: re-establish dual links for next disconnect"
                )
                slave_peer_addr, _ = _c553973_ensure_dual_links(
                    wifi_dut,
                    master_client,
                    slave_client,
                    dut_address,
                    bus,
                    case_id=case_id,
                )
                time.sleep(STEP_SETTLE_SEC)

        logger().info(
            f"Step 23: completed {C553973_RECONNECT_CYCLES} central+peripheral disconnects"
        )

    finally:
        if dut_address:
            try:
                _c553973_disconnect_all(
                    wifi_dut,
                    master_client,
                    slave_client,
                    dut_address,
                    slave_peer_addr,
                    case_id=case_id,
                )
            except Exception as exc:
                logger().warning(f"finally disconnect_all: {exc}")
            _suite_finally_cleanup(
                wifi_dut,
                list(ble_clients),
                dut_address,
                slave_peer_addrs=[slave_peer_addr] if slave_peer_addr else [],
            )

    logger().info(
        f"dual-role stability + "
        f"{C553973_RECONNECT_CYCLES}x central/peripheral disconnect"
    )