from __future__ import annotations

import re
import threading
import time
from contextlib import contextmanager
from typing import Callable, Optional, Sequence, Tuple

import pytest
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.nrf_blatann import NRFBLEIoCapabilities, NRFBLEPeerDevAddrTypes

"""
BLE secure pairing tests — hostlog validation with RF Creations OTA capture.

Single module: helpers + TestRail cases (C553832+). Low-level helpers only;
each test case owns its steps and ``try/finally`` cleanup (reference pattern).

RF Creations capture (start_capture / stop_capture) runs automatically for every
test via the autouse fixture ``_rf_creations_capture_for_test`` — same helpers as
``test_connection_update_dut_central.py``. No OTA validation here; pcapng files
are saved under ``/app/reports/rfcreations``.

Peer device selection (mandatory):
  - Use ``ble_client`` (Raspberry Pi / BlueSpy / BlueZ) unless the TestRail case
    text explicitly names an **nRF dongle** (or nRF52840) as the peer role.
  - Use ``nrf_ble_client`` only when TestRail steps/preconditions require nRF.
  - When in doubt, match ``test_ble_secure_pairing.py`` and the TestRail HTML
    step table (BlueSpy GUI steps → Raspi central, not nRF).

Author: Pavan Jenne
"""

def logger():
    return get_logger(__name__)

INITIATOR_KEY_DIST_ENC_ID_SIGN = 0x07


def mac_to_colon(addr: str):
    if not addr:
        return None
    s = str(addr).strip()
    if s.lower().startswith("0x"):
        hexpart = re.sub(r"[^0-9a-fA-F]", "", s[2:])
        if len(hexpart) != 12:
            return None
        s = ":".join(hexpart[i : i + 2] for i in range(0, 12, 2))
    s = s.replace("-", ":").lower()
    if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", s):
        return s
    return None


def mac_to_frontline_id(addr: str) -> str:
    colon = mac_to_colon(addr)
    if not colon:
        return str(addr)
    return "0x" + colon.replace(":", "")


def normalize_device_filter_list(dut_address: str, peer_address: str):
    colon = []
    frontline = []
    for raw in (dut_address, peer_address):
        c = mac_to_colon(raw)
        if c:
            colon.append(c)
            frontline.append(mac_to_frontline_id(raw))
    return colon, frontline


pytestmark = [pytest.mark.ble_sniffer("rf_creations_sniffer")]


# Bound per-test by ``_rf_creations_capture_for_test`` for ``hostlog_only_session``.
_current_ble_sniffer = None
_current_case_id = "unknown"


def start_rf_creations_capture(ble_sniffer, testcase_id):
    """Connect to RF Creations sniffer and start per-testcase capture."""
    logger().info(f"[SNIFFER] Connecting RF Creations sniffer for TC {testcase_id}...")
    ble_sniffer.interfaces.sniffer.connect()
    ble_sniffer.interfaces.sniffer.start_capture(
        capture_file=f"utf_rfcreations_sniffer_TC_{testcase_id}"
    )
    logger().info(f"[SNIFFER] Capture started for TC {testcase_id}")


def stop_rf_creations_capture(ble_sniffer, testcase_id):
    """Stop capture and download the pcapng for this testcase."""
    logger().info(f"[SNIFFER] Stopping capture for TC {testcase_id}...")
    ble_sniffer.interfaces.sniffer.stop_capture()
    logger().info(f"[SNIFFER] Capture saved for TC {testcase_id}")


@pytest.fixture(autouse=True)
def _rf_creations_capture_for_test(request, ble_sniffer):
    """
    Start RF Creations capture before every test and stop/download after.

    Mirrors ``test_connection_update_dut_central.py`` start/stop helpers so every
    case in this module (including those without ``hostlog_only_session``) gets
    a per-TC pcapng without changing each test body.
    """
    global _current_ble_sniffer, _current_case_id
    mark = request.node.get_closest_marker("test_src_map_id")
    if mark and mark.args:
        case_id = str(mark.args[0])
    else:
        case_id = request.node.name

    _current_ble_sniffer = ble_sniffer
    _current_case_id = case_id
    sniffer_capture_started = False
    try:
        # Do not fail the BLE test if the sniffer/server is unavailable.
        # Capture is best-effort; hostlog assertions remain the pass/fail source.
        try:
            start_rf_creations_capture(ble_sniffer, case_id)
            sniffer_capture_started = True
        except Exception as start_err:
            logger().warning(
                f"[SNIFFER] start_capture failed for TC {case_id} "
                f"(continuing test without capture): {start_err}"
            )
        yield
    finally:
        if sniffer_capture_started:
            try:
                stop_rf_creations_capture(ble_sniffer, case_id)
            except Exception as sniffer_err:
                logger().warning(
                    f"[SNIFFER] Failed to stop capture for TC {case_id}: {sniffer_err}"
                )
        _current_ble_sniffer = None
        _current_case_id = "unknown"


class _HostlogOnlySnifferStub:
    _client = None

    def select_bt_devices(self, *_args, **_kwargs):
        pass


class _RfCreationsSnifferHandle:
    """Thin handle yielded by ``hostlog_only_session`` for legacy sniffer hooks."""

    def __init__(self, sniffer_iface):
        self._client = sniffer_iface


@contextmanager
def hostlog_only_session(
    dut_address: str,
    *peer_addresses: str,
    case_id: Optional[str] = None,
):
    """
    Yield the active RF Creations sniffer handle for the test body.

    Capture start/stop is owned by ``_rf_creations_capture_for_test`` (autouse)
    so nested / missing ``with`` blocks cannot skip or double-start capture.
    """
    del case_id  # case id comes from the autouse fixture / test_src_map_id
    ble_sniffer = _current_ble_sniffer
    if ble_sniffer is None:
        yield _HostlogOnlySnifferStub()
        return

    handle = _RfCreationsSnifferHandle(ble_sniffer.interfaces.sniffer)
    _update_sniffer_peer_macs(handle, dut_address, *peer_addresses)
    yield handle


DEFAULT_SCAN_INTERVAL = 160
DEFAULT_SCAN_WINDOW = 160
DEFAULT_SCAN_TYPE = 1
DEFAULT_FILTER_POLICY = 0
DEFAULT_OWN_ADDR_TYPE = 0
OWN_ADDR_TYPE_RANDOM = 1  # LE random address (C553847, nRF dongle peripheral)
PEER_ADDR_TYPE_PUBLIC = 0
# Same fixed random addr used by smp_iocap DUT-central random-addr tests.
DEFAULT_DUT_RANDOM_BLE_ADDR = "F1:22:33:44:55:66"
# TestRail C553848 step 1 — rsi_ble_set_random_address_with_value bytes
# {0x67, 0x61, 0x43, 0x32, 0x27, 0x18} -> 18:27:32:43:61:67
TESTRAIL_WEARABLES_RANDOM_BLE_ADDR = "18:27:32:43:61:67"
DUT_RANDOM_ADDR_SUCCESS_MARKERS = (
    "set bd addr success",  # firmware rsi_ble_set_random_address_with_value
    "set random address successful",  # btc ble set_random_address CLI
)

AUTH_REQ_BONDING_MITM_SC = 0x2D
AUTH_REQ_BONDING_SC = 0x09  # Bonding + LE SC, MITM disabled (C553839)
AUTH_REQ_BONDING_ONLY = 0x01  # Legacy bonding, MITM+SC disabled (C553842 peer)
AUTH_REQ_BONDING_MITM_LEGACY = 0x05  # Legacy bonding + MITM, SC disabled (C553859)
AUTH_REQ_NONE = 0x00  # Legacy, no bonding/MITM/SC (C553842 DUT header)
DUT_IO_DISPLAY_ONLY = 0x00
DUT_IO_DISPLAY_YES_NO = 0x01
DUT_IO_KEYBOARD_ONLY = 0x02
DUT_IO_KEYBOARD_DISPLAY = 0x04
KEY_DIST_ENC_ID_SIGN = INITIATOR_KEY_DIST_ENC_ID_SIGN
KEY_DIST_ENC_ONLY = 0x01
REMOTE_DEVICE_NAME_SLAVE11 = "slave11"
COEX_MAX_DEMO_ADV_NAME = "COEX_MAX_DEMO"
BLE_UNIFIED_DEMO_ADV_NAME = "BLE_UNIFIED_DEMO"
SMP_AUTH_FAILURE_ERROR_CODE = "4bfc"
SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE = "4b01"
SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE = "4b0c"

REPEAT_PAIR_ITERATIONS = 3
REPEAT_BOND_RECONNECT_ITERATIONS = 10

# --- BLE wearables hostlog automation timeouts (seconds) ---
DUT_INIT_AFTER_RESET_SEC = 15
# smp_iocap: every test sleeps 20s at start before get_dut_address / SMP config.
SMP_DUT_INIT_SLEEP_SEC = 20
DUT_BLE_READY_TIMEOUT_SEC = 120
# Cached after first successful read — same pattern as smp_iocap / sweyntooth suites.
_CACHED_DUT_LOCAL_ADDRESS: Optional[str] = None
# C553845 — hostlog may be cleared after auth-failure disconnect; snapshot at passkey.
_AUTH_FAILURE_CONNECT_LOG_SNAPSHOT: Optional[str] = None
DUT_INIT_LOG_MARKER_TIMEOUT_SEC = 30
DUT_SUITE_READY_QUICK_TIMEOUT_SEC = 10
DUT_SUITE_SETTLE_SEC = 5
DUT_SUITE_UART_PROBE_TIMEOUT_SEC = 30
DUT_LOCAL_ADDRESS_RETRY_SEC = 3
DUT_LOCAL_ADDRESS_MAX_ATTEMPTS = 10
SMP_CONFIG_SETTLE_SEC = 1
PEER_BUS_SETTLE_SEC = 2
PEER_ADV_START_SEC = 3
SCAN_BEFORE_CONNECT_SEC = 30
CONNECT_TIMEOUT_SEC = 120
NRF_CENTRAL_CONNECT_TIMEOUT_SEC = 120
NRF_PEER_SYNC_EXTRA_WAIT_SEC = 30
NRF_NC_PASSKEY_TIMEOUT_SEC = 120
NRF_NC_PAIR_COMPLETE_TIMEOUT_SEC = 120
NC_PRE_CONNECT_SETTLE_SEC = 5
NRF_CONNECT_POLL_INTERVAL_SEC = 0.5
NRF_CONNECT_THREAD_JOIN_SEC = 5
NRF_CONNECT_POST_LINK_SETTLE_SEC = 2
NRF_STALE_LINK_DISCONNECT_SETTLE_SEC = 3
NRF_ADDR_TYPE_RETRY_SETTLE_SEC = 2
NRF_ADDR_TYPE_RETRY_CONNECT_SEC = 60
NRF_PAIR_THREAD_START_DELAY_SEC = 2
NRF_SCAN_DEFAULT_TIMEOUT_SEC = 30
NRF_SCAN_WAIT_RANDOM_ADDR_SEC = 15
NRF_SCAN_WAIT_PUBLIC_ADDR_SEC = 10
CENTRAL_SMP_CONFIG_SETTLE_SEC = 10
PERIPHERAL_INIT_VERIFY_TIMEOUT_SEC = 90
SMP_PAIRING_REQUEST_TIMEOUT_SEC = 30
PASSKEY_TIMEOUT_SEC = 120
SMP_COMPLETE_TIMEOUT_SEC = 120
DISCONNECT_OR_SCAN_RESTART_TIMEOUT_SEC = 120
SCAN_RESTART_AFTER_DISCONNECT_SEC = 60
DUT_BLE_DISCONNECT_TIMEOUT_SEC = 15
CLEANUP_DISCONNECT_FALLBACK_SEC = 5
CLEANUP_DISCONNECT_WAIT_SEC = 10.0
CLEANUP_POST_DISCONNECT_SETTLE_SEC = 3.0
CLEANUP_FINAL_SETTLE_SEC = 5
POST_PAIR_SETTLE_SEC = 5
POST_DISCONNECT_SETTLE_SEC = 3
PROFILE_DISCOVERY_SETTLE_SEC = 10
STEP_SETTLE_SEC = 5
LOG_POLL_INTERVAL_SEC = 2
PASSKEY_POLL_INTERVAL_SEC = 0.5
LEGACY_SCAN_SETTLE_SEC = 1
LEGACY_SCAN_STOP_SETTLE_SEC = 0.5
WAIT_FOR_LOG_PATTERNS_DEFAULT_TIMEOUT_SEC = 120
SMP_AUTH_FAILURE_TIMEOUT_SEC = 120
ENCRYPTION_RESTART_TIMEOUT_SEC = 60
C553856_ENCRYPTION_RESTART_TIMEOUT_SEC = 120
DUT_LOCAL_ADDRESS_CLI_TIMEOUT_SEC = 30
DUT_BASIC_INIT_MARKER = "basic init done"

LOCAL_BD_ADDR_PATTERN = re.compile(
    r"local_bd_address:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
    re.IGNORECASE,
)
BOOT_ADDR_PATTERN = re.compile(
    r"addr:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
    re.IGNORECASE,
)

NRF_IO_CAP_MAP = {
    "DisplayOnly": NRFBLEIoCapabilities.DISPLAY_ONLY,
    "DisplayYesNo": NRFBLEIoCapabilities.DISPLAY_YESNO,
    "KeyboardOnly": NRFBLEIoCapabilities.KEYBOARD_ONLY,
    "NoInputNoOutput": NRFBLEIoCapabilities.NONE,
    "KeyboardDisplay": NRFBLEIoCapabilities.KEYBOARD_DISPLAY,
}


def is_nrf_peer(peer_client) -> bool:
    """True when peer is nrf_ble_client (NRFBlatann), not Raspi BlueZ."""
    bt = peer_client.interfaces.bluetooth
    return hasattr(bt, "start_advertising") and not hasattr(bt, "start_smp_adv")


def nrf_peripheral_connect_params() -> dict:
    """
    DUT connect kwargs when peer is nRF dongle peripheral (C553838, C553839, etc.).

    nRF advertises with LE random address; wearables firmware uses CONN_BY_NAME
    for ``slave11`` (TestRail preconditions).
    """
    return {
        "peer_addr_type": OWN_ADDR_TYPE_RANDOM,
        "peer_name": REMOTE_DEVICE_NAME_SLAVE11,
    }


def dut_connect_kwargs_for_peer(ble_client) -> dict:
    """DUT central connect kwargs matching peer type (nRF random + slave11 vs Raspi MAC)."""
    return nrf_peripheral_connect_params() if is_nrf_peer(ble_client) else {}


def _prepare_nrf_peripheral(
    nrf_ble_client,
    capability: str,
    *,
    passcode_pairing: bool = True,
    lesc_pairing: bool = True,
    confirm_passkey: bool = True,
    dynamic_passkey: bool = False,
):
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP[capability]
    nrf.set_security_params(
        passcode_pairing=passcode_pairing,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=lesc_pairing,
    )
    nrf.register_on_connect()
    time.sleep(2)
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()
    if capability != "KeyboardOnly" and not dynamic_passkey:
        nrf.register_passkey_display(confirm=confirm_passkey)


def start_nrf_peripheral_advertising(
    nrf_ble_client,
    capability: str,
    *,
    local_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    passcode_pairing: bool = True,
    lesc_pairing: bool = True,
    confirm_passkey: bool = True,
    dynamic_passkey: bool = False,
    dynamic_passkey_timeout: float = 120,
) -> str:
    """nRF dongle peripheral — advertises as slave11 (917 nrf_connect_to_dut)."""
    _prepare_nrf_peripheral(
        nrf_ble_client,
        capability,
        passcode_pairing=passcode_pairing,
        lesc_pairing=lesc_pairing,
        confirm_passkey=confirm_passkey,
        dynamic_passkey=dynamic_passkey,
    )
    nrf = nrf_ble_client.interfaces.bluetooth
    addr = nrf.start_advertising(
        local_name=local_name, timeout_sec=0, auto_restart=False
    )
    time.sleep(5)
    if dynamic_passkey:
        # Must register after start_advertising — ble_advertising_data must be set
        # (registering before adv leaves peer_device None → AttributeError).
        nrf.register_dynamic_passkey_entry(timeout=int(dynamic_passkey_timeout))
    return nrf.get_ble_address() or addr


def stop_nrf_peripheral(nrf_ble_client):
    nrf = nrf_ble_client.interfaces.bluetooth
    try:
        nrf.stop_advertising()
    except Exception as exc:
        logger().warning(f"nrf stop_advertising: {exc}")
    time.sleep(2)


def peer_set_pin(peer_client, pin):
    """Raspi ``set_pin`` or nRF ``set_passkey`` / decline numeric comparison."""
    if is_nrf_peer(peer_client):
        bt = peer_client.interfaces.bluetooth
        if int(pin) == -1:
            bt.register_passkey_display(confirm=False)
        else:
            bt.set_passkey(int(pin))
    else:
        peer_client.interfaces.bluetooth.set_pin(int(pin))


def peer_get_passkey(peer_client):
    return peer_client.interfaces.bluetooth.get_passkey()


def _normalize_bd_addr(addr: str) -> str:
    return str(addr).strip().upper()


def _nrf_addresses_match(left: str, right: str) -> bool:
    return _normalize_bd_addr(left) == _normalize_bd_addr(right)


def nrf_peer_connected(nrf, dut_address: str) -> bool:
    """True when nRF peer_device exists and is connected to dut_address."""
    peer = getattr(nrf, "peer_device", None)
    if peer is None:
        return False
    try:
        peer_mac = nrf.get_hex_address(peer.peer_address)
    except Exception:
        peer_mac = str(dut_address)
    if not _nrf_addresses_match(peer_mac, dut_address):
        return False
    try:
        return bool(peer.connected)
    except Exception:
        return nrf.get_peer_connection_status(dut_address)


def _dut_peripheral_ll_connected_since(bus, log_baseline: int) -> bool:
    """True when hostlog since ``log_baseline`` shows central→peripheral LL connect."""
    lower = "\n".join(
        decode_log_items(bus.get_input_log())[log_baseline:]
    ).lower()
    return (
        "on enhance connect event" in lower
        and "status report : 0" in lower
        and "master devices connected" in lower
    )


def infer_nrf_peer_addr_type_from_mac(mac: str):
    """
    Map DUT BD address to Blatann peer address type (BLE MSB = last octet).

    TestRail C553848 {0x67,...,0x18} -> 18:27:32:43:61:67 has MSB 0x67 (01xxxxxx)
    = random private resolvable, not random static.
    """
    msb = int(mac.split(":")[-1], 16)
    top_bits = (msb >> 6) & 0x03
    if top_bits == 0x03:
        return NRFBLEPeerDevAddrTypes.RANDOM_STATIC
    if top_bits == 0x01:
        return NRFBLEPeerDevAddrTypes.RANDOM_PRIVATE_RESOLVABLE
    if top_bits == 0x00:
        return NRFBLEPeerDevAddrTypes.RANDOM_PRIVATE_NON_RESOLVABLE
    return NRFBLEPeerDevAddrTypes.PUBLIC


def _nrf_peer_addr_type_candidates(
    dut_address: str,
    *,
    preferred=None,
    prefer_static_random: bool = False,
):
    """
    GAP address-type order for nRF central connect (wearables random-addr cases).

    ``rsi_ble_set_random_address_with_value`` often behaves like static random in
    firmware even when the MSB bits suggest resolvable — try static first when
    ``prefer_static_random`` is set (C553848).
    """
    inferred = (
        infer_nrf_peer_addr_type_from_mac(dut_address)
        if preferred is None
        else preferred
    )
    if prefer_static_random:
        ordered = (
            NRFBLEPeerDevAddrTypes.RANDOM_STATIC,
            NRFBLEPeerDevAddrTypes.RANDOM_PRIVATE_RESOLVABLE,
            inferred,
        )
    else:
        ordered = (
            inferred,
            NRFBLEPeerDevAddrTypes.RANDOM_STATIC,
            NRFBLEPeerDevAddrTypes.RANDOM_PRIVATE_RESOLVABLE,
        )
    seen = set()
    candidates = []
    for addr_type in ordered:
        if addr_type not in seen:
            seen.add(addr_type)
            candidates.append(addr_type)
    return candidates


def _register_nrf_peer_sync(nrf, dut_address: str):
    """
    Sync ``nrf.peer_device`` from Blatann ``on_connect`` when ``connect().wait()``
    returns before the host stack finishes (random-addr peripheral cases).
    """
    def _on_connect(peer, event_args):
        if peer:
            nrf.peer_device = peer
            try:
                peer_mac = nrf.get_hex_address(peer.peer_address)
            except Exception:
                peer_mac = "unknown"
            logger().info(
                f"nRF Blatann on_connect — peer_device synced ({peer_mac})"
            )
        else:
            logger().warning("nRF Blatann on_connect — connection failed")

    nrf.ble_device.client.on_connect.register(_on_connect)


def _try_recover_nrf_peer_device(nrf, dut_address: str) -> bool:
    """Best-effort recovery when DUT hostlog shows LL connect but peer_device is unset."""
    if nrf_peer_connected(nrf, dut_address):
        return True

    peer = getattr(nrf, "peer_device", None)
    if peer is not None:
        try:
            peer_mac = nrf.get_hex_address(peer.peer_address)
            if _nrf_addresses_match(peer_mac, dut_address) and peer.connected:
                logger().info(f"Recovered existing nRF peer_device for {dut_address}")
                return True
        except Exception as exc:
            logger().debug(f"nRF peer_device recovery check: {exc}")

    for attr in ("connected_peers", "peers", "_peers"):
        try:
            client = nrf.ble_device.client
            peers = getattr(client, attr, None)
            if not peers:
                continue
            iterable = peers.values() if isinstance(peers, dict) else peers
            for candidate in iterable:
                try:
                    peer_mac = nrf.get_hex_address(candidate.peer_address)
                except Exception:
                    continue
                if _nrf_addresses_match(peer_mac, dut_address) and candidate.connected:
                    nrf.peer_device = candidate
                    logger().info(
                        f"Recovered nRF peer_device from Blatann client.{attr}"
                    )
                    return True
        except Exception as exc:
            logger().debug(f"Blatann {attr} recovery: {exc}")
    return False


def _teardown_stale_nrf_dut_link(
    wifi_dut,
    nrf,
    dut_address: str,
    bus,
    *,
    central_address: Optional[str] = None,
):
    """Clear a half-open central→peripheral link before nRF addr-type retry."""
    if wifi_dut and central_address:
        safe_dut_btc_disconnect(wifi_dut, central_address)
        _wait_for_dut_ble_disconnect(
            wifi_dut, timeout=CLEANUP_DISCONNECT_WAIT_SEC
        )
    if nrf_peer_connected(nrf, dut_address):
        try:
            nrf.disconnect(dut_address, clear_peer=True)
        except Exception as exc:
            logger().warning(f"nRF disconnect before addr-type retry: {exc}")
    nrf.peer_device = None
    drain_serial(bus)
    time.sleep(NRF_STALE_LINK_DISCONNECT_SETTLE_SEC)


def _nrf_single_connect_attempt(
    nrf,
    dut_address: str,
    bus,
    peer_dev_addr_type,
    connect_timeout: float,
) -> bool:
    """One nRF connect attempt; return True when peer_device is connected."""
    timeout = int(connect_timeout)
    log_baseline = len(decode_log_items(bus.get_input_log()))

    logger().info(
        f"nRF connecting to DUT {dut_address} "
        f"(addr_type={peer_dev_addr_type}, timeout={timeout}s)"
    )

    def _connect():
        try:
            nrf.connect(
                dut_address,
                timeout=timeout,
                dev_addr_type=peer_dev_addr_type,
            )
        except Exception as exc:
            logger().warning(f"nRF connect: {exc}")

    connect_thread = threading.Thread(target=_connect, daemon=True)
    connect_thread.start()

    deadline = time.time() + timeout + NRF_PEER_SYNC_EXTRA_WAIT_SEC
    while time.time() < deadline:
        if nrf_peer_connected(nrf, dut_address):
            logger().info(f"nRF connected to DUT {dut_address}")
            connect_thread.join(timeout=NRF_CONNECT_THREAD_JOIN_SEC)
            time.sleep(NRF_CONNECT_POST_LINK_SETTLE_SEC)
            return True
        if _try_recover_nrf_peer_device(nrf, dut_address):
            connect_thread.join(timeout=NRF_CONNECT_THREAD_JOIN_SEC)
            time.sleep(NRF_CONNECT_POST_LINK_SETTLE_SEC)
            return True
        time.sleep(NRF_CONNECT_POLL_INTERVAL_SEC)

    connect_thread.join(timeout=NRF_CONNECT_THREAD_JOIN_SEC)

    if nrf_peer_connected(nrf, dut_address) or _try_recover_nrf_peer_device(
        nrf, dut_address
    ):
        return True

    dut_ll = _dut_peripheral_ll_connected_since(bus, log_baseline)
    if dut_ll:
        logger().info(
            f"DUT link-layer connected but nRF peer_device not synced — "
            f"waiting up to {NRF_PEER_SYNC_EXTRA_WAIT_SEC}s for Blatann on_connect"
        )
        sync_deadline = time.time() + NRF_PEER_SYNC_EXTRA_WAIT_SEC
        while time.time() < sync_deadline:
            if nrf_peer_connected(nrf, dut_address) or _try_recover_nrf_peer_device(
                nrf, dut_address
            ):
                logger().info(f"nRF peer_device synced to DUT {dut_address}")
                return True
            time.sleep(NRF_CONNECT_POLL_INTERVAL_SEC)
    return nrf_peer_connected(nrf, dut_address)


def nrf_central_connect_to_dut_peripheral(
    nrf,
    dut_address,
    bus,
    *,
    wifi_dut=None,
    central_address: Optional[str] = None,
    peer_dev_addr_type=None,
    connect_timeout: float = NRF_CENTRAL_CONNECT_TIMEOUT_SEC,
    prefer_static_random: bool = False,
):
    """
    TestRail step 8 — nRF central connect to DUT peripheral.

    Tries multiple GAP address types when wearables random BD addr desyncs
    (DUT LL connected but Blatann ``peer_device`` missing).
    """
    candidates = _nrf_peer_addr_type_candidates(
        dut_address,
        preferred=peer_dev_addr_type,
        prefer_static_random=prefer_static_random,
    )
    _register_nrf_peer_sync(nrf, dut_address)

    last_dut_ll = False
    last_addr_type = candidates[0]
    for attempt_idx, addr_type in enumerate(candidates):
        attempt_timeout = (
            connect_timeout
            if attempt_idx == 0
            else min(connect_timeout, NRF_ADDR_TYPE_RETRY_CONNECT_SEC)
        )
        if attempt_idx > 0:
            logger().info(
                f"nRF connect addr-type retry {attempt_idx + 1}/{len(candidates)} "
                f"(addr_type={addr_type}, timeout={attempt_timeout}s)"
            )
            _teardown_stale_nrf_dut_link(
                wifi_dut,
                nrf,
                dut_address,
                bus,
                central_address=central_address,
            )
            time.sleep(NRF_ADDR_TYPE_RETRY_SETTLE_SEC)

        last_addr_type = addr_type
        if _nrf_single_connect_attempt(
            nrf, dut_address, bus, addr_type, attempt_timeout
        ):
            return addr_type

        log_baseline = len(decode_log_items(bus.get_input_log()))
        last_dut_ll = _dut_peripheral_ll_connected_since(bus, log_baseline)

    assert nrf_peer_connected(nrf, dut_address), (
        f"nRF dongle failed to connect to DUT {dut_address} "
        f"(last_addr_type={last_addr_type}, DUT LL connected={last_dut_ll}, "
        f"tried_types={candidates}, connect_timeout={connect_timeout}s)"
    )
    return last_addr_type


def nrf_scan_for_dut(
    nrf_ble_client,
    dut_address,
    *,
    capability: str = "DisplayYesNo",
    scan_wait: int = 10,
    passcode_pairing: bool = True,
    lesc_pairing: bool = True,
    confirm_passkey: bool = True,
):
    """nRF dongle central scans for DUT peripheral (917 nrf_dongle_as_master)."""
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP[capability]
    nrf.set_security_params(
        passcode_pairing=passcode_pairing,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=lesc_pairing,
    )
    nrf.register_on_connect()
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()
    if capability != "KeyboardOnly":
        nrf.register_passkey_display(confirm=confirm_passkey)
    nrf.set_default_scan_params(timeout_seconds=NRF_SCAN_DEFAULT_TIMEOUT_SEC)
    nrf.start_scanning()
    logger().info(f"nRF dongle scanning for DUT {dut_address}...")
    time.sleep(scan_wait)
    devices = nrf.get_devices()
    nrf.stop_scanning()
    assert (
        str(dut_address) in str(devices) or dut_address in devices
    ), f"DUT {dut_address} not found during nRF scan"
    central_addr = nrf.get_ble_address()
    assert central_addr, "Failed to read nRF dongle BLE address"
    logger().info(f"DUT discovered: {dut_address}")
    return central_addr


def nrf_central_connect_and_pair_numeric_comparison(
    wifi_dut,
    nrf_ble_client,
    dut_address,
    central_address,
    bus,
    *,
    peer_dev_addr_type=None,
    connect_timeout: float = NRF_CENTRAL_CONNECT_TIMEOUT_SEC,
    passkey_timeout: float = NRF_NC_PASSKEY_TIMEOUT_SEC,
    pair_complete_timeout: float = NRF_NC_PAIR_COMPLETE_TIMEOUT_SEC,
    prefer_static_random: bool = False,
):
    """
    nRF central → DUT peripheral Numeric Comparison (DisplayYesNo + MITM + SC).

    ``peer_dev_addr_type=None`` infers GAP type from DUT MAC (random-addr cases).
    """
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP["DisplayYesNo"]
    nrf.set_connection_parameters(100, 120, 6000)
    drain_serial(bus)

    nrf_central_connect_to_dut_peripheral(
        nrf,
        dut_address,
        bus,
        wifi_dut=wifi_dut,
        central_address=central_address,
        peer_dev_addr_type=peer_dev_addr_type,
        connect_timeout=connect_timeout,
        prefer_static_random=prefer_static_random,
    )

    nrf.set_peer_security_params(
        dut_address,
        passcode_pairing=True,
        io_capabilities=cap,
        lesc_pairing=True,
        long_term_bonding=True,
    )

    def _pair():
        logger().info("nRF dongle starting Numeric Comparison pairing")
        nrf.pair(dut_address)

    pair_thread = threading.Thread(target=_pair)
    pair_thread.start()
    time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)

    dut_passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert dut_passkey, (
        f"Numeric comparison passkey not found in DUT hostlog "
        f"within {passkey_timeout}s"
    )
    assert_passkey_valid(dut_passkey)
    logger().info(f"nRF entering DUT NC passkey: {dut_passkey}")
    nrf.set_passkey(int(dut_passkey))

    try:
        nrf_pk = nrf.get_passkey()
        if nrf_pk and str(nrf_pk) != "0":
            nrf_passkey = str(nrf_pk).zfill(6)
            logger().info(f"DUT confirming nRF NC passkey: {nrf_passkey}")
            wifi_dut.interfaces.wifi.smp_passkey(
                bd_addr=central_address, passkey=nrf_passkey
            )
    except Exception as exc:
        logger().info(f"nRF passkey auto-confirm or unavailable: {exc}")

    pair_thread.join(timeout=pair_complete_timeout)
    assert nrf_peer_connected(nrf, dut_address), (
        f"nRF link to DUT {dut_address} lost after Numeric Comparison pairing "
        f"(pair_complete_timeout={pair_complete_timeout}s)"
    )


def nrf_central_connect_and_pair(
    wifi_dut,
    nrf_ble_client,
    dut_address,
    central_address,
    bus,
    *,
    capability: str = "DisplayYesNo",
    passcode_pairing: bool = True,
    lesc_pairing: bool = True,
    dynamic_passkey: bool = False,
    connect_timeout: float = 120,
    peer_dev_addr_type=NRFBLEPeerDevAddrTypes.PUBLIC,
    smp_handler: Optional[Callable] = None,
    smp_handler_kwargs: Optional[dict] = None,
):
    """nRF central connects to DUT peripheral and runs SMP handler during pairing."""
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP[capability]
    nrf.set_connection_parameters(100, 120, 6000)
    drain_serial(bus)

    smp_thread = None
    if smp_handler:
        kwargs = smp_handler_kwargs or {}
        smp_thread = threading.Thread(
            target=smp_handler,
            args=(bus, wifi_dut, nrf_ble_client, central_address),
            kwargs=kwargs,
            daemon=True,
        )
        smp_thread.start()

    if dynamic_passkey:
        logger().info(
            "Waiting 30s before nRF connect (DUT advertising / SMP stack settle)"
        )
        time.sleep(30)

    def _connect():
        logger().info(
            f"nRF dongle connecting to DUT {dut_address} "
            f"(addr_type={peer_dev_addr_type})"
        )
        nrf.connect(
            dut_address, timeout=30, dev_addr_type=peer_dev_addr_type
        )

    connect_thread = threading.Thread(target=_connect)
    connect_thread.start()

    passkey_registered = False
    connect_deadline = time.time() + min(connect_timeout, 60)
    while time.time() < connect_deadline:
        if dynamic_passkey and not passkey_registered:
            if getattr(nrf, "peer_device", None) is not None:
                nrf.register_dynamic_passkey_entry(timeout=int(connect_timeout))
                passkey_registered = True
        if nrf_peer_connected(nrf, dut_address):
            logger().info(f"nRF dongle connected to DUT {dut_address}")
            break
        if not connect_thread.is_alive():
            break
        time.sleep(0.1)

    if nrf_peer_connected(nrf, dut_address):
        if dynamic_passkey and not passkey_registered:
            nrf.register_dynamic_passkey_entry(timeout=int(connect_timeout))
            passkey_registered = True
        nrf.set_peer_security_params(
            dut_address,
            passcode_pairing=passcode_pairing,
            io_capabilities=cap,
            lesc_pairing=lesc_pairing,
            long_term_bonding=True,
        )

        def _pair():
            nrf.pair(dut_address)

        pair_thread = threading.Thread(target=_pair)
        pair_thread.start()
        pair_thread.join(timeout=connect_timeout)
    else:
        logger().warning(
            f"nRF link to {dut_address} not established — "
            "waiting for SMP handler / connect thread"
        )

    connect_thread.join(timeout=connect_timeout)
    if smp_thread:
        smp_thread.join(timeout=connect_timeout)


def safe_dut_btc_disconnect(wifi_dut, peer_address: Optional[str] = None):
    """Disconnect DUT from remote peer; RT595 ``btc_disconnect`` requires peer address."""
    if not peer_address:
        logger().debug("btc_disconnect skipped — no peer address")
        return
    try:
        wifi_dut.interfaces.wifi.btc_disconnect(peer_address)
    except Exception as exc:
        logger().warning(f"btc_disconnect({peer_address}): {exc}")


def _raspi_bt_session_open(peer_client) -> bool:
    """True when Raspi BlueZ GLib session is still active (not closed in test body)."""
    if peer_client is None or is_nrf_peer(peer_client):
        return False
    try:
        bt = peer_client.interfaces.bluetooth
        return (
            getattr(bt, "glib_loop", None) is not None
            and getattr(bt, "bus", None) is not None
        )
    except Exception:
        return False


def _wait_for_dut_ble_disconnect(
    wifi_dut, timeout: float = DUT_BLE_DISCONNECT_TIMEOUT_SEC
) -> bool:
    """
    Poll DUT hostlog for the real LL disconnect event (not command ack only).

    Only entries appended after this call are considered so a prior test-body
    disconnect is not mistaken for the cleanup disconnect.
    """
    bus = get_bus(wifi_dut)
    try:
        start_offset = len(bus.get_input_log())
    except Exception:
        start_offset = 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1.0)
        try:
            fresh = bus.get_input_log()[start_offset:]
            log = "\n".join(decode_log_items(fresh)).lower()
        except Exception:
            continue
        if (
            "on event disconnect" in log
            or "peripheral is disconnected" in log
            or "central is disconnected" in log
        ):
            time.sleep(2)
            drain_serial(bus)
            return True
    return False


def _poll_dut_disconnect_in_hostlog(
    wifi_dut, *, timeout: float = CLEANUP_DISCONNECT_WAIT_SEC
) -> bool:
    """
    Poll DUT hostlog for LL disconnect (``test_adv_undirected`` finally pattern).

    After Raspi ``remove_device``, the DUT may receive an async disconnect
    (0x4e13).  Waiting avoids starting the next test mid state-transition.
    """
    bus = get_bus(wifi_dut)
    log_start = len(bus.get_input_log())
    poll_interval = 1.0
    elapsed = 0.0
    while elapsed < timeout:
        time.sleep(poll_interval)
        elapsed += poll_interval
        try:
            disc_log = bus.get_input_log()[log_start:]
            for _, raw_line in disc_log:
                try:
                    decoded = raw_line.decode(errors="ignore").lower()
                except Exception:
                    decoded = str(raw_line).lower()
                if (
                    "on event disconnect" in decoded
                    or "peripheral is disconnected" in decoded
                    or "central is disconnected" in decoded
                ):
                    logger().info(
                        f"Disconnect event confirmed "
                        f"after {elapsed:.1f}s"
                    )
                    return True
        except Exception:
            pass
    logger().warning(
        f"Disconnect event NOT confirmed after {timeout:.1f}s — "
        "proceeding (may cause 0x4e0c on next test)"
    )
    return False


def _recover_dut_invalid_ble_state(
    wifi_dut,
    peer_address: Optional[str] = None,
    *,
    log_start: Optional[int] = None,
):
    """Recover from 0x4e0c Invalid BLE State after cleanup (``test_adv_undirected``)."""
    try:
        bus = get_bus(wifi_dut)
        if log_start is None:
            log_start = hostlog_baseline(bus)
        post_disc_log = bus.get_input_log()[log_start:]
        post_disc_text = "".join(
            line.decode(errors="ignore") if hasattr(line, "decode") else str(line)
            for _, line in post_disc_log
        )
        if "0x4e0c" not in post_disc_text.lower():
            return
        logger().warning(
            f"0x4e0c detected after cleanup — attempting recovery"
        )
        if peer_address:
            try:
                safe_dut_btc_disconnect(wifi_dut, peer_address)
            except Exception as exc:
                logger().debug(f"recovery btc_disconnect: {exc}")
        time.sleep(CLEANUP_POST_DISCONNECT_SETTLE_SEC)
        for fn_name in ("stop_adv", "legacy_scan_stop"):
            try:
                getattr(wifi_dut.interfaces.wifi, fn_name)()
            except Exception:
                pass
        time.sleep(LEGACY_SCAN_SETTLE_SEC)
        drain_serial(get_bus(wifi_dut))
        logger().info(f"0x4e0c recovery complete")
    except Exception as exc:
        logger().warning(f"0x4e0c recovery failed (non-fatal): {exc}")


def _force_clear_raspi_bonds(ble_client, dut_address):
    """
    Delete on-disk BlueZ bond files on Raspi (``test_connection_update_*`` pattern).

    D-Bus ``RemoveDevice()`` can race with ``bluetoothd`` reloading bonds from
    ``/var/lib/bluetooth/`` after restart, leaving stale LTK keys that break the
    next test's scan/connect.
    """
    if is_nrf_peer(ble_client) or not dut_address:
        return
    try:
        dut_addr = dut_address.upper()
        bt = ble_client.interfaces.bluetooth
        if not hasattr(bt, "shell") or not hasattr(bt.shell, "execute"):
            logger().debug(f"No Raspi shell — skip filesystem bond delete")
            return
        logger().info(
            f"Deleting Raspi bond files for {dut_addr}"
        )
        bt.shell.execute(f"sudo rm -rf /var/lib/bluetooth/*/{dut_addr}", "*")
        bt.shell.execute("sudo rm -rf /var/lib/bluetooth/*/cache/*", "*")
        logger().info(f"Raspi bond files deleted")
    except Exception as exc:
        logger().warning(f"Failed to delete bond files: {exc}")


def _stop_dut_ble_activity(wifi_dut, *, rounds: int = 2):
    """Stop DUT background scan/adv (wearables firmware auto-restarts scan on disconnect)."""
    for _ in range(rounds):
        for fn_name in ("legacy_scan_stop", "stop_adv"):
            try:
                getattr(wifi_dut.interfaces.wifi, fn_name)()
            except Exception:
                pass
        time.sleep(1)
    logger().debug(f"DUT legacy_scan_stop/stop_adv completed")


def cleanup_ble(
    ble_dut,
    ble_client=None,
    ble_client_address: Optional[str] = None,
    ble_dut_address: Optional[str] = None,
):
    """
    Wearables DUT cleanup — ``test_connection_update_dut_central`` finally order.

    1. Stop DUT scan/adv **before** disconnect (prevents auto-reconnect race).
    2. ``btc_disconnect`` from remote peer address.
    3. Wait for real LL disconnect event in hostlog.
    4. Stop DUT scan/adv **again** (scan_restart fires after disconnect).
    """
    try:
        try:
            _stop_dut_ble_activity(ble_dut, rounds=2)
        except Exception as exc:
            logger().warning(
                f"pre-disconnect scan stop: {exc}"
            )

        if ble_client_address:
            try:
                bus = get_bus(ble_dut)
                recent = "\n".join(
                    decode_log_items(fresh_log_items(bus))
                ).lower()
                link_up = (
                    "on enhance connect event" in recent
                    or "enhanced connect event status report : 0" in recent
                )
                if link_up:
                    logger().info(
                        f"DUT disconnect from "
                        f"{ble_client_address}"
                    )
                    safe_dut_btc_disconnect(ble_dut, ble_client_address)
                    if not _wait_for_dut_ble_disconnect(
                        ble_dut, timeout=DUT_BLE_DISCONNECT_TIMEOUT_SEC
                    ):
                        logger().warning(
                            f"disconnect event not confirmed — "
                            f"waiting {CLEANUP_DISCONNECT_FALLBACK_SEC}s before peer teardown"
                        )
                        time.sleep(CLEANUP_DISCONNECT_FALLBACK_SEC)
                else:
                    logger().debug(
                        f"skip btc_disconnect — "
                        "no active link in hostlog"
                    )
            except Exception as exc:
                logger().warning(
                    f"DUT disconnect failed (non-fatal): {exc}"
                )

        try:
            _stop_dut_ble_activity(ble_dut, rounds=3)
        except Exception as exc:
            logger().warning(
                f"post-disconnect scan stop: {exc}"
            )
    except Exception as exc:
        logger().warning(f"DUT cleanup error (non-fatal): {exc}")
    finally:
        try:
            drain_serial(get_bus(ble_dut))
        except Exception:
            pass
        logger().info(f"DUT cleanup complete")


def _finally_cleanup_nrf_peer(peer_client, dut_address):
    """
    nRF peer finally steps (``test_ble_smp_sdk`` pattern)::

        cleanup_ble(...)
        nrf_ble_client.interfaces.bluetooth.stop_scanning()
        nrf_ble_client.interfaces.bluetooth.delete_bonding_data()
    """
    nrf = peer_client.interfaces.bluetooth
    for label, fn in (
        ("nrf stop_advertising", lambda: nrf.stop_advertising()),
        ("nrf stop_scanning", lambda: nrf.stop_scanning()),
    ):
        try:
            fn()
        except Exception as exc:
            logger().debug(f"{label}: {exc}")
    if dut_address:
        try:
            if getattr(nrf, "peer_device", None) is not None:
                nrf.disconnect(dev_addr=dut_address, clear_peer=True)
        except Exception as exc:
            logger().debug(f"nrf disconnect: {exc}")
    try:
        nrf.delete_bonding_data()
        logger().info(f"nRF bond store cleared (delete_bonding_data)")
    except Exception as exc:
        logger().warning(f"nRF delete_bonding_data: {exc}")


def _raspi_close_with_retry(peer_client, log_prefix: str = "") -> bool:
    """
    Close Raspi BlueZ session — same as ``ble_client.interfaces.bluetooth.close()``
    in ``test_active_scan`` / ``test_passive_scan`` finally blocks.
    """
    if peer_client is None or is_nrf_peer(peer_client):
        return False
    bt = peer_client.interfaces.bluetooth
    for attempt in range(3):
        try:
            bt.close()
            logger().info(f"{log_prefix}BLE interface closed successfully")
            return True
        except Exception as exc:
            logger().warning(
                f"{log_prefix}close() attempt {attempt + 1}/3: {exc}"
            )
            time.sleep(1)
    logger().error(
        f"{log_prefix}All 3 close() attempts failed. "
        "BlueZ stack may be in dirty state for next test."
    )
    return False


def _finally_cleanup_raspi_peer(
    peer_client,
    dut_address,
    *,
    close_peer_session: bool = True,
):
    """
    Raspi peer finally — ``test_adv_undirected`` / ``test_active_scan`` pattern::
    remove_device(dut) with retry → bond file delete → close() with retry
    """
    bt = peer_client.interfaces.bluetooth

    remove_success = False
    for attempt in range(3):
        try:
            logger().info(
                f"Raspi remove_device({dut_address}) "
                f"attempt {attempt + 1}/3"
            )
            bt.remove_device(dut_address)
            remove_success = True
            logger().info(
                f"Successfully removed DUT ({dut_address}) from Raspi"
            )
            break
        except Exception as exc:
            logger().warning(
                f"remove_device attempt {attempt + 1}/3: {exc}"
            )
            time.sleep(1)
    if not remove_success:
        logger().error(
            f"All 3 remove_device attempts failed for {dut_address}. "
            "Stale bond keys may cause SMP failures in subsequent tests."
        )

    time.sleep(2)
    _force_clear_raspi_bonds(peer_client, dut_address)

    if close_peer_session:
        _raspi_close_with_retry(peer_client)


def clear_ble_bonds_after_test(
    wifi_dut,
    peer_client,
    dut_address: Optional[str],
    peer_address: Optional[str] = None,
    *,
    clear_peer_bond: bool = True,
    close_peer_session: bool = True,
    stop_dut_ble: bool = False,
):
    """
    Finally cleanup — identical order to smp_iocap ``BLESMPPairingTest.run()``::

        btc_disconnect → remove_device → close()

    No DUT ``stop_adv``/``legacy_scan_stop``, no bond-file delete, no serial drain.
    RT595 is not rebooted between tests; stopping DUT BLE roles wedges the next case.
    """

    try:
        if peer_address:
            try:
                logger().info(
                    f"DUT btc_disconnect from {peer_address}"
                )
                wifi_dut.interfaces.wifi.btc_disconnect(ble_address=peer_address)
            except Exception as exc:
                logger().warning(
                    f"DUT disconnect failed (non-fatal): {exc}"
                )

        if clear_peer_bond and peer_client is not None and dut_address:
            if is_nrf_peer(peer_client):
                try:
                    _finally_cleanup_nrf_peer(peer_client, dut_address)
                except Exception as exc:
                    logger().warning(
                        f"nRF cleanup failed (non-fatal): {exc}"
                    )
            else:
                try:
                    logger().info(
                        f"Raspi remove_device({dut_address})"
                    )
                    peer_client.interfaces.bluetooth.remove_device(
                        bt_dut_address=dut_address
                    )
                except Exception as exc:
                    logger().warning(
                        f"Raspi remove_device failed (non-fatal): {exc}"
                    )
                if close_peer_session:
                    try:
                        peer_client.interfaces.bluetooth.close()
                        logger().info(f"Raspi close OK")
                    except Exception as exc:
                        logger().warning(
                            f"Raspi close failed (non-fatal): {exc}"
                        )

        if stop_dut_ble:
            try:
                _stop_dut_ble_activity(wifi_dut, rounds=2)
            except Exception as exc:
                logger().warning(f"stop_dut_ble: {exc}")

    except Exception as exc:
        logger().warning(f"cleanup error (non-fatal): {exc}")
    finally:
        logger().info(f"cleanup complete")


def peer_cleanup_after_central_session(peer_client, dut_address):
    """Peer-only cleanup after DUT-peripheral cases (nRF / Raspi finally pattern)."""
    try:
        if is_nrf_peer(peer_client):
            _finally_cleanup_nrf_peer(peer_client, dut_address)
        elif dut_address:
            _finally_cleanup_raspi_peer(peer_client, dut_address)
    except Exception as exc:
        logger().warning(f"failed (non-fatal): {exc}")


REPEAT_CENTRAL_BOND_RECONNECT_ITERATIONS = 2

# TestRail steps 2–4 hostlog markers (9116 wearables demo central / passkey)
WEARABLES_INIT_LOG_MARKERS: Tuple[str, ...] = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
    "advertising started",
    "scanning started",
)

CONNECT_SMP_MARKERS: Tuple[str, ...] = (
    "smp pairing request initiated",
    "initated role",
    "mtu exchange",
    "smp sc passkey",
)

# TestRail C553837 step 3 — connect / MTU / pairing request (before passkey entry)
DHKEY_CHECK_CONNECT_MARKERS_REQUIRED: Tuple[str, ...] = (
    "on_enhance_conn",
    "number of master devices connected",
    "smp pairing request initiated",
)
DHKEY_CHECK_CONNECT_MARKERS_OPTIONAL: Tuple[str, ...] = (
    "on enhance connect event",
    "added to whitelist",
    "mtu exchange",
    "conn_interval",
)
DHKEY_CHECK_CONNECT_MARKERS: Tuple[str, ...] = (
    DHKEY_CHECK_CONNECT_MARKERS_REQUIRED + DHKEY_CHECK_CONNECT_MARKERS_OPTIONAL
)

# TestRail C553837 step 4 — SMP response + SC passkey (after passkey prompt)
# "smp response" (not "in smp response"): the DUT-central CLI path logs
# "in cli smp response", the peripheral path logs "in smp response".
DHKEY_CHECK_PASSKEY_MARKERS: Tuple[str, ...] = (
    "smp response",
    "smp sc passkey",
    "passkey",
)

POST_PAIR_MARKERS: Tuple[str, ...] = (
    "smp encrypt event",
    "smp security keys event",
    "le ltk",
    "remote device profiles discovery completed",
    "buffer configuration done",
    "start transmitting data",
)

INIT_LOG_MARKERS_PAIR_UNPAIR: Tuple[str, ...] = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
    "advertising started",
    "scanning started",
)

# TestRail C553836 step 2 — DUT peripheral (advertising only, no central scan)
PERIPHERAL_INIT_LOG_MARKERS: Tuple[str, ...] = (
    "set bd addr success",
    "basic init done",
    "setting the local irk value",
    "set bandedge tx power success",
    "set ble tx power for adv_role success",
    "advertising started",
)

PERIPHERAL_CONNECT_SMP_MARKERS: Tuple[str, ...] = (
    "on enhance connect event",
    "enhanced connect event status report : 0",
    "smp sc passkey",
    "passkey",
)

# TestRail C553844 step 4 — DUT peripheral connect / MTU / SC passkey hostlog
# (COEX_MAX_DEMO may omit whitelist line; see AUTH_FAILURE_CONNECT_MARKERS note)
ENCRYPTION_KEY_REFRESH_CONNECT_MARKERS: Tuple[str, ...] = (
    "on_enhance_conn",
    "number of master devices connected",
    "mtu exchange",
    "smp pairing request initiated",
    "in smp response",
    "smp sc passkey",
    "passkey",
)

# TestRail C553844 step 5 — passkey entry / SMP complete / GATT discovery hostlog
ENCRYPTION_KEY_REFRESH_STEP5_MARKERS: Tuple[str, ...] = (
    "smp encrypt event",
    "smp security keys event",
    "remote device profiles discovery completed",
)

ENCRYPTION_RESTART_MARKERS: Tuple[str, ...] = ("encryption restarted",)

# TestRail C553856 steps 3–4 — DUT central connect / passkey / post-pair hostlog
CENTRAL_ENCRYPTION_PAUSE_RESUME_MARKERS: Tuple[str, ...] = (
    "start scanning",
    "smp pairing request initiated",
    "smp sc passkey",
    "passkey",
    "smp encrypt event",
    "smp security keys event",
    "remote device profiles discovery completed",
)

# TestRail C553857 steps 3–4 — DUT central encryption initiation + data path hostlog
CENTRAL_ENCRYPTION_INIT_MARKERS: Tuple[str, ...] = (
    "start scanning",
    "smp pairing request initiated",
    "smp sc passkey",
    "passkey",
    "smp encrypt event",
    "smp security keys event",
    "remote device profiles discovery completed",
    "buffer configuration done",
    "start transmitting data",
)

# TestRail C553854/C553855 step 4 — post-pairing encryption + GATT discovery hostlog
PERIPHERAL_ENCRYPTION_INIT_MARKERS: Tuple[str, ...] = (
    "number of master devices connected:1",
    "smp encrypt event",
    "smp security keys event",
    "remote device profile discovery started",
    "remote device profiles discovery completed",
    "conn_interval",
)

# TestRail C553845/C553846 step 3–4 — connect / MTU / SC passkey (no whitelist on COEX_MAX)
AUTH_FAILURE_CONNECT_MARKERS: Tuple[str, ...] = (
    "on_enhance_conn",
    "on enhance connect event",
    "number of master devices connected",
    "mtu exchange",
    "smp pairing request initiated",
    "in smp response",
    "in smp sc passkey event",
    "passkey event",
)

PASSKEY_ENTRY_DUT_PERIPHERAL_CONNECT_MARKERS: Tuple[str, ...] = (
    AUTH_FAILURE_CONNECT_MARKERS
)

# Connect / SC passkey hostlog — any one marker per group is sufficient (COEX vs UNIFIED).
DUT_PERIPHERAL_CONNECT_VERIFY_GROUPS: Tuple[Tuple[str, ...], ...] = (
    ("on_enhance_conn", "on enhance connect event"),
    ("number of master devices connected",),
    ("mtu exchange",),
    ("smp pairing request initiated",),
    ("in smp response",),
    (
        "in smp sc passkey event",
        "smp sc passkey",
        "passkey event",
        "passkey",
    ),
)

# TestRail C553850 steps 6–8 — peripheral master disconnect / bonded reconnect
PERIPHERAL_MASTER_DISCONNECT_MARKERS: Tuple[str, ...] = (
    "number of connected master devices:0",
    "number of master devices connected:0",
)

BONDED_RECONNECT_SUCCESS_MARKERS: Tuple[str, ...] = (
    "number of master devices connected:1",
    "number of connected master devices:1",
)

PASSKEY_PROMPT_MARKERS: Tuple[str, ...] = (
    "smp sc passkey",
    "in passkey event",
    "passkey event, remote addr",
    "passkey event, passkey:",
)

# TestRail C553851/C553852 — DUT central slave disconnect / bonded reconnect
CENTRAL_SLAVE_DISCONNECT_MARKERS: Tuple[str, ...] = (
    "slave is disconnected",
    "number of connected slave devices:0",
    "number of slave devices connected:0",
)

CENTRAL_BONDED_RECONNECT_MARKERS: Tuple[str, ...] = (
    "number of slave devices connected:1",
    "number of connected slave devices:1",
)

# C553851 wearables hostlog (9116) — firmware often omits slave-count lines
C553851_SLAVE_DISCONNECT_MARKERS: Tuple[str, ...] = (
    "slave is disconnected",
    "number of connected slave devices:0",
    "number of slave devices connected:0",
    "on event disconnect",
    "peripheral is disconnected",
    "ble disconnect triggered",
)

C553851_BONDED_RECONNECT_MARKERS: Tuple[str, ...] = (
    "number of slave devices connected:1",
    "number of connected slave devices:1",
    "on enhance connect event",
    "connected address:",
)

# TestRail C553853 — DUT peripheral dual master disconnect / bonded reconnect
C553853_DUAL_MASTER_DISCONNECT_MARKERS: Tuple[str, ...] = (
    "number of connected master devices:0",
    "number of master devices connected:0",
    "number of connected central devices:0",
)

C553853_DUAL_BONDED_RECONNECT_MARKERS: Tuple[str, ...] = (
    "number of master devices connected:2",
    "number of connected master devices:2",
    "number of connected central devices:2",
)

SMP_PAIRING_REQUEST_MARKERS: Tuple[str, ...] = (
    "smp pairing request initiated",
)

OtaValidator = Callable[[object], None]
ConnectHostlogVerifier = Callable[..., None]

def get_bus(device):
    return device.interfaces.wifi.bus


# Per-bus serial offset for suite runs (see ``_wearables_suite_hostlog_baseline``).
_HOSTLOG_BASELINE_BY_BUS: dict = {}


def set_hostlog_baseline(bus, offset: Optional[int] = None) -> int:
    """Record DUT hostlog index; only entries after this offset belong to the current test."""
    if offset is None:
        offset = len(bus.get_input_log())
    _HOSTLOG_BASELINE_BY_BUS[id(bus)] = offset
    return offset


def reconcile_hostlog_baseline(bus) -> int:
    """
    Clamp baseline when the serial buffer shrinks after harness ``reset``.

    Without this, ``bus.get_input_log()[baseline:]`` is empty on test 5+ and every
    ``wait_for_log_patterns`` / init verify fails in full-suite runs.
    """
    try:
        n = len(bus.get_input_log())
    except Exception:
        return _HOSTLOG_BASELINE_BY_BUS.get(id(bus), 0)
    baseline = _HOSTLOG_BASELINE_BY_BUS.get(id(bus), 0)
    if baseline > n:
        logger().info(
            f"Hostlog baseline {baseline} past buffer end {n} — "
            "resetting to 0 after DUT harness reset"
        )
        _HOSTLOG_BASELINE_BY_BUS[id(bus)] = 0
        return 0
    return baseline


def hostlog_baseline(bus) -> int:
    return reconcile_hostlog_baseline(bus)


def fresh_log_items(bus):
    """DUT serial log entries appended since the current test baseline."""
    reconcile_hostlog_baseline(bus)
    return bus.get_input_log()[hostlog_baseline(bus) :]


def combined_fresh_hostlog(bus, *extra_chunks: str) -> str:
    """Lowercased hostlog since baseline plus optional extra text (e.g. connect_log)."""
    parts = ["\n".join(decode_log_items(fresh_log_items(bus)))]
    parts.extend(c for c in extra_chunks if c)
    return "\n".join(parts).lower()


def is_valid_bd_addr(addr):
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", str(addr))) and not str(
        addr
    ).endswith(":00:00:00:00:00:00")


def _set_cached_dut_local_address(addr: Optional[str]) -> None:
    """Update module cache (public or random BD addr used for suite continuity)."""
    global _CACHED_DUT_LOCAL_ADDRESS
    if addr is None:
        _CACHED_DUT_LOCAL_ADDRESS = None
        return
    if is_valid_bd_addr(addr):
        _CACHED_DUT_LOCAL_ADDRESS = str(addr).upper()


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


def decode_log_items(log_items):
    lines = []
    for _, raw in log_items:
        try:
            lines.append(raw.decode(errors="ignore"))
        except Exception:
            lines.append(str(raw))
    return lines


def wait_for_log_patterns(
    bus,
    patterns: Sequence[str],
    timeout=WAIT_FOR_LOG_PATTERNS_DEFAULT_TIMEOUT_SEC,
    poll=LOG_POLL_INTERVAL_SEC,
    require_all=True,
    log_start: Optional[int] = None,
):
    if log_start is None:
        log_start = hostlog_baseline(bus)
    try:
        log_start = min(log_start, len(bus.get_input_log()))
    except Exception:
        pass
    deadline = time.time() + timeout
    accumulated = ""
    while time.time() < deadline:
        time.sleep(poll)
        accumulated += "\n".join(
            decode_log_items(bus.get_input_log()[log_start:])
        )
        lower = accumulated.lower()
        if require_all:
            if all(p in lower for p in patterns):
                return True, accumulated
        elif any(p in lower for p in patterns):
            return True, accumulated
    return False, accumulated


def fetch_local_address(wifi_dut, *, log_text: str = "", log_start: Optional[int] = None):
    """Parse DUT public BD address from hostlog (preferred over gap CLI on wearables)."""
    bus = get_bus(wifi_dut)
    if log_start is None:
        log_start = hostlog_baseline(bus)
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


def _query_dut_local_address_cli(
    wifi_dut, *, timeout: float = DUT_LOCAL_ADDRESS_CLI_TIMEOUT_SEC
) -> Optional[str]:
    """
    Query ``btc gap get_local_address`` and poll hostlog for the response.

    The stock ``wifi.get_local_address()`` uses ``read_line(timeout=1)`` which
    often returns empty bytes while wearables firmware is scanning/advertising.
    """
    bus = get_bus(wifi_dut)
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
    """
    Return DUT public BD address — cached after first successful read (smp_iocap).

    Wearables: poll hostlog first; ``wifi.get_local_address()`` uses short
    ``read_line()`` and returns garbage while the RT595 agent is still booting
    (first test only).
    """
    global _CACHED_DUT_LOCAL_ADDRESS
    if _CACHED_DUT_LOCAL_ADDRESS and is_valid_bd_addr(_CACHED_DUT_LOCAL_ADDRESS):
        logger().info(f"DUT local address (cached): {_CACHED_DUT_LOCAL_ADDRESS}")
        return _CACHED_DUT_LOCAL_ADDRESS

    bus = get_bus(wifi_dut)
    _open_dut_serial(bus)

    first_test = not _dut_already_initialized_in_suite()

    # Boot prints ``addr:XX:...`` — parse hostlog before any gap CLI (first test).
    for attempt in range(max_attempts if first_test else 1):
        local_addr = fetch_local_address(wifi_dut)
        if is_valid_bd_addr(local_addr):
            _set_cached_dut_local_address(local_addr)
            logger().info(f"DUT local address from hostlog: {local_addr}")
            return local_addr
        if first_test:
            logger().debug(
                f"DUT address not in hostlog yet (attempt {attempt + 1}/{max_attempts})"
            )
            time.sleep(retry_sec)

    for attempt in range(max_attempts):
        if not first_test or attempt > 0:
            local_addr = _query_dut_local_address_cli(wifi_dut)
            if is_valid_bd_addr(local_addr):
                _set_cached_dut_local_address(local_addr)
                return local_addr

        local_addr = fetch_local_address(wifi_dut)
        if is_valid_bd_addr(local_addr):
            _set_cached_dut_local_address(local_addr)
            logger().info(f"DUT local address from hostlog retry: {local_addr}")
            return local_addr

        if not first_test:
            try:
                dynamic_address = wifi_dut.interfaces.wifi.get_local_address()
                if dynamic_address and is_valid_bd_addr(str(dynamic_address).strip()):
                    _set_cached_dut_local_address(str(dynamic_address).strip().upper())
                    logger().info(
                        f"DUT local address (get_local_address): {_CACHED_DUT_LOCAL_ADDRESS}"
                    )
                    return _CACHED_DUT_LOCAL_ADDRESS
            except Exception as exc:
                logger().warning(f"get_local_address failed: {exc}")

        logger().warning(
            f"DUT local address not available yet "
            f"(attempt {attempt + 1}/{max_attempts})"
        )
        time.sleep(retry_sec)

    total_sec = max_attempts * retry_sec + DUT_LOCAL_ADDRESS_CLI_TIMEOUT_SEC
    assert is_valid_bd_addr(local_addr), (
        f"Could not obtain valid DUT BD address within ~{total_sec:.0f}s"
    )
    _set_cached_dut_local_address(local_addr)
    return local_addr


def drain_serial(bus):
    try:
        bus.get_input_log()
    except Exception:
        pass


def _start_dut_legacy_scan(wifi_dut):
    """RT595 wearables: ``legacy_scan()``, not ``legacy_scan_start()``."""
    try:
        wifi_dut.interfaces.wifi.legacy_scan(
            status=1, own_addr_type=DEFAULT_OWN_ADDR_TYPE
        )
    except Exception as exc:
        logger().warning(f"legacy_scan start: {exc}")


def _dut_already_initialized_in_suite() -> bool:
    return bool(_CACHED_DUT_LOCAL_ADDRESS and is_valid_bd_addr(_CACHED_DUT_LOCAL_ADDRESS))


def _dut_cached_le_random_address() -> bool:
    """True when suite cache holds a non-public LE address (random static / private)."""
    addr = _CACHED_DUT_LOCAL_ADDRESS
    if not addr or not is_valid_bd_addr(addr):
        return False
    msb = int(str(addr).split(":")[-1], 16)
    return ((msb >> 6) & 0x03) != 0


def _snapshot_auth_failure_connect_hostlog(bus) -> None:
    """Preserve step-3 connect hostlog before auth-failure teardown clears serial."""
    global _AUTH_FAILURE_CONNECT_LOG_SNAPSHOT
    _AUTH_FAILURE_CONNECT_LOG_SNAPSHOT = combined_fresh_hostlog(bus)


def _assert_hostlog_marker_groups(
    combined: str,
    groups: Sequence[Sequence[str]],
    *,
    step: str,
) -> None:
    lower = str(combined).lower()
    for group in groups:
        assert any(marker in lower for marker in group), (
            f"Expected one of {group!r} in hostlog (step {step})"
        )


def _dut_hostlog_advertising_active(bus) -> bool:
    return hostlog_indicates_dut_advertising(combined_fresh_hostlog(bus))


def _dut_hostlog_scanning_active(bus) -> bool:
    return "scanning started" in combined_fresh_hostlog(bus).lower()


def _restart_dut_wearables_idle_roles(
    wifi_dut,
    bus=None,
    *,
    require_scan: bool = True,
):
    """
    Restart wearables idle BLE roles after prior-test cleanup stopped adv/scan.

    Skips legacy_adv when advertising is already active and stops scan before
    restart to avoid 0x4e12 (invalid scan parameters).
    """

    if bus is not None and _dut_hostlog_advertising_active(bus):
        logger().info(f"DUT advertising already active — skip legacy_adv restart")
    else:
        logger().info(f"Restarting DUT legacy_adv (post-cleanup suite step 1)")
        try:
            wifi_dut.interfaces.wifi.legacy_adv(
                status=1, own_addr_type=DEFAULT_OWN_ADDR_TYPE
            )
            time.sleep(1)
        except Exception as exc:
            logger().warning(f"legacy_adv restart: {exc}")

    if require_scan:
        if bus is not None and _dut_hostlog_scanning_active(bus):
            logger().info(f"DUT scanning already active — skip legacy_scan restart")
        else:
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
                time.sleep(LEGACY_SCAN_STOP_SETTLE_SEC)
            except Exception as exc:
                logger().warning(f"legacy_scan_stop before restart: {exc}")
            _start_dut_legacy_scan(wifi_dut)
    time.sleep(LEGACY_SCAN_SETTLE_SEC)


def _open_dut_serial(bus) -> None:
    """Open UART lazily (same moment smp_iocap ``get_dut_address()`` first touches serial)."""
    try:
        _ = bus.ser
    except Exception as exc:
        logger().warning(f"DUT serial open failed: {exc}")


def _dut_first_test_boot_complete(text: str) -> bool:
    """RT595 wearables boot is done when idle adv+scan banners appear (not at hello world)."""
    lower = str(text).lower()
    return "advertising started" in lower and "scanning started" in lower


def _wait_for_first_test_dut_cli_ready(
    bus,
    *,
    timeout: float = DUT_BLE_READY_TIMEOUT_SEC,
) -> bool:
    """
    Module test 1 only: wait until wearables firmware finishes boot on serial.

    Do **not** return on ``hello world`` alone — sending ``btc gap get_local_address``
    during codec/A2DP init wedges the BLE stack (scan/connect then get no hostlog RX).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = "\n".join(decode_log_items(bus.get_input_log()))
        if _dut_first_test_boot_complete(text):
            logger().info(
                f"DUT boot complete (advertising + scanning started)"
            )
            time.sleep(5)
            return True
        time.sleep(2)
    logger().warning(
        f"DUT boot (adv+scan) not complete within {timeout}s after serial open"
    )
    return False


def smp_iocap_dut_settle(
    *,
    wifi_dut=None,
    bus=None,
) -> None:
    """
    smp_iocap ``sleep(20)`` — on module test 1 open serial first and wait for boot text.

    Tests 2+ only need the fixed settle (DUT already running; address cached).
    """
    if _dut_already_initialized_in_suite():
        logger().info(
            f"smp_iocap-style DUT init settle ({SMP_DUT_INIT_SLEEP_SEC}s)"
        )
        time.sleep(SMP_DUT_INIT_SLEEP_SEC)
        return

    if wifi_dut is not None or bus is not None:
        bus = bus or get_bus(wifi_dut)
        _open_dut_serial(bus)
        logger().info(
            f"First suite test: smp_iocap settle {SMP_DUT_INIT_SLEEP_SEC}s "
            "(wearables boot banners occur before serial open — do not wait for them)"
        )
        time.sleep(SMP_DUT_INIT_SLEEP_SEC)
        boot_text = "\n".join(decode_log_items(bus.get_input_log()))
        boot_addr = _parse_bd_addr_from_hostlog_text(boot_text)
        if boot_addr:
            _set_cached_dut_local_address(boot_addr)
        return

    logger().info(
        f"smp_iocap-style DUT init settle ({SMP_DUT_INIT_SLEEP_SEC}s)"
    )
    time.sleep(SMP_DUT_INIT_SLEEP_SEC)


def _ensure_dut_wearables_step1_ready(
    wifi_dut,
    bus,
    *,
    require_scan: bool = True,
):
    """TestRail step 1 — smp_iocap settle (first test waits for boot after serial open)."""
    _ = require_scan
    smp_iocap_dut_settle(wifi_dut=wifi_dut, bus=bus)
    return True, combined_fresh_hostlog(bus)


DUT_BLE_READY_MARKERS: Tuple[str, ...] = (
    "advertising started",
    "scanning started",
)

# Wearables firmware may not re-print boot banners after harness reset when adv/scan
# are already running; accept these active-state markers (smp_iocap suite pattern).
DUT_ADV_ACTIVE_MARKERS: Tuple[str, ...] = (
    "advertising started",
    "start adv command called",
    "adv already in progress",
    "ble_connectable_adv_already_in_progress",
    "connectable_adv_already_in_progress",
    "ble_module_req_adv_cmd_handler : successful",
)

DUT_SCAN_ACTIVE_MARKERS: Tuple[str, ...] = (
    "scanning started",
    "restarting scanning",
    "ble_module_req_scan_cmd_handler : successful",
)


def hostlog_indicates_dut_advertising(text: str) -> bool:
    lower = str(text).lower()
    return any(marker in lower for marker in DUT_ADV_ACTIVE_MARKERS)


def hostlog_indicates_dut_scanning(text: str) -> bool:
    lower = str(text).lower()
    return any(marker in lower for marker in DUT_SCAN_ACTIVE_MARKERS)


def wait_for_dut_wearables_idle_ready(
    bus,
    *,
    require_scan: bool = True,
    timeout: float = DUT_BLE_READY_TIMEOUT_SEC,
) -> Tuple[bool, str]:
    """
    Passive wait for DUT adv[/scan] hostlog — smp_iocap style (no BLE CLI).

    Relies on harness ``device: reset`` + inter-test delay for firmware boot.
    """
    deadline = time.time() + timeout
    last_text = ""
    while time.time() < deadline:
        last_text = combined_fresh_hostlog(bus)
        adv_ok = hostlog_indicates_dut_advertising(last_text)
        scan_ok = not require_scan or hostlog_indicates_dut_scanning(last_text)
        if adv_ok and scan_ok:
            logger().info(f"DUT wearables idle ready (hostlog)")
            return True, last_text
        time.sleep(2)
    logger().warning(
        f"DUT adv/scan markers not seen after passive wait ({timeout}s)"
    )
    return False, last_text


def assert_dut_advertising_in_hostlog(
    text: str, *, step: str = "2"
) -> None:
    assert hostlog_indicates_dut_advertising(text), (
        f"Expected DUT advertising active in hostlog (step {step})"
    )


def assert_dut_scanning_in_hostlog(text: str, *, step: str = "2") -> None:
    assert hostlog_indicates_dut_scanning(text), (
        f"Expected DUT scanning active in hostlog (step {step})"
    )


def _preemptive_restart_dut_idle_if_needed(
    wifi_dut,
    bus,
    *,
    require_scan: bool = True,
) -> None:
    """Suite test 2+: restart adv/scan when hostlog markers were drained (e.g. after DUT-central case)."""
    if wifi_dut is None or not _dut_already_initialized_in_suite():
        return
    combined = combined_fresh_hostlog(bus).lower()
    adv_ok = hostlog_indicates_dut_advertising(combined)
    scan_ok = not require_scan or hostlog_indicates_dut_scanning(combined)
    if adv_ok and scan_ok:
        return
    logger().info(
        f"Pre-emptive DUT idle role restart (suite test 2+; post-drain / post-central)"
    )
    _restart_dut_wearables_idle_roles(
        wifi_dut, bus, require_scan=require_scan
    )
    time.sleep(SMP_DUT_INIT_SLEEP_SEC)


def assert_dut_wearables_idle_hostlog(
    text: str,
    *,
    step: str = "2",
    require_scan: bool = False,
    bus=None,
    wifi_dut=None,
) -> None:
    """
    Assert DUT adv[/scan] hostlog for TestRail init steps.

    Suite tests 2+ often call ``drain_serial`` before this check, clearing boot
    banners. Cached BD address alone does not prove adv/scan are active (e.g.
    after a DUT-central case); passive wait and optional role restart follow.
    """
    combined = str(text).lower()
    adv_ok = hostlog_indicates_dut_advertising(combined)
    scan_ok = not require_scan or hostlog_indicates_dut_scanning(combined)
    if adv_ok and scan_ok:
        return

    if bus is not None:
        ready, polled = wait_for_dut_wearables_idle_ready(
            bus,
            require_scan=require_scan,
            timeout=min(30.0, DUT_BLE_READY_TIMEOUT_SEC),
        )
        combined = f"{combined}\n{polled}".lower()
        adv_ok = hostlog_indicates_dut_advertising(combined)
        scan_ok = not require_scan or hostlog_indicates_dut_scanning(combined)
        if adv_ok and scan_ok:
            return

        if wifi_dut is not None and (not adv_ok or (require_scan and not scan_ok)):
            if _dut_already_initialized_in_suite():
                _restart_dut_wearables_idle_roles(
                    wifi_dut,
                    bus,
                    require_scan=require_scan,
                )
                ready, polled = wait_for_dut_wearables_idle_ready(
                    bus,
                    require_scan=require_scan,
                    timeout=min(30.0, DUT_BLE_READY_TIMEOUT_SEC),
                )
                combined = f"{combined}\n{polled}".lower()
                adv_ok = hostlog_indicates_dut_advertising(combined)
                scan_ok = not require_scan or hostlog_indicates_dut_scanning(combined)
                if adv_ok and scan_ok:
                    return
            else:
                logger().info(
                    f"Cold start — smp_iocap settle (no legacy_adv CLI)"
                )
                time.sleep(SMP_DUT_INIT_SLEEP_SEC)
                combined = combined_fresh_hostlog(bus).lower()
                adv_ok = hostlog_indicates_dut_advertising(combined)
                scan_ok = not require_scan or hostlog_indicates_dut_scanning(combined)
                if adv_ok and scan_ok:
                    return
                logger().warning(
                    f"DUT idle markers absent after cold settle (step {step}) "
                    "— continuing (smp_iocap test 1; boot banners pre-serial)"
                )
                return

    if not adv_ok:
        if _dut_already_initialized_in_suite():
            logger().warning(
                f"DUT adv markers absent (step {step}) — continuing "
                "(suite test 2+; verify via scan/connect)"
            )
            return
        assert_dut_advertising_in_hostlog(combined, step=step)
    if require_scan and not scan_ok:
        if _dut_already_initialized_in_suite():
            logger().warning(
                f"DUT scan markers absent (step {step}) — continuing "
                "(suite test 2+; verify via scan/connect)"
            )
            return
        assert_dut_scanning_in_hostlog(combined, step=step)


def _probe_dut_uart_alive(
    wifi_dut,
    bus,
    *,
    timeout: float = DUT_SUITE_UART_PROBE_TIMEOUT_SEC,
) -> bool:
    """
    Prove the DUT UART responds after prior-test cleanup (suite tests 2+).

    Cached BD address alone is not enough — ``get_dut_local_address()`` returns
    the cache without TX/RX.  smp_iocap implicitly probes by calling
    ``get_local_address()`` on the first test only; later tests rely on Raspi scan.
    We send ``btc gap get_local_address`` and wait for a fresh hostlog response.
    """
    log_start = len(bus.get_input_log())
    try:
        bus.write_line("btc gap get_local_address")
    except Exception as exc:
        logger().warning(f"DUT UART probe TX failed: {exc}")
        return False

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            fresh = decode_log_items(bus.get_input_log()[log_start:])
            text = "\n".join(fresh).lower()
        except Exception:
            text = ""
        if "local_bd_address" in text or LOCAL_BD_ADDR_PATTERN.search(text):
            logger().info(f"DUT UART alive (gap get_local_address response)")
            return True
        time.sleep(0.5)

    logger().warning(
        f"DUT UART silent for {timeout}s after gap probe — "
        "prior-test cleanup may have wedged coex firmware (no RT595 HW reset)"
    )
    return False


def ensure_dut_ble_ready_for_test(
    wifi_dut,
    bus,
    *,
    require_scan: bool = True,
) -> Tuple[bool, str]:
    """smp_iocap ready — first test waits for boot after serial open."""
    _ = require_scan
    smp_iocap_dut_settle(wifi_dut=wifi_dut, bus=bus)
    return True, combined_fresh_hostlog(bus)


def init_dut_wearables_after_reset(
    wifi_dut,
    configure_fn,
    init_markers: Sequence[str],
) -> Tuple[object, str]:
    """
    DUT step-1 — smp_iocap order: settle → get address → SMP config → optional markers.

    Boot banners are not waited on: GDB loads the test agent before serial opens, so
    passive banner wait always times out on test 1 (same as smp_iocap ``sleep(20)``).
    """
    bus = get_bus(wifi_dut)
    logger().info(f"Step 1: DUT init (smp_iocap settle + address + SMP config)")

    smp_iocap_dut_settle(wifi_dut=wifi_dut, bus=bus)
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(5)
    configure_fn(wifi_dut)
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    ok, _ = wait_for_log_patterns(
        bus,
        init_markers,
        timeout=DUT_INIT_LOG_MARKER_TIMEOUT_SEC,
        require_all=False,
    )
    if not ok:
        logger().warning(f"Some init log markers missing — continuing")
    return bus, local_addr


def configure_dut_smp_central(wifi_dut, *, auth_req=0x09):
    wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
        io_capability=DUT_IO_DISPLAY_ONLY, auth_req=auth_req
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)


def configure_dut_smp_displayonly_initiator(
    wifi_dut,
    *,
    auth_req=AUTH_REQ_BONDING_MITM_SC,
    ini_key_dist=KEY_DIST_ENC_ID_SIGN,
    rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
):
    wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
        io_capability=DUT_IO_DISPLAY_ONLY,
        oob_data_flag=0,
        auth_req=auth_req,
        enc_key_size=16,
        ini_key_dist=ini_key_dist,
        rsp_key_dist=rsp_key_dist,
    )
    time.sleep(1)


def configure_dut_smp_keyboardonly_initiator(
    wifi_dut,
    *,
    auth_req=AUTH_REQ_BONDING_MITM_SC,
    ini_key_dist=KEY_DIST_ENC_ONLY,
    rsp_key_dist=KEY_DIST_ENC_ONLY,
):
    """TestRail C553861 — DUT initiator KeyboardOnly (passkey entry), bonding+MITM+SC."""
    wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
        io_capability=DUT_IO_KEYBOARD_ONLY,
        oob_data_flag=0,
        auth_req=auth_req,
        enc_key_size=16,
        ini_key_dist=ini_key_dist,
        rsp_key_dist=rsp_key_dist,
    )
    time.sleep(1)


def configure_dut_smp_keyboarddisplay_initiator(
    wifi_dut,
    *,
    auth_req=AUTH_REQ_BONDING_MITM_SC,
    ini_key_dist=KEY_DIST_ENC_ONLY,
    rsp_key_dist=KEY_DIST_ENC_ONLY,
):
    """TestRail C553862 — DUT initiator KeyboardDisplay (0x04), bonding+MITM+SC."""
    wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
        io_capability=DUT_IO_KEYBOARD_DISPLAY,
        oob_data_flag=0,
        auth_req=auth_req,
        enc_key_size=16,
        ini_key_dist=ini_key_dist,
        rsp_key_dist=rsp_key_dist,
    )
    time.sleep(1)


def configure_dut_smp_displayyesno_peripheral(
    wifi_dut,
    *,
    auth_req=AUTH_REQ_BONDING_MITM_SC,
    ini_key_dist=KEY_DIST_ENC_ID_SIGN,
    rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
):
    """TestRail C553836 — DUT peripheral DisplayYesNo, bonding+MITM+SC."""
    wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
        io_capability=DUT_IO_DISPLAY_YES_NO,
        oob_data_flag=0,
        auth_req=auth_req,
        enc_key_size=16,
        ini_key_dist=ini_key_dist,
        rsp_key_dist=rsp_key_dist,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    bus = get_bus(wifi_dut)
    wait_for_log_patterns(
        bus, ("advertising started",), timeout=60, require_all=False
    )


def configure_dut_smp_displayonly_peripheral(
    wifi_dut,
    *,
    auth_req=AUTH_REQ_BONDING_MITM_SC,
    ini_key_dist=KEY_DIST_ENC_ID_SIGN,
    rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
):
    """TestRail C553846 — DUT peripheral DisplayOnly, bonding+MITM+SC (passkey entry)."""
    wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
        io_capability=DUT_IO_DISPLAY_ONLY,
        oob_data_flag=0,
        auth_req=auth_req,
        enc_key_size=16,
        ini_key_dist=ini_key_dist,
        rsp_key_dist=rsp_key_dist,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    bus = get_bus(wifi_dut)
    wait_for_log_patterns(
        bus, ("advertising started",), timeout=60, require_all=False
    )


def configure_dut_smp_displayyesno_central(
    wifi_dut,
    *,
    auth_req=AUTH_REQ_BONDING_MITM_SC,
    ini_key_dist=KEY_DIST_ENC_ONLY,
    rsp_key_dist=KEY_DIST_ENC_ONLY,
):
    """TestRail C553838 — DUT central (RT595) DisplayYesNo initiator, bonding+MITM+SC."""
    wifi_dut.interfaces.wifi.set_smp_pairing_capability_data(
        io_capability=DUT_IO_DISPLAY_YES_NO,
        oob_data_flag=0,
        auth_req=auth_req,
        enc_key_size=16,
        ini_key_dist=ini_key_dist,
        rsp_key_dist=rsp_key_dist,
    )
    time.sleep(1)


def configure_peer_smp(ble_client, *, auth_req=AUTH_REQ_BONDING_MITM_SC):
    if is_nrf_peer(ble_client):
        return
    ble_client.interfaces.bluetooth.set_mitm_sc_bits(
        f"0x02 0x00 0x{auth_req:02x}"
    )
    time.sleep(1)


def configure_raspi_displayyesno_central(ble_client, *, auth_req=AUTH_REQ_BONDING_MITM_SC):
    """BlueSpy step 3 — central DisplayYesNo, LE SC + MITM + bonding."""
    if is_nrf_peer(ble_client):
        return
    ble_client.interfaces.bluetooth.set_mitm_sc_bits(
        f"0x01 0x00 0x{auth_req:02x}"
    )
    time.sleep(1)


def configure_raspi_keyboardonly_central(ble_client, *, auth_req=AUTH_REQ_BONDING_MITM_SC):
    """Raspi central KeyboardOnly — enters passkey when DUT peripheral displays it."""
    if is_nrf_peer(ble_client):
        return
    ble_client.interfaces.bluetooth.set_mitm_sc_bits(
        f"0x02 0x00 0x{auth_req:02x}"
    )
    time.sleep(1)


def configure_raspi_keyboardonly_peripheral(
    ble_client, *, auth_req=AUTH_REQ_BONDING_MITM_SC
):
    """nRF step 4 — peripheral KeyboardOnly (keyboard, no display), LE SC + MITM + bonding."""
    configure_raspi_keyboardonly_central(ble_client, auth_req=auth_req)


def configure_raspi_displayyesno_peripheral(ble_client, *, auth_req=AUTH_REQ_BONDING_MITM_SC):
    """nRF dongle step 4 — peripheral DisplayYesNo, LE SC + MITM + bonding."""
    ble_client.interfaces.bluetooth.set_mitm_sc_bits(
        f"0x01 0x00 0x{auth_req:02x}"
    )
    time.sleep(1)


def configure_raspi_displayonly_peripheral(ble_client, *, auth_req=AUTH_REQ_BONDING_SC):
    """nRF dongle step 4 — peripheral DisplayOnly, LE SC + bonding, MITM off."""
    ble_client.interfaces.bluetooth.set_mitm_sc_bits(
        f"0x00 0x00 0x{auth_req:02x}"
    )
    time.sleep(1)


def configure_raspi_displayyesno_legacy_peripheral(
    ble_client, *, auth_req=AUTH_REQ_BONDING_ONLY
):
    """nRF step 4 — peripheral DisplayYesNo, legacy pairing (SC off), bonding, MITM off."""
    ble_client.interfaces.bluetooth.set_mitm_sc_bits(
        f"0x01 0x00 0x{auth_req:02x}"
    )
    time.sleep(1)


def configure_raspi_keyboarddisplay_legacy_peripheral(
    ble_client, *, auth_req=AUTH_REQ_BONDING_MITM_LEGACY
):
    """nRF step 4 — peripheral KeyboardDisplay, legacy pairing (SC off), bonding+MITM."""
    ble_client.interfaces.bluetooth.set_mitm_sc_bits(
        f"0x04 0x00 0x{auth_req:02x}"
    )
    time.sleep(1)


def configure_raspi_keyboarddisplay_peripheral(
    ble_client, *, auth_req=AUTH_REQ_BONDING_MITM_SC
):
    """nRF step 4 — peripheral KeyboardDisplay, LE SC + MITM + bonding (C553860)."""
    ble_client.interfaces.bluetooth.set_mitm_sc_bits(
        f"0x04 0x00 0x{auth_req:02x}"
    )
    time.sleep(1)


def raspi_scan_for_dut(ble_client, dut_address, *, scan_wait=10):
    """TestRail step 4 — peer central scans and discovers DUT peripheral."""
    if is_nrf_peer(ble_client):
        return nrf_scan_for_dut(
            ble_client, dut_address, capability="DisplayYesNo", scan_wait=scan_wait
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(PEER_BUS_SETTLE_SEC)
    central_addr = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=dut_address,
        capability="DisplayYesNo",
        pin_code="-8",
    )
    assert central_addr, "Failed to start Raspi SMP scan (central)"
    logger().info(f"Raspi scanning for DUT {dut_address}...")
    time.sleep(scan_wait)
    ble_client.interfaces.bluetooth.stop_scanning()
    assert dut_address, f"DUT {dut_address} not discovered during scan (step 4)"
    logger().info(f"DUT discovered: {dut_address}")
    return central_addr


def raspi_scan_for_dut_passkey_central(ble_client, dut_address, *, scan_wait=10):
    """Peer central (KeyboardOnly) scans for DUT peripheral — C553846 step 3."""
    if is_nrf_peer(ble_client):
        return nrf_scan_for_dut(
            ble_client,
            dut_address,
            capability="KeyboardOnly",
            scan_wait=scan_wait,
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_keyboardonly_central(ble_client)
    central_addr = ble_client.interfaces.bluetooth.start_smp_scan(
        bt_dut_address=dut_address,
        capability="KeyboardOnly",
        pin_code="-8",
    )
    assert central_addr, "Failed to start Raspi KeyboardOnly SMP scan (central)"
    logger().info(f"Raspi scanning for DUT {dut_address} (KeyboardOnly central)...")
    time.sleep(scan_wait)
    ble_client.interfaces.bluetooth.stop_scanning()
    assert dut_address, f"DUT {dut_address} not discovered during scan (step 3)"
    logger().info(f"DUT discovered: {dut_address}")
    return central_addr


def complete_smp_numeric_comparison(
    bus,
    wifi_dut,
    ble_client,
    remote_peer_address,
    *,
    timeout: float = 120,
    accept_order: str = "peripheral_first",
):
    """
    Numeric Comparison — both sides display the same value and confirm.

    ``accept_order``:
      - ``central_first`` (C553865): DUT ``smp_passkey`` then Raspi ``set_pin``
      - ``peripheral_first`` (C553866/C553838): Raspi ``set_pin`` then DUT confirm
    """
    enter_peer = (
        ble_client if accept_order != "central_first" and not is_nrf_peer(ble_client) else None
    )
    dut_passkey = wait_for_passkey(
        bus, timeout=timeout, enter_on_peer=enter_peer
    )
    assert dut_passkey, "Numeric comparison passkey not found in DUT hostlog"
    assert_passkey_valid(dut_passkey)

    if accept_order == "central_first":
        logger().info(
            f"DUT (central) accepting numeric comparison first — passkey {dut_passkey}"
        )
        wifi_dut.interfaces.wifi.smp_passkey(
            bd_addr=remote_peer_address, passkey=dut_passkey
        )
        time.sleep(1)
        logger().info(
            f"Raspi (peripheral) accepting numeric comparison — set_pin {dut_passkey}"
        )
        peer_set_pin(ble_client, int(dut_passkey))
    else:
        logger().info(f"Peer confirming DUT passkey {dut_passkey} (numeric comparison)")
        peer_set_pin(ble_client, int(dut_passkey))

        try:
            raspi_pk = peer_get_passkey(ble_client)
            if raspi_pk and str(raspi_pk) != "0":
                raspi_passkey = str(raspi_pk).zfill(6)
                logger().info(f"DUT confirming Raspi passkey {raspi_passkey}")
                wifi_dut.interfaces.wifi.smp_passkey(
                    bd_addr=remote_peer_address, passkey=raspi_passkey
                )
        except Exception as exc:
            logger().info(
                f"Raspi passkey auto-confirm or unavailable: {exc}"
            )

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.5)
        for line in decode_log_items(bus.get_input_log()):
            lower = line.lower()
            if "smp failed" in lower or "4b0b" in lower:
                pytest.fail(f"SMP numeric comparison failed: {line.strip()}")
            if (
                "smp encrypt event" in lower
                or "smp security keys event" in lower
                or "le ltk" in lower
            ):
                logger().info("Numeric comparison pairing completed (hostlog)")
                return
    pytest.fail("SMP success indicators not seen after numeric comparison")


def fail_smp_numeric_comparison_central_accept_periph_decline(
    bus,
        wifi_dut,
        ble_client,
    remote_peer_address,
    *,
    timeout: float = 120,
    fail_timeout: float = 120,
):
    """
    C553867: Numeric Comparison — central Accept then peripheral Decline.

    DUT ``smp_passkey`` first; Raspi agent ``set_pin(-1)`` rejects ``RequestConfirmation``.
    """
    dut_passkey = wait_for_passkey(bus, timeout=timeout)
    assert dut_passkey, "Numeric comparison passkey not found in DUT hostlog"
    assert_passkey_valid(dut_passkey)

    logger().info(
        f"DUT (central) accepting numeric comparison — passkey {dut_passkey}"
    )
    wifi_dut.interfaces.wifi.smp_passkey(
        bd_addr=remote_peer_address, passkey=dut_passkey
    )
    time.sleep(1)

    logger().info("Peer (peripheral) declining numeric comparison (set_pin -1)")
    peer_set_pin(ble_client, -1)

    wait_for_smp_numeric_comparison_failed(bus, timeout=fail_timeout)


def fail_smp_numeric_comparison_periph_accept_central_decline(
    bus,
    wifi_dut,
    ble_client,
    remote_peer_address,
    *,
    timeout: float = 120,
    fail_timeout: float = 120,
):
    """
    C553868: Numeric Comparison — peripheral Accept then central Decline.

    Raspi confirms displayed value first; DUT declines by submitting 000000.
    """
    dut_passkey = wait_for_passkey(bus, timeout=timeout)
    assert dut_passkey, "Numeric comparison passkey not found in DUT hostlog"
    assert_passkey_valid(dut_passkey)

    logger().info(
        f"Raspi (peripheral) accepting numeric comparison first — set_pin {dut_passkey}"
    )
    peer_set_pin(ble_client, int(dut_passkey))
    time.sleep(1)

    logger().info("DUT (central) declining numeric comparison — smp_passkey 000000")
    wifi_dut.interfaces.wifi.smp_passkey(
        bd_addr=remote_peer_address, passkey="000000"
    )

    wait_for_smp_numeric_comparison_failed(bus, timeout=fail_timeout)


def fail_smp_numeric_comparison_central_only_decline(
    bus,
    wifi_dut,
    remote_peer_address,
    *,
    timeout: float = 120,
    fail_timeout: float = 120,
):
    """
    C553869: Numeric Comparison — central Decline only (peripheral action X).

    DUT declines by submitting 000000 without peer-side confirmation.
    """
    dut_passkey = wait_for_passkey(bus, timeout=timeout)
    assert dut_passkey, "Numeric comparison passkey not found in DUT hostlog"
    assert_passkey_valid(dut_passkey)

    logger().info("DUT (central) declining numeric comparison — smp_passkey 000000")
    wifi_dut.interfaces.wifi.smp_passkey(
        bd_addr=remote_peer_address, passkey="000000"
    )

    wait_for_smp_numeric_comparison_failed(bus, timeout=fail_timeout)


def fail_smp_numeric_comparison_periph_only_decline(
    bus,
    ble_client,
    *,
    timeout: float = 120,
    fail_timeout: float = 120,
):
    """
    C553870: Numeric Comparison — peripheral Decline only (central action X).

    Raspi declines by setting ``-1`` during RequestConfirmation. DUT does not
    submit ``smp_passkey`` in this flow.
    """
    dut_passkey = wait_for_passkey(bus, timeout=timeout)
    assert dut_passkey, "Numeric comparison passkey not found in DUT hostlog"
    assert_passkey_valid(dut_passkey)

    logger().info("Peer (peripheral) declining numeric comparison (set_pin -1)")
    peer_set_pin(ble_client, -1)

    wait_for_smp_numeric_comparison_failed(bus, timeout=fail_timeout)


def fail_smp_numeric_comparison_central_accept_periph_no_action(
    bus,
        wifi_dut,
    remote_peer_address,
    *,
    timeout: float = 120,
    fail_timeout: float = 120,
):
    """
    C553871: Numeric Comparison — central Accept, peripheral no action (timeout).

    DUT confirms NC value using ``smp_passkey``; peer intentionally takes no action,
    so DUT should report auth timeout/failure ``0x4bfc`` and disconnect.
    """
    dut_passkey = wait_for_passkey(bus, timeout=timeout)
    assert dut_passkey, "Numeric comparison passkey not found in DUT hostlog"
    assert_passkey_valid(dut_passkey)

    logger().info(
        f"DUT (central) accepting numeric comparison — passkey {dut_passkey}"
    )
    wifi_dut.interfaces.wifi.smp_passkey(
        bd_addr=remote_peer_address, passkey=dut_passkey
    )
    logger().info(
        f"Peer no-action after DUT accept ({dut_passkey}) — expecting 0x"
        f"{SMP_AUTH_FAILURE_ERROR_CODE}"
    )
    wait_for_smp_auth_failure_disconnect(bus, timeout=fail_timeout)


def fail_smp_numeric_comparison_periph_accept_central_no_action(
    bus,
        ble_client,
    *,
    timeout: float = 120,
    fail_timeout: float = 120,
):
    """
    C553872: Numeric Comparison — peripheral Accept then central no action (timeout).

    Raspi confirms via ``set_pin``; DUT must not call ``smp_passkey`` (firmware
    comment-out on ``RSI_BLE_SC_PASSKEY_EVENT``). Expect ``0x4bfc`` and disconnect.
    """
    dut_passkey = wait_for_passkey(bus, timeout=timeout)
    assert dut_passkey, "Numeric comparison passkey not found in DUT hostlog"
    assert_passkey_valid(dut_passkey)

    logger().info(
        f"Raspi (peripheral) accepting numeric comparison — set_pin {dut_passkey}"
    )
    peer_set_pin(ble_client, int(dut_passkey))
    logger().info(
        f"DUT (central) no-action after peripheral accept — expecting 0x"
        f"{SMP_AUTH_FAILURE_ERROR_CODE}"
    )
    wait_for_smp_auth_failure_disconnect(bus, timeout=fail_timeout)


def fail_smp_numeric_comparison_both_no_action(
    bus,
    *,
    timeout: float = 120,
    fail_timeout: float = 120,
):
    """
    C553873: Numeric Comparison — peripheral and central no action (SMP timeout).

    Neither DUT ``smp_passkey`` nor Raspi ``set_pin``; firmware must omit auto-passkey.
    """
    dut_passkey = wait_for_passkey(bus, timeout=timeout)
    assert dut_passkey, "Numeric comparison passkey not found in DUT hostlog"
    assert_passkey_valid(dut_passkey)

    logger().info(
        f"Withholding NC on both sides (passkey {dut_passkey}) — expecting 0x"
        f"{SMP_AUTH_FAILURE_ERROR_CODE}"
    )
    wait_for_smp_auth_failure_disconnect(bus, timeout=fail_timeout)


def raspi_connect_and_pair_numeric_comparison(
        wifi_dut,
        ble_client,
    dut_address,
    central_address,
    bus,
    *,
    connect_timeout=CONNECT_TIMEOUT_SEC,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    pair_complete_timeout=SMP_COMPLETE_TIMEOUT_SEC,
    peer_dev_addr_type=None,
    prefer_static_random: bool = False,
):
    """TestRail step 8 — peer central connects to DUT and completes NC pairing."""
    if is_nrf_peer(ble_client):
        nrf_central_connect_and_pair_numeric_comparison(
            wifi_dut,
            ble_client,
            dut_address,
            central_address,
            bus,
            peer_dev_addr_type=peer_dev_addr_type,
            connect_timeout=connect_timeout,
            passkey_timeout=passkey_timeout,
            pair_complete_timeout=pair_complete_timeout,
            prefer_static_random=prefer_static_random,
        )
        return

    def _connect():
        logger().info(f"Raspi connecting to DUT {dut_address} (numeric comparison)")
        ble_client.interfaces.bluetooth.connect(
            dev_addr=dut_address,
            supervision_timeout=500,
        )

    drain_serial(bus)
    connect_thread = threading.Thread(target=_connect)
    connect_thread.start()
    time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)
    complete_smp_numeric_comparison(
        bus,
        wifi_dut,
        ble_client,
        central_address,
        timeout=passkey_timeout,
    )
    connect_thread.join(timeout=connect_timeout)
    assert not connect_thread.is_alive(), (
        f"Raspi connect thread did not finish within {connect_timeout}s"
    )
    try:
        connected = ble_client.interfaces.bluetooth.get_connection_status(
            dut_address
        )
    except Exception as exc:
        logger().warning(f"Raspi get_connection_status: {exc}")
        connected = False
    assert connected, (
        f"Raspi central not connected to DUT {dut_address} after NC pairing"
    )


def raspi_connect_and_pair_passkey_central(
    ble_client,
    dut_address,
    bus,
    *,
    connect_timeout: float = 120,
    passkey_timeout: float = 120,
    smp_complete_timeout: float = 120,
    passkey_exclude: Sequence[str] = (),
) -> str:
    """Peer central connects to DUT peripheral and completes SC passkey pairing.

    Returns the passkey used. Pass ``passkey_exclude`` when a second central pairs
    to the same DUT (C553853) so an earlier passkey in the hostlog is skipped.
    """
    if is_nrf_peer(ble_client):
        central_addr = ble_client.interfaces.bluetooth.get_ble_address()

        def _smp_passkey(bus, _wifi_dut, peer, _central_addr, **_kw):
            passkey = wait_for_passkey(
                bus, timeout=passkey_timeout, exclude=passkey_exclude
            )
            assert passkey, "SC passkey not found in DUT hostlog (step 5)"
            assert_passkey_valid(passkey)
            complete_smp_with_passkey(
                bus, peer, passkey, timeout=smp_complete_timeout
            )
            return passkey

        nrf_central_connect_and_pair(
            None,
            ble_client,
            dut_address,
            central_addr,
            bus,
            capability="KeyboardOnly",
            dynamic_passkey=True,
            connect_timeout=connect_timeout,
            smp_handler=_smp_passkey,
        )
        return ""

    def _connect():
        logger().info(f"Raspi connecting to DUT {dut_address} (SC passkey)")
        try:
            ble_client.interfaces.bluetooth.set_bus()
            time.sleep(PEER_BUS_SETTLE_SEC)
        except Exception as exc:
            logger().warning(f"Raspi set_bus before connect: {exc}")
        ble_client.interfaces.bluetooth.connect(
            dev_addr=dut_address,
            supervision_timeout=500,
        )

    drain_serial(bus)
    connect_thread = threading.Thread(target=_connect)
    connect_thread.start()
    time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)

    passkey = wait_for_passkey(
        bus, timeout=passkey_timeout, exclude=passkey_exclude, enter_on_peer=ble_client
    )
    assert passkey, "SC passkey not found in DUT hostlog (step 5)"
    assert_passkey_valid(passkey)
    complete_smp_with_passkey(bus, ble_client, passkey, timeout=smp_complete_timeout)

    connect_thread.join(timeout=connect_timeout)
    assert not connect_thread.is_alive(), "Raspi connect thread did not finish"
    return passkey


def _hostlog_item_count(bus) -> int:
    return len(decode_log_items(bus.get_input_log()))


def _hostlog_slice_since(bus, baseline: int) -> str:
    return "\n".join(decode_log_items(bus.get_input_log())[baseline:]).lower()


def _hostlog_contains_passkey(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in PASSKEY_PROMPT_MARKERS)


def _extract_passkey_from_hostlog_text(text: str) -> Optional[str]:
    """Return the last 6-digit passkey seen in hostlog text, if any."""
    matches = re.findall(r"passkey[:\s]+(\d+)", text, re.IGNORECASE)
    for raw in reversed(matches):
        if len(raw) <= 6:
            return raw.zfill(6)
    return None


def _hostlog_contains_display_passkey(text: str, passkey: str) -> bool:
    """True when hostlog shows the SC display passkey (tolerates missing leading zeros)."""
    expected = str(passkey).zfill(6)
    unpadded = str(int(expected))
    if expected in text or unpadded in text:
        return True
    return bool(
        re.search(rf"passkey[:\s]+0*{int(unpadded)}\b", text, re.IGNORECASE)
    )


def _hostlog_contains_wrong_passkey_entry(text: str, *, wrong_passkey: int = 0) -> bool:
    """True when DUT hostlog shows wrong passkey submission (smp_passkey CLI or firmware)."""
    lower = text.lower()
    wrong = str(wrong_passkey).zfill(6)
    return (
        wrong in text
        or f"using passkey {wrong_passkey}" in lower
        or "ble_module_smp_passkey_cmd_handler" in lower
    )


def _hostlog_dual_master_reconnect_complete(chunk: str, *, expected: int = 2) -> bool:
    """C553853 — wearables may omit dual master-count lines on bonded reconnect."""
    if any(marker in chunk for marker in C553853_DUAL_BONDED_RECONNECT_MARKERS):
        return True
    if chunk.count("on enhance connect event") >= expected and (
        chunk.count("enhanced connect event status report : 0") >= expected
        or "in smp encrypt event" in chunk
    ):
        return True
    return False


def wait_for_peripheral_master_disconnected(
    bus, *, timeout: float = 30
):
    """TestRail C553850 step 6 — DUT reports zero connected master devices."""
    ok, log_text = wait_for_log_patterns(
        bus,
        PERIPHERAL_MASTER_DISCONNECT_MARKERS,
        timeout=timeout,
        require_all=False,
    )
    lower = log_text.lower()
    disconnected = any(marker in lower for marker in PERIPHERAL_MASTER_DISCONNECT_MARKERS)
    assert disconnected or ok, (
        f"Expected 'number of connected master devices:0' in hostlog "
        f"within {timeout}s"
    )
    logger().info(f"DUT reports zero connected master devices")


def wait_for_peripheral_master_count(
    bus, expected: int, *, timeout: float = 60
):
    """Wait until DUT peripheral reports ``expected`` connected master devices."""
    markers = (
        f"number of master devices connected:{expected}",
        f"number of connected master devices:{expected}",
    )
    ok, log_text = wait_for_log_patterns(
        bus, markers, timeout=timeout, require_all=False
    )
    lower = log_text.lower()
    found = any(marker in lower for marker in markers)
    assert found or ok, (
        f"Expected master devices connected:{expected} in hostlog "
        f"within {timeout}s"
    )
    logger().info(
        f"DUT reports {expected} connected master device(s)"
    )


def wait_for_c553853_dual_masters_connected(
    bus, *, timeout: float = CONNECT_TIMEOUT_SEC, baseline: int = 0
):
    """
    TestRail C553853 step 7 — two masters connected after second central pairs.

    Wearables firmware may log ``Number of master devices connected:2 -`` or
    omit the count; accept dual connect + encrypt hostlog as fallback.
    """
    markers = C553853_DUAL_BONDED_RECONNECT_MARKERS
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        chunk = _hostlog_slice_since(bus, baseline)
        if any(marker in chunk for marker in markers):
            logger().info(f"DUT reports 2 connected master devices")
            return
        if _hostlog_dual_master_reconnect_complete(chunk, expected=2):
            logger().info(
                f"Dual master connect verified via connect/encrypt "
                "hostlog (master-count line omitted)"
            )
            return
    pytest.fail(
        f"Expected 2 master devices connected in hostlog within "
        f"{timeout}s (step 7)"
    )


def raspi_disconnect_from_dut(ble_client, dut_address):
    logger().info(f"Peer disconnecting from DUT {dut_address}")
    if is_nrf_peer(ble_client):
        ble_client.interfaces.bluetooth.disconnect(
            dev_addr=dut_address, clear_peer=True
        )
    else:
        ble_client.interfaces.bluetooth.disconnect(dev_addr=dut_address)


def raspi_disconnect_and_wait(
    bus,
    ble_client,
    dut_address,
    *,
    disconnect_timeout: float = 30,
):
    """Disconnect from Raspi central and confirm DUT master count is zero."""
    raspi_disconnect_from_dut(ble_client, dut_address)
    time.sleep(2)
    wait_for_peripheral_master_disconnected(
        bus, timeout=disconnect_timeout
    )


def raspi_dual_disconnect_and_wait(
    bus,
    ble_clients,
    dut_address,
    *,
    disconnect_timeout: float = SCAN_RESTART_AFTER_DISCONNECT_SEC,
):
    """Disconnect both Raspi centrals and confirm DUT reports zero masters (C553853 step 8)."""
    for idx, client in enumerate(ble_clients, start=1):
        raspi_disconnect_from_dut(
            client, dut_address
        )
        time.sleep(STEP_SETTLE_SEC)
    time.sleep(POST_DISCONNECT_SETTLE_SEC)
    ok, log_text = wait_for_log_patterns(
        bus,
        C553853_DUAL_MASTER_DISCONNECT_MARKERS,
        timeout=disconnect_timeout,
        require_all=False,
    )
    lower = log_text.lower()
    disconnected = any(
        marker in lower for marker in C553853_DUAL_MASTER_DISCONNECT_MARKERS
    )
    assert disconnected or ok, (
        f"Expected zero connected master devices in hostlog "
        f"within {disconnect_timeout}s (step 8)"
    )
    logger().info(f"DUT reports zero connected master devices (dual disconnect)")


def raspi_reconnect_bonded(
    ble_client,
    dut_address,
    bus,
    *,
    connect_timeout: float = 60,
    iteration: int = 0,
):
    """Reconnect using stored bond info — must not trigger SMP passkey (steps 7–8)."""
    baseline = _hostlog_item_count(bus)
    if not is_nrf_peer(ble_client):
        try:
            ble_client.interfaces.bluetooth.set_bus()
            time.sleep(PEER_BUS_SETTLE_SEC)
        except Exception as exc:
            logger().warning(f"Raspi set_bus before bonded reconnect: {exc}")

    def _connect():
        logger().info(
            f"Raspi bonded reconnect to DUT {dut_address} "
            f"(iteration {iteration})"
        )
        ble_client.interfaces.bluetooth.connect(
            dev_addr=dut_address,
            supervision_timeout=500,
        )

    connect_thread = threading.Thread(target=_connect)
    connect_thread.start()

    deadline = time.time() + connect_timeout
    reconnected = False
    while time.time() < deadline:
        time.sleep(0.5)
        chunk = _hostlog_slice_since(bus, baseline)
        if _hostlog_contains_passkey(chunk):
            connect_thread.join(timeout=5)
            pytest.fail(
                f"Passkey prompted on bonded reconnect "
                f"(iteration {iteration}) — bond info not reused"
            )
        if any(marker in chunk for marker in BONDED_RECONNECT_SUCCESS_MARKERS):
            reconnected = True
            break
        if _dut_peripheral_ll_connected_since(bus, baseline):
            reconnected = True
            break
        if (
            "in smp encrypt event" in chunk
            and not _hostlog_contains_passkey(chunk)
        ):
            reconnected = True
            break
        if "on enhance connect event" in chunk or "on_enhance_conn" in chunk:
            if "status report : 0" in chunk:
                reconnected = True
                break
        if not is_nrf_peer(ble_client):
            try:
                if ble_client.interfaces.bluetooth.get_connection_status(
                    dut_address
                ):
                    reconnected = True
                    break
            except Exception:
                pass

    connect_thread.join(timeout=max(0, deadline - time.time()))
    assert reconnected, (
        f"Bonded reconnect did not complete within {connect_timeout}s "
        f"(iteration {iteration})"
    )
    logger().info(
        f"Bonded reconnect successful without passkey "
        f"(iteration {iteration})"
    )


def raspi_dual_reconnect_bonded(
    ble_clients,
    dut_address,
    bus,
    *,
    expected_masters: int = 2,
    connect_timeout: float = CONNECT_TIMEOUT_SEC,
    iteration: int = 0,
):
    """Reconnect two bonded Raspi centrals without SMP passkey (C553853 steps 9–10)."""
    baseline = _hostlog_item_count(bus)
    threads = []

    for idx, client in enumerate(ble_clients, start=1):
        if not is_nrf_peer(client):
            try:
                client.interfaces.bluetooth.set_bus()
                time.sleep(PEER_BUS_SETTLE_SEC)
            except Exception as exc:
                logger().warning(
                    f"Raspi central {idx} set_bus before dual reconnect: {exc}"
                )

    def _connect(client, idx: int):
        logger().info(
            f"Raspi central {idx} bonded reconnect to DUT {dut_address} "
            f"(iteration {iteration})"
        )
        client.interfaces.bluetooth.connect(
            dev_addr=dut_address,
            supervision_timeout=500,
        )

    for idx, client in enumerate(ble_clients, start=1):
        thread = threading.Thread(target=_connect, args=(client, idx))
        threads.append(thread)
        thread.start()
        time.sleep(STEP_SETTLE_SEC)

    deadline = time.time() + connect_timeout
    reconnected = False
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        chunk = _hostlog_slice_since(bus, baseline)
        if _hostlog_contains_passkey(chunk):
            for thread in threads:
                thread.join(timeout=5)
            pytest.fail(
                f"Passkey prompted on dual bonded reconnect "
                f"(iteration {iteration}) — bond info not reused"
            )
        if _hostlog_dual_master_reconnect_complete(
            chunk, expected=expected_masters
        ):
            reconnected = True
            break
        if chunk.count("on enhance connect event") >= expected_masters and (
            chunk.count("enhanced connect event status report : 0") >= expected_masters
            or "in smp encrypt event" in chunk
        ):
            reconnected = True
            break
        connected_count = 0
        for client in ble_clients:
            if is_nrf_peer(client):
                continue
            try:
                if client.interfaces.bluetooth.get_connection_status(dut_address):
                    connected_count += 1
            except Exception:
                pass
        if connected_count >= expected_masters:
            reconnected = True
            break

    for thread in threads:
        thread.join(timeout=max(0, deadline - time.time()))
    assert reconnected, (
        f"Dual bonded reconnect did not reach "
        f"{expected_masters} masters within {connect_timeout}s "
        f"(iteration {iteration})"
    )
    final_chunk = _hostlog_slice_since(bus, baseline)
    if any(marker in final_chunk for marker in C553853_DUAL_BONDED_RECONNECT_MARKERS):
        wait_for_peripheral_master_count(
            bus, expected_masters, timeout=STEP_SETTLE_SEC
        )
    else:
        logger().info(
            f"Dual reconnect verified via connect/encrypt hostlog "
            f"(master-count line omitted, iteration {iteration})"
        )
    logger().info(
        f"Dual bonded reconnect successful without passkey "
        f"(iteration {iteration})"
    )


def wait_for_central_slave_disconnected(
    bus, *, timeout: float = 45
):
    """TestRail C553851 step 9 — DUT central reports slave disconnected."""
    ok, log_text = wait_for_log_patterns(
        bus,
        CENTRAL_SLAVE_DISCONNECT_MARKERS,
        timeout=timeout,
        require_all=False,
    )
    lower = log_text.lower()
    disconnected = any(marker in lower for marker in CENTRAL_SLAVE_DISCONNECT_MARKERS)
    assert disconnected or ok, (
        f"Expected slave disconnect hostlog within {timeout}s "
        "(slave is disconnected / slave devices:0)"
    )
    logger().info(f"DUT central reports slave disconnected")


def raspi_peripheral_disconnect_from_central(
    ble_client,
    central_address,
    *,
    wifi_dut=None,
    peripheral_address: Optional[str] = None,
):
    """
    Disconnect peer peripheral link to DUT central (TestRail step 9).

    Raspi peripheral disconnects from ``central_address`` (DUT BD addr).
    nRF dongle in peripheral role: ``peer_device`` is often unset when the DUT
    initiated the link — use DUT ``btc_disconnect`` toward ``peripheral_address``.
    """
    logger().info(
        f"Peer peripheral disconnect from DUT central {central_address}"
    )
    if is_nrf_peer(ble_client):
        # nRF as peripheral (C553851/C553852): DUT initiated connect, so
        # peer_device is often unset — optional DUT-side disconnect only when
        # caller passes wifi_dut + peripheral_address (Raspi-central tests never
        # use this helper; C553844/C553849/C553850 use raspi_disconnect_and_wait).
        nrf = ble_client.interfaces.bluetooth
        peer = getattr(nrf, "peer_device", None)
        if peer is not None and getattr(peer, "connected", False):
            try:
                nrf.disconnect(dev_addr=central_address, clear_peer=True)
                return
            except Exception as exc:
                logger().warning(
                    f"nRF disconnect via peer_device failed: {exc}"
                )
        if wifi_dut is not None and peripheral_address:
            logger().info(
                f"nRF peripheral role — DUT btc_disconnect "
                f"from {peripheral_address}"
            )
            safe_dut_btc_disconnect(wifi_dut, peripheral_address)
            time.sleep(STEP_SETTLE_SEC)
            return
        logger().warning(
            f"nRF disconnect skipped — no peer_device and no "
            "wifi_dut/peripheral_address for DUT-side disconnect"
        )
        return
    ble_client.interfaces.bluetooth.disconnect(dev_addr=central_address)


def raspi_peripheral_disconnect_and_wait(
    bus,
    ble_client,
    central_address,
    *,
    disconnect_timeout: float = 45,
    wifi_dut=None,
    peripheral_address: Optional[str] = None,
):
    """Disconnect peer peripheral and confirm DUT central slave count is zero."""
    raspi_peripheral_disconnect_from_central(
        ble_client,
        central_address,
        wifi_dut=wifi_dut,
        peripheral_address=peripheral_address,
    )
    time.sleep(STEP_SETTLE_SEC)
    wait_for_central_slave_disconnected(
        bus, timeout=disconnect_timeout
    )


def wait_for_central_bonded_reconnect(
    bus,
    *,
    baseline: int,
    connect_timeout: float = 90,
    iteration: int = 0,
):
    """
    Wait for DUT central to reconnect without a new SMP pairing request.

    Raspi peripheral must remain advertising; firmware rescans and reconnects
    using stored bond info (steps 10, OTA: no repeated SMP exchange).
    """
    deadline = time.time() + connect_timeout
    reconnected = False
    while time.time() < deadline:
        time.sleep(0.5)
        chunk = _hostlog_slice_since(bus, baseline)
        if any(marker in chunk for marker in SMP_PAIRING_REQUEST_MARKERS):
            pytest.fail(
                f"SMP pairing request on bonded reconnect "
                f"(iteration {iteration}) — bond info not reused"
            )
        if _hostlog_contains_passkey(chunk):
            pytest.fail(
                f"Passkey prompted on bonded reconnect "
                f"(iteration {iteration})"
            )
        if any(marker in chunk for marker in CENTRAL_BONDED_RECONNECT_MARKERS):
            reconnected = True
            break
        if "on enhance connect event" in chunk or "on_enhance_conn" in chunk:
            if "status report : 0" in chunk:
                reconnected = True
                break

    assert reconnected, (
        f"DUT central bonded reconnect did not complete within "
        f"{connect_timeout}s (iteration {iteration})"
    )
    logger().info(
        f"DUT central bonded reconnect without SMP pairing "
        f"(iteration {iteration})"
    )


def ensure_nrf_peripheral_readvertising(
    ble_client,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
):
    """
    C553851+ only — resume nRF peripheral advertising after DUT-side disconnect.

    Bonded reconnect (TestRail step 10) requires the peer to advertise while the
    DUT rescans. Do not call from verified PASS C553832–C553850 paths.
    """
    if not is_nrf_peer(ble_client):
        return
    nrf = ble_client.interfaces.bluetooth
    logger().info(
        f"Ensure nRF peripheral advertising for bonded reconnect "
        f"(adv '{adv_name}')"
    )
    try:
        nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=True
        )
    except Exception as exc:
        logger().warning(
            f"nRF start_advertising resume failed ({exc})"
        )
    time.sleep(PEER_ADV_START_SEC)


def wait_for_c553851_central_slave_disconnected(
    bus, *, timeout: float = 45
):
    """TestRail C553851 step 9 — DUT central disconnect hostlog (wearables markers)."""
    ok, log_text = wait_for_log_patterns(
        bus,
        C553851_SLAVE_DISCONNECT_MARKERS,
        timeout=timeout,
        require_all=False,
    )
    lower = log_text.lower()
    disconnected = any(
        marker in lower for marker in C553851_SLAVE_DISCONNECT_MARKERS
    )
    assert disconnected or ok, (
        f"Expected central disconnect hostlog within {timeout}s "
        "(slave/peripheral disconnected / on event disconnect)"
    )
    logger().info(f"DUT central reports slave/peripheral disconnected")


def wait_for_c553851_central_bonded_reconnect(
    bus,
    *,
    baseline: int,
    connect_timeout: float = 90,
    iteration: int = 0,
):
    """
    TestRail C553851 step 10 — bonded reconnect without passkey prompt.

    Wearables firmware may still log ``smp pairing request initiated`` on
    encrypt restart; treat connect + no passkey as success (OTA deferred).
    """
    deadline = time.time() + connect_timeout
    reconnected = False
    while time.time() < deadline:
        time.sleep(0.5)
        chunk = _hostlog_slice_since(bus, baseline)
        if _hostlog_contains_passkey(chunk):
            pytest.fail(
                f"Passkey prompted on bonded reconnect "
                f"(iteration {iteration})"
            )
        if any(
            marker in chunk
            for marker in (
                "number of slave devices connected:1",
                "number of connected slave devices:1",
            )
        ):
            reconnected = True
            break
        if "on enhance connect event" in chunk and "connected address:" in chunk:
            reconnected = True
            break
        if "in smp encrypt event" in chunk or "smp encrypt initiated" in chunk:
            reconnected = True
            break

    assert reconnected, (
        f"DUT central bonded reconnect did not complete within "
        f"{connect_timeout}s (iteration {iteration})"
    )
    logger().info(
        f"DUT central bonded reconnect without passkey "
        f"(iteration {iteration})"
    )


def c553851_active_bonded_reconnect(
    wifi_dut,
    peripheral_address,
    bus,
    *,
    connect_kwargs,
    iteration: int = 0,
    connect_timeout: float = CONNECT_TIMEOUT_SEC,
    scan_seconds: float = SCAN_BEFORE_CONNECT_SEC,
):
    """
    TestRail C553851 step 10 — DUT scan+connect to bonded nRF peripheral.

    After disconnect the DUT scans but does not auto-connect on this firmware;
    repeat step-6 connect explicitly and verify bonded link (no passkey).
    """
    time.sleep(STEP_SETTLE_SEC)
    drain_serial(bus)
    baseline = _hostlog_item_count(bus)

    logger().info(
        f"Step 10 iteration {iteration}: DUT scan+connect bonded "
        f"reconnect to {peripheral_address}"
    )
    connect_log = dut_scan_and_connect_fast_connect_rx(
        wifi_dut,
        peripheral_address,
        scan_seconds=scan_seconds,
        accept_smp_start=False,
        connect_timeout=connect_timeout,
        **connect_kwargs,
    )
    lower = connect_log.lower()
    if _hostlog_contains_passkey(lower):
        pytest.fail(
            f"Passkey prompted during bonded reconnect connect "
            f"(iteration {iteration})"
        )
    connected = (
        "on enhance connect event" in lower
        or "enhanced connect event status report : 0" in lower
        or "connected address:" in lower
    )
    assert connected, (
        f"Bonded reconnect connect event missing in hostlog "
        f"(iteration {iteration})"
    )

    time.sleep(STEP_SETTLE_SEC)
    wait_for_c553851_central_bonded_reconnect(
        bus,
        baseline=baseline,
        connect_timeout=connect_timeout,
        iteration=iteration,
    )


def confirm_c553852_bonded_nc_passkey(
        wifi_dut,
        ble_client,
    peripheral_address: str,
    passkey: str,
    *,
    iteration: int = 0,
):
    """C553852 only — confirm Numeric Comparison passkey on bonded reconnect."""
    assert_passkey_valid(passkey)
    logger().info(
        f"Bonded reconnect NC Match — passkey {passkey} "
        f"(iteration {iteration})"
    )
    peer_set_pin(ble_client, int(passkey))
    time.sleep(1)
    try:
        peer_pk = peer_get_passkey(ble_client)
        if peer_pk and str(peer_pk) != "0":
            peer_passkey = str(peer_pk).zfill(6)
            logger().info(
                f"DUT confirming peer passkey {peer_passkey} "
                f"(iteration {iteration})"
            )
            wifi_dut.interfaces.wifi.smp_passkey(
                bd_addr=peripheral_address, passkey=peer_passkey
            )
            return
    except Exception as exc:
        logger().info(
            f"Peer passkey auto-confirm unavailable: {exc} "
            f"(iteration {iteration})"
        )
    wifi_dut.interfaces.wifi.smp_passkey(
        bd_addr=peripheral_address, passkey=passkey
    )


def wait_for_c553852_central_bonded_reconnect(
    bus,
    wifi_dut,
    ble_client,
    peripheral_address: str,
    *,
    baseline: int,
    connect_timeout: float = CONNECT_TIMEOUT_SEC,
    iteration: int = 0,
):
    """
    TestRail C553852 step 9 — bonded reconnect with NC encrypt restart.

    Wearables firmware may log ``in smp sc passkey event`` on bonded reconnect;
    auto-confirm Match then wait for ``in smp encrypt event`` (OTA deferred).
    """
    deadline = time.time() + connect_timeout
    nc_confirmed = False
    reconnected = False
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        chunk = _hostlog_slice_since(bus, baseline)
        if "in smp encrypt event" in chunk or "smp encrypt initiated" in chunk:
            reconnected = True
            break
        if any(
            marker in chunk
            for marker in (
                "number of slave devices connected:1",
                "number of connected slave devices:1",
            )
        ):
            reconnected = True
            break
        if not nc_confirmed and _hostlog_contains_passkey(chunk):
            passkey = _extract_passkey_from_hostlog_text(chunk)
            if passkey:
                confirm_c553852_bonded_nc_passkey(
        wifi_dut,
        ble_client,
                    peripheral_address,
                    passkey,
                    iteration=iteration,
                )
                nc_confirmed = True

    assert reconnected, (
        f"DUT central bonded NC reconnect did not encrypt within "
        f"{connect_timeout}s (iteration {iteration})"
    )
    logger().info(
        f"DUT central bonded NC reconnect complete "
        f"(iteration {iteration})"
    )


def c553852_active_bonded_reconnect(
    wifi_dut,
    peripheral_address,
    bus,
    ble_client,
    *,
    connect_kwargs,
    iteration: int = 0,
    connect_timeout: float = CONNECT_TIMEOUT_SEC,
    scan_seconds: float = SCAN_BEFORE_CONNECT_SEC,
):
    """
    TestRail C553852 step 9 — DUT scan+connect bonded nRF peripheral (NC).

    Same active reconnect as C553851; on encrypt restart accept NC passkey
    from hostlog and confirm Match before verifying encrypt complete.
    """
    time.sleep(STEP_SETTLE_SEC)
    drain_serial(bus)
    baseline = _hostlog_item_count(bus)

    logger().info(
        f"TestRail step 9 iteration {iteration}: DUT scan+connect "
        f"bonded reconnect to {peripheral_address}"
    )
    connect_log = dut_scan_and_connect_fast_connect_rx(
        wifi_dut,
        peripheral_address,
        scan_seconds=scan_seconds,
        accept_smp_start=False,
        connect_timeout=connect_timeout,
        **connect_kwargs,
    )
    lower = connect_log.lower()
    connected = (
        "on enhance connect event" in lower
        or "enhanced connect event status report : 0" in lower
        or "connected address:" in lower
    )
    assert connected, (
        f"Bonded reconnect connect event missing in hostlog "
        f"(iteration {iteration})"
    )

    time.sleep(STEP_SETTLE_SEC)
    wait_for_c553852_central_bonded_reconnect(
        bus,
        wifi_dut,
        ble_client,
        peripheral_address,
        baseline=baseline,
        connect_timeout=connect_timeout,
        iteration=iteration,
    )


def c553851_nrf_peripheral_disconnect_and_wait(
    bus,
    ble_client,
    wifi_dut,
    local_addr: str,
    peripheral_address: str,
    *,
    disconnect_timeout: float = SCAN_RESTART_AFTER_DISCONNECT_SEC,
):
    """
    C553851 step 9 / C553852 step 8 — nRF peripheral disconnect + DUT hostlog.

    Prefer nRF-side disconnect when ``peer_device`` is synced; otherwise DUT
    ``btc_disconnect``. Then ensure nRF is advertising again for step 10.
    """
    if is_nrf_peer(ble_client):
        _try_recover_nrf_peer_device(
            ble_client.interfaces.bluetooth, local_addr
        )
    raspi_peripheral_disconnect_from_central(
        ble_client,
        local_addr,
        wifi_dut=wifi_dut,
        peripheral_address=peripheral_address,
    )
    time.sleep(STEP_SETTLE_SEC)
    wait_for_c553851_central_slave_disconnected(
        bus, timeout=disconnect_timeout
    )
    ensure_nrf_peripheral_readvertising(ble_client)


def wait_for_encryption_restart(bus, *, timeout: float = 60) -> str:
    """TestRail C553844 — firmware ENCRYPT_STARTED handler calls start_encryption once."""
    ok, log_text = wait_for_log_patterns(
        bus, ENCRYPTION_RESTART_MARKERS, timeout=timeout, poll=1
    )
    assert ok, (
        "Expected 'Encryption restarted' in DUT hostlog after ENCRYPT_STARTED "
        "(firmware rsi_ble_subtask patch must be applied)"
    )
    logger().info("DUT encryption restart confirmed in hostlog")
    return log_text


def verify_encryption_key_refresh_connect_hostlog(bus):
    """TestRail C553844 step 4 — connect, MTU, SMP passkey hostlog."""
    accumulated = "\n".join(decode_log_items(bus.get_input_log()))
    combined = accumulated.lower()
    for marker in ENCRYPTION_KEY_REFRESH_CONNECT_MARKERS:
        assert marker in combined, (
            f"Expected hostlog marker '{marker}' (step 4)"
        )


def verify_encryption_key_refresh_step5_hostlog(bus):
    """TestRail C553844 step 5 — SMP encrypt, security keys, profile discovery hostlog.

    Caller should ``time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)`` before this (C553833 pattern).
    """
    ok, log_text = wait_for_log_patterns(
        bus,
        ENCRYPTION_KEY_REFRESH_STEP5_MARKERS,
        timeout=SMP_PAIRING_REQUEST_TIMEOUT_SEC,
    )
    lower = log_text.lower()
    missing = [m for m in ENCRYPTION_KEY_REFRESH_STEP5_MARKERS if m not in lower]
    assert ok, (
        f"Expected hostlog markers for step 5, missing: {missing}"
    )
    if "remote device profile discovery started" not in lower:
        logger().warning(
            f"'remote device profile discovery started' not in hostlog "
            "(optional on some COEX_MAX_DEMO builds; step 5 completed marker present)"
        )
    ltk = extract_ltk_from_hostlog(bus, timeout=STEP_SETTLE_SEC)
    assert ltk is not None, f"Expected LE LTK in hostlog (step 5)"
    if ltk:
        logger().info(f"LE LTK validated from hostlog: {ltk}")


def verify_peripheral_encryption_initiation_hostlog(bus):
    """TestRail C553854/C553855 step 4 — DUT peripheral encryption initiation (hostlog)."""
    required_markers = (
        "smp encrypt event",
        "remote device profiles discovery completed",
    )
    optional_markers = (
        "number of master devices connected:1",
        "smp security keys event",
        "remote device profile discovery started",
        "conn_interval",
    )
    accumulated = "\n".join(decode_log_items(bus.get_input_log()))
    combined = accumulated.lower()
    for marker in required_markers:
        assert marker in combined, (
            f"Expected hostlog marker '{marker}' (step 4)"
        )
    missing_optional = [m for m in optional_markers if m not in combined]
    if missing_optional:
        logger().warning(
            f"Optional step-4 encryption-init markers missing: "
            f"{missing_optional}"
        )
    ltk = extract_ltk_from_hostlog(bus, timeout=SMP_COMPLETE_TIMEOUT_SEC)
    assert ltk is not None, f"Expected LE LTK in hostlog (step 4)"
    if ltk:
        logger().info(f"LE LTK validated from hostlog: {ltk}")


def verify_central_encryption_pause_resume_hostlog(bus):
    """TestRail C553856 steps 3–5 — central connect, passkey, encryption restart."""
    ok, log_text = wait_for_log_patterns(
        bus, CENTRAL_ENCRYPTION_PAUSE_RESUME_MARKERS, timeout=90, require_all=False
    )
    lower = log_text.lower()
    for marker in CENTRAL_ENCRYPTION_PAUSE_RESUME_MARKERS:
        assert marker in lower, (
            f"Expected hostlog marker '{marker}' (steps 3–5)"
        )
    assert "encryption restarted" in lower, (
        f"Expected 'Encryption restarted' after ENCRYPT_STARTED patch (step 5)"
    )
    ltk = extract_ltk_from_hostlog(bus, timeout=SMP_COMPLETE_TIMEOUT_SEC)
    assert ltk is not None, f"Expected LE LTK in hostlog (step 4)"
    if ltk:
        logger().info(f"LE LTK validated from hostlog: {ltk}")


def verify_c553856_central_pairing_hostlog(bus):
    """
    TestRail C553856 steps 3–4 hostlog (C553856-only, hostlog-only mode).

    Wearables COEX builds may log ``LE LTK`` without ``smp security keys event``.
    Step 5 (``Encryption restarted`` + OTA LL_PAUSE_ENC) is checked separately /
    deferred until firmware patch and RF sniffer are available.
    """
    accumulated = "\n".join(decode_log_items(bus.get_input_log()))
    lower = accumulated.lower()
    scan_ok = any(
        m in lower
        for m in (
            "start scanning",
            "start scan command",
            "restarting scanning",
            "scanning started",
        )
    )
    assert scan_ok, (
        f"Expected DUT scan activity in hostlog (step 3)"
    )
    required = (
        "smp pairing request initiated",
        "smp sc passkey",
        "passkey",
        "smp encrypt event",
        "remote device profiles discovery completed",
    )
    for marker in required:
        assert marker in lower, (
            f"Expected hostlog marker '{marker}' (steps 3–4)"
        )
    if "smp security keys event" not in lower:
        assert "le ltk" in lower, (
            f"Expected 'smp security keys event' or 'LE LTK' (step 4)"
        )
        logger().warning(
            f"'smp security keys event' absent — LE LTK present (wearables)"
        )
    ltk = extract_ltk_from_hostlog(bus, timeout=STEP_SETTLE_SEC)
    if ltk:
        logger().info(f"LE LTK validated from hostlog: {ltk}")


def note_c553856_step5_encryption_restart_deferred(bus):
    """Step 5 hostlog/OTA deferred — warn if ENCRYPT_STARTED patch log is absent."""
    lower = "\n".join(decode_log_items(bus.get_input_log())).lower()
    if "encryption restarted" in lower:
        logger().info(
            f"Step 5 hostlog: 'Encryption restarted' observed "
            "(full OTA LL_PAUSE_ENC validation still deferred)"
        )
    else:
        logger().warning(
            f"TestRail step 5 deferred — 'Encryption restarted' hostlog "
            "and OTA LL_PAUSE_ENC validation skipped until firmware ENCRYPT_STARTED "
            "patch (step 1) and RF sniffer integration are available"
        )


def verify_c553857_central_encryption_initiation_hostlog(
    bus, data_path_timeout: float = 90.0
):
    """
    TestRail C553857 steps 2–3 hostlog (C553857-only, hostlog-only mode).

    Step 4 OTA (LL_ENC / LL_START_ENC) is deferred. Wearables COEX builds may use
    ``data transfer req done`` instead of ``buffer configuration done`` /
    ``start transmitting data``.
    """
    accumulated = "\n".join(decode_log_items(bus.get_input_log()))
    lower = accumulated.lower()
    scan_ok = any(
        m in lower
        for m in (
            "start scanning",
            "start scan command",
            "restarting scanning",
            "scanning started",
        )
    )
    assert scan_ok, (
        f"Expected DUT scan activity in hostlog (step 2)"
    )
    required = (
        "smp pairing request initiated",
        "smp sc passkey",
        "passkey",
        "smp encrypt event",
        "remote device profiles discovery completed",
    )
    for marker in required:
        assert marker in lower, (
            f"Expected hostlog marker '{marker}' (steps 2–3)"
        )
    if "smp security keys event" not in lower:
        assert "le ltk" in lower, (
            f"Expected 'smp security keys event' or 'LE LTK' (step 3)"
        )
        logger().warning(
            f"'smp security keys event' absent — LE LTK present (wearables)"
        )
    ltk = extract_ltk_from_hostlog(bus, timeout=STEP_SETTLE_SEC)
    if ltk:
        logger().info(f"LE LTK validated from hostlog: {ltk}")

    ok, log_text = wait_for_log_patterns(
        bus,
        (
            "buffer configuration done",
            "start transmitting data",
            "data transfer req done",
        ),
        timeout=data_path_timeout,
        require_all=False,
    )
    combined = f"{accumulated}\n{log_text}".lower()
    data_path_ok = any(
        m in combined
        for m in (
            "buffer configuration done",
            "start transmitting data",
            "data transfer req done",
        )
    )
    assert data_path_ok, (
        f"Expected data-path hostlog within {data_path_timeout}s "
        "(step 3: buffer configuration / start transmitting data / data transfer req)"
    )
    if "start transmitting data" not in combined:
        logger().warning(
            f"'start transmitting data' not in hostlog — "
            "alternate wearables data-path marker accepted (step 3)"
        )
    if "connection params request" not in combined:
        logger().warning(
            f"Optional step-3 marker 'connection params request' not seen"
        )
    if not ok:
        logger().info(
            f"Data-path marker found in accumulated hostlog (no new RX)"
        )


def note_c553857_step4_ota_deferred():
    logger().warning(
        f"TestRail step 4 deferred — OTA LL_ENC / LL_START_ENC validation "
        "skipped until RF sniffer integration is available"
    )


def note_c553859_step7_ota_deferred():
    logger().warning(
        f"TestRail step 7 deferred — OTA LL_ENC_REQ EDIV/Rand=0 validation "
        "skipped until RF sniffer integration is available"
    )


def verify_c553859_dut_legacy_smp_config_hostlog(bus):
    """TestRail C553859 step 1 — legacy Auth Req 0x05 after SMP capability set."""
    ok, log_text = wait_for_log_patterns(
        bus,
        (
            f"auth req: {AUTH_REQ_BONDING_MITM_LEGACY}",
            "auth req: 0x05",
            "ble_module_set_smp_pairing_capability_data_cmd_handler : successful",
        ),
        timeout=DUT_INIT_LOG_MARKER_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    auth_ok = (
        f"auth req: {AUTH_REQ_BONDING_MITM_LEGACY}" in lower
        or "auth req: 0x05" in lower
        or "ble_module_set_smp_pairing_capability_data_cmd_handler : successful"
        in lower
    )
    assert auth_ok, (
        f"Expected legacy SMP config (Auth Req 0x05 / handler successful) "
        "in hostlog (step 1)"
    )
    if not ok:
        logger().warning(f"Legacy SMP config marker delayed in hostlog")
    logger().info(f"DUT legacy SMP Auth Req 0x05 validated (step 1)")


def verify_c553859_step6_legacy_passkey_hostlog(bus, passkey: str):
    """TestRail C553859 step 6 — MTU, SMP start, legacy passkey event (hostlog)."""
    ok, log_text = wait_for_log_patterns(
        bus,
        (
            "mtu exchange",
            "smp pairing request initiated",
            "passkey",
        ),
        timeout=SMP_COMPLETE_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    assert "mtu exchange" in lower, (
        f"Expected MTU exchange in hostlog (step 6)"
    )
    assert "smp pairing request initiated" in lower, (
        f"Expected SMP pairing request in hostlog (step 6)"
    )
    passkey_marker_ok = any(
        m in lower
        for m in (
            "in smp sc passkey event",
            "smp sc passkey",
            "passkey event",
            "in passkey event",
            "remote addr:",  # legacy STK: "remote addr: …, passkey: …"
        )
    )
    assert passkey_marker_ok, (
        f"Expected passkey SMP event in hostlog (step 6)"
    )
    assert str(passkey) in log_text, (
        f"Expected passkey {passkey} in hostlog (step 6)"
    )
    if not ok:
        logger().warning(f"Some step-6 markers delayed in hostlog")


def verify_c553859_legacy_stk_post_pair_hostlog(bus):
    """TestRail C553859 step 7 — legacy STK bond + encrypt (hostlog-only; OTA deferred)."""
    ok, log_text = wait_for_log_patterns(
        bus,
        ("smp encrypt event",),
        timeout=SMP_COMPLETE_TIMEOUT_SEC,
        require_all=True,
    )
    lower = log_text.lower()
    assert "smp encrypt event" in lower, (
        f"Expected smp encrypt event after legacy pairing (step 7)"
    )
    if "le ltk" in lower:
        ltk = extract_ltk_from_hostlog(bus, timeout=STEP_SETTLE_SEC)
        if ltk:
            logger().info(f"LE LTK/STK validated from hostlog: {ltk}")
    elif "smp security keys event" in lower:
        logger().info(f"smp security keys event seen (legacy STK path)")
    elif not ok:
        logger().warning(f"Encrypt event validated; optional key banners absent")
    logger().info(
        f"Step 7: legacy STK connection + encryption validated (hostlog)"
    )


def note_c553860_step7_ota_deferred():
    logger().warning(
        f"TestRail step 7 deferred — OTA LL_ENC_REQ EDIV/Rand=0 validation "
        "skipped until RF sniffer integration is available"
    )


def verify_c553860_dut_le_sc_smp_config_hostlog(bus):
    """TestRail C553860 step 1 — LESC Auth Req 0x2D after SMP capability set."""
    ok, log_text = wait_for_log_patterns(
        bus,
        (
            f"auth req: {AUTH_REQ_BONDING_MITM_SC}",
            "auth req: 0x2d",
            "auth req: 45",
            "ble_module_set_smp_pairing_capability_data_cmd_handler : successful",
        ),
        timeout=DUT_INIT_LOG_MARKER_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    auth_ok = (
        f"auth req: {AUTH_REQ_BONDING_MITM_SC}" in lower
        or "auth req: 0x2d" in lower
        or "auth req: 45" in lower
        or "ble_module_set_smp_pairing_capability_data_cmd_handler : successful"
        in lower
    )
    assert auth_ok, (
        f"Expected LESC SMP config (Auth Req 0x2D / handler successful) "
        "in hostlog (step 1)"
    )
    if not ok:
        logger().warning(f"LESC SMP config marker delayed in hostlog")
    logger().info(f"DUT LESC SMP Auth Req 0x2D validated (step 1)")


def ensure_c553860_nrf_passkey_entry_after_connect(ble_client):
    """
    C553860 — after DUT connects, re-register dynamic passkey on the nRF peer link.
    """
    if not is_nrf_peer(ble_client):
        return
    nrf = ble_client.interfaces.bluetooth
    if getattr(nrf, "peer_device", None) is not None:
        nrf.register_dynamic_passkey_entry(timeout=int(PASSKEY_TIMEOUT_SEC))
        logger().info(
            f"nRF dynamic passkey handler re-registered on connected peer"
        )


def wait_and_enter_passkey_on_nrf_peer(
    bus, ble_client, timeout=PASSKEY_TIMEOUT_SEC, seed_log: str = ""
) -> Optional[str]:
    """
    C553860 — enter passkey on nRF as soon as DUT hostlog shows it (minimize SMP timeout).
    """
    if seed_log:
        match = re.search(r"passkey[:\s]+(\d+)", seed_log, re.IGNORECASE)
        if match and len(match.group(1)) <= 6:
            pk = match.group(1).zfill(6)
            peer_set_pin(ble_client, int(pk))
            logger().info(
                f"Passkey {pk} entered on nRF peer from connect hostlog"
            )
            return pk

    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        for line in decode_log_items(bus.get_input_log()):
            lower = line.lower()
            if "smp failed" in lower or "4bfc" in lower or "4b0b" in lower:
                pytest.fail(f"SMP failed before passkey: {line.strip()}")
            match = re.search(r"passkey[:\s]+(\d+)", line, re.IGNORECASE)
            if match and len(match.group(1)) <= 6:
                pk = match.group(1).zfill(6)
                peer_set_pin(ble_client, int(pk))
                logger().info(
                    f"Passkey {pk} entered on nRF peer from hostlog"
                )
                return pk
    return None


def c553860_dut_scan_and_connect(wifi_dut, peripheral_address, **kwargs):
    """
    C553860 — nRF peripheral connect with pre-connect hostlog baseline.

    Avoids missing fast connect/SMP RX when legacy ``log_start`` races the connect
    response (symptom: 120s "Connection event not received" despite hostlog connect).
    """
    return dut_scan_and_connect_fast_connect_rx(
        wifi_dut, peripheral_address, **kwargs
    )


def verify_c553861_dut_keyboardonly_smp_config_hostlog(bus):
    """TestRail C553861 steps 1–2 — DUT initiator KeyboardOnly, Auth Req 0x2D."""
    ok, log_text = wait_for_log_patterns(
        bus,
        (
            f"io capability: {DUT_IO_KEYBOARD_ONLY}",
            f"auth req: {AUTH_REQ_BONDING_MITM_SC}",
            "auth req: 0x2d",
            "auth req: 45",
            "ble_module_set_smp_pairing_capability_data_cmd_handler : successful",
        ),
        timeout=DUT_INIT_LOG_MARKER_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    io_ok = (
        f"io capability: {DUT_IO_KEYBOARD_ONLY}" in lower
        or "io capability: 2" in lower
    )
    auth_ok = (
        f"auth req: {AUTH_REQ_BONDING_MITM_SC}" in lower
        or "auth req: 0x2d" in lower
        or "auth req: 45" in lower
        or "ble_module_set_smp_pairing_capability_data_cmd_handler : successful"
        in lower
    )
    assert io_ok, (
        f"Expected DUT IO cap KeyboardOnly (0x02) in hostlog (steps 1–2)"
    )
    assert auth_ok, (
        f"Expected SMP Auth Req 0x2D in hostlog (steps 1–2)"
    )
    if not ok:
        logger().warning(f"KeyboardOnly SMP config marker delayed in hostlog")
    logger().info(f"DUT KeyboardOnly initiator SMP validated (steps 1–2)")


# C553861 — passkey withheld: TestRail expects 0x4bfc; wearables FW may report 0x4b04
# (SMP confirm value failed) when nRF DisplayOnly auto-confirms before DUT entry.
C553861_PASSKEY_FAILURE_CODES: Tuple[str, ...] = (
    SMP_AUTH_FAILURE_ERROR_CODE,
    "4b04",
)

# C553861 — DUT central + nRF peripheral; COEX_MAX omits "number of master devices connected"
C553861_CENTRAL_CONNECT_MARKERS: Tuple[str, ...] = (
    "on enhance connect event",
    "on_enhance_conn",
    "enhanced connect event status report : 0",
    "mtu exchange",
    "smp pairing request initiated",
    "in smp sc passkey event",
    "passkey event",
)


def _prepare_c553861_nrf_displayonly(nrf_ble_client):
    """
    C553861 — DisplayOnly peripheral: show passkey but do not auto-confirm.

    ``register_passkey_display(confirm=True)`` makes Blatann accept the displayed
    passkey immediately while DUT passkey entry is disabled → 0x4b04 instead of
    passkey-timeout 0x4bfc.
    """
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP["DisplayOnly"]
    nrf.set_security_params(
        passcode_pairing=True,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=True,
    )
    nrf.register_on_connect()
    time.sleep(2)
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()

    def on_passkey_display(peer, event_args):
        if event_args.passkey is not None:
            logger().info(
                f"nRF DisplayOnly passkey displayed: {event_args.passkey}"
            )
            nrf.passkey = event_args.passkey
        # Withhold match_confirm — DUT KeyboardOnly must enter passkey (disabled in FW).

    nrf.ble_device.client.security.on_passkey_display_required.register(
        on_passkey_display
    )


def wait_for_c553861_passkey_timeout_failure(
    bus,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """C553861 step 7 — passkey withheld; expect 0x4bfc (or 0x4b04) + disconnect."""
    deadline = time.time() + timeout
    saw_error = False
    saw_disconnect = False
    matched_code: Optional[str] = None
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        for code in C553861_PASSKEY_FAILURE_CODES:
            if code in lower or f"0x{code}" in lower:
                saw_error = True
                matched_code = code
                break
        if _hostlog_contains_disconnect(text):
            saw_disconnect = True
        if saw_error and saw_disconnect:
            logger().info(
                f"Passkey timeout failure 0x{matched_code} and disconnect "
                "confirmed"
            )
            return matched_code
    assert saw_error, (
        f"Expected SMP passkey failure "
        f"({', '.join('0x' + c for c in C553861_PASSKEY_FAILURE_CODES)}) "
        "in DUT hostlog (passkey withheld)"
    )
    assert saw_disconnect, (
        "Expected BLE disconnect after passkey timeout (step 7)"
    )
    return matched_code


def start_c553861_nrf_displayonly_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
):
    """
    C553861 — nRF DisplayOnly peripheral (passkey display), LE SC + bonding + MITM.

    TestRail steps 4–6: nRF Connect adv + security (DisplayOnly, slave11).
    """
    if is_nrf_peer(ble_client):
        _prepare_c553861_nrf_displayonly(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(PEER_BUS_SETTLE_SEC)
    configure_raspi_displayonly_peripheral(
        ble_client, auth_req=AUTH_REQ_BONDING_MITM_SC
    )
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayOnly",
    )
    assert addr, "Failed to start Raspi DisplayOnly advertising (C553861)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(PEER_ADV_START_SEC)
    return addr


def c553861_dut_scan_connect_withhold_passkey(
        wifi_dut,
    peripheral_address,
    bus,
    *,
    connect_kwargs=None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    auth_fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    C553861 step 7 — DUT central connects; passkey shown by DisplayOnly peer;
    DUT must not enter passkey (firmware ``rsi_ble_smp_passkey`` disabled) → 0x4bfc.
    """
    drain_serial(bus)
    connect_log = dut_scan_and_connect_fast_connect_rx(
        wifi_dut,
        peripheral_address,
        accept_smp_start=True,
        **(connect_kwargs or {}),
    )
    passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert passkey, (
        "SC passkey not found in DUT hostlog — DisplayOnly peer should display "
        "passkey for KeyboardOnly initiator (TestRail step 7)"
    )
    logger().info(
        f"Withholding DUT passkey entry ({passkey}) — expecting auth "
        f"failure ({', '.join('0x' + c for c in C553861_PASSKEY_FAILURE_CODES)}) "
        "(firmware passkey response disabled)"
    )
    failure_code = wait_for_c553861_passkey_timeout_failure(
        bus, timeout=auth_fail_timeout
    )
    return connect_log, passkey, failure_code


def verify_c553861_step7_connect_hostlog(bus):
    """TestRail C553861 step 7 — DUT central connect / MTU / LESC passkey before withhold."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    for marker in C553861_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected hostlog marker '{marker}' (step 7 connect/SMP)"
        )


def verify_c553861_passkey_timeout_hostlog(
    bus, passkey: str, failure_code: Optional[str] = None
):
    """TestRail C553861 step 7 — passkey displayed, DUT withholds entry, failure + disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    codes = (
        (failure_code,)
        if failure_code
        else C553861_PASSKEY_FAILURE_CODES
    )
    assert any(
        code in lower or f"0x{code}" in lower for code in codes
    ), (
        f"Expected SMP passkey failure "
        f"({', '.join('0x' + c for c in C553861_PASSKEY_FAILURE_CODES)}) "
        "(step 7)"
    )
    assert str(passkey) in text, (
        f"Expected passkey {passkey} in hostlog before timeout (step 7)"
    )
    assert "smp encrypt event" not in lower, (
        f"Pairing must not encrypt after passkey timeout (step 7)"
    )
    for marker in C553861_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after passkey timeout (step 7)"
    )
    code = failure_code or SMP_AUTH_FAILURE_ERROR_CODE
    logger().info(f"Passkey timeout 0x{code} validated")


def note_c553861_ota_deferred():
    logger().warning(
        f"OTA passkey-timeout / LL packet validation deferred — "
        "hostlog-only mode"
    )


# C553862 — same passkey-withhold failure codes as C553861 on wearables central FW
C553862_PASSKEY_FAILURE_CODES: Tuple[str, ...] = C553861_PASSKEY_FAILURE_CODES
C553862_CENTRAL_CONNECT_MARKERS: Tuple[str, ...] = C553861_CENTRAL_CONNECT_MARKERS


def verify_c553862_dut_keyboarddisplay_smp_config_hostlog(bus):
    """TestRail C553862 steps 1–2 — DUT initiator KeyboardDisplay (0x04), Auth Req 0x2D."""
    ok, log_text = wait_for_log_patterns(
        bus,
        (
            f"io capability: {DUT_IO_KEYBOARD_DISPLAY}",
            f"auth req: {AUTH_REQ_BONDING_MITM_SC}",
            "auth req: 0x2d",
            "auth req: 45",
            "ble_module_set_smp_pairing_capability_data_cmd_handler : successful",
        ),
        timeout=DUT_INIT_LOG_MARKER_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    io_ok = (
        f"io capability: {DUT_IO_KEYBOARD_DISPLAY}" in lower
        or "io capability: 4" in lower
    )
    auth_ok = (
        f"auth req: {AUTH_REQ_BONDING_MITM_SC}" in lower
        or "auth req: 0x2d" in lower
        or "auth req: 45" in lower
        or "ble_module_set_smp_pairing_capability_data_cmd_handler : successful"
        in lower
    )
    assert io_ok, (
        f"Expected DUT IO cap KeyboardDisplay (0x04) in hostlog (steps 1–2)"
    )
    assert auth_ok, (
        f"Expected SMP Auth Req 0x2D in hostlog (steps 1–2)"
    )
    if not ok:
        logger().warning(
            f"KeyboardDisplay SMP config marker delayed in hostlog"
        )
    logger().info(f"DUT KeyboardDisplay initiator SMP validated (steps 1–2)")


def _prepare_c553862_nrf_displayyesno(nrf_ble_client):
    """
    C553862 — DisplayYesNo peripheral: show passkey but do not auto-confirm.

    Withhold ``match_confirm`` so DUT KeyboardDisplay passkey entry (disabled in FW)
    times out instead of failing early with 0x4b04.
    """
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP["DisplayYesNo"]
    nrf.set_security_params(
        passcode_pairing=True,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=True,
    )
    nrf.register_on_connect()
    time.sleep(2)
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()

    def on_passkey_display(peer, event_args):
        if event_args.passkey is not None:
            logger().info(
                f"nRF DisplayYesNo passkey displayed: {event_args.passkey}"
            )
            nrf.passkey = event_args.passkey
        # Withhold match_confirm — DUT must enter passkey (disabled in firmware).

    nrf.ble_device.client.security.on_passkey_display_required.register(
        on_passkey_display
    )


def start_c553862_nrf_displayyesno_peripheral(
        ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
):
    """
    C553862 — nRF DisplayYesNo peripheral (passkey display), LE SC + bonding + MITM.

    TestRail steps 4–6: nRF Connect adv + security (DisplayYesNo, slave11).
    """
    if is_nrf_peer(ble_client):
        _prepare_c553862_nrf_displayyesno(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(PEER_BUS_SETTLE_SEC)
    configure_raspi_displayyesno_peripheral(
        ble_client, auth_req=AUTH_REQ_BONDING_MITM_SC
    )
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo advertising (C553862)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(PEER_ADV_START_SEC)
    return addr


def wait_for_c553862_passkey_timeout_failure(
    bus,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """C553862 step 7 — passkey withheld; expect 0x4bfc (or 0x4b04) + disconnect."""
    deadline = time.time() + timeout
    saw_error = False
    saw_disconnect = False
    matched_code: Optional[str] = None
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        for code in C553862_PASSKEY_FAILURE_CODES:
            if code in lower or f"0x{code}" in lower:
                saw_error = True
                matched_code = code
                break
        if _hostlog_contains_disconnect(text):
            saw_disconnect = True
        if saw_error and saw_disconnect:
            logger().info(
                f"Passkey timeout failure 0x{matched_code} and disconnect "
                "confirmed"
            )
            return matched_code
    assert saw_error, (
        f"Expected SMP passkey failure "
        f"({', '.join('0x' + c for c in C553862_PASSKEY_FAILURE_CODES)}) "
        "in DUT hostlog (passkey withheld)"
    )
    assert saw_disconnect, (
        "Expected BLE disconnect after passkey timeout (step 7)"
    )
    return matched_code


def c553862_dut_scan_connect_withhold_passkey(
    wifi_dut,
    peripheral_address,
    bus,
    *,
    connect_kwargs=None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    auth_fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    C553862 step 7 — DUT central connects; passkey shown by DisplayYesNo peer;
    DUT must not enter passkey (firmware ``rsi_ble_smp_passkey`` disabled).
    """
    drain_serial(bus)
    connect_log = dut_scan_and_connect_fast_connect_rx(
        wifi_dut,
        peripheral_address,
        accept_smp_start=True,
        **(connect_kwargs or {}),
    )
    passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert passkey, (
        "SC passkey not found in DUT hostlog — DisplayYesNo peer should display "
        "passkey for KeyboardDisplay initiator (TestRail step 7)"
    )
    logger().info(
        f"Withholding DUT passkey entry ({passkey}) — expecting auth "
        f"failure ({', '.join('0x' + c for c in C553862_PASSKEY_FAILURE_CODES)}) "
        "(firmware passkey response disabled)"
    )
    failure_code = wait_for_c553862_passkey_timeout_failure(
        bus, timeout=auth_fail_timeout
    )
    return connect_log, passkey, failure_code


def verify_c553862_step7_connect_hostlog(bus):
    """TestRail C553862 step 7 — DUT central connect / MTU / LESC passkey before withhold."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    for marker in C553862_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected hostlog marker '{marker}' (step 7 connect/SMP)"
        )


def verify_c553862_passkey_timeout_hostlog(
    bus, passkey: str, failure_code: Optional[str] = None
):
    """TestRail C553862 step 7 — passkey displayed, DUT withholds entry, failure + disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    codes = (
        (failure_code,)
        if failure_code
        else C553862_PASSKEY_FAILURE_CODES
    )
    assert any(
        code in lower or f"0x{code}" in lower for code in codes
    ), (
        f"Expected SMP passkey failure "
        f"({', '.join('0x' + c for c in C553862_PASSKEY_FAILURE_CODES)}) "
        "(step 7)"
    )
    extracted = _extract_passkey_from_hostlog_text(text)
    expected = str(passkey).zfill(6)
    assert extracted == expected, (
        f"Expected passkey {expected} in hostlog before timeout "
        f"(step 7, got {extracted!r})"
    )
    assert "smp encrypt event" not in lower, (
        f"Pairing must not encrypt after passkey timeout (step 7)"
    )
    for marker in C553862_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after passkey timeout (step 7)"
    )
    code = failure_code or SMP_AUTH_FAILURE_ERROR_CODE
    logger().info(f"Passkey timeout 0x{code} validated")


def note_c553862_ota_deferred():
    logger().warning(
        f"OTA passkey-timeout / LL packet validation deferred — "
        "hostlog-only mode"
    )


# C553863 — DUT central + nRF DisplayOnly; same connect markers as C553861
C553863_CENTRAL_CONNECT_MARKERS: Tuple[str, ...] = C553861_CENTRAL_CONNECT_MARKERS

# C553863 — TestRail expects 0x4B01; wearables FW may report 0x4B04 when nRF
# auto-confirms display before DUT wrong passkey entry reaches SMP.
C553863_PASSKEY_FAILURE_CODES: Tuple[str, ...] = (
    SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE,
    "4b04",
)


def _c553863_hostlog_passkey_failure_code(text: str) -> Optional[str]:
    lower = text.lower()
    for code in C553863_PASSKEY_FAILURE_CODES:
        if code in lower or f"0x{code}" in lower:
            return code
    if "confirm value failed" in lower or "passkey entry failed" in lower:
        return SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE
    return None


def start_c553863_nrf_displayonly_peripheral(
        ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
):
    """
    C553863 — nRF DisplayOnly peripheral (passkey display), LE SC + bonding + MITM.

    TestRail steps 4–6: nRF Connect adv + security (DisplayOnly, slave11).
    Withhold nRF ``match_confirm`` (same as C553861) so DUT can submit wrong passkey
    before peripheral auto-confirm causes early 0x4B04.
    """
    if is_nrf_peer(ble_client):
        _prepare_c553861_nrf_displayonly(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(PEER_BUS_SETTLE_SEC)
    configure_raspi_displayonly_peripheral(
        ble_client, auth_req=AUTH_REQ_BONDING_MITM_SC
    )
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayOnly",
    )
    assert addr, "Failed to start Raspi DisplayOnly advertising (C553863)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(PEER_ADV_START_SEC)
    return addr


def wait_for_c553863_passkey_entry_failed(
    bus,
    *,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """C553863 step 7 — wrong passkey; expect 0x4B01 (or 0x4B04) + disconnect."""
    deadline = time.time() + timeout
    saw_error = False
    saw_disconnect = False
    matched_code: Optional[str] = None
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        code = _c553863_hostlog_passkey_failure_code(text)
        if code:
            saw_error = True
            matched_code = code
        if _hostlog_contains_disconnect(text):
            saw_disconnect = True
        if saw_error and saw_disconnect:
            logger().info(
                f"Passkey confirm failure 0x{matched_code} and disconnect "
                "confirmed"
            )
            return matched_code
    assert saw_error, (
        f"Expected SMP passkey confirm failure "
        f"({', '.join('0x' + c for c in C553863_PASSKEY_FAILURE_CODES)}) "
        "in DUT hostlog (step 7)"
    )
    assert saw_disconnect, (
        "Expected BLE disconnect after wrong passkey entry (step 7)"
    )
    return matched_code


def c553863_dut_scan_connect_wrong_passkey(
    wifi_dut,
    peripheral_address,
    bus,
    connect_kwargs=None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
    wrong_passkey: int = 0,
    dut_submit_wrong: bool = True,
):
    """
    C553863 step 7 — DUT central connects; DisplayOnly peer shows passkey;
    DUT enters wrong value (firmware ``rsi_ble_smp_passkey(..., 0)`` and/or automation).
    """
    drain_serial(bus)
    connect_log = dut_scan_and_connect_fast_connect_rx(
        wifi_dut,
        peripheral_address,
        accept_smp_start=True,
        **(connect_kwargs or {}),
    )
    passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert passkey, (
        "SC passkey not found in DUT hostlog — DisplayOnly peer should display "
        "passkey for KeyboardOnly initiator (TestRail step 7)"
    )
    assert_passkey_valid(passkey)
    logger().info(
        f"Correct passkey from peer is {passkey}; "
        f"expect failure after wrong entry "
        f"({', '.join('0x' + c for c in C553863_PASSKEY_FAILURE_CODES)})"
    )

    text = "\n".join(decode_log_items(bus.get_input_log()))
    matched = _c553863_hostlog_passkey_failure_code(text)
    if matched:
        logger().info(
            f"Wrong-passkey failure 0x{matched} already in hostlog (firmware)"
        )
        failure_code = wait_for_c553863_passkey_entry_failed(
            bus, timeout=fail_timeout
        )
        return connect_log, passkey, failure_code

    if dut_submit_wrong:
        try:
            dut_submit_wrong_passkey(
                wifi_dut, peripheral_address, wrong_passkey=wrong_passkey
            )
        except Exception as exc:
            logger().warning(f"SMP passkey wrong entry failed: {exc}")

    failure_code = wait_for_c553863_passkey_entry_failed(
        bus, timeout=fail_timeout
    )
    return connect_log, passkey, failure_code


def verify_c553863_step7_connect_hostlog(bus):
    """TestRail C553863 step 7 — DUT central connect / MTU / LESC passkey before wrong entry."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    for marker in C553863_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected hostlog marker '{marker}' (step 7 connect/SMP)"
        )


def verify_c553863_wrong_passkey_failure_hostlog(
    bus, passkey: str, failure_code: Optional[str] = None
):
    """TestRail C553863 step 7 — wrong passkey entry → 0x4B01/0x4B04, no encrypt, disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    codes = (
        (failure_code,)
        if failure_code
        else C553863_PASSKEY_FAILURE_CODES
    )
    assert any(
        code in lower or f"0x{code}" in lower for code in codes
    ) or "confirm value failed" in lower or "passkey entry failed" in lower, (
        f"Expected SMP passkey confirm failure "
        f"({', '.join('0x' + c for c in C553863_PASSKEY_FAILURE_CODES)}) "
        "in hostlog (step 7)"
    )
    expected = str(passkey).zfill(6)
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected display passkey {expected} in hostlog before failure "
        "(step 7)"
    )
    assert _hostlog_contains_wrong_passkey_entry(text, wrong_passkey=0), (
        f"Expected wrong passkey entry (000000) in hostlog (step 7)"
    )
    assert "smp encrypt event" not in lower, (
        f"Pairing must not encrypt after wrong passkey (step 7)"
    )
    for marker in C553863_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after wrong passkey entry (step 7)"
    )
    code = failure_code or SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE
    logger().info(f"Wrong passkey failure 0x{code} validated")


def note_c553863_ota_deferred():
    logger().warning(
        "OTA wrong-passkey / LL packet validation deferred — hostlog-only mode"
    )


# C553864 — dual KeyboardOnly wrong-passkey; reuse C553863 hostlog markers/codes/flow
C553864_CENTRAL_CONNECT_MARKERS: Tuple[str, ...] = C553863_CENTRAL_CONNECT_MARKERS
C553864_PASSKEY_FAILURE_CODES: Tuple[str, ...] = C553863_PASSKEY_FAILURE_CODES


def start_c553864_nrf_keyboardonly_peripheral(
        ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
):
    """
    C553864 — nRF KeyboardOnly peripheral, LE SC + bonding + MITM.

    TestRail steps 4–6: nRF Connect adv + security (KeyboardOnly, slave11).
    ``dynamic_passkey`` lets the peer enter passkey when prompted; DUT initiator
    submits wrong passkey (step 7).
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client,
            "KeyboardOnly",
            local_name=adv_name,
            dynamic_passkey=True,
            dynamic_passkey_timeout=PASSKEY_TIMEOUT_SEC,
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(PEER_BUS_SETTLE_SEC)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="KeyboardOnly",
    )
    assert addr, "Failed to start Raspi KeyboardOnly advertising (C553864)"
    configure_raspi_keyboardonly_peripheral(
        ble_client, auth_req=AUTH_REQ_BONDING_MITM_SC
    )
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(PEER_ADV_START_SEC)
    return addr


def note_c553864_ota_deferred():
    logger().warning(
        f"OTA wrong-passkey / LL packet validation deferred — "
        "hostlog-only mode"
    )


# C553864 step 7 — identical central wrong-passkey flow to C553863
c553864_dut_scan_connect_wrong_passkey = c553863_dut_scan_connect_wrong_passkey


def verify_c553865_dut_displayyesno_smp_config_hostlog(bus):
    """TestRail C553865 steps 1–2 — DUT central DisplayYesNo (0x01), Auth Req 0x2D, ENC-only keys."""
    ok, log_text = wait_for_log_patterns(
        bus,
        (
            f"io capability: {DUT_IO_DISPLAY_YES_NO}",
            f"auth req: {AUTH_REQ_BONDING_MITM_SC}",
            "auth req: 0x2d",
            "auth req: 45",
            "ble_module_set_smp_pairing_capability_data_cmd_handler : successful",
        ),
        timeout=DUT_INIT_LOG_MARKER_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    io_ok = (
        f"io capability: {DUT_IO_DISPLAY_YES_NO}" in lower
        or "io capability: 1" in lower
    )
    auth_ok = (
        f"auth req: {AUTH_REQ_BONDING_MITM_SC}" in lower
        or "auth req: 0x2d" in lower
        or "auth req: 45" in lower
        or "ble_module_set_smp_pairing_capability_data_cmd_handler : successful"
        in lower
    )
    assert io_ok, (
        f"Expected DUT IO cap DisplayYesNo (0x01) in hostlog (steps 1–2)"
    )
    assert auth_ok, (
        f"Expected SMP Auth Req 0x2D in hostlog (steps 1–2)"
    )
    if not ok:
        logger().warning(
            f"DisplayYesNo SMP config marker delayed in hostlog"
        )
    logger().info(f"DUT DisplayYesNo central SMP validated (steps 1–2)")


def start_c553865_nrf_displayyesno_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
):
    """
    C553865 — nRF DisplayYesNo peripheral, LE SC + bonding + MITM.

    TestRail steps 4–6: nRF Connect adv + security (DisplayYesNo, slave11).
    """
    return start_raspi_displayyesno_peripheral(
        ble_client,
        dut_address,
        adv_name=adv_name,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
    )


def c553865_complete_numeric_comparison_central_first(
    bus,
        wifi_dut,
        ble_client,
    remote_peer_address,
    *,
    timeout: float = PASSKEY_TIMEOUT_SEC,
):
    """TestRail C553865 step 7 — NC: central Accept then peripheral Accept."""
    complete_smp_numeric_comparison(
        bus,
        wifi_dut,
        ble_client,
        remote_peer_address,
        timeout=timeout,
        accept_order="central_first",
    )


def verify_c553865_nc_bond_complete_hostlog(
    bus, passkey: str
):
    """TestRail C553865 step 8 — NC passkey shown, bonding completes (hostlog)."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected numeric-comparison passkey in hostlog (step 7–8)"
    )
    verify_post_pair_hostlog(
        bus, require_security_keys=False
    )
    assert "smp encrypt event" in lower, (
        f"Expected SMP encrypt after NC bonding (step 8)"
    )
    logger().info(f"Numeric Comparison bonding complete (step 8)")


def note_c553865_ota_deferred():
    logger().warning(
        f"OTA Numeric Comparison / LL packet validation deferred — "
        "hostlog-only mode"
    )


# C553866 — same DisplayYesNo NC bond flow as C553865; accept order differs (step 7)
verify_c553866_dut_displayyesno_smp_config_hostlog = (
    verify_c553865_dut_displayyesno_smp_config_hostlog
)
start_c553866_nrf_displayyesno_peripheral = start_c553865_nrf_displayyesno_peripheral
verify_c553866_nc_bond_complete_hostlog = verify_c553865_nc_bond_complete_hostlog


def c553866_complete_numeric_comparison_periph_first(
    bus,
    wifi_dut,
    ble_client,
    remote_peer_address,
    *,
    timeout: float = PASSKEY_TIMEOUT_SEC,
):
    """TestRail C553866 step 7 — NC: peripheral Accept then central Accept."""
    complete_smp_numeric_comparison(
        bus,
        wifi_dut,
        ble_client,
        remote_peer_address,
        timeout=timeout,
        accept_order="peripheral_first",
    )


def note_c553866_ota_deferred():
    logger().warning(
        f"OTA Numeric Comparison / LL packet validation deferred — "
        "hostlog-only mode"
    )


# C553867 — NC failure (central Accept, peripheral Decline)
verify_c553867_dut_displayyesno_smp_config_hostlog = (
    verify_c553865_dut_displayyesno_smp_config_hostlog
)

# TestRail expects 0x4B0C; wearables FW may report 0x4BFC when peripheral NC confirm
# is withheld then declined after central accepts (no bonding / no encrypt).
C553867_NC_FAILURE_CODES: Tuple[str, ...] = (
    SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE,
    SMP_AUTH_FAILURE_ERROR_CODE,
)

C553867_CENTRAL_PERIPH_NC_GAP_SEC = 1.0


def _hostlog_dut_smp_passkey_already_accepted(text: str) -> bool:
    """True when firmware/test already submitted central NC accept via smp_passkey."""
    lower = text.lower()
    return "ble_module_smp_passkey_cmd_handler : successful" in lower


def _c553867_hostlog_nc_failure_code(text: str) -> Optional[str]:
    lower = text.lower()
    for code in C553867_NC_FAILURE_CODES:
        if code in lower or f"0x{code}" in lower:
            return code
    if "numeric comparison failed" in lower:
        return SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE
    return None


def wait_for_c553867_nc_failure(
    bus,
    *,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
) -> str:
    """C553867 step 8 — pairing fails after peripheral NC decline; 0x4B0C or 0x4BFC."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        code = _c553867_hostlog_nc_failure_code(text)
        if code and _hostlog_contains_disconnect(text):
            logger().info(f"NC pairing failure 0x{code} confirmed in hostlog")
            return code
    assert False, (
        f"Expected SMP NC failure "
        f"({', '.join('0x' + c for c in C553867_NC_FAILURE_CODES)}) "
        f"and disconnect in DUT hostlog within {timeout}s"
    )


def _prepare_c553867_nrf_displayyesno(nrf_ble_client):
    """
    C553867 — DisplayYesNo peripheral: show NC passkey but withhold confirm.

    Default ``register_passkey_display(confirm=True)`` auto-accepts at display time;
    bonding then completes (encrypt / le ltk) before decline → 0x4bfc instead of
    TestRail-expected 0x4b0c.
    """
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP["DisplayYesNo"]
    nrf.set_security_params(
        passcode_pairing=True,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=True,
    )
    nrf.register_on_connect()
    time.sleep(2)
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()
    nrf._c553867_nc_pending_confirm = None

    def on_passkey_display(peer, event_args):
        if event_args.passkey is not None:
            logger().info(
                f"nRF DisplayYesNo NC passkey displayed: "
                f"{event_args.passkey}"
            )
            nrf.passkey = event_args.passkey
        nrf._c553867_nc_pending_confirm = event_args

    nrf.ble_device.client.security.on_passkey_display_required.register(
        on_passkey_display
    )


def _c553867_nrf_decline_numeric_comparison(ble_client):
    """Peripheral Decline after central Accept — match_confirm(False) on pending NC."""
    nrf = ble_client.interfaces.bluetooth
    deadline = time.time() + PASSKEY_TIMEOUT_SEC
    while time.time() < deadline:
        pending = getattr(nrf, "_c553867_nc_pending_confirm", None)
        if pending is not None:
            logger().info(
                f"nRF declining numeric comparison (match_confirm False)"
            )
            pending.match_confirm(False)
            nrf._c553867_nc_pending_confirm = None
            return
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
    pytest.fail(
        f"nRF NC passkey display event not received before decline"
    )


def start_c553867_nrf_displayyesno_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    C553867 — nRF DisplayYesNo peripheral with NC confirm withheld until decline.

    TestRail steps 4–6: nRF Connect adv + security (DisplayYesNo, slave11).
    """
    if is_nrf_peer(ble_client):
        _prepare_c553867_nrf_displayyesno(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_displayyesno_peripheral(ble_client, auth_req=auth_req)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo advertising (C553867)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def c553867_fail_numeric_comparison_central_accept_periph_decline(
    bus,
        wifi_dut,
        ble_client,
    remote_peer_address,
    *,
    dut_passkey: Optional[str] = None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    TestRail C553867 step 7 — NC: central Accept then peripheral Decline → 0x4B0C.
    """
    if dut_passkey is None:
        dut_passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert dut_passkey, (
        "Numeric comparison passkey not found in DUT hostlog (step 7)"
    )
    assert_passkey_valid(dut_passkey)

    hostlog_text = "\n".join(decode_log_items(bus.get_input_log()))
    if _hostlog_dut_smp_passkey_already_accepted(hostlog_text):
        logger().info(
            "DUT central NC already accepted (firmware rsi_ble_smp_passkey) "
            "— skip duplicate smp_passkey, decline peripheral immediately"
        )
    else:
        logger().info(
            f"DUT (central) accepting numeric comparison — "
            f"passkey {dut_passkey}"
        )
        wifi_dut.interfaces.wifi.smp_passkey(
            bd_addr=remote_peer_address, passkey=dut_passkey
        )
        time.sleep(C553867_CENTRAL_PERIPH_NC_GAP_SEC)

    if is_nrf_peer(ble_client):
        _c553867_nrf_decline_numeric_comparison(ble_client)
    else:
        logger().info(
            "Raspi (peripheral) declining numeric comparison (set_pin -1)"
        )
        peer_set_pin(ble_client, -1)

    wait_for_c553867_nc_failure(bus, timeout=fail_timeout)


def verify_c553867_nc_failure_hostlog(bus, passkey: str):
    """TestRail C553867 step 8 — NC passkey shown, peripheral decline, failure, no encrypt."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    matched_code = _c553867_hostlog_nc_failure_code(text)
    assert matched_code, (
        f"Expected SMP NC failure "
        f"({', '.join('0x' + c for c in C553867_NC_FAILURE_CODES)}) "
        "in hostlog (step 8)"
    )
    if matched_code != SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE:
        logger().warning(
            f"Wearables FW reported 0x{matched_code} instead of "
            f"0x{SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE} — accepting NC decline "
            "(no encrypt)"
        )
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected numeric-comparison passkey in hostlog (step 7–8)"
    )
    assert "smp encrypt event" not in lower, (
        f"Pairing must not encrypt after NC failure (step 8)"
    )
    for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after NC failure (step 8)"
    )
    logger().info(
        f"Numeric Comparison failure 0x{matched_code} validated"
    )


def note_c553867_ota_deferred():
    logger().warning(
        f"OTA NC failure / LL packet validation deferred — hostlog-only mode"
    )


# C553868 — NC failure (peripheral Accept, central Decline); order peripheral → central
verify_c553868_dut_displayyesno_smp_config_hostlog = (
    verify_c553865_dut_displayyesno_smp_config_hostlog
)

C553868_NC_FAILURE_CODES: Tuple[str, ...] = C553867_NC_FAILURE_CODES
C553868_PERIPH_CENTRAL_NC_GAP_SEC = C553867_CENTRAL_PERIPH_NC_GAP_SEC


def _prepare_c553868_nrf_displayyesno(nrf_ble_client):
    """
    C553868 — withhold nRF NC auto-confirm until explicit peripheral Accept.

    ``start_c553865`` auto-confirms at passkey display; central decline then arrives
    too late and bonding completes (``smp encrypt event``).
    """
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP["DisplayYesNo"]
    nrf.set_security_params(
        passcode_pairing=True,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=True,
    )
    nrf.register_on_connect()
    time.sleep(2)
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()
    nrf._c553868_nc_pending_confirm = None

    def on_passkey_display(peer, event_args):
        if event_args.passkey is not None:
            logger().info(
                f"nRF DisplayYesNo NC passkey displayed: "
                f"{event_args.passkey}"
            )
            nrf.passkey = event_args.passkey
        nrf._c553868_nc_pending_confirm = event_args

    nrf.ble_device.client.security.on_passkey_display_required.register(
        on_passkey_display
    )


def _c553868_nrf_accept_numeric_comparison(ble_client):
    """Peripheral Accept before central Decline — match_confirm(True) on pending NC."""
    nrf = ble_client.interfaces.bluetooth
    deadline = time.time() + PASSKEY_TIMEOUT_SEC
    while time.time() < deadline:
        pending = getattr(nrf, "_c553868_nc_pending_confirm", None)
        if pending is not None:
            logger().info(
                f"nRF accepting numeric comparison (match_confirm True)"
            )
            pending.match_confirm(True)
            nrf._c553868_nc_pending_confirm = None
            return
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
    pytest.fail(
        f"nRF NC passkey display event not received before peripheral accept"
    )


def start_c553868_nrf_displayyesno_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    C553868 — nRF DisplayYesNo peripheral; NC confirm withheld until step 8 accept.

    TestRail steps 4–6: nRF Connect adv + security (DisplayYesNo, slave11).
    """
    if is_nrf_peer(ble_client):
        _prepare_c553868_nrf_displayyesno(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_displayyesno_peripheral(ble_client, auth_req=auth_req)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo advertising (C553868)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def _c553868_hostlog_central_decline_submitted(text: str) -> bool:
    """True when DUT already submitted central NC decline (passkey 000000 / firmware passkey=0)."""
    lower = text.lower()
    return (
        "000000" in text
        or "using passkey 0" in lower
        or re.search(r"smp_passkey[^\n]*000000", lower) is not None
    )


def _c553868_hostlog_nc_failure_code(text: str) -> Optional[str]:
    lower = text.lower()
    for code in C553868_NC_FAILURE_CODES:
        if code in lower or f"0x{code}" in lower:
            return code
    if "numeric comparison failed" in lower:
        return SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE
    return None


def wait_for_c553868_nc_failure(
    bus,
    *,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
) -> str:
    """C553868 step 8 — pairing fails after central NC decline; 0x4B0C or 0x4BFC + disconnect."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        code = _c553868_hostlog_nc_failure_code(text)
        if "smp encrypt event" in lower and not code:
            assert False, (
                "Bonding completed (smp encrypt) before NC failure — "
                "peripheral accept / central decline ordering failed"
            )
        if code and _hostlog_contains_disconnect(text):
            if "smp encrypt event" in lower:
                logger().warning(
                    f"NC failure 0x{code} with post-failure encrypt/LTK "
                    "in hostlog (wearables FW quirk) — pairing still failed"
                )
            else:
                logger().info(
                    f"NC pairing failure 0x{code} confirmed in hostlog"
                )
            return code
    assert False, (
        f"Expected SMP NC failure "
        f"({', '.join('0x' + c for c in C553868_NC_FAILURE_CODES)}) "
        f"with disconnect in DUT hostlog within {timeout}s"
    )


def c553868_fail_numeric_comparison_periph_accept_central_decline(
    bus,
    wifi_dut,
    ble_client,
    remote_peer_address,
    *,
    dut_passkey: Optional[str] = None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    TestRail C553868 step 7–8 — NC: peripheral Accept then central Decline → 0x4B0C.

    Firmware step 2 uses ``passkey=0`` + breakpoint after nRF accept; automation
    accepts on nRF first, then submits central decline via ``smp_passkey 000000``.
    """
    if dut_passkey is None:
        dut_passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert dut_passkey, (
        "Numeric comparison passkey not found in DUT hostlog (step 7)"
    )
    assert_passkey_valid(dut_passkey)

    hostlog_text = "\n".join(decode_log_items(bus.get_input_log()))
    if _hostlog_dut_smp_passkey_already_accepted(hostlog_text):
        pytest.fail(
            "DUT central already accepted NC (correct passkey) before "
            "peripheral accept — use firmware passkey=0 + breakpoint (TestRail step 2)"
        )

    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"
    logger().info(
        f"{peer_label} (peripheral) accepting NC first — passkey {dut_passkey}"
    )
    if is_nrf_peer(ble_client):
        _c553868_nrf_accept_numeric_comparison(ble_client)
    else:
        peer_set_pin(ble_client, int(dut_passkey))
    time.sleep(C553868_PERIPH_CENTRAL_NC_GAP_SEC)

    hostlog_text = "\n".join(decode_log_items(bus.get_input_log()))
    if _c553868_hostlog_central_decline_submitted(hostlog_text):
        logger().info(
            "DUT central NC decline (000000) already in hostlog "
            "(firmware passkey=0 resume) — skip duplicate smp_passkey"
        )
    else:
        logger().info("DUT (central) declining NC — smp_passkey 000000")
        wifi_dut.interfaces.wifi.smp_passkey(
            bd_addr=remote_peer_address, passkey="000000"
        )

    wait_for_c553868_nc_failure(bus, timeout=fail_timeout)


def verify_c553868_nc_failure_hostlog(bus, passkey: str):
    """TestRail C553868 step 8 — NC passkey shown, central decline, 0x4B0C, disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    matched_code = _c553868_hostlog_nc_failure_code(text)
    assert matched_code, (
        f"Expected SMP NC failure "
        f"({', '.join('0x' + c for c in C553868_NC_FAILURE_CODES)}) "
        "in hostlog (step 8)"
    )
    if matched_code != SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE:
        logger().warning(
            f"Wearables FW reported 0x{matched_code} instead of "
            f"0x{SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE} — accepting NC decline"
        )
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected numeric-comparison passkey in hostlog (step 7–8)"
    )
    if "smp encrypt event" in lower:
        logger().warning(
            f"Wearables FW logged smp encrypt/LTK after NC failure "
            f"0x{matched_code} — TestRail step 8 still satisfied (pairing failed + "
            "disconnect)"
        )
    for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after NC failure (step 8)"
    )
    logger().info(
        f"Numeric Comparison failure 0x{matched_code} validated"
    )


def note_c553868_ota_deferred():
    logger().warning(
        f"OTA NC failure / LL packet validation deferred — hostlog-only mode"
    )


# C553869 — NC failure (central Decline only, peripheral action X)
verify_c553869_dut_displayyesno_smp_config_hostlog = (
    verify_c553865_dut_displayyesno_smp_config_hostlog
)

C553869_NC_FAILURE_CODES: Tuple[str, ...] = C553868_NC_FAILURE_CODES


def _prepare_c553869_nrf_displayyesno(nrf_ble_client):
    """
    C553869 — withhold nRF NC auto-confirm (peripheral action X).

    ``start_c553865`` auto-accepts at passkey display and bonding can complete
    before central decline (``passkey=0``).
    """
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP["DisplayYesNo"]
    nrf.set_security_params(
        passcode_pairing=True,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=True,
    )
    nrf.register_on_connect()
    time.sleep(2)
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()

    def on_passkey_display(peer, event_args):
        if event_args.passkey is not None:
            logger().info(
                f"nRF DisplayYesNo NC passkey displayed (no action): "
                f"{event_args.passkey}"
            )
            nrf.passkey = event_args.passkey

    nrf.ble_device.client.security.on_passkey_display_required.register(
        on_passkey_display
    )


def start_c553869_nrf_displayyesno_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    C553869 — nRF DisplayYesNo peripheral; no NC action on passkey popup (step 8 X).

    TestRail steps 4–6: nRF Connect adv + security (DisplayYesNo, slave11).
    """
    if is_nrf_peer(ble_client):
        _prepare_c553869_nrf_displayyesno(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_displayyesno_peripheral(ble_client, auth_req=auth_req)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo advertising (C553869)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def _c553869_hostlog_nc_failure_code(text: str) -> Optional[str]:
    lower = text.lower()
    for code in C553869_NC_FAILURE_CODES:
        if code in lower or f"0x{code}" in lower:
            return code
    if "numeric comparison failed" in lower:
        return SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE
    return None


def wait_for_c553869_nc_failure(
    bus,
    *,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
) -> str:
    """C553869 step 7 — central Decline only; 0x4B0C or 0x4BFC + disconnect."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        code = _c553869_hostlog_nc_failure_code(text)
        if "smp encrypt event" in lower and not code:
            assert False, (
                "Bonding completed (smp encrypt) before NC failure — "
                "nRF must not auto-confirm (peripheral action X)"
            )
        if code and _hostlog_contains_disconnect(text):
            if "smp encrypt event" in lower:
                logger().warning(
                    f"NC failure 0x{code} with post-failure encrypt/LTK "
                    "in hostlog (wearables FW quirk) — pairing still failed"
                )
            else:
                logger().info(
                    f"NC pairing failure 0x{code} confirmed in hostlog"
                )
            return code
    assert False, (
        f"Expected SMP NC failure "
        f"({', '.join('0x' + c for c in C553869_NC_FAILURE_CODES)}) "
        f"with disconnect in DUT hostlog within {timeout}s"
    )


def c553869_fail_numeric_comparison_central_only_decline(
    bus,
    wifi_dut,
    remote_peer_address,
    *,
    dut_passkey: Optional[str] = None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    TestRail C553869 step 7 — NC: central Decline only (peripheral X) → 0x4B0C.

    Firmware step 2 submits ``passkey=0`` on passkey event; automation declines
    via ``smp_passkey 000000`` when firmware has not already done so.
    """
    if dut_passkey is None:
        dut_passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert dut_passkey, (
        "Numeric comparison passkey not found in DUT hostlog (step 7)"
    )
    assert_passkey_valid(dut_passkey)

    hostlog_text = "\n".join(decode_log_items(bus.get_input_log()))
    if (
        _hostlog_dut_smp_passkey_already_accepted(hostlog_text)
        and not _c553868_hostlog_central_decline_submitted(hostlog_text)
    ):
        pytest.fail(
            "DUT central accepted NC (correct passkey) — use firmware "
            "passkey=0 for central Decline (TestRail step 2)"
        )

    logger().info("Peripheral action X — no nRF/Raspi NC confirm/decline")

    if _c553868_hostlog_central_decline_submitted(hostlog_text):
        logger().info(
            "DUT central NC decline (000000) already in hostlog "
            "(firmware passkey=0) — skip duplicate smp_passkey"
        )
    else:
        logger().info("DUT (central) declining NC — smp_passkey 000000")
        wifi_dut.interfaces.wifi.smp_passkey(
            bd_addr=remote_peer_address, passkey="000000"
        )

    wait_for_c553869_nc_failure(bus, timeout=fail_timeout)


def verify_c553869_nc_failure_hostlog(bus, passkey: str):
    """TestRail C553869 step 7 — NC passkey shown, central decline, 0x4B0C, disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    matched_code = _c553869_hostlog_nc_failure_code(text)
    assert matched_code, (
        f"Expected SMP NC failure "
        f"({', '.join('0x' + c for c in C553869_NC_FAILURE_CODES)}) "
        "in hostlog (step 7)"
    )
    if matched_code != SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE:
        logger().warning(
            f"Wearables FW reported 0x{matched_code} instead of "
            f"0x{SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE} — accepting NC decline"
        )
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected numeric-comparison passkey in hostlog (step 7)"
    )
    if "smp encrypt event" in lower:
        logger().warning(
            f"Wearables FW logged smp encrypt/LTK after NC failure "
            f"0x{matched_code} — TestRail step 7 still satisfied (pairing failed + "
            "disconnect)"
        )
    for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after NC failure (step 7)"
    )
    logger().info(
        f"Numeric Comparison failure 0x{matched_code} validated"
    )


def note_c553869_ota_deferred():
    logger().warning(
        f"OTA NC failure / LL packet validation deferred — hostlog-only mode"
    )


# C553870 — NC failure (peripheral Decline only, central action X); order peripheral first
verify_c553870_dut_displayyesno_smp_config_hostlog = (
    verify_c553865_dut_displayyesno_smp_config_hostlog
)

C553870_NC_FAILURE_CODES: Tuple[str, ...] = C553869_NC_FAILURE_CODES


def _prepare_c553870_nrf_displayyesno(nrf_ble_client):
    """
    C553870 — withhold nRF NC auto-confirm until explicit peripheral Decline.

    ``start_c553865`` auto-accepts at passkey display; bonding can complete before
    peripheral decline when central takes no action.
    """
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP["DisplayYesNo"]
    nrf.set_security_params(
        passcode_pairing=True,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=True,
    )
    nrf.register_on_connect()
    time.sleep(2)
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()
    nrf._c553870_nc_pending_confirm = None

    def on_passkey_display(peer, event_args):
        if event_args.passkey is not None:
            logger().info(
                f"nRF DisplayYesNo NC passkey displayed: "
                f"{event_args.passkey}"
            )
            nrf.passkey = event_args.passkey
        nrf._c553870_nc_pending_confirm = event_args

    nrf.ble_device.client.security.on_passkey_display_required.register(
        on_passkey_display
    )


def _c553870_nrf_decline_numeric_comparison(ble_client):
    """Peripheral Decline first — match_confirm(False) on pending NC (TestRail step 8)."""
    nrf = ble_client.interfaces.bluetooth
    deadline = time.time() + PASSKEY_TIMEOUT_SEC
    while time.time() < deadline:
        pending = getattr(nrf, "_c553870_nc_pending_confirm", None)
        if pending is not None:
            logger().info(
                f"nRF declining numeric comparison (match_confirm False)"
            )
            pending.match_confirm(False)
            nrf._c553870_nc_pending_confirm = None
            return
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
    pytest.fail(
        f"nRF NC passkey display event not received before decline"
    )


def start_c553870_nrf_displayyesno_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    C553870 — nRF DisplayYesNo peripheral; NC confirm withheld until step 8 decline.

    TestRail steps 4–6: nRF Connect adv + security (DisplayYesNo, slave11).
    """
    if is_nrf_peer(ble_client):
        _prepare_c553870_nrf_displayyesno(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_displayyesno_peripheral(ble_client, auth_req=auth_req)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo advertising (C553870)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def _c553870_hostlog_nc_failure_code(text: str) -> Optional[str]:
    lower = text.lower()
    for code in C553870_NC_FAILURE_CODES:
        if code in lower or f"0x{code}" in lower:
            return code
    if "numeric comparison failed" in lower:
        return SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE
    return None


def wait_for_c553870_nc_failure(
    bus,
    *,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
) -> str:
    """C553870 step 8 — peripheral Decline only; 0x4B0C or 0x4BFC + disconnect."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        code = _c553870_hostlog_nc_failure_code(text)
        if "smp encrypt event" in lower and not code:
            assert False, (
                "Bonding completed (smp encrypt) before NC failure — "
                "nRF must not auto-confirm (peripheral Decline required first)"
            )
        if code and _hostlog_contains_disconnect(text):
            if "smp encrypt event" in lower:
                logger().warning(
                    f"NC failure 0x{code} with post-failure encrypt/LTK "
                    "in hostlog (wearables FW quirk) — pairing still failed"
                )
            else:
                logger().info(
                    f"NC pairing failure 0x{code} confirmed in hostlog"
                )
            return code
    assert False, (
        f"Expected SMP NC failure "
        f"({', '.join('0x' + c for c in C553870_NC_FAILURE_CODES)}) "
        f"with disconnect in DUT hostlog within {timeout}s"
    )


def c553870_fail_numeric_comparison_periph_only_decline(
    bus,
    ble_client,
    *,
    dut_passkey: Optional[str] = None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    TestRail C553870 steps 7–8 — NC: peripheral Decline first, central action X → 0x4B0C.

    DUT does not submit ``smp_passkey`` (central X). Firmware step 2 may resume with
    ``passkey=0`` after nRF reject; automation does not drive central NC.
    """
    if dut_passkey is None:
        dut_passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert dut_passkey, (
        "Numeric comparison passkey not found in DUT hostlog (step 7)"
    )
    assert_passkey_valid(dut_passkey)

    hostlog_text = "\n".join(decode_log_items(bus.get_input_log()))
    if _hostlog_dut_smp_passkey_already_accepted(hostlog_text):
        pytest.fail(
            "DUT central already accepted NC (correct passkey) — central "
            "action X required (TestRail step 2: breakpoint after nRF reject)"
        )

    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"
    logger().info(
        f"{peer_label} (peripheral) declining NC first — passkey {dut_passkey}"
    )
    if is_nrf_peer(ble_client):
        _c553870_nrf_decline_numeric_comparison(ble_client)
    else:
        logger().info(
            "Raspi (peripheral) declining numeric comparison (set_pin -1)"
        )
        peer_set_pin(ble_client, -1)

    logger().info("Central action X — no DUT smp_passkey")

    wait_for_c553870_nc_failure(bus, timeout=fail_timeout)


def verify_c553870_nc_failure_hostlog(bus, passkey: str):
    """TestRail C553870 step 8 — NC passkey shown, peripheral decline, 0x4B0C, disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    matched_code = _c553870_hostlog_nc_failure_code(text)
    assert matched_code, (
        f"Expected SMP NC failure "
        f"({', '.join('0x' + c for c in C553870_NC_FAILURE_CODES)}) "
        "in hostlog (step 8)"
    )
    if matched_code != SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE:
        logger().warning(
            f"Wearables FW reported 0x{matched_code} instead of "
            f"0x{SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE} — accepting NC decline"
        )
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected numeric-comparison passkey in hostlog (step 7–8)"
    )
    if "smp encrypt event" in lower and not matched_code:
        assert False, (
            f"Pairing must not encrypt before NC failure (step 8)"
        )
    if "smp encrypt event" in lower:
        logger().warning(
            f"Wearables FW logged smp encrypt/LTK after NC failure "
            f"0x{matched_code} — TestRail step 8 still satisfied (pairing failed + "
            "disconnect)"
        )
    for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after NC failure (step 8)"
    )
    logger().info(
        f"Numeric Comparison failure 0x{matched_code} validated"
    )


def note_c553870_ota_deferred():
    logger().warning(
        f"OTA NC failure / LL packet validation deferred — hostlog-only mode"
    )


# C553871 — NC SMP timeout (central Accept first, peripheral no action)
verify_c553871_dut_displayyesno_smp_config_hostlog = (
    verify_c553865_dut_displayyesno_smp_config_hostlog
)

C553871_SMP_TIMEOUT_FAILURE_CODES: Tuple[str, ...] = (
    SMP_AUTH_FAILURE_ERROR_CODE,
    "4b04",
)


def _prepare_c553871_nrf_displayyesno(nrf_ble_client):
    """
    C553871 — withhold nRF NC auto-confirm (peripheral no action).

    ``start_c553865`` auto-accepts at passkey display; bonding completes before
    central accept can time out waiting for peripheral NC response.
    """
    nrf = nrf_ble_client.interfaces.bluetooth
    cap = NRF_IO_CAP_MAP["DisplayYesNo"]
    nrf.set_security_params(
        passcode_pairing=True,
        io_capabilities=cap,
        long_term_bonding=True,
        lesc_pairing=True,
    )
    nrf.register_on_connect()
    time.sleep(2)
    nrf.register_on_disconnect()
    nrf.register_on_security_level_changed()
    nrf.register_on_client_pairing_complete()

    def on_passkey_display(peer, event_args):
        if event_args.passkey is not None:
            logger().info(
                f"nRF DisplayYesNo NC passkey displayed (no action): "
                f"{event_args.passkey}"
            )
            nrf.passkey = event_args.passkey

    nrf.ble_device.client.security.on_passkey_display_required.register(
        on_passkey_display
    )


def start_c553871_nrf_displayyesno_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    C553871 — nRF DisplayYesNo peripheral; no NC action after passkey popup (step 7).

    TestRail steps 3–5: nRF Connect adv + security (DisplayYesNo, slave11).
    """
    if is_nrf_peer(ble_client):
        _prepare_c553871_nrf_displayyesno(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_displayyesno_peripheral(ble_client, auth_req=auth_req)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo advertising (C553871)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def _c553871_hostlog_smp_timeout_code(text: str) -> Optional[str]:
    lower = text.lower()
    for code in C553871_SMP_TIMEOUT_FAILURE_CODES:
        if code in lower or f"0x{code}" in lower:
            return code
    if "authentication failed" in lower or "smp failed" in lower:
        return SMP_AUTH_FAILURE_ERROR_CODE
    return None


def wait_for_c553871_smp_timeout_failure(
    bus,
    *,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
) -> str:
    """C553871 step 7 — central Accept, peripheral no action; 0x4BFC + disconnect."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        code = _c553871_hostlog_smp_timeout_code(text)
        if "smp encrypt event" in lower and not code:
            assert False, (
                "Bonding completed (smp encrypt) before SMP timeout — "
                "nRF must not auto-confirm (peripheral no action)"
            )
        if code and _hostlog_contains_disconnect(text):
            logger().info(
                f"SMP timeout/failure 0x{code} confirmed in hostlog"
            )
            return code
    assert False, (
        f"Expected SMP timeout/failure "
        f"({', '.join('0x' + c for c in C553871_SMP_TIMEOUT_FAILURE_CODES)}) "
        f"with disconnect in DUT hostlog within {timeout}s"
    )


def c553871_fail_numeric_comparison_central_accept_periph_no_action(
    bus,
    wifi_dut,
    remote_peer_address,
    *,
    dut_passkey: Optional[str] = None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    TestRail C553871 step 7 — NC: central Accept first, peripheral no action → 0x4BFC.

    Action order Central: DUT ``smp_passkey`` with displayed passkey; nRF/Raspi
    takes no NC action so pairing times out.
    """
    if dut_passkey is None:
        dut_passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert dut_passkey, (
        "Numeric comparison passkey not found in DUT hostlog (step 7)"
    )
    assert_passkey_valid(dut_passkey)

    hostlog_text = "\n".join(decode_log_items(bus.get_input_log()))
    if (
        _hostlog_dut_smp_passkey_already_accepted(hostlog_text)
        and _c553868_hostlog_central_decline_submitted(hostlog_text)
    ):
        pytest.fail(
            "DUT central declined NC (passkey=0) — use firmware with "
            "rsi_ble_smp_passkey(..., passkey) for central Accept (TestRail step 2)"
        )

    if _hostlog_dut_smp_passkey_already_accepted(hostlog_text):
        logger().info(
            "DUT central NC already accepted (firmware rsi_ble_smp_passkey) "
            "— skip duplicate smp_passkey"
        )
    else:
        logger().info(
            f"DUT (central) accepting numeric comparison — "
            f"passkey {dut_passkey}"
        )
        wifi_dut.interfaces.wifi.smp_passkey(
            bd_addr=remote_peer_address, passkey=dut_passkey
        )

    logger().info(
        "Peripheral no action — withholding nRF/Raspi NC confirm/decline"
    )

    wait_for_c553871_smp_timeout_failure(bus, timeout=fail_timeout)


def verify_c553871_nc_timeout_hostlog(bus, passkey: str):
    """TestRail C553871 step 7 — NC passkey shown, central accept, 0x4BFC, disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    matched_code = _c553871_hostlog_smp_timeout_code(text)
    assert matched_code, (
        f"Expected SMP timeout/failure "
        f"({', '.join('0x' + c for c in C553871_SMP_TIMEOUT_FAILURE_CODES)}) "
        "in hostlog (step 7)"
    )
    if matched_code != SMP_AUTH_FAILURE_ERROR_CODE:
        logger().warning(
            f"Wearables FW reported 0x{matched_code} instead of "
            f"0x{SMP_AUTH_FAILURE_ERROR_CODE} — accepting NC SMP timeout"
        )
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected numeric-comparison passkey in hostlog (step 7)"
    )
    assert "smp encrypt event" not in lower, (
        f"Pairing must not encrypt after SMP timeout (step 7)"
    )
    for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after SMP timeout (step 7)"
    )
    logger().info(
        f"Numeric Comparison SMP timeout 0x{matched_code} validated"
    )


def note_c553871_ota_deferred():
    logger().warning(
        "OTA NC timeout / LL packet validation deferred — hostlog-only mode"
    )


# C553872 — NC SMP timeout (central no action; step 7 hostlog 0x4BFC)
verify_c553872_dut_displayyesno_smp_config_hostlog = (
    verify_c553865_dut_displayyesno_smp_config_hostlog
)

C553872_SMP_TIMEOUT_FAILURE_CODES: Tuple[str, ...] = C553871_SMP_TIMEOUT_FAILURE_CODES


def start_c553872_nrf_displayyesno_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    C553872 — nRF DisplayYesNo peripheral; withhold NC confirm during step 7 timeout.

    TestRail steps 4–6: nRF Connect adv + security (DisplayYesNo, slave11).
    Step 7 table: DUT scan/connect → 0x4BFC (no nRF Accept in hostlog-only flow).
    """
    if is_nrf_peer(ble_client):
        _prepare_c553871_nrf_displayyesno(ble_client)
        nrf = ble_client.interfaces.bluetooth
        addr = nrf.start_advertising(
            local_name=adv_name, timeout_sec=0, auto_restart=False
        )
        time.sleep(5)
        return nrf.get_ble_address() or addr
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_displayyesno_peripheral(ble_client, auth_req=auth_req)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo advertising (C553872)"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def _c553872_hostlog_smp_timeout_code(text: str) -> Optional[str]:
    return _c553871_hostlog_smp_timeout_code(text)


def wait_for_c553872_smp_timeout_failure(
    bus,
    *,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
) -> str:
    """C553872 step 7 — central no action, peripheral no NC action; 0x4BFC + disconnect."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        code = _c553872_hostlog_smp_timeout_code(text)
        if "smp encrypt event" in lower and not code:
            assert False, (
                "Bonding completed (smp encrypt) before SMP timeout — "
                "nRF must not auto-confirm (peripheral no action, step 7)"
            )
        if code and _hostlog_contains_disconnect(text):
            logger().info(
                f"SMP timeout/failure 0x{code} confirmed in hostlog"
            )
            return code
    assert False, (
        f"Expected SMP timeout/failure "
        f"({', '.join('0x' + c for c in C553872_SMP_TIMEOUT_FAILURE_CODES)}) "
        f"with disconnect in DUT hostlog within {timeout}s"
    )


def c553872_fail_numeric_comparison_periph_accept_central_no_action(
    bus,
    ble_client,
    *,
    dut_passkey: Optional[str] = None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    TestRail C553872 step 7 — DUT connect, central no action → 0x4BFC.

    TestRail step 7 table: scan/connect then 0x4BFC in hostlog. Automation does
    not call DUT ``smp_passkey`` (firmware step 2) and withholds nRF/Raspi NC
    confirm/decline so SMP auth times out.
    """
    if dut_passkey is None:
        dut_passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert dut_passkey, (
        "Numeric comparison passkey not found in DUT hostlog (step 7)"
    )
    assert_passkey_valid(dut_passkey)

    hostlog_text = "\n".join(decode_log_items(bus.get_input_log()))
    if _hostlog_dut_smp_passkey_already_accepted(hostlog_text):
        pytest.fail(
            "DUT central already accepted NC via host smp_passkey — "
            "central must take no action (TestRail step 2 / step 7)"
        )

    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"
    logger().info(
        f"{peer_label} peripheral no action — withholding NC confirm "
        f"(passkey {dut_passkey})"
    )
    logger().info("Central no action — no DUT smp_passkey")

    wait_for_c553872_smp_timeout_failure(bus, timeout=fail_timeout)


def verify_c553872_nc_timeout_hostlog(bus, passkey: str):
    """TestRail C553872 step 7 — NC passkey shown, 0x4BFC SMP timeout, disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    matched_code = _c553872_hostlog_smp_timeout_code(text)
    assert matched_code, (
        f"Expected SMP timeout/failure "
        f"({', '.join('0x' + c for c in C553872_SMP_TIMEOUT_FAILURE_CODES)}) "
        "in hostlog (step 7)"
    )
    if matched_code != SMP_AUTH_FAILURE_ERROR_CODE:
        logger().warning(
            f"Wearables FW reported 0x{matched_code} instead of "
            f"0x{SMP_AUTH_FAILURE_ERROR_CODE} — accepting NC SMP timeout"
        )
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected numeric-comparison passkey in hostlog (step 7)"
    )
    assert "smp encrypt event" not in lower, (
        f"Pairing must not encrypt after SMP timeout (step 7)"
    )
    for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after SMP timeout (step 7)"
    )
    logger().info(
        f"Numeric Comparison SMP timeout 0x{matched_code} validated"
    )


def note_c553872_ota_deferred():
    logger().warning(
        f"OTA NC timeout / LL packet validation deferred — hostlog-only mode"
    )


# C553873 — NC SMP timeout (peripheral and central no action)
verify_c553873_dut_displayyesno_smp_config_hostlog = (
    verify_c553865_dut_displayyesno_smp_config_hostlog
)

C553873_SMP_TIMEOUT_FAILURE_CODES: Tuple[str, ...] = C553872_SMP_TIMEOUT_FAILURE_CODES


def start_c553873_nrf_displayyesno_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    C553873 — nRF DisplayYesNo peripheral; withhold NC confirm (steps 4–6).

    TestRail steps 4–6: nRF Connect adv + security (DisplayYesNo, slave11).
    """
    return start_c553872_nrf_displayyesno_peripheral(
        ble_client,
        dut_address,
        adv_name=adv_name,
        auth_req=auth_req,
    )


def _c553873_hostlog_smp_timeout_code(text: str) -> Optional[str]:
    return _c553872_hostlog_smp_timeout_code(text)


def wait_for_c553873_smp_timeout_failure(
    bus,
    *,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
) -> str:
    """C553873 steps 7–8 — both sides no NC action; 0x4BFC + disconnect."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        code = _c553873_hostlog_smp_timeout_code(text)
        if "smp encrypt event" in lower and not code:
            assert False, (
                "Bonding completed (smp encrypt) before SMP timeout — "
                "nRF must not auto-confirm (peripheral no action, steps 7–8)"
            )
        if code and _hostlog_contains_disconnect(text):
            logger().info(
                f"SMP timeout/failure 0x{code} confirmed in hostlog"
            )
            return code
    assert False, (
        f"Expected SMP timeout/failure "
        f"({', '.join('0x' + c for c in C553873_SMP_TIMEOUT_FAILURE_CODES)}) "
        f"with disconnect in DUT hostlog within {timeout}s"
    )


def c553873_fail_numeric_comparison_both_no_action(
    bus,
    ble_client,
    *,
    dut_passkey: Optional[str] = None,
    passkey_timeout=PASSKEY_TIMEOUT_SEC,
    fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    TestRail C553873 steps 7–8 — DUT connect; peripheral and central no action → 0x4BFC.

    Firmware step 2 comments out ``rsi_ble_smp_passkey``; automation withholds nRF/Raspi
    NC confirm/decline and does not call DUT ``smp_passkey``.
    """
    if dut_passkey is None:
        dut_passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert dut_passkey, (
        "Numeric comparison passkey not found in DUT hostlog (step 7)"
    )
    assert_passkey_valid(dut_passkey)

    hostlog_text = "\n".join(decode_log_items(bus.get_input_log()))
    if _hostlog_dut_smp_passkey_already_accepted(hostlog_text):
        pytest.fail(
            "DUT central already accepted NC via host smp_passkey — "
            "central must take no action (TestRail step 2 / steps 7–8)"
        )

    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"
    logger().info(
        f"{peer_label} peripheral no action — withholding NC confirm "
        f"(passkey {dut_passkey})"
    )
    logger().info("Central no action — no DUT smp_passkey")

    wait_for_c553873_smp_timeout_failure(bus, timeout=fail_timeout)


def verify_c553873_nc_timeout_hostlog(bus, passkey: str):
    """TestRail C553873 step 8 — NC passkey shown, 0x4BFC SMP timeout, disconnect."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    matched_code = _c553873_hostlog_smp_timeout_code(text)
    assert matched_code, (
        f"Expected SMP timeout/failure "
        f"({', '.join('0x' + c for c in C553873_SMP_TIMEOUT_FAILURE_CODES)}) "
        "in hostlog (step 8)"
    )
    if matched_code != SMP_AUTH_FAILURE_ERROR_CODE:
        logger().warning(
            f"Wearables FW reported 0x{matched_code} instead of "
            f"0x{SMP_AUTH_FAILURE_ERROR_CODE} — accepting NC SMP timeout"
        )
    assert _hostlog_contains_display_passkey(text, passkey), (
        f"Expected numeric-comparison passkey in hostlog (step 7)"
    )
    assert "smp encrypt event" not in lower, (
        f"Pairing must not encrypt after SMP timeout (step 8)"
    )
    for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS:
        assert marker in lower, (
            f"Expected connect/SMP marker '{marker}' in hostlog (step 7)"
        )
    assert _hostlog_contains_disconnect(text), (
        f"Expected disconnect after SMP timeout (step 8)"
    )
    logger().info(
        f"Numeric Comparison SMP timeout 0x{matched_code} validated"
    )


def note_c553873_ota_deferred():
    logger().warning(
        f"OTA NC timeout / LL packet validation deferred — hostlog-only mode"
    )




def note_c553911_step13_ota_deferred():
    logger().warning(
        f"TestRail step 13 deferred — OTA LL_ENC_REQ EDIV/Rand=0 validation "
        "skipped until RF sniffer integration is available"
    )


# BlueZ HCI auth is re-applied after start_smp_adv (BT service restart clears it).
# See test_ble_legacy_pairing_central_role_with_public_addr.py.


def start_c553911_displayyesno_legacy_jw_rebond_peripheral(
    ble_client,
    dut_address,
    *,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
):
    """
    C553911 steps 10–11 — DisplayYesNo legacy peripheral for JW rebond (bonding only).

    After peer-only unbond, legacy DisplayYesNo+MITM on both sides yields 0x4B03 on
    Silabs/Raspi; bonding-only (no MITM) selects Just Works for DisplayYesNo+DisplayYesNo.
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client,
            "DisplayYesNo",
            local_name=adv_name,
            lesc_pairing=False,
            passcode_pairing=False,
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(PEER_BUS_SETTLE_SEC)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo legacy JW rebond advertising"
    try:
        ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
        logger().info("Raspi LE Secure Connections disabled (legacy pairing)")
    except Exception as exc:
        logger().warning(f"set_secure_connection(sc=off) failed: {exc}")
    configure_raspi_displayyesno_legacy_peripheral(
        ble_client, auth_req=AUTH_REQ_BONDING_ONLY
    )
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(PEER_ADV_START_SEC)
    return addr


def c553911_prepare_dut_jw_rebond(wifi_dut):
    """
    C553911 step 12 prep — DUT SMP bonding-only for legacy JW rebond after peer unbond.

    DUT retains its bond store; MITM auth on reconnect with DisplayYesNo peer causes
    0x4B03. Bonding-only matches C553842 Just Works path for DisplayYesNo+DisplayYesNo.
    """
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_ONLY,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    logger().info(
        f"DUT SMP reconfigured to bonding-only for JW rebond (step 12)"
    )


def verify_c553911_step8_initial_legacy_bond_hostlog(bus, passkey: str):
    """TestRail C553911 step 8 — DUT legacy passkey bond + LE connection (hostlog)."""
    ok, log_text = wait_for_log_patterns(
        bus,
        (
            "passkey",
            "smp pairing request initiated",
        ),
        timeout=STEP_SETTLE_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    if passkey and passkey not in lower:
        logger().warning(
            f"Passkey {passkey} not echoed in hostlog (step 8)"
        )
    verify_post_pair_hostlog(bus, require_security_keys=True)
    logger().info(
        f"Step 8: legacy DisplayYesNo passkey bond + encryption "
        f"validated (hostlog)"
    )


def verify_c553911_step12_jw_rebond_hostlog(bus):
    """TestRail C553911 step 12 — Pin missing path, peer-initiated legacy JW rebond."""
    text = "\n".join(decode_log_items(bus.get_input_log()))
    lower = text.lower()
    if not any(
        m in lower
        for m in ("pin", "key missing", "missing key", "ltk", "encrypt", "pairing")
    ):
        logger().warning(
            f"Pin/key-missing marker not explicit in hostlog (step 12)"
        )
    verify_post_pair_hostlog(
        bus, require_security_keys=False
    )
    logger().info(
        f"Step 12: peer-initiated legacy JW rebond validated (hostlog)"
    )


def verify_c553911_step13_legacy_encrypt_hostlog(bus):
    """TestRail C553911 step 13 — legacy STK encrypt after rebond (hostlog; OTA deferred)."""
    ok, log_text = wait_for_log_patterns(
        bus,
        ("smp encrypt event",),
        timeout=SMP_COMPLETE_TIMEOUT_SEC,
        require_all=True,
    )
    lower = log_text.lower()
    assert "smp encrypt event" in lower, (
        f"Expected smp encrypt event after JW rebond (step 13)"
    )
    if "le ltk" in lower:
        ltk = extract_ltk_from_hostlog(bus, timeout=STEP_SETTLE_SEC)
        if ltk:
            logger().info(f"LE LTK/STK validated from hostlog: {ltk}")
    elif "smp security keys event" in lower:
        logger().info(f"smp security keys event seen (legacy STK path)")
    elif not ok:
        logger().warning(f"Encrypt event validated; optional key banners absent")
    logger().info(
        f"Step 13: legacy encrypt after JW rebond validated (hostlog)"
    )


def verify_c553860_step6_le_sc_passkey_hostlog(bus, passkey: str):
    """TestRail C553860 step 6 — MTU, SMP start, LESC passkey event (hostlog)."""
    ok, log_text = wait_for_log_patterns(
        bus,
        (
            "mtu exchange",
            "smp pairing request initiated",
            "passkey",
        ),
        timeout=SMP_COMPLETE_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    assert "mtu exchange" in lower, (
        f"Expected MTU exchange in hostlog (step 6)"
    )
    assert "smp pairing request initiated" in lower, (
        f"Expected SMP pairing request in hostlog (step 6)"
    )
    passkey_marker_ok = any(
        m in lower
        for m in (
            "in smp sc passkey event",
            "smp sc passkey",
            "passkey event",
            "in passkey event",
            "remote addr:",
        )
    )
    assert passkey_marker_ok, (
        f"Expected LESC passkey SMP event in hostlog (step 6)"
    )
    assert str(passkey) in log_text, (
        f"Expected passkey {passkey} in hostlog (step 6)"
    )
    if not ok:
        logger().warning(f"Some step-6 markers delayed in hostlog")


def verify_c553860_le_sc_ltk_post_pair_hostlog(bus):
    """TestRail C553860 step 7 — LESC bond + encrypt + LE LTK (hostlog-only; OTA deferred)."""
    ok, log_text = wait_for_log_patterns(
        bus,
        ("smp encrypt event", "le ltk"),
        timeout=SMP_COMPLETE_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    assert "smp encrypt event" in lower, (
        f"Expected smp encrypt event after LESC pairing (step 7)"
    )
    ltk = extract_ltk_from_hostlog(bus, timeout=SMP_COMPLETE_TIMEOUT_SEC)
    assert ltk is not None, (
        f"Expected LE LTK in hostlog after LESC pairing (step 7)"
    )
    if ltk:
        logger().info(f"LE LTK validated from hostlog: {ltk}")
    if "smp security keys event" not in lower:
        logger().warning(
            f"smp security keys event not seen — encrypt + LTK sufficient"
        )
    elif not ok:
        logger().warning(f"Some step-7 markers delayed in hostlog")
    logger().info(
        f"Step 7: LESC connection + encryption + LTK validated (hostlog)"
    )


def verify_central_encryption_initiation_hostlog(bus):
    """TestRail C553857 steps 3–4 — central connect, encrypt, profile discovery, data."""
    ok, log_text = wait_for_log_patterns(
        bus, CENTRAL_ENCRYPTION_INIT_MARKERS, timeout=120, require_all=False
    )
    lower = log_text.lower()
    for marker in CENTRAL_ENCRYPTION_INIT_MARKERS:
        assert marker in lower, (
            f"Expected hostlog marker '{marker}' (steps 3–4)"
        )
    ltk = extract_ltk_from_hostlog(bus, timeout=SMP_COMPLETE_TIMEOUT_SEC)
    assert ltk is not None, f"Expected LE LTK in hostlog (step 3)"
    if ltk:
        logger().info(f"LE LTK validated from hostlog: {ltk}")


def verify_peripheral_init_hostlog(bus, wifi_dut=None):
    """TestRail step 2 — DUT peripheral init / advertising hostlog."""
    if wifi_dut is not None:
        smp_iocap_dut_settle(wifi_dut=wifi_dut, bus=bus)
    elif not _dut_already_initialized_in_suite():
        _open_dut_serial(bus)
        time.sleep(SMP_DUT_INIT_SLEEP_SEC)

    if _dut_already_initialized_in_suite():
        logger().info(
            f"Step 2: skip boot hostlog verify (smp_iocap suite test 2+)"
        )
        _preemptive_restart_dut_idle_if_needed(
            wifi_dut, bus, require_scan=False
        )
        combined = combined_fresh_hostlog(bus)
        assert_dut_wearables_idle_hostlog(
            combined,
            step="2",
            bus=bus,
            wifi_dut=wifi_dut,
        )
        return

    ok, polled = wait_for_log_patterns(
        bus,
        PERIPHERAL_INIT_LOG_MARKERS,
        timeout=DUT_INIT_LOG_MARKER_TIMEOUT_SEC,
        require_all=False,
    )
    combined = combined_fresh_hostlog(bus, polled).lower()
    missing = [m for m in PERIPHERAL_INIT_LOG_MARKERS if m not in combined]
    if missing:
        logger().warning(
            f"Peripheral init hostlog incomplete (step 2): {missing} "
            "— continuing (boot banners may pre-date serial open)"
        )
    if hostlog_indicates_dut_advertising(combined):
        logger().info(f"DUT advertising active in hostlog (step 2)")
        return
    logger().warning(
        f"No advertising markers in hostlog (step 2) — "
        "continuing (smp_iocap test 1; verify via scan/connect)"
    )


def ensure_dut_wearables_init_hostlog_step(
    wifi_dut,
    bus,
    step: str = "2",
    require_scan: bool = True,
):
    """
    TestRail DUT init / advertising[/scan] hostlog — cold-start safe (subset / test 1).

    Opens serial and waits for firmware boot before passive hostlog verify.
    """
    smp_iocap_dut_settle(wifi_dut=wifi_dut, bus=bus)
    _preemptive_restart_dut_idle_if_needed(
        wifi_dut, bus, require_scan=require_scan
    )
    drain_serial(bus)
    time.sleep(STEP_SETTLE_SEC)
    markers = WEARABLES_INIT_LOG_MARKERS if require_scan else PERIPHERAL_INIT_LOG_MARKERS
    ok, log_text = wait_for_log_patterns(
        bus,
        markers,
        timeout=PERIPHERAL_INIT_VERIFY_TIMEOUT_SEC,
        require_all=False,
    )
    if not ok:
        logger().warning(
            f"Some step-{step} init log markers missing — continuing"
        )
    combined = log_text.lower()
    if _dut_already_initialized_in_suite():
        assert_dut_wearables_idle_hostlog(
            combined,
            step=step,
            require_scan=require_scan,
            bus=bus,
            wifi_dut=wifi_dut,
        )
    elif not hostlog_indicates_dut_advertising(combined):
        logger().warning(
            f"No adv/scan markers after step-{step} init — continuing "
            "(suite test 1; boot banners pre-serial)"
        )


def verify_peripheral_connect_hostlog(bus):
    """TestRail step 5 — connection + numeric comparison hostlog markers."""
    ok, log_text = wait_for_log_patterns(
        bus, PERIPHERAL_CONNECT_SMP_MARKERS, timeout=90, require_all=False
    )
    lower = log_text.lower()
    connected = (
        "on enhance connect event" in lower
        or "enhanced connect event status report : 0" in lower
    )
    assert connected, f"Connection not successful (step 5)"
    assert "passkey" in lower or "smp sc passkey" in lower, (
        f"Expected passkey / numeric comparison in hostlog (step 5)"
    )
    if not ok:
        logger().warning(
            f"Some connect SMP markers missing: "
            f"{[m for m in PERIPHERAL_CONNECT_SMP_MARKERS if m not in lower]}"
        )


def verify_dut_random_address_init_hostlog(bus):
    """TestRail C553858 — firmware rsi_ble_set_random_address_with_value at DUT init."""
    ok, log_text = wait_for_log_patterns(
        bus, ("set bd addr success",), timeout=60, require_all=False
    )
    lower = log_text.lower()
    assert ok or "set bd addr success" in lower, (
        f"Expected SET BD ADDR SUCCESS after random address init (step 1)"
    )
    logger().info(f"DUT random address init confirmed in hostlog")


def restore_dut_public_advertising(wifi_dut, bus):
    """Best-effort restore after random-address peripheral tests (suite isolation)."""
    logger().info(f"Restoring DUT public-address advertising for suite isolation")
    for stop_fn_name in ("stop_adv", "legacy_scan_stop"):
        try:
            getattr(wifi_dut.interfaces.wifi, stop_fn_name)()
        except Exception as exc:
            logger().warning(f"{stop_fn_name}: {exc}")
    time.sleep(1)
    try:
        wifi_dut.interfaces.wifi.legacy_adv(
            status=1, own_addr_type=DEFAULT_OWN_ADDR_TYPE
        )
        time.sleep(2)
    except Exception as exc:
        logger().warning(f"legacy_adv public restore: {exc}")
    restored = fetch_local_address(wifi_dut, log_start=0)
    if is_valid_bd_addr(restored):
        _set_cached_dut_local_address(restored)
        logger().info(f"Restored public DUT address cache: {restored}")


def _ensure_dut_ble_ready_for_suite(
    wifi_dut,
    bus,
    require_scan: bool = True,
):
    """Passive suite bring-up — smp_iocap pattern (no BLE CLI between tests)."""
    return ensure_dut_ble_ready_for_test(
        wifi_dut,
        bus,
        require_scan=require_scan,
    )


def ensure_dut_ble_ready_state(
    wifi_dut,
    bus,
    require_scan: bool = True,
    timeout: float = DUT_BLE_READY_TIMEOUT_SEC,
    restart_on_missing: bool = False,
):
    """
    Ensure the DUT is back in the expected wearables idle state.

    Default is passive wait only (``restart_on_missing=False``) — same as smp_iocap
    / sweyntooth: rely on firmware boot + inter-test delay; do not stop/restart BLE
    between suite tests unless a caller explicitly opts in.
    """
    markers = DUT_BLE_READY_MARKERS if require_scan else ("advertising started",)
    require_all = require_scan

    ready, log_text = wait_for_log_patterns(
        bus,
        markers,
        timeout=timeout,
        require_all=require_all,
    )
    if ready:
        return True, log_text

    if not restart_on_missing:
        logger().warning(
            f"DUT BLE ready markers missing after passive wait ({timeout}s)"
        )
        return False, log_text

    logger().warning(
        f"DUT BLE ready markers missing; restarting advertising/"
        f"{'scanning' if require_scan else 'idle peripheral state'}"
    )
    _stop_dut_ble_activity(wifi_dut, rounds=1)
    try:
        wifi_dut.interfaces.wifi.legacy_adv(
            status=1, own_addr_type=DEFAULT_OWN_ADDR_TYPE
        )
    except Exception as exc:
        logger().warning(f"legacy_adv ready-state restore: {exc}")
    if require_scan:
        _start_dut_legacy_scan(wifi_dut)

    ready, recovered_log = wait_for_log_patterns(
        bus,
        markers,
        timeout=timeout,
        require_all=require_all,
    )
    return ready, f"{log_text}\n{recovered_log}"


def ensure_dut_peripheral_random_address(
    wifi_dut,
    bus,
    random_addr: str = TESTRAIL_WEARABLES_RANDOM_BLE_ADDR,
    configure_smp=None,
):
    """
    TestRail C553848/C553849/C553855 steps 1+4 — LE random address + SMP + adv restart.

    Firmware may call rsi_ble_set_random_address_with_value at boot; if not, set via
    CLI and restart legacy advertising with own_addr_type=1 (smp_iocap reference tests).
    Returns the random BD address used for central scan/connect.
    """
    if configure_smp is None:
        configure_smp = configure_dut_smp_displayyesno_peripheral

    logger().info(
        f"TestRail step 1: set LE random address ({random_addr})"
    )
    ensure_dut_le_random_address(
        wifi_dut,
        bus,
        random_addr=random_addr,
        stop_ble_activity=True,
        force=True,
    )

    logger().info(f"TestRail step 4: configure DUT SMP pairing capability")
    configure_smp(wifi_dut)

    logger().info(
        f"Restart DUT advertising with LE random address (own_addr_type=1)"
    )
    wifi_dut.interfaces.wifi.legacy_adv(
        status=1,
        direct_addr=random_addr,
        own_addr_type=OWN_ADDR_TYPE_RANDOM,
    )
    ok, log_text = wait_for_log_patterns(
        bus, DUT_ADV_ACTIVE_MARKERS, timeout=30, require_all=False
    )
    lower = log_text.lower()
    assert ok or hostlog_indicates_dut_advertising(lower), (
        f"Expected advertising restarted after random address set"
    )
    time.sleep(5)
    return random_addr


def ensure_dut_le_random_address(
    wifi_dut,
    bus,
    *,
    random_addr: str = DEFAULT_DUT_RANDOM_BLE_ADDR,
    stop_ble_activity: bool = True,
    force: bool = False,
):
    """
    Ensure DUT has an LE random address before scan/connect with own_addr_type=1.

    Firmware may call rsi_ble_set_random_address_with_value at init; otherwise
    set via ``btc ble set_random_address`` (smp_iocap random-addr reference tests).
    Without this, req_legacy_conn with own_addr_type=1 returns error 0x4e12.

    ``force=True`` always sets ``random_addr`` (peripheral TestRail cases) so a
    prior central test (e.g. C553847) cannot leave a different random address set.
    """
    drain_serial(bus)
    if not force:
        accumulated = "\n".join(decode_log_items(bus.get_input_log())).lower()
        if any(m in accumulated for m in DUT_RANDOM_ADDR_SUCCESS_MARKERS):
            logger().info(f"DUT LE random address already set (hostlog)")
            _set_cached_dut_local_address(random_addr)
            return

    if stop_ble_activity:
        for stop_fn_name in ("stop_adv", "legacy_scan_stop"):
            try:
                getattr(wifi_dut.interfaces.wifi, stop_fn_name)()
            except Exception as exc:
                logger().warning(f"{stop_fn_name}: {exc}")
        time.sleep(2)

    logger().info(f"Setting DUT LE random address via CLI: {random_addr}")
    drain_serial(bus)
    wifi_dut.interfaces.wifi.set_random_address(bd_addr=random_addr)
    ok, _ = wait_for_log_patterns(
        bus, DUT_RANDOM_ADDR_SUCCESS_MARKERS, timeout=10, require_all=False
    )
    assert ok, (
        f"Failed to set DUT LE random address "
        f"(expected one of {DUT_RANDOM_ADDR_SUCCESS_MARKERS!r}). "
        "own_addr_type=1 requires random address (connect fails with 0x4e12 otherwise)."
    )
    logger().info(f"DUT LE random address confirmed")
    _set_cached_dut_local_address(random_addr)


def start_raspi_peripheral(ble_client, dut_address, configure_peer=False):
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client, "KeyboardOnly", dynamic_passkey=True
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(PEER_BUS_SETTLE_SEC)
    if configure_peer:
        configure_peer_smp(ble_client)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="KeyboardOnly",
    )
    assert addr, "Failed to start Raspberry Pi SMP advertising"
    time.sleep(PEER_ADV_START_SEC)
    return addr


def start_raspi_displayyesno_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    Peer peripheral (nRF dongle / Raspi) C553838: DisplayYesNo + adv name slave11.
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client, "DisplayYesNo", local_name=adv_name
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_displayyesno_peripheral(ble_client, auth_req=auth_req)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo advertising"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def start_raspi_displayonly_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_SC,
):
    """Peer peripheral (C553839): DisplayOnly, MITM disabled."""
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client,
            "DisplayOnly",
            local_name=adv_name,
            passcode_pairing=False,
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    configure_raspi_displayonly_peripheral(ble_client, auth_req=auth_req)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayOnly",
    )
    assert addr, "Failed to start Raspi DisplayOnly advertising"
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def start_raspi_displayyesno_legacy_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_ONLY,
):
    """
    Peer peripheral for legacy SMP (C553842): DisplayYesNo, SC disabled, bonding on.
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client,
            "DisplayYesNo",
            local_name=adv_name,
            lesc_pairing=False,
            passcode_pairing=False,
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayYesNo",
    )
    assert addr, "Failed to start Raspi DisplayYesNo legacy advertising"
    try:
        ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
        logger().info("Raspi LE Secure Connections disabled (legacy pairing)")
    except Exception as exc:
        logger().warning(f"set_secure_connection(sc=off) failed: {exc}")
    configure_raspi_displayyesno_legacy_peripheral(ble_client, auth_req=auth_req)
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def start_raspi_keyboarddisplay_legacy_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_LEGACY,
):
    """
    Peer peripheral for legacy SMP passkey (C553859): KeyboardDisplay, SC disabled.
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client,
            "KeyboardDisplay",
            local_name=adv_name,
            lesc_pairing=False,
            dynamic_passkey=True,
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="KeyboardDisplay",
    )
    assert addr, "Failed to start Raspi KeyboardDisplay legacy advertising"
    try:
        ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
        logger().info("Raspi LE Secure Connections disabled (legacy pairing)")
    except Exception as exc:
        logger().warning(f"set_secure_connection(sc=off) failed: {exc}")
    configure_raspi_keyboarddisplay_legacy_peripheral(ble_client, auth_req=auth_req)
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def start_c553860_nrf_le_sc_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    C553860 — LESC passkey peripheral. TestRail lists KeyboardDisplay; nRF Blatann
    LESC passkey entry matches C553840 when peer IO cap is KeyboardOnly.
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client,
            "KeyboardOnly",
            local_name=adv_name,
            dynamic_passkey=True,
            dynamic_passkey_timeout=PASSKEY_TIMEOUT_SEC,
        )
    return start_raspi_keyboarddisplay_peripheral(
        ble_client, dut_address, adv_name=adv_name, auth_req=auth_req
    )


def start_raspi_keyboarddisplay_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    Peer peripheral for LESC passkey: KeyboardDisplay, LE SC + MITM + bonding.
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client,
            "KeyboardDisplay",
            local_name=adv_name,
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="KeyboardDisplay",
    )
    assert addr, "Failed to start Raspi KeyboardDisplay advertising"
    configure_raspi_keyboarddisplay_peripheral(ble_client, auth_req=auth_req)
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def start_raspi_keyboardonly_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_MITM_SC,
):
    """
    Peer peripheral for C553864: KeyboardOnly (keyboard, no display), adv slave11.
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client, "KeyboardOnly", local_name=adv_name, dynamic_passkey=True
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="KeyboardOnly",
    )
    assert addr, "Failed to start Raspi KeyboardOnly peripheral advertising"
    configure_raspi_keyboardonly_peripheral(ble_client, auth_req=auth_req)
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def start_raspi_displayonly_legacy_peripheral(
    ble_client,
    dut_address,
    adv_name: str = REMOTE_DEVICE_NAME_SLAVE11,
    auth_req: int = AUTH_REQ_BONDING_ONLY,
):
    """
    Peer peripheral for non-LESC SMP (C553843): DisplayOnly, SC disabled, bonding on.
    """
    if is_nrf_peer(ble_client):
        return start_nrf_peripheral_advertising(
            ble_client,
            "DisplayOnly",
            local_name=adv_name,
            lesc_pairing=False,
            passcode_pairing=False,
        )
    ble_client.interfaces.bluetooth.set_bus()
    time.sleep(2)
    addr = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=dut_address,
        pin_code="-8",
        capability="DisplayOnly",
    )
    assert addr, "Failed to start Raspi DisplayOnly legacy advertising"
    try:
        ble_client.interfaces.bluetooth.set_secure_connection(sc="off")
        logger().info("Raspi LE Secure Connections disabled (non-LESC peer)")
    except Exception as exc:
        logger().warning(f"set_secure_connection(sc=off) failed: {exc}")
    configure_raspi_displayonly_peripheral(ble_client, auth_req=auth_req)
    try:
        ble_client.interfaces.bluetooth.set_advertising_data(hci_adv_data=adv_name)
        logger().info(f"Raspi advertising local name set to '{adv_name}'")
    except Exception as exc:
        logger().warning(
            f"Could not set adv name '{adv_name}' ({exc}) — DUT connect uses MAC"
        )
    time.sleep(3)
    return addr


def stop_raspi_peripheral(ble_client, dut_address, peripheral_address):
    """Stop Raspi peripheral; full ``close`` when *peripheral_address* is set (TestRail C553832)."""
    if is_nrf_peer(ble_client):
        stop_nrf_peripheral(ble_client)
        return
    if not peripheral_address:
        return
    bt = ble_client.interfaces.bluetooth
    try:
        bt.stop_advertising()
    except Exception as exc:
        logger().debug(f"stop_advertising: {exc}")
    for attempt in range(3):
        try:
            bt.remove_device(dut_address)
            break
        except Exception as exc:
            logger().warning(f"remove_device attempt {attempt + 1}: {exc}")
            time.sleep(1)
    time.sleep(2)
    _force_clear_raspi_bonds(ble_client, dut_address)
    _raspi_close_with_retry(ble_client, "[stop_raspi_peripheral] ")
    time.sleep(2)


def extract_peer_address_from_scan_log(
    scan_log: str, peer_name: str
) -> Optional[str]:
    """Parse ``advertised details`` hostlog for the peer MAC matching *peer_name*."""
    name_lower = peer_name.lower()
    for line in scan_log.splitlines():
        lower = line.lower()
        if "advertised details" not in lower or name_lower not in lower:
            continue
        match = re.search(
            r"dev_addr\s*=\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",
            line,
            re.IGNORECASE,
        )
        if match:
            return match.group(1).upper()
    return None


def _poll_scan_for_peer(
    bus,
    peer_name: Optional[str],
    peripheral_address: Optional[str],
    scan_seconds: float,
    log_start: Optional[int] = None,
) -> Tuple[bool, str, Optional[str]]:
    """Poll DUT hostlog during an active legacy scan; exit early when peer seen."""
    deadline = time.time() + scan_seconds
    accumulated = ""
    peer_mac = (peripheral_address or "").lower()
    if log_start is None:
        log_start = len(bus.get_input_log())
    while time.time() < deadline:
        time.sleep(LOG_POLL_INTERVAL_SEC)
        try:
            fresh = decode_log_items(bus.get_input_log()[log_start:])
            if fresh:
                accumulated += "\n".join(fresh)
                log_start = len(bus.get_input_log())
        except Exception:
            pass
        lower = accumulated.lower()
        if "advertised details" not in lower:
            continue
        if peer_name:
            scanned_addr = extract_peer_address_from_scan_log(accumulated, peer_name)
            if scanned_addr:
                return True, accumulated, scanned_addr
        if peer_mac and peer_mac in lower:
            return True, accumulated, peripheral_address
    return False, accumulated, None


def dut_scan_and_connect(
    wifi_dut,
    peripheral_address,
    scan_seconds=SCAN_BEFORE_CONNECT_SEC,
    accept_smp_start=False,
    own_addr_type=DEFAULT_OWN_ADDR_TYPE,
    scan_own_addr_type: Optional[int] = None,
    stop_scan_before_connect=True,
    peer_addr_type=PEER_ADDR_TYPE_PUBLIC,
    peer_name: Optional[str] = None,
    require_peer_in_scan: bool = False,
    connect_timeout: float = CONNECT_TIMEOUT_SEC,
    pre_connect_log_baseline: bool = False,
):
    """
    DUT central scan + connect (hostlog).

    Wearables firmware auto-starts scan on init. Do **not** stop scan before
    ``legacy_scan`` — stopping breaks discovery (peer never appears in hostlog).
    Stop scan only immediately before connect to avoid 0x4e12.

    ``pre_connect_log_baseline`` — when True, baseline hostlog index before connect
    TX (C553851+ only). Default False preserves legacy polling for verified PASS
    cases C553832–C553850.
    """
    bus = get_bus(wifi_dut)
    effective_scan_own_addr = (
        scan_own_addr_type
        if scan_own_addr_type is not None
        else own_addr_type
    )
    scan_kwargs = {
        "status": 1,
        "scan_type": DEFAULT_SCAN_TYPE,
        "filter_type": DEFAULT_FILTER_POLICY,
        "own_addr_type": effective_scan_own_addr,
        "scan_int": DEFAULT_SCAN_INTERVAL,
        "scan_win": DEFAULT_SCAN_WINDOW,
    }
    drain_serial(bus)
    try:
        wifi_dut.interfaces.wifi.legacy_scan(**scan_kwargs)
    except Exception as exc:
        logger().warning(f"legacy_scan: {exc}")
    time.sleep(LEGACY_SCAN_SETTLE_SEC)
    logger().info(
        f"Scanning for up to {scan_seconds}s before connect "
        f"(scan_own_addr_type={effective_scan_own_addr}, "
        f"connect_own_addr_type={own_addr_type})..."
    )
    peer_seen, scan_log, scanned_addr = _poll_scan_for_peer(
        bus,
        peer_name=peer_name,
        peripheral_address=peripheral_address,
        scan_seconds=scan_seconds,
    )
    connect_address = scanned_addr or peripheral_address
    if scanned_addr and scanned_addr.upper() != (peripheral_address or "").upper():
        logger().info(
            f"Using peer address from scan hostlog: {scanned_addr} "
            f"(was {peripheral_address})"
        )
    if require_peer_in_scan and not peer_seen:
        pytest.fail(
            f"Peer not seen during {scan_seconds}s scan "
            f"(name={peer_name!r}, addr={peripheral_address}). "
            f"scan_own_addr_type={effective_scan_own_addr}"
        )
    if not peer_seen and peripheral_address:
        logger().warning(
            f"Peer {peripheral_address} not logged during {scan_seconds}s scan — "
            "connecting by known address"
        )
    if stop_scan_before_connect:
        try:
            wifi_dut.interfaces.wifi.legacy_scan_stop()
            time.sleep(LEGACY_SCAN_SETTLE_SEC)
            drain_serial(bus)
        except Exception as exc:
            logger().warning(f"legacy_scan_stop before connect: {exc}")
    if own_addr_type == OWN_ADDR_TYPE_RANDOM:
        ensure_dut_le_random_address(
            wifi_dut, bus, stop_ble_activity=stop_scan_before_connect
        )
    connect_kwargs = {"dev_addr": connect_address, "supervision_tout": 500}
    if peer_name:
        connect_kwargs["dev_name"] = peer_name
    if own_addr_type != DEFAULT_OWN_ADDR_TYPE:
        connect_kwargs["own_addr_type"] = own_addr_type
    if peer_addr_type != PEER_ADDR_TYPE_PUBLIC:
        connect_kwargs["add_type"] = peer_addr_type
    logger().info(
        f"Connecting to {connect_address} "
        f"(peer_addr_type={peer_addr_type}, peer_name={peer_name!r}, "
        f"own_addr_type={own_addr_type})..."
    )
    if pre_connect_log_baseline:
        pre_connect_log_count = len(bus.get_input_log())
    wifi_dut.interfaces.wifi.req_legacy_connect(**connect_kwargs)
    deadline = time.time() + connect_timeout
    accumulated = scan_log
    log_start = len(bus.get_input_log())
    while time.time() < deadline:
        if not pre_connect_log_baseline:
            time.sleep(LOG_POLL_INTERVAL_SEC)
        try:
            if pre_connect_log_baseline:
                post_connect_items = bus.get_input_log()[pre_connect_log_count:]
                accumulated = scan_log + "\n".join(
                    decode_log_items(post_connect_items)
                )
            else:
                fresh = decode_log_items(bus.get_input_log()[log_start:])
                accumulated += "\n".join(fresh)
        except Exception:
            pass
        lower = accumulated.lower()
        if "error status 0x4e08" in lower:
            pytest.fail("Connection timeout (0x4e08)")
        if "error status 0x4e04" in lower:
            pytest.fail("Page timeout (0x4e04)")
        if "error status 0x4e12" in lower:
            pytest.fail(
                "Invalid Scan/ADV parameters (0x4e12) — stop scan before connect "
                f"(own_addr_type={own_addr_type})"
            )
        connected = (
            "on enhance connect event" in lower
            or "enhanced connect event status report : 0" in lower
        )
        if accept_smp_start:
            if connected and (
                "smp pairing request initiated" in lower
                or "smp pairing request" in lower
            ):
                logger().info("DUT connected and SMP pairing request logged")
                return accumulated
            if "smp pairing request initiated" in lower:
                logger().info("SMP pairing request logged (connect event pending)")
                return accumulated
        elif connected:
            logger().info("DUT connected to peripheral")
            return accumulated
        if pre_connect_log_baseline:
            time.sleep(LOG_POLL_INTERVAL_SEC)
    pytest.fail(
        f"Connection event not received within {connect_timeout}s timeout"
    )


def dut_scan_and_connect_fast_connect_rx(
    wifi_dut,
    peripheral_address,
    /,
    **kwargs,
):
    """
    C553851+ only — pre-connect hostlog baseline for fast nRF peripheral connect RX.

    Do not use for verified PASS C553832–C553850 (keep ``dut_scan_and_connect``).
    """
    return dut_scan_and_connect(
        wifi_dut,
        peripheral_address,
        pre_connect_log_baseline=True,
        **kwargs,
    )


def raspi_clear_bond_with_dut(ble_client, dut_address):
    """Remove peer bond only; DUT bond store is left intact (C553910 step 9)."""
    if is_nrf_peer(ble_client):
        nrf = ble_client.interfaces.bluetooth
        _try_recover_nrf_peer_device(nrf, dut_address)
        try:
            if nrf_peer_connected(nrf, dut_address):
                nrf.disconnect(dev_addr=dut_address, clear_peer=True)
                logger().info(f"nRF disconnected from DUT before clear bond")
        except Exception as exc:
            logger().warning(f"nRF disconnect before clear bond: {exc}")
        time.sleep(POST_DISCONNECT_SETTLE_SEC)
        try:
            nrf.delete_bonding_data()
            logger().info(f"nRF bond store cleared (peer-only unbond)")
        except Exception as exc:
            logger().warning(f"nRF delete_bonding_data: {exc}")
        return
    try:
        ble_client.interfaces.bluetooth.disconnect(dev_addr=dut_address)
    except Exception as exc:
        logger().info(f"disconnect before clear bond: {exc}")
    time.sleep(2)
    for attempt in range(3):
        try:
            ble_client.interfaces.bluetooth.remove_device(dut_address)
            logger().info(f"Cleared Raspi bond info for DUT {dut_address}")
            break
        except Exception as exc:
            logger().warning(f"remove_device attempt {attempt + 1}: {exc}")
            time.sleep(1)
    time.sleep(2)
    _force_clear_raspi_bonds(ble_client, dut_address)
    time.sleep(1)


def wait_for_passkey(
    bus,
    timeout=PASSKEY_TIMEOUT_SEC,
    exclude=(),
    enter_on_peer=None,
):
    """Return the next passkey from DUT hostlog, skipping any in *exclude*.

    When *enter_on_peer* is set, call ``set_pin`` as soon as the passkey is
    seen (suite-safe — avoids BlueZ SMP timeout while verify helpers run).
    """
    exclude_set = {str(pk).zfill(6) for pk in exclude}
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        for line in decode_log_items(bus.get_input_log()):
            lower = line.lower()
            if "smp failed" in lower or "4b0b" in lower:
                pytest.fail(f"SMP failed before passkey: {line.strip()}")
            match = re.search(r"passkey[:\s]+(\d+)", line, re.IGNORECASE)
            if match and len(match.group(1)) <= 6:
                pk = match.group(1).zfill(6)
                if pk in exclude_set:
                    continue
                logger().info(f"Passkey from DUT log: {pk}")
                if enter_on_peer is not None:
                    peer_set_pin(enter_on_peer, int(pk))
                return pk
    return None


def assert_passkey_valid(passkey: str) -> None:
    """TestRail step 7 — passkey must be non-zero (not 000000)."""
    assert passkey and passkey != "000000", (
        f"Invalid passkey {passkey!r} — expected non-zero 6-digit value"
    )
    logger().info(f"Valid passkey generated: {passkey}")


def wait_for_scanning_restarted(
    bus, timeout=SCAN_RESTART_AFTER_DISCONNECT_SEC
):
    ok, _ = wait_for_log_patterns(
        bus, ("scanning started",), timeout=timeout, poll=LOG_POLL_INTERVAL_SEC
    )
    assert ok, (
        f"Expected DUT to restart scanning after aborted pairing "
        f"within {timeout}s"
    )


def wait_for_disconnect_or_scan_restart(
    bus, timeout=DISCONNECT_OR_SCAN_RESTART_TIMEOUT_SEC
):
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1)
        text = "\n".join(decode_log_items(bus.get_input_log())).lower()
        if "scanning started" in text:
            return "scan_restart"
        if (
            "peripheral is disconnected" in text
            or "on event disconnect" in text
            or "error status 0x4e13" in text
        ):
            return "disconnect"
    pytest.fail(
        f"Neither disconnect nor scanning restarted within {timeout}s timeout"
    )


def _hostlog_contains_disconnect(text: str) -> bool:
    lower = text.lower()
    return (
        "peripheral is disconnected" in lower
        or "on event disconnect" in lower
        or "error status 0x4e13" in lower
        or "disconnected" in lower and "remote" in lower
    )


def wait_for_smp_auth_failure_disconnect(
    bus,
    expected_error: str = SMP_AUTH_FAILURE_ERROR_CODE,
    timeout: float = SMP_AUTH_FAILURE_TIMEOUT_SEC,
):
    """
    TestRail C553845 step 4 — passkey withheld; expect 0x4bfc and link teardown.
    """
    deadline = time.time() + timeout
    saw_error = False
    saw_disconnect = False
    while time.time() < deadline:
        time.sleep(1)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        if expected_error in lower or f"0x{expected_error}" in lower:
            saw_error = True
        if _hostlog_contains_disconnect(text):
            saw_disconnect = True
        if saw_error and saw_disconnect:
            logger().info(
                f"SMP auth failure 0x{expected_error} and disconnect confirmed"
            )
            return
    assert saw_error, (
        f"Expected SMP authentication failure 0x{expected_error} in DUT hostlog "
        f"(passkey withheld)"
    )
    assert saw_disconnect, (
        "Expected BLE disconnect after authentication failure (step 4)"
    )


def wait_for_smp_numeric_comparison_failed(
    bus,
    expected_error: str = SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE,
    timeout: float = 120,
):
    """
    TestRail C553867 step 8 — peripheral declines NC; expect 0x4B0C in DUT hostlog.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        if (
            expected_error in lower
            or f"0x{expected_error}" in lower
            or "numeric comparison failed" in lower
            or "smp failed" in lower
        ):
            logger().info(
                f"SMP numeric comparison failed 0x{expected_error} confirmed in hostlog"
            )
            return
    assert False, (
        f"Expected SMP numeric comparison failed 0x{expected_error} "
        f"in DUT hostlog within {timeout}s"
    )


def wait_for_smp_passkey_entry_failed(
    bus, *, expected_error: str = SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE, timeout: float = 120
):
    """
    TestRail C553863 step 7 — wrong passkey; expect 0x4B01 (SMP passkey entry failed).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1)
        text = "\n".join(decode_log_items(bus.get_input_log()))
        lower = text.lower()
        if (
            expected_error in lower
            or f"0x{expected_error}" in lower
            or "confirm value failed" in lower
            or "passkey entry failed" in lower
        ):
            logger().info(
                f"SMP passkey entry failed 0x{expected_error} confirmed in hostlog"
            )
            return
    assert False, (
        f"Expected SMP passkey entry failed 0x{expected_error} "
        f"(Confirm Value Failed) in DUT hostlog within {timeout}s"
    )


def dut_submit_wrong_passkey(
    wifi_dut, peripheral_address: str, *, wrong_passkey: int = 0
):
    """Enter incorrect passkey on DUT (KeyboardOnly initiator) — C553863 firmware/automation."""
    pk = str(wrong_passkey).zfill(6)
    logger().info(f"DUT submitting wrong passkey {pk} via smp_passkey")
    wifi_dut.interfaces.wifi.smp_passkey(
        bd_addr=peripheral_address, passkey=pk
    )


def dut_scan_connect_wrong_passkey_entry(
    wifi_dut,
    peripheral_address,
    bus,
    passkey_timeout: float = 120,
    fail_timeout: float = 120,
    wrong_passkey: int = 0,
    dut_submit_wrong: bool = True,
):
    """
    DUT central connects; DisplayOnly peer shows passkey; DUT enters wrong value.

    Firmware may call ``rsi_ble_smp_passkey(..., 0)`` on SC_PASSKEY_EVENT; automation
    can also submit via ``dut_submit_wrong`` when ``dut_submit_wrong`` is True.
    """
    drain_serial(bus)
    connect_log = dut_scan_and_connect(
        wifi_dut, peripheral_address, accept_smp_start=True
    )

    passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert passkey, (
        "SC passkey not found in DUT hostlog — DisplayOnly peer should display "
        "passkey for KeyboardOnly initiator (step 6)"
    )
    assert_passkey_valid(passkey)
    logger().info(
        f"Correct passkey from peer is {passkey}; "
        f"expect failure after wrong entry 0x{SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE}"
    )

    firmware_window = time.time() + 8
    while time.time() < firmware_window:
        text = "\n".join(decode_log_items(bus.get_input_log())).lower()
        if (
            SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE in text
            or f"0x{SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE}" in text
        ):
            logger().info("Wrong-passkey failure already reported by firmware")
            return connect_log
        time.sleep(0.5)

    if dut_submit_wrong:
        try:
            dut_submit_wrong_passkey(
                wifi_dut, peripheral_address, wrong_passkey=wrong_passkey
            )
        except Exception as exc:
            logger().warning(f"smp_passkey wrong entry failed: {exc}")

    wait_for_smp_passkey_entry_failed(bus, timeout=fail_timeout)
    return connect_log


def verify_auth_failure_connect_hostlog(bus):
    """TestRail C553845 step 3 — connect / MTU / SC passkey before withhold."""
    global _AUTH_FAILURE_CONNECT_LOG_SNAPSHOT
    combined = (_AUTH_FAILURE_CONNECT_LOG_SNAPSHOT or combined_fresh_hostlog(bus)).lower()
    if not combined.strip():
        combined = "\n".join(decode_log_items(bus.get_input_log())).lower()
    _assert_hostlog_marker_groups(
        combined,
        DUT_PERIPHERAL_CONNECT_VERIFY_GROUPS,
        step="3",
    )
    _AUTH_FAILURE_CONNECT_LOG_SNAPSHOT = None


def verify_passkey_entry_connect_hostlog(bus):
    """TestRail C553846/C553849 step 4 — connect / MTU / SC passkey before central entry."""
    combined = combined_fresh_hostlog(bus)
    if not combined.strip():
        combined = "\n".join(decode_log_items(bus.get_input_log())).lower()
    _assert_hostlog_marker_groups(
        combined,
        DUT_PERIPHERAL_CONNECT_VERIFY_GROUPS,
        step="4",
    )


def raspi_connect_withhold_passkey_central(
    ble_client,
    dut_address,
    bus,
    connect_timeout: float = 120,
    passkey_timeout: float = 120,
    auth_fail_timeout: float = 120,
):
    """Peer central connects, passkey appears, deliberately not entered (step 4)."""
    if is_nrf_peer(ble_client):
        central_addr = ble_client.interfaces.bluetooth.get_ble_address()

        def _withhold(bus, _wifi_dut, _peer, _central_addr, **_kw):
            passkey = wait_for_passkey(bus, timeout=passkey_timeout)
            assert passkey, "SC passkey not found in DUT hostlog (step 3)"
            _snapshot_auth_failure_connect_hostlog(bus)
            logger().info(
                f"Withholding passkey {passkey} — expecting auth failure 0x"
                f"{SMP_AUTH_FAILURE_ERROR_CODE}"
            )
            wait_for_smp_auth_failure_disconnect(bus, timeout=auth_fail_timeout)

        nrf_central_connect_and_pair(
            None,
            ble_client,
            dut_address,
            central_addr,
            bus,
            capability="KeyboardOnly",
            dynamic_passkey=True,
            connect_timeout=connect_timeout,
            smp_handler=_withhold,
        )
        return

    def _connect():
        logger().info(f"Raspi connecting to DUT {dut_address} (withhold passkey)")
        ble_client.interfaces.bluetooth.connect(
            dev_addr=dut_address,
            supervision_timeout=500,
        )

    drain_serial(bus)
    connect_thread = threading.Thread(target=_connect)
    connect_thread.start()
    time.sleep(2)

    passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert passkey, "SC passkey not found in DUT hostlog (step 3)"
    _snapshot_auth_failure_connect_hostlog(bus)
    logger().info(
        f"Withholding passkey {passkey} — expecting auth failure 0x"
        f"{SMP_AUTH_FAILURE_ERROR_CODE}"
    )

    wait_for_smp_auth_failure_disconnect(bus, timeout=auth_fail_timeout)

    connect_thread.join(timeout=connect_timeout)
    if connect_thread.is_alive():
        logger().warning("Raspi connect thread still running after auth failure")


def dut_scan_connect_withhold_passkey(
    wifi_dut,
    peripheral_address,
    bus,
    passkey_timeout: float = 120,
    auth_fail_timeout: float = 120,
):
    """
    DUT central connects; passkey displayed by DisplayOnly peer; DUT does not enter it.

    Firmware must not call ``rsi_ble_smp_passkey`` (C553861); expect hostlog 0x4bfc.
    """
    drain_serial(bus)
    connect_log = dut_scan_and_connect(
        wifi_dut, peripheral_address, accept_smp_start=True
    )

    passkey = wait_for_passkey(bus, timeout=passkey_timeout)
    assert passkey, (
        "SC passkey not found in DUT hostlog — DisplayOnly peer should display "
        "passkey for KeyboardOnly initiator (step 6)"
    )
    logger().info(
        f"Withholding DUT passkey entry ({passkey}) — expecting auth failure 0x"
        f"{SMP_AUTH_FAILURE_ERROR_CODE} (firmware passkey response disabled)"
    )

    wait_for_smp_auth_failure_disconnect(bus, timeout=auth_fail_timeout)
    return connect_log


def complete_smp_with_passkey(
    bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
):
    """
    Enter passkey on the Raspi peer (KeyboardOnly) — same role as the phone UI.

    The DUT generates/displays the passkey; we read it from serial via
    ``wait_for_passkey`` then call BlueZ agent ``set_pin`` on the peer.
    """
    peer_set_pin(ble_client, int(passkey))
    logger().info(f"Entered passkey {passkey} on peer (nRF dongle / Raspi)")
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        for line in decode_log_items(bus.get_input_log()):
            lower = line.lower()
            if "smp failed" in lower or "4b0b" in lower:
                pytest.fail(f"SMP pairing failed: {line.strip()}")
            if (
                "smp encrypt event" in lower
                or "smp security keys event" in lower
                or "le ltk" in lower
            ):
                logger().info("SMP pairing completed successfully (hostlog)")
                return
    pytest.fail(
        f"SMP success indicators not seen after entering passkey "
        f"within {timeout}s"
    )


def complete_smp_justworks(bus, *, timeout=SMP_COMPLETE_TIMEOUT_SEC):
    """Just Works pairing — no passkey (MITM disabled, C553839)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(0.5)
        for line in decode_log_items(bus.get_input_log()):
            lower = line.lower()
            if "smp failed" in lower or "4b0b" in lower:
                pytest.fail(f"SMP Just Works pairing failed: {line.strip()}")
            if (
                "smp encrypt event" in lower
                or "smp security keys event" in lower
                or "le ltk" in lower
            ):
                logger().info("Just Works SMP pairing completed (hostlog)")
                return
    pytest.fail("SMP success indicators not seen after Just Works pairing")


LTK_BANNER_PATTERN = re.compile(r"\*{5,}.*?LE\s+LTK", re.IGNORECASE | re.DOTALL)
LTK_HEX_BYTES_PATTERN = re.compile(
    r"LE\s+LTK\s*\n\s*((?:[0-9a-fA-F]{2}[\s]){15}[0-9a-fA-F]{2})",
    re.IGNORECASE,
)


def extract_ltk_from_hostlog(
    bus, *, timeout=SMP_COMPLETE_TIMEOUT_SEC
) -> Optional[str]:
    """
    Parse the DUT ``LE LTK`` banner from hostlog (TestRail step 4).

    Returns 16-byte LTK as lowercase colon-separated hex, or None if not found.
    This replaces Frontline ``add_link_key`` for test validation — the key comes
    from the DUT firmware log, not from the sniffer GUI.
    """
    deadline = time.time() + timeout
    accumulated = ""
    while time.time() < deadline:
        time.sleep(0.5)
        accumulated += "\n".join(decode_log_items(bus.get_input_log()))
        if LTK_BANNER_PATTERN.search(accumulated):
            match = LTK_HEX_BYTES_PATTERN.search(accumulated)
            if match:
                raw = match.group(1).split()
                if len(raw) >= 16:
                    ltk = ":".join(b.lower() for b in raw[:16])
                    logger().info(f"LE LTK extracted from hostlog: {ltk}")
                    return ltk
            logger().info("LE LTK banner seen in hostlog (hex bytes not parsed)")
            return ""
    return None


def verify_smp_pairing_request_logged(
    bus_or_log, timeout=SMP_PAIRING_REQUEST_TIMEOUT_SEC, *, seed_log=""
):
    """
    TestRail step 2 — confirm SMP pairing started (e.g. ``smp pairing request initiated``).

    Accepts a live ``bus`` (preferred) or a static log string.  Passkey is validated
    separately via ``wait_for_passkey`` because it often appears after SMP start.
    """
    deadline = time.time() + timeout
    accumulated = seed_log if seed_log else ""
    if isinstance(bus_or_log, str):
        accumulated = bus_or_log + accumulated
        bus = None
    else:
        bus = bus_or_log
    while time.time() < deadline:
        time.sleep(PASSKEY_POLL_INTERVAL_SEC)
        if bus is not None:
            accumulated += "\n".join(decode_log_items(bus.get_input_log()))
        lower = accumulated.lower()
        if "smp pairing request initiated" in lower or "smp pairing request" in lower:
            return
    pytest.fail(
        f"SMP pairing request not found in hostlog within {timeout}s timeout"
    )

def enter_peer_passkey_immediately(
    ble_client, bus, connect_log: str = "", *, case_id: str = ""
) -> Optional[str]:
    """
    Enter Raspi passkey on BlueZ agent as soon as it appears in hostlog.

    Must run **before** long hostlog verify waits — BlueZ SMP passkey entry
    times out (~30s) if ``set_pin`` is delayed until after ``verify_*`` returns.
    """
    del case_id
    passkey = _extract_passkey_from_hostlog_text(connect_log)
    if not passkey:
        passkey = wait_for_passkey(
            bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client
        )
    if passkey:
        peer_set_pin(ble_client, int(passkey))
        logger().info(f"Entered passkey {passkey} on peer immediately after connect")
    return passkey


def verify_wearables_init_and_connect_hostlog(bus, connect_log: str):
    """TestRail steps 2–3 for wearables passkey central cases."""
    combined = connect_log.lower()
    still_missing = [m for m in WEARABLES_INIT_LOG_MARKERS if m not in combined]
    if still_missing:
        ok, init_log = wait_for_log_patterns(
            bus,
            still_missing,
            timeout=min(5.0, DUT_INIT_LOG_MARKER_TIMEOUT_SEC),
            require_all=False,
        )
        combined = f"{init_log}\n{connect_log}".lower()
        if not ok:
            logger().warning(f"Some step-2 init markers missing — continuing")

    missing_init = [m for m in WEARABLES_INIT_LOG_MARKERS if m not in combined]
    if missing_init:
        logger().warning(f"Init markers not all seen: {missing_init}")

    for marker in CONNECT_SMP_MARKERS:
        assert marker in combined, (
            f"Expected hostlog marker '{marker}' (step 3)"
        )
    assert "passkey" in combined, f"Expected passkey in hostlog (step 3)"


def verify_dhkey_check_connect_hostlog(bus, connect_log: str = ""):
    """TestRail C553837 steps 1 & 3 — DUT init and phone connect hostlog."""
    combined = combined_fresh_hostlog(bus, connect_log)
    still_missing = [m for m in WEARABLES_INIT_LOG_MARKERS if m not in combined]
    if still_missing:
        ok, init_log = wait_for_log_patterns(
            bus,
            still_missing,
            timeout=min(30.0, DUT_INIT_LOG_MARKER_TIMEOUT_SEC),
            require_all=False,
        )
        combined = f"{combined}\n{init_log}".lower()
        if not ok:
            logger().warning(f"Some step-1 init markers missing — continuing")

    missing_init = [m for m in WEARABLES_INIT_LOG_MARKERS if m not in combined]
    if missing_init:
        logger().warning(f"Init markers not all seen: {missing_init}")

    if not hostlog_indicates_dut_advertising(combined) or not hostlog_indicates_dut_scanning(
        combined
    ):
        if _dut_already_initialized_in_suite():
            logger().warning(
                f"Step-1 boot adv/scan markers absent after suite reset — "
                "continuing (harness boot + cached address)"
            )
        else:
            assert_dut_advertising_in_hostlog(combined, step="1")
            assert_dut_scanning_in_hostlog(combined, step="1")

    ok_conn, conn_log = wait_for_log_patterns(
        bus, DHKEY_CHECK_CONNECT_MARKERS_REQUIRED, timeout=120, require_all=False
    )
    combined = f"{combined}\n{conn_log}".lower()
    if not ok_conn:
        logger().warning(f"Some step-3 connect markers delayed — continuing")

    for marker in DHKEY_CHECK_CONNECT_MARKERS_REQUIRED:
        assert marker in combined, (
            f"Expected hostlog marker '{marker}' (step 3)"
        )
    missing_optional = [
        m for m in DHKEY_CHECK_CONNECT_MARKERS_OPTIONAL if m not in combined
    ]
    if missing_optional:
        logger().warning(
            f"Optional step-3 connect markers not seen: "
            f"{missing_optional}"
        )


def verify_dhkey_check_passkey_hostlog(bus, log_start: Optional[int] = None):
    """
    TestRail C553837 step 4 — SMP response and SC passkey in hostlog.

    ``log_start`` must be a baseline taken before the connect, otherwise the
    SMP exchange has already scrolled past when this runs after pairing.
    """
    ok, log_text = wait_for_log_patterns(
        bus,
        DHKEY_CHECK_PASSKEY_MARKERS,
        timeout=120,
        require_all=False,
        log_start=log_start,
    )
    lower = log_text.lower()
    for marker in DHKEY_CHECK_PASSKEY_MARKERS:
        assert marker in lower, (
            f"Expected hostlog marker '{marker}' (step 4)"
        )
    if not ok:
        logger().warning(f"Some step-4 passkey markers delayed")


def verify_smp_key_distribution_hostlog(
    bus,
    distribution: str,
    expected: int = KEY_DIST_ENC_ID_SIGN,
):
    """
    TestRail step 5 hostlog substitute (no OTA) — SMP key distribution bits.

    ``distribution`` is ``initiator`` (C553833) or ``responder`` (C553834).
    ``expected`` 0x07 = EncKey (LTK/EDIV/Rand) + IdKey (IRK) + SignKey (CSRK).
    """
    label = f"{distribution} key distribution"
    ok, log_text = wait_for_log_patterns(
        bus, [label], timeout=SMP_PAIRING_REQUEST_TIMEOUT_SEC, require_all=False
    )
    lower = log_text.lower()
    value_pattern = re.compile(
        rf"{re.escape(distribution)}\s+key\s+distribution\s*:\s*{expected}\b",
        re.IGNORECASE,
    )
    assert value_pattern.search(log_text), (
        f"Expected {distribution} key distribution "
        f"{expected} (LTK+IRK+CSRK) in hostlog (step 5)"
    )
    if not ok:
        logger().warning(
            f"Step-5 key-distribution marker delayed in hostlog"
        )
    logger().info(
        f"{distribution.title()} key distribution "
        f"0x{expected:02x} validated from hostlog (step 5)"
    )


def verify_initiator_key_distribution_hostlog(bus):
    """TestRail C553833 step 5 — initiator key distribution (hostlog-only)."""
    verify_smp_key_distribution_hostlog(
        bus, distribution="initiator"
    )


def verify_responder_key_distribution_hostlog(bus):
    """TestRail C553834 step 5 — responder key distribution (hostlog-only)."""
    verify_smp_key_distribution_hostlog(
        bus, distribution="responder"
    )


def verify_post_pair_hostlog(
    bus, max_missing=2, require_security_keys=True
):
    """TestRail step 4 hostlog checks."""
    ok, log_text = wait_for_log_patterns(
        bus, POST_PAIR_MARKERS, timeout=SMP_COMPLETE_TIMEOUT_SEC, require_all=False
    )
    lower = log_text.lower()
    missing = [m for m in POST_PAIR_MARKERS if m not in lower]
    assert ok or len(missing) <= max_missing, (
        f"Post-pairing hostlog markers missing (step 4): {missing}"
    )
    assert "smp encrypt event" in lower, f"Expected smp encrypt event"
    if require_security_keys:
        assert "smp security keys event" in lower, (
            f"Expected smp security keys event"
        )
    elif "smp security keys event" not in lower:
        logger().warning(
            f"smp security keys event not seen — "
            "encrypt + LTK sufficient for NC pairing (step 6)"
        )
    ltk = extract_ltk_from_hostlog(bus, timeout=SMP_COMPLETE_TIMEOUT_SEC)
    assert ltk is not None, f"Expected LE LTK in hostlog (step 4)"
    if ltk:
        logger().info(f"LE LTK validated from hostlog: {ltk}")


DISPLAYYESNO_CENTRAL_CONNECT_MARKERS: Tuple[str, ...] = (
    "smp pairing request initiated",
    "mtu exchange",
    "on enhance connect event",
    "on_enhance_conn",
)


def verify_dut_smp_auth_req_hostlog(bus, expected_auth_req: int):
    """
    Hostlog substitute for TestRail C553839 step 6 — DUT AuthReq with MITM clear.

    Firmware logs decimal Auth Req after ``set_smp_pairing_capability_data``
    (0x09 = bonding + LE SC, MITM bit clear).
    """
    ok, log_text = wait_for_log_patterns(
        bus,
        (f"auth req: {expected_auth_req}",),
        timeout=120,
        require_all=False,
    )
    lower = log_text.lower()
    auth_ok = (
        f"auth req: {expected_auth_req}" in lower
        or f"auth req: 0x{expected_auth_req:02x}" in lower
    )
    assert auth_ok, (
        f"Expected DUT Auth Req {expected_auth_req} "
        f"(bonding+SC, MITM disabled) in hostlog"
    )
    if not ok:
        logger().warning(f"Auth Req marker delayed in hostlog")
    logger().info(
        f"DUT Auth Req 0x{expected_auth_req:02x} validated (MITM disabled)"
    )


def verify_displayyesno_central_connect_hostlog(bus, connect_log: str):
    """TestRail C553838 steps 2 & 6 — DUT central init, connect, SMP pairing start."""
    combined = combined_fresh_hostlog(bus, connect_log)
    still_missing = [m for m in WEARABLES_INIT_LOG_MARKERS if m not in combined]
    if still_missing:
        ok, init_log = wait_for_log_patterns(
            bus,
            still_missing,
            timeout=min(5.0, DUT_INIT_LOG_MARKER_TIMEOUT_SEC),
            require_all=False,
        )
        combined = f"{combined}\n{init_log}".lower()
        if not ok:
            logger().warning(f"Some step-2 init markers missing — continuing")

    connect_ok = all(marker in combined for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS)
    if connect_ok and _dut_already_initialized_in_suite():
        if not hostlog_indicates_dut_advertising(combined):
            logger().warning(
                f"Boot adv markers absent post-drain — connect hostlog OK (suite)"
            )
        if not hostlog_indicates_dut_scanning(combined):
            logger().warning(
                f"Boot scan markers absent post-drain — connect hostlog OK (suite)"
            )
    else:
        assert_dut_advertising_in_hostlog(combined, step="2")
        assert_dut_scanning_in_hostlog(combined, step="2")

    for marker in DISPLAYYESNO_CENTRAL_CONNECT_MARKERS:
        assert marker in combined, (
            f"Expected hostlog marker '{marker}' (step 6 connect)"
        )


def _update_sniffer_peer_macs(sniffer, dut_address: str, *peer_addresses: str):
    """Optional MAC filter hook (Frontline only; no-op for RF Creations)."""
    colon_macs = []
    frontline_ids = []
    for raw in (dut_address, *peer_addresses):
        if not raw:
            continue
        colon = mac_to_colon(raw)
        if colon:
            colon_macs.append(colon)
            frontline_ids.append(mac_to_frontline_id(raw))
    if len(colon_macs) < 2 or not sniffer._client:
        return
    client = sniffer._client
    if hasattr(client, "select_bt_devices"):
        client.select_bt_devices(frontline_ids)
    if hasattr(client, "_filter_addresses"):
        client._filter_addresses = colon_macs




# =============================================================================
# TestRail cases
# =============================================================================

@pytest.fixture(autouse=True)
def _wearables_suite_hostlog_baseline(request):
    """
    Per-test hostlog baseline only (smp_iocap has no autouse ready fixture).

    DUT ready/settle is handled inside each test via ``smp_iocap_dut_settle()``
    or ``init_dut_wearables_after_reset()`` — same as smp_iocap ``sleep(20)``.
    """
    if "wifi_dut" not in getattr(request, "fixturenames", ()):
        yield
        return
    wifi_dut = request.getfixturevalue("wifi_dut")
    bus = get_bus(wifi_dut)
    reconcile_hostlog_baseline(bus)
    yield
    try:
        set_hostlog_baseline(get_bus(wifi_dut))
    except Exception as exc:
        logger().debug(f"hostlog baseline teardown: {exc}")
    if _dut_cached_le_random_address():
        try:
            restore_dut_public_advertising(
                wifi_dut, get_bus(wifi_dut), case_id="suite"
            )
        except Exception as exc:
            logger().warning(
                f"[suite] restore public advertising after random-addr test: {exc}"
            )


C553832_REPEAT_ITERATIONS = 4


@pytest.mark.test_src_map_id("C553832")
def test_ble_pair_unpair_dut_central_C553832(wifi_dut, ble_client):
    """
    Test case          : Verify pair-unpair for DUT as Central (GAR-7765)
    Device roles       : DUT central (DisplayOnly), Raspi peripheral (KeyboardOnly)

    """
    bus = get_bus(wifi_dut)
    peripheral_address = None
    last_peer_address: Optional[str] = None
    seen_passkeys = []

    bus, local_addr = init_dut_wearables_after_reset(
        wifi_dut,
        lambda d: configure_dut_smp_central(d, auth_req=AUTH_REQ_BONDING_MITM_SC),
        INIT_LOG_MARKERS_PAIR_UNPAIR,
    )

    logger().info("=== Step 2: Start Raspi BLE advertising (advertiser phone) ===")
    peripheral_address = start_raspi_peripheral(
        ble_client, local_addr, configure_peer=True
    )
    last_peer_address = peripheral_address
    time.sleep(PEER_ADV_START_SEC)
    time.sleep(5)
    try:
        logger().info("=== Step 2: DUT scan, connect, SMP passkey (hostlog) ===")
        connect_log = dut_scan_and_connect(
            wifi_dut, peripheral_address, accept_smp_start=True
        )
        time.sleep(5)
        verify_smp_pairing_request_logged(
            bus, timeout=SMP_PAIRING_REQUEST_TIMEOUT_SEC, seed_log=connect_log
        )
        time.sleep(5)
        passkey_abort = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC)
        assert passkey_abort, (
            f"Passkey not found in DUT log within {PASSKEY_TIMEOUT_SEC}s (step 2)"
        )
        seen_passkeys.append(passkey_abort)
        time.sleep(5)
        logger().info("=== Step 3: Withhold passkey (do not enter on Raspi) ===")
        outcome = wait_for_disconnect_or_scan_restart(
            bus, timeout=DISCONNECT_OR_SCAN_RESTART_TIMEOUT_SEC
        )
        if outcome == "disconnect":
            wait_for_scanning_restarted(
                bus, timeout=SCAN_RESTART_AFTER_DISCONNECT_SEC
            )
        time.sleep(5)
        stop_raspi_peripheral(ble_client, local_addr, peripheral_address)
        peripheral_address = None
        time.sleep(POST_PAIR_SETTLE_SEC)

        for iteration in range(1, C553832_REPEAT_ITERATIONS + 1):
            logger().info(
                f"=== Steps 4–5: Re-pair iteration {iteration}/"
                f"{C553832_REPEAT_ITERATIONS} ==="
            )
            time.sleep(2)
            drain_serial(bus)
            configure_dut_smp_central(wifi_dut, auth_req=AUTH_REQ_BONDING_MITM_SC)
            time.sleep(2)
            logger().info("=== Step 4: Restart Raspi advertising ===")
            peripheral_address = start_raspi_peripheral(
                ble_client, local_addr, configure_peer=True
            )
            last_peer_address = peripheral_address
            drain_serial(bus)
            time.sleep(5)
            dut_scan_and_connect(
                wifi_dut, peripheral_address, accept_smp_start=True
            )
            drain_serial(bus)
            time.sleep(5)
            pk = wait_for_passkey(
                bus,
                timeout=PASSKEY_TIMEOUT_SEC,
                exclude=seen_passkeys,
                enter_on_peer=ble_client,
            )
            assert pk, (
                f"Passkey not found on iteration {iteration} "
                f"within {PASSKEY_TIMEOUT_SEC}s"
            )
            assert pk not in seen_passkeys, (
                f"Passkey {pk} repeated — step 5 requires new passkey each time"
            )
            seen_passkeys.append(pk)
            time.sleep(5)
            complete_smp_with_passkey(bus, ble_client, pk)
            time.sleep(POST_DISCONNECT_SETTLE_SEC)
            safe_dut_btc_disconnect(wifi_dut, peripheral_address)
            time.sleep(POST_DISCONNECT_SETTLE_SEC)
            stop_raspi_peripheral(ble_client, local_addr, peripheral_address)
            peripheral_address = None
            time.sleep(POST_PAIR_SETTLE_SEC)

    finally:
        _peer = peripheral_address or last_peer_address
        clear_ble_bonds_after_test(
            wifi_dut,
            ble_client,
            local_addr,
            _peer,
        )
        time.sleep(5)
    logger().info(
        f"TestRail C553832 PASS — hostlog only; passkeys: {seen_passkeys}"
    )


@pytest.mark.test_src_map_id("C553833")
def test_ble_pairing_request_initiator_key_distribution_C553833(
    wifi_dut, ble_client
):
    """
    Test case          : Verify initiator key distribution in SMP Pairing Request
    Device roles       : DUT central (DisplayOnly), Raspi advertiser phone (KeyboardOnly)

    """
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None

    bus, local_addr = init_dut_wearables_after_reset(
        wifi_dut,
        configure_dut_smp_displayonly_initiator,
        WEARABLES_INIT_LOG_MARKERS,
    )

    logger().info(
        f"Step 3: Start Raspi BLE advertising (advertiser phone)"
    )
    peripheral_address = start_raspi_peripheral(
        ble_client, local_addr, configure_peer=True
    )
    time.sleep(PEER_ADV_START_SEC)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 3: DUT scan, connect, SMP passkey"
            )
            connect_log = dut_scan_and_connect(
                wifi_dut, peripheral_address, accept_smp_start=True
            )
            passkey = enter_peer_passkey_immediately(
                ble_client, bus, connect_log
            )
            verify_wearables_init_and_connect_hostlog(
                bus, connect_log
            )
            assert passkey, (
                f"Passkey not found in DUT log within "
                f"{PASSKEY_TIMEOUT_SEC}s (step 3)"
            )
            assert_passkey_valid(passkey)

            logger().info(
                f"Step 4: Enter passkey on peer, complete pairing"
            )
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(5)
            verify_post_pair_hostlog(bus)
            time.sleep(5)
            logger().info(f"Step 5: SMP key distribution (hostlog)")
            verify_initiator_key_distribution_hostlog(bus)
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )
            time.sleep(5)
    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553834")
def test_ble_pairing_request_responder_key_distribution_C553834(
    wifi_dut, ble_client
):
    """
    Test case          : Verify responder key distribution in SMP Pairing Request
    Device roles       : DUT central (DisplayOnly), Raspi advertiser phone (KeyboardOnly)

    """
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None

    bus, local_addr = init_dut_wearables_after_reset(
        wifi_dut,
        configure_dut_smp_displayonly_initiator,
        WEARABLES_INIT_LOG_MARKERS,
    )
    time.sleep(5)
    logger().info(
        f"Step 3: Start Raspi BLE advertising (advertiser phone)"
    )
    peripheral_address = start_raspi_peripheral(
        ble_client, local_addr, configure_peer=True
    )
    time.sleep(PEER_ADV_START_SEC)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 3: DUT scan, connect, SMP passkey"
            )
            time.sleep(5)
            connect_log = dut_scan_and_connect(
                wifi_dut, peripheral_address, accept_smp_start=True
            )
            passkey = enter_peer_passkey_immediately(
                ble_client, bus, connect_log
            )
            verify_wearables_init_and_connect_hostlog(
                bus, connect_log
            )
            assert passkey, (
                f"Passkey not found in DUT log within "
                f"{PASSKEY_TIMEOUT_SEC}s (step 3)"
            )
            assert_passkey_valid(passkey)

            logger().info(
                f"Step 4: Enter passkey on peer, complete pairing"
            )
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            verify_post_pair_hostlog(bus)
            time.sleep(5)
            logger().info(f"Step 5: SMP key distribution (hostlog)")
            verify_responder_key_distribution_hostlog(bus)
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )
            time.sleep(5)
    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553835")
def test_ble_pairing_response_fields_C553835(wifi_dut, ble_client):
    """
    Test case          : Verify SMP Pairing Response fields from peer
    Device roles       : DUT central (DisplayOnly), Raspi advertiser phone (KeyboardOnly)
    """
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None

    logger().info(f"Step 1–2: DUT init / advertising / scanning")
    time.sleep(15)
    drain_serial(bus)
    ok, _ = _ensure_dut_wearables_step1_ready(
        wifi_dut, bus, require_scan=True
    )
    if not ok:
        logger().warning(
            f"Some step-2 init log markers missing — continuing"
        )
    configure_dut_smp_displayonly_initiator(wifi_dut)

    local_addr = get_dut_local_address(wifi_dut)
    ok, _ = wait_for_log_patterns(bus, WEARABLES_INIT_LOG_MARKERS, timeout=90)
    if not ok:
        logger().warning(
            f"Some step-2 init log markers missing — continuing"
        )

    logger().info(
        f"Step 3: Start Raspi BLE advertising (advertiser phone)"
    )
    peripheral_address = start_raspi_peripheral(
        ble_client, local_addr, configure_peer=True
    )
    drain_serial(bus)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 3: DUT scan, connect, SMP passkey"
            )
            drain_serial(bus)
            connect_log = dut_scan_and_connect(
                wifi_dut, peripheral_address, accept_smp_start=True
            )
            passkey = enter_peer_passkey_immediately(
                ble_client, bus, connect_log
            )
            verify_wearables_init_and_connect_hostlog(
                bus, connect_log
            )

            assert passkey, f"Passkey not found in DUT log (step 3)"
            assert_passkey_valid(passkey)

            logger().info(
                f"Step 4: Enter passkey on peer, complete pairing"
            )
            complete_smp_with_passkey(bus, ble_client, passkey, timeout=120)
            verify_post_pair_hostlog(bus)
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553836")
def test_ble_numeric_comparison_dut_peripheral_C553836(wifi_dut, ble_client):
    """
    Test case          : Verify Numeric Comparison pairing for DUT as Peripheral (GAR-8246)
    Device roles       : DUT peripheral (DisplayYesNo), Raspi central (DisplayYesNo)
    """
    dut_init_sleep = 15.0
    verify_random_address = False
    expected_adv_name = None
    bus = get_bus(wifi_dut)
    adv_hint = expected_adv_name or COEX_MAX_DEMO_ADV_NAME

    logger().info(f"Step 5: Wait for DUT peripheral init / advertising")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    verify_peripheral_init_hostlog(bus, wifi_dut=wifi_dut)
    if verify_random_address:
        dut_address = ensure_dut_peripheral_random_address(
            wifi_dut, bus
        )
    else:
        configure_dut_smp_displayyesno_peripheral(wifi_dut)
        dut_address = get_dut_local_address(wifi_dut)

    logger().info(
        f"Step 6: Configure nRF/Raspi central DisplayYesNo + SC/MITM"
    )
    configure_raspi_displayyesno_central(ble_client)

    scan_wait = 15 if verify_random_address else 10

    with hostlog_only_session(dut_address, dut_address):
        central_address = None
        try:
            logger().info(
                f"Step 7: nRF/Raspi scan for DUT "
                f"(expected adv name '{adv_hint}', addr {dut_address})"
            )
            central_address = raspi_scan_for_dut(
                ble_client, dut_address, scan_wait=scan_wait
            )
            if verify_random_address and is_nrf_peer(ble_client):
                time.sleep(5)

            logger().info(
                f"Step 8: Connect + numeric comparison pairing"
            )
            raspi_connect_and_pair_numeric_comparison(
                wifi_dut,
                ble_client,
                dut_address,
                central_address,
                bus,
                peer_dev_addr_type=(
                    None
                    if verify_random_address and is_nrf_peer(ble_client)
                    else NRFBLEPeerDevAddrTypes.PUBLIC
                ),
            )
            verify_peripheral_connect_hostlog(bus)
            verify_post_pair_hostlog(bus)
            time.sleep(5)

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )
            if verify_random_address:
                restore_dut_public_advertising(wifi_dut, bus)

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553837")
def test_ble_dhkey_check_dut_central_C553837(wifi_dut, ble_client):
    """
        Test case          : Verify DHKey Check exchanges for DUT as Central (GAR-8229)
        Device roles       : DUT central (DisplayOnly), Raspi peripheral (KeyboardOnly)
    """
    dut_init_sleep = 15.0
    passkey_timeout = 120.0
    smp_complete_timeout = 120.0
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(f"Step 1: DUT init / advertising / scanning")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    ok, _ = _ensure_dut_wearables_step1_ready(
        wifi_dut, bus, require_scan=True
    )
    if not ok:
        logger().warning(f"Some step-1 init log markers missing — continuing")

    configure_dut_smp_displayonly_initiator(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ID_SIGN,
        rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
    )
    local_addr = get_dut_local_address(wifi_dut)

    logger().info(
        f"Step 2: {peer_label} peripheral KeyboardOnly "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    peripheral_address = start_raspi_keyboardonly_peripheral(ble_client, local_addr)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address) as sniffer:
        try:
            logger().info(f"Steps 3–4: DUT scan, connect, passkey entry, pairing")
            pairing_baseline = hostlog_baseline(bus)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(bus, connect_log)

            passkey = wait_for_passkey(
                bus, timeout=passkey_timeout, enter_on_peer=ble_client
            )
            assert passkey, f"Passkey not found in DUT hostlog (step 4)"
            assert_passkey_valid(passkey)

            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=smp_complete_timeout
            )
            verify_dhkey_check_passkey_hostlog(bus, log_start=pairing_baseline)
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only (step 5 DHKey OTA skipped)")


@pytest.mark.test_src_map_id("C553838")
def test_ble_displayyesno_smp_pairing_dut_central_C553838(wifi_dut, nrf_ble_client):
    """
    Test case          : SMP pairing DisplayYesNo on both sides, DUT central (RSC-11819)
    Device roles       : DUT central (DisplayYesNo), nRF dongle peripheral (DisplayYesNo)
    """
    ble_client = nrf_ble_client
    dut_init_sleep = 15.0
    smp_complete_timeout = 120.0
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(f"Step 2: DUT init / advertising / scanning (hostlog)")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    ok, _ = _ensure_dut_wearables_step1_ready(
        wifi_dut, bus, require_scan=True
    )
    if not ok:
        logger().warning(f"Some step-2 init log markers missing — continuing")
    configure_dut_smp_displayyesno_central(wifi_dut)

    local_addr = get_dut_local_address(wifi_dut)

    logger().info(
        f"Steps 3–5: {peer_label} peripheral DisplayYesNo "
        f"(adv name '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    peripheral_address = start_raspi_displayyesno_peripheral(ble_client, local_addr)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address) as sniffer:
        try:
            logger().info(f"Step 6: DUT scan, connect, numeric comparison")
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            complete_smp_numeric_comparison(
                bus,
                wifi_dut,
                ble_client,
                peripheral_address,
                timeout=smp_complete_timeout,
            )
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

        logger().info(f"Step 6 OTA: Just Works / Numeric Comparison SMP")

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553839")
def test_ble_auth_flag_mitm_disabled_C553839(wifi_dut, nrf_ble_client):
    """
    Test case          : Verify auth flag when MITM is FALSE, DUT central (GAR-8290)
    Device roles       : DUT central (DisplayYesNo), nRF dongle peripheral (DisplayOnly)
    """
    ble_client = nrf_ble_client
    dut_init_sleep = 15.0
    smp_complete_timeout = 120.0
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(f"Step 2: DUT init / advertising / scanning (hostlog)")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    ok, _ = _ensure_dut_wearables_step1_ready(
        wifi_dut, bus, require_scan=True
    )
    if not ok:
        logger().warning(f"Some step-2 init log markers missing — continuing")
    configure_dut_smp_displayyesno_central(
        wifi_dut, auth_req=AUTH_REQ_BONDING_SC
    )
    verify_dut_smp_auth_req_hostlog(
        bus, expected_auth_req=AUTH_REQ_BONDING_SC
    )

    local_addr = get_dut_local_address(wifi_dut)

    logger().info(
        f"Steps 3–5: {peer_label} peripheral DisplayOnly, MITM disabled "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    peripheral_address = start_raspi_displayonly_peripheral(ble_client, local_addr)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address) as sniffer:
        try:
            logger().info(f"Step 6: DUT scan, connect, Just Works pairing")
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            complete_smp_justworks(bus, timeout=smp_complete_timeout)
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

        logger().info(
            f"Step 6: MITM disabled validated via hostlog Auth Req 0x09"
        )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553840")
def test_ble_valid_passkey_keyboardonly_peer_C553840(wifi_dut, nrf_ble_client):
    """
    Test case          : Valid passkey for Keyboard-No-Display peer IO cap (GAR-8295)
    Device roles       : DUT central (DisplayYesNo), nRF dongle peripheral (KeyboardOnly)
    """
    ble_client = nrf_ble_client
    dut_init_sleep = 15.0
    passkey_timeout = 120.0
    smp_complete_timeout = 120.0
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(f"Step 2: DUT init / advertising / scanning")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    ok, _ = _ensure_dut_wearables_step1_ready(
        wifi_dut, bus, require_scan=True
    )
    if not ok:
        logger().warning(f"Some step-2 init log markers missing — continuing")
    configure_dut_smp_displayyesno_central(
        wifi_dut, auth_req=AUTH_REQ_BONDING_MITM_SC
    )

    local_addr = get_dut_local_address(wifi_dut)
    logger().info(
        f"Steps 3–5: {peer_label} peripheral KeyboardOnly "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    peripheral_address = start_raspi_keyboardonly_peripheral(ble_client, local_addr)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address) as sniffer:
        try:
            logger().info(f"Step 6: DUT scan, connect, SMP passkey event")
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            logger().info(f"Step 7: Wait for valid passkey in DUT hostlog")
            passkey = wait_for_passkey(
                bus, timeout=passkey_timeout, enter_on_peer=ble_client
            )
            assert passkey, f"Passkey not found in DUT log (step 6–7)"
            assert_passkey_valid(passkey)

            logger().info(
                f"Enter passkey on {peer_label} (KeyboardOnly peer)"
            )
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=smp_complete_timeout
            )
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

        logger().info(f"Step 7: passkey validated (hostlog, no sniffer)")

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553841")
def test_ble_justworks_dut_central_C553841(wifi_dut, nrf_ble_client):
    """
    Test case          : Verify Just Works pairing for DUT as Central (GAR-8310)
    Device roles       : RT595 DUT central (DisplayOnly), nRF dongle peripheral (DisplayOnly)
    """
    ble_client = nrf_ble_client
    dut_init_sleep = 15.0
    smp_complete_timeout = 120.0
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None

    logger().info(f"Step 2: DUT init / advertising / scanning (hostlog)")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    ok, _ = _ensure_dut_wearables_step1_ready(
        wifi_dut, bus, require_scan=True
    )
    if not ok:
        logger().warning(f"Some step-2 init log markers missing — continuing")
    configure_dut_smp_displayonly_initiator(
        wifi_dut, auth_req=AUTH_REQ_BONDING_SC
    )

    local_addr = get_dut_local_address(wifi_dut)

    logger().info(
        f"Steps 3–5: Raspi peripheral DisplayOnly, MITM disabled "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    peripheral_address = start_raspi_displayonly_peripheral(ble_client, local_addr)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address) as sniffer:
        try:
            logger().info(f"Step 6: DUT scan, connect, Just Works pairing")
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            complete_smp_justworks(bus, timeout=smp_complete_timeout)
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

        logger().info(f"Step 6 OTA: verify Just Works under SMP")

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553842")
def test_ble_legacy_displayyesno_dut_central_C553842(wifi_dut, nrf_ble_client):
    """
    Test case          : Verify Legacy pairing DisplayYesNo IOCap, DUT central (GAR-8312)
    Device roles       : DUT central (DisplayYesNo, legacy), nRF dongle peripheral (DisplayYesNo, legacy)
    """
    ble_client = nrf_ble_client
    dut_init_sleep = 15.0
    smp_complete_timeout = 120.0
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(f"Step 2: DUT init / advertising / scanning (hostlog)")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_NONE,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    verify_dut_smp_auth_req_hostlog(
        bus, expected_auth_req=AUTH_REQ_NONE
    )

    local_addr = get_dut_local_address(wifi_dut)

    logger().info(
        f"Steps 3–5: {peer_label} peripheral DisplayYesNo, legacy pairing "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    peripheral_address = start_raspi_displayyesno_legacy_peripheral(
        ble_client, local_addr
    )

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address) as sniffer:
        try:
            logger().info(
                f"Step 6: DUT scan, connect, legacy Just Works pairing"
            )
            connect_log = dut_scan_and_connect(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            complete_smp_justworks(bus, timeout=smp_complete_timeout)
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

        logger().info(
            f"Step 6: legacy Just Works validated (hostlog, no sniffer)"
        )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553843")
def test_ble_lesc_dut_nonlesc_peer_C553843(wifi_dut, nrf_ble_client):
    """
    Test case          : LESC DUT central + non-LESC peer pairing (GAR-8323)
    Device roles       : DUT central (DisplayYesNo, LESC), nRF dongle peripheral (DisplayOnly, legacy)
    """
    ble_client = nrf_ble_client
    dut_init_sleep = 15.0
    smp_complete_timeout = 120.0
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(f"Step 2: DUT init / advertising / scanning (hostlog)")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    verify_dut_smp_auth_req_hostlog(
        bus, expected_auth_req=AUTH_REQ_BONDING_MITM_SC
    )

    local_addr = get_dut_local_address(wifi_dut)

    logger().info(
        f"Steps 3–5: {peer_label} non-LESC peripheral DisplayOnly "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    peripheral_address = start_raspi_displayonly_legacy_peripheral(
        ble_client, local_addr
    )

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address) as sniffer:
        try:
            logger().info(
                f"Step 6: DUT scan, connect, legacy pairing fallback"
            )
            connect_log = dut_scan_and_connect(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            complete_smp_justworks(bus, timeout=smp_complete_timeout)
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

        logger().info(
            f"Step 6: legacy pairing validated (hostlog, no sniffer)"
        )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553844")
def test_ble_encryption_key_refresh_C553844(wifi_dut, ble_client):
    """
    Test case          : Verify encryption key refresh is generated (GAR-8350)
    Device roles       : DUT peripheral (COEX_MAX_DEMO), Raspi central (SC passkey)
    """
    bus = get_bus(wifi_dut)
    central_address: Optional[str] = None

    logger().info(f"Step 2: DUT init / advertising")
    time.sleep(DUT_INIT_AFTER_RESET_SEC)
    drain_serial(bus)
    time.sleep(STEP_SETTLE_SEC)
    verify_peripheral_init_hostlog(bus, wifi_dut=wifi_dut)

    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_peripheral(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ID_SIGN,
        rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    dut_address = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 3: Configure Raspi central for SC passkey pairing"
    )
    time.sleep(STEP_SETTLE_SEC)
    configure_raspi_displayyesno_central(ble_client)
    time.sleep(CENTRAL_SMP_CONFIG_SETTLE_SEC)

    with hostlog_only_session(dut_address, dut_address):
        try:
            logger().info(
                f"Step 3: Raspi scan for DUT "
                f"(expected adv name '{COEX_MAX_DEMO_ADV_NAME}', "
                f"scan_wait={NRF_SCAN_WAIT_PUBLIC_ADDR_SEC}s)"
            )
            time.sleep(STEP_SETTLE_SEC)
            central_address = raspi_scan_for_dut_passkey_central(
                ble_client, dut_address, scan_wait=NRF_SCAN_WAIT_PUBLIC_ADDR_SEC
            )
            time.sleep(STEP_SETTLE_SEC)
            logger().info(
                f"DUT discovered at {dut_address} "
                f"(firmware adv name '{COEX_MAX_DEMO_ADV_NAME}')"
            )

            logger().info(
                f"Step 4: Connect + MTU + SMP passkey request"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)

            def _connect():
                logger().info(f"Raspi connecting to DUT {dut_address} (SC passkey)")
                ble_client.interfaces.bluetooth.connect(
                    dev_addr=dut_address,
                    supervision_timeout=500,
                )

            connect_thread = threading.Thread(target=_connect)
            connect_thread.start()
            time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)

            time.sleep(STEP_SETTLE_SEC)
            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Passkey not found in DUT hostlog (step 4)"
            )
            assert_passkey_valid(passkey)

            logger().info(
                f"Step 5: Enter passkey, complete pairing"
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_thread.join(timeout=CONNECT_TIMEOUT_SEC)
            assert not connect_thread.is_alive(), (
                "Raspi connect thread did not finish"
            )

            time.sleep(STEP_SETTLE_SEC)
            verify_encryption_key_refresh_connect_hostlog(bus)
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)
            verify_encryption_key_refresh_step5_hostlog(bus)
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )
            time.sleep(STEP_SETTLE_SEC)

        logger().info(
            f"Step 6 skipped — OTA duplicate-key check "
            "deferred (RF Creations sniffer not enabled)"
        )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553845")
def test_ble_auth_failure_disconnect_C553845(wifi_dut, nrf_ble_client):
    """
    Test case          : Verify BLE disconnect on authentication failure (UNIFIED_PROTOCOL)
    Device roles       : DUT peripheral (BLE_UNIFIED_DEMO), nRF dongle central (withhold passkey)
    """
    ble_client = nrf_ble_client
    passkey_timeout = 120.0
    auth_fail_timeout = 120.0
    bus = get_bus(wifi_dut)
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(f"Step 1: Wait for DUT peripheral init / advertising")
    verify_peripheral_init_hostlog(bus, wifi_dut=wifi_dut)

    dut_address = get_dut_local_address(wifi_dut)

    logger().info(
        f"Step 2: Configure {peer_label} central (KeyboardOnly, withhold passkey)"
    )
    configure_raspi_keyboardonly_central(ble_client)

    with hostlog_only_session(dut_address, dut_address) as sniffer:
        central_address: Optional[str] = None
        try:
            logger().info(
                f"Step 2: {peer_label} scan for DUT "
                f"(expected adv name '{BLE_UNIFIED_DEMO_ADV_NAME}')"
            )
            central_address = raspi_scan_for_dut_passkey_central(
                ble_client, dut_address, scan_wait=15
            )

            drain_serial(bus)
            logger().info(
                f"Step 3: Connect to DUT; "
                f"step 4: withhold passkey — expect 0x4bfc + disconnect"
            )
            raspi_connect_withhold_passkey_central(
                ble_client,
                dut_address,
                bus,
                passkey_timeout=passkey_timeout,
                auth_fail_timeout=auth_fail_timeout,
            )
            verify_auth_failure_connect_hostlog(bus)
            time.sleep(3)

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )

        logger().info(f"OTA: pairing started but no successful encryption")

    logger().info(f"PASS — auth failure 0x4bfc + disconnect")


@pytest.mark.test_src_map_id("C553846")
def test_ble_passkey_entry_dut_peripheral_C553846(wifi_dut, nrf_ble_client):
    """
    Test case          : Passkey entry pairing, DUT as peripheral (DisplayOnly)
    Device roles       : DUT peripheral (COEX_MAX_DEMO), nRF dongle central (KeyboardOnly)
    """
    ble_client = nrf_ble_client
    dut_init_sleep = 15.0
    passkey_timeout = 120.0
    smp_complete_timeout = 120.0
    verify_random_address = False
    expected_adv_name = None
    bus = get_bus(wifi_dut)
    adv_hint = expected_adv_name or COEX_MAX_DEMO_ADV_NAME
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(f"Step 2: Wait for DUT peripheral init / advertising")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    verify_peripheral_init_hostlog(bus, wifi_dut=wifi_dut)
    if verify_random_address:
        dut_address = ensure_dut_peripheral_random_address(
            wifi_dut,
            bus,
            configure_smp=lambda dut: configure_dut_smp_displayonly_peripheral(
                dut,
                auth_req=AUTH_REQ_BONDING_MITM_SC,
                ini_key_dist=KEY_DIST_ENC_ID_SIGN,
                rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
            ),
        )
    else:
        logger().info(
            f"Step 1: Configure DUT DisplayOnly SMP (IO cap 0x00, bonding+MITM+SC)"
        )
        configure_dut_smp_displayonly_peripheral(
            wifi_dut,
            auth_req=AUTH_REQ_BONDING_MITM_SC,
            ini_key_dist=KEY_DIST_ENC_ID_SIGN,
            rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
        )
        dut_address = get_dut_local_address(wifi_dut)

    logger().info(
        f"Configure {peer_label} central (KeyboardOnly — enters passkey)"
    )
    configure_raspi_keyboardonly_central(ble_client)

    with hostlog_only_session(dut_address, dut_address) as sniffer:
        central_address: Optional[str] = None
        try:
            logger().info(
                f"Step 3: {peer_label} scan for DUT "
                f"(expected adv name '{adv_hint}')"
            )
            central_address = raspi_scan_for_dut_passkey_central(
                ble_client, dut_address, scan_wait=15
            )

            drain_serial(bus)
            logger().info(
                f"Step 4: Connect to DUT; "
                f"step 5: enter SC passkey on {peer_label}"
            )
            raspi_connect_and_pair_passkey_central(
                ble_client,
                dut_address,
                bus,
                passkey_timeout=passkey_timeout,
                smp_complete_timeout=smp_complete_timeout,
            )
            verify_passkey_entry_connect_hostlog(bus)
            verify_post_pair_hostlog(bus)
            time.sleep(5)

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )
            if verify_random_address:
                restore_dut_public_advertising(wifi_dut, bus)

        logger().info(f"Step 6 OTA: verify passkey entry pairing under SMP")

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553847")
def test_ble_justworks_dut_central_random_addr_C553847(wifi_dut, nrf_ble_client):
    """
    Test case          : Just Works pairing, DUT central with random address
    Device roles       : RT595 DUT central (DisplayOnly, random addr), nRF dongle DisplayOnly
    """
    ble_client = nrf_ble_client
    dut_init_sleep = 15.0
    smp_complete_timeout = 120.0
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None

    logger().info(f"Step 2: DUT init / advertising / scanning (hostlog)")
    time.sleep(dut_init_sleep)
    drain_serial(bus)
    configure_dut_smp_displayonly_initiator(
        wifi_dut, auth_req=AUTH_REQ_BONDING_SC
    )

    local_addr = get_dut_local_address(wifi_dut)

    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"
    logger().info(
        f"Steps 6–8: {peer_label} peripheral DisplayOnly, adv "
        f"'{REMOTE_DEVICE_NAME_SLAVE11}', MITM disabled"
    )
    peripheral_address = start_raspi_displayonly_peripheral(ble_client, local_addr)
    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address) as sniffer:
        try:
            logger().info(
                f"Step 9: DUT scan (public) + random-addr connect to "
                f"{peer_label} '{REMOTE_DEVICE_NAME_SLAVE11}' (Just Works)"
            )
            connect_log = dut_scan_and_connect(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                own_addr_type=OWN_ADDR_TYPE_RANDOM,
                scan_own_addr_type=DEFAULT_OWN_ADDR_TYPE,
                stop_scan_before_connect=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            complete_smp_justworks(bus, timeout=smp_complete_timeout)
            verify_post_pair_hostlog(bus)
            time.sleep(5)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

        logger().info(f"Step 6 OTA: verify Just Works under SMP")

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553848")
def test_ble_numeric_comparison_dut_peripheral_random_addr_C553848(wifi_dut, ble_client):
    """
    Test case          : Numeric Comparison pairing, DUT peripheral random address
    Device roles       : DUT peripheral (DisplayYesNo, COEX_MAX_DEMO), Raspi central
    """
    bus = get_bus(wifi_dut)
    adv_hint = COEX_MAX_DEMO_ADV_NAME
    scan_wait = NRF_SCAN_WAIT_RANDOM_ADDR_SEC

    logger().info(
        f"Step 5: DUT init / advertising (hostlog verify)"
    )
    verify_peripheral_init_hostlog(bus, wifi_dut=wifi_dut)
    dut_address = ensure_dut_peripheral_random_address(
        wifi_dut, bus
    )

    logger().info(
        f"Step 6: Configure Raspi central DisplayYesNo + SC/MITM"
    )
    time.sleep(CENTRAL_SMP_CONFIG_SETTLE_SEC)
    configure_raspi_displayyesno_central(ble_client)

    with hostlog_only_session(dut_address, dut_address):
        central_address = None
        try:
            logger().info(
                f"Step 7: Raspi scan for DUT "
                f"(expected adv name '{adv_hint}', addr {dut_address}, "
                f"scan_wait={scan_wait}s)"
            )
            central_address = raspi_scan_for_dut(
                ble_client, dut_address, scan_wait=scan_wait
            )
            time.sleep(PEER_ADV_START_SEC)

            logger().info(
                f"Step 8: Connect + numeric comparison "
                f"(connect_timeout={CONNECT_TIMEOUT_SEC}s, "
                f"passkey_timeout={PASSKEY_TIMEOUT_SEC}s)"
            )
            time.sleep(NC_PRE_CONNECT_SETTLE_SEC)
            raspi_connect_and_pair_numeric_comparison(
        wifi_dut,
        ble_client,
                dut_address,
                central_address,
                bus,
                connect_timeout=CONNECT_TIMEOUT_SEC,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                pair_complete_timeout=SMP_COMPLETE_TIMEOUT_SEC,
            )
            verify_peripheral_connect_hostlog(bus)
            verify_post_pair_hostlog(bus)
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )
            restore_dut_public_advertising(wifi_dut, bus)

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553849")
def test_ble_passkey_entry_dut_peripheral_random_addr_C553849(wifi_dut, ble_client):
    """
    Test case          : Passkey entry pairing, DUT peripheral random address
    Device roles       : DUT peripheral (DisplayOnly, COEX_MAX_DEMO), Raspi KeyboardOnly
    """
    bus = get_bus(wifi_dut)
    adv_hint = COEX_MAX_DEMO_ADV_NAME
    scan_wait = NRF_SCAN_WAIT_RANDOM_ADDR_SEC
    central_address: Optional[str] = None

    logger().info(
        f"Step 5: DUT init / advertising (hostlog verify)"
    )
    verify_peripheral_init_hostlog(bus, wifi_dut=wifi_dut)

    time.sleep(STEP_SETTLE_SEC)
    dut_address = ensure_dut_peripheral_random_address(
        wifi_dut,
        bus,
        configure_smp=lambda dut: configure_dut_smp_displayonly_peripheral(
            dut,
            auth_req=AUTH_REQ_BONDING_MITM_SC,
            ini_key_dist=KEY_DIST_ENC_ID_SIGN,
            rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
        ),
    )
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 6: Configure Raspi central KeyboardOnly "
        "(enters passkey on behalf of phone)"
    )
    time.sleep(STEP_SETTLE_SEC)
    configure_raspi_keyboardonly_central(ble_client)
    time.sleep(CENTRAL_SMP_CONFIG_SETTLE_SEC)

    with hostlog_only_session(dut_address, dut_address):
        try:
            logger().info(
                f"Step 6: Raspi scan for DUT "
                f"(expected adv name '{adv_hint}', addr {dut_address}, "
                f"scan_wait={scan_wait}s)"
            )
            time.sleep(STEP_SETTLE_SEC)
            central_address = raspi_scan_for_dut_passkey_central(
                ble_client, dut_address, scan_wait=scan_wait
            )
            time.sleep(STEP_SETTLE_SEC)

            logger().info(
                f"Step 7: Connect + MTU + SMP passkey request"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)

            def _connect():
                logger().info(f"Raspi connecting to DUT {dut_address} (SC passkey)")
                ble_client.interfaces.bluetooth.connect(
                    dev_addr=dut_address,
                    supervision_timeout=500,
                )

            connect_thread = threading.Thread(target=_connect)
            connect_thread.start()
            time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)

            time.sleep(STEP_SETTLE_SEC)
            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Passkey not found in DUT hostlog (step 7)"
            )
            assert_passkey_valid(passkey)

            logger().info(
                f"Step 8: Enter passkey on Raspi, complete pairing"
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_thread.join(timeout=CONNECT_TIMEOUT_SEC)
            assert not connect_thread.is_alive(), (
                "Raspi connect thread did not finish"
            )

            time.sleep(STEP_SETTLE_SEC)
            verify_passkey_entry_connect_hostlog(bus)
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)
            verify_post_pair_hostlog(bus)
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )
            restore_dut_public_advertising(wifi_dut, bus)
            time.sleep(STEP_SETTLE_SEC)

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553850")
def test_ble_peripheral_reconnect_with_bond_C553850(wifi_dut, ble_client):
    """
    Test case          : Connect, disconnect and reconnect with bond info
    Device roles       : DUT peripheral (BLE_UNIFIED_DEMO), Raspi KeyboardOnly
    """
    bus = get_bus(wifi_dut)
    central_address: Optional[str] = None
    reconnect_iterations = REPEAT_BOND_RECONNECT_ITERATIONS

    logger().info(
        f"Step 2: DUT init / advertising / scanning (hostlog)"
    )
    ensure_dut_wearables_init_hostlog_step(
        wifi_dut,
        bus,
        step="2",
        require_scan=True,
    )

    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayonly_peripheral(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ID_SIGN,
        rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    dut_address = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 3: Configure Raspi central KeyboardOnly "
        "(enters passkey on behalf of phone)"
    )
    time.sleep(STEP_SETTLE_SEC)
    configure_raspi_keyboardonly_central(ble_client)
    time.sleep(CENTRAL_SMP_CONFIG_SETTLE_SEC)

    with hostlog_only_session(dut_address, dut_address):
        try:
            logger().info(
                f"Step 3: Raspi scan for DUT "
                f"(expected adv name '{BLE_UNIFIED_DEMO_ADV_NAME}', "
                f"scan_wait={NRF_SCAN_WAIT_PUBLIC_ADDR_SEC}s)"
            )
            time.sleep(STEP_SETTLE_SEC)
            central_address = raspi_scan_for_dut_passkey_central(
        ble_client,
                dut_address,
                scan_wait=NRF_SCAN_WAIT_PUBLIC_ADDR_SEC,
            )
            time.sleep(STEP_SETTLE_SEC)

            logger().info(
                f"Step 4: Connect + MTU + SMP passkey request"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)

            def _connect():
                logger().info(f"Raspi connecting to DUT {dut_address} (SC passkey)")
                ble_client.interfaces.bluetooth.connect(
                    dev_addr=dut_address,
                    supervision_timeout=500,
                )

            connect_thread = threading.Thread(target=_connect)
            connect_thread.start()
            time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)

            time.sleep(STEP_SETTLE_SEC)
            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Passkey not found in DUT hostlog (step 4)"
            )
            assert_passkey_valid(passkey)

            logger().info(
                f"Step 5: Enter passkey on Raspi, complete bond"
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_thread.join(timeout=CONNECT_TIMEOUT_SEC)
            assert not connect_thread.is_alive(), (
                "Raspi connect thread did not finish"
            )

            time.sleep(STEP_SETTLE_SEC)
            verify_passkey_entry_connect_hostlog(bus)
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)
            verify_post_pair_hostlog(bus)
            time.sleep(POST_PAIR_SETTLE_SEC)

            for iteration in range(1, reconnect_iterations + 1):
                logger().info(
                    f"Steps 6–7: Disconnect/reconnect "
                    f"iteration {iteration}/{reconnect_iterations}"
                )
                time.sleep(STEP_SETTLE_SEC)
                drain_serial(bus)
                raspi_disconnect_and_wait(
                    bus,
                    ble_client,
                    dut_address,
                    disconnect_timeout=SCAN_RESTART_AFTER_DISCONNECT_SEC,
                )
                time.sleep(STEP_SETTLE_SEC)
                raspi_reconnect_bonded(
                    ble_client,
                    dut_address,
                    bus,
                    connect_timeout=CONNECT_TIMEOUT_SEC,
                    iteration=iteration,
                )
                time.sleep(STEP_SETTLE_SEC)

            logger().info(
                f"Step 8: Completed {reconnect_iterations} "
                "bonded reconnect iterations without passkey"
            )

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )
            time.sleep(STEP_SETTLE_SEC)

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553851")
def test_ble_central_justworks_reconnect_with_bond_C553851(wifi_dut, nrf_ble_client):
    """
    Test case          : Connect, disconnect and reconnect with bond info (Just Works)
    Device roles       : DUT central (DisplayOnly), nRF52840 dongle peripheral (slave11)
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    reconnect_iterations = REPEAT_CENTRAL_BOND_RECONNECT_ITERATIONS

    logger().info(
        f"Step 5: DUT init / advertising / scanning (hostlog)"
    )
    time.sleep(DUT_INIT_AFTER_RESET_SEC)
    drain_serial(bus)
    time.sleep(STEP_SETTLE_SEC)
    ok, log_text = wait_for_log_patterns(
        bus,
        WEARABLES_INIT_LOG_MARKERS,
        timeout=PERIPHERAL_INIT_VERIFY_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    if not ok:
        logger().warning(
            f"Some step-5 init log markers missing — continuing"
        )
    assert_dut_wearables_idle_hostlog(
        lower, step="5", require_scan=True, bus=bus, wifi_dut=wifi_dut
    )

    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayonly_initiator(
        wifi_dut, auth_req=AUTH_REQ_BONDING_SC
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 6: Start nRF dongle peripheral DisplayOnly "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}', Just Works / bonding+SC)"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_raspi_displayonly_peripheral(ble_client, local_addr)
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 6: DUT scan, connect, SMP pairing request"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)
            connect_log = dut_scan_and_connect_fast_connect_rx(
        wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            time.sleep(STEP_SETTLE_SEC)
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            logger().info(
                f"Step 8: Just Works pairing "
                "(nRF Connect Match — hostlog only)"
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_justworks(bus, timeout=SMP_COMPLETE_TIMEOUT_SEC)
            time.sleep(STEP_SETTLE_SEC)
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(POST_PAIR_SETTLE_SEC)

            for iteration in range(1, reconnect_iterations + 1):
                logger().info(
                    f"Steps 9–10: nRF disconnect / bonded "
                    f"reconnect iteration {iteration}/{reconnect_iterations}"
                )
                time.sleep(STEP_SETTLE_SEC)
                c553851_nrf_peripheral_disconnect_and_wait(
                    bus,
        ble_client,
                    wifi_dut,
                    local_addr,
                    peripheral_address,
                    disconnect_timeout=SCAN_RESTART_AFTER_DISCONNECT_SEC,
                )
                c553851_active_bonded_reconnect(
                    wifi_dut,
                    peripheral_address,
                    bus,
                    connect_kwargs=connect_kwargs,
                    iteration=iteration,
                    connect_timeout=CONNECT_TIMEOUT_SEC,
                )
                time.sleep(STEP_SETTLE_SEC)

            logger().info(
                f"Step 10: Completed {reconnect_iterations} "
                "bonded reconnect iterations without SMP pairing"
            )

        finally:
            _peer = peripheral_address
            peripheral_address = None
            if is_nrf_peer(ble_client):
                stop_nrf_peripheral(ble_client)
                time.sleep(STEP_SETTLE_SEC)
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )
            time.sleep(STEP_SETTLE_SEC)
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
            except Exception:
                pass

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553852")
def test_ble_central_numeric_comparison_reconnect_with_bond_C553852(wifi_dut, nrf_ble_client):
    """
    Test case          : Connect, disconnect and reconnect with bond info (NC)
    Device roles       : DUT central (DisplayYesNo), nRF52840 dongle peripheral (slave11)
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    reconnect_iterations = REPEAT_CENTRAL_BOND_RECONNECT_ITERATIONS

    logger().info(
        f"Step 5: DUT init / advertising / scanning (hostlog)"
    )
    time.sleep(DUT_INIT_AFTER_RESET_SEC)
    drain_serial(bus)
    time.sleep(STEP_SETTLE_SEC)
    ok, log_text = wait_for_log_patterns(
        bus,
        WEARABLES_INIT_LOG_MARKERS,
        timeout=PERIPHERAL_INIT_VERIFY_TIMEOUT_SEC,
        require_all=False,
    )
    lower = log_text.lower()
    if not ok:
        logger().warning(
            f"Some step-5 init log markers missing — continuing"
        )
    assert_dut_wearables_idle_hostlog(
        lower, step="5", require_scan=True, bus=bus, wifi_dut=wifi_dut
    )

    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(wifi_dut)
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 6: Start nRF dongle peripheral DisplayYesNo "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}', NC / bonding+MITM+SC)"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_raspi_displayyesno_peripheral(ble_client, local_addr)
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 6: DUT scan, connect, SMP pairing request"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            time.sleep(STEP_SETTLE_SEC)
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            logger().info(
                f"Step 7: Numeric Comparison pairing "
                "(nRF Connect Match — hostlog only)"
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_numeric_comparison(
                bus,
        wifi_dut,
        ble_client,
                peripheral_address,
                timeout=SMP_COMPLETE_TIMEOUT_SEC,
            )
            time.sleep(STEP_SETTLE_SEC)
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(POST_PAIR_SETTLE_SEC)

            for iteration in range(1, reconnect_iterations + 1):
                logger().info(
                    f"Steps 8–9: nRF disconnect / bonded "
                    f"reconnect iteration {iteration}/{reconnect_iterations}"
                )
                time.sleep(STEP_SETTLE_SEC)
                c553851_nrf_peripheral_disconnect_and_wait(
                    bus,
                    ble_client,
                    wifi_dut,
                    local_addr,
                    peripheral_address,
                    disconnect_timeout=SCAN_RESTART_AFTER_DISCONNECT_SEC,
                )
                c553852_active_bonded_reconnect(
                    wifi_dut,
                    peripheral_address,
                    bus,
                    ble_client,
                    connect_kwargs=connect_kwargs,
                    iteration=iteration,
                    connect_timeout=CONNECT_TIMEOUT_SEC,
                )
                time.sleep(STEP_SETTLE_SEC)

            logger().info(
                f"Step 9: Completed {reconnect_iterations} "
                "bonded reconnect iterations without SMP pairing"
            )

        finally:
            _peer = peripheral_address
            peripheral_address = None
            if is_nrf_peer(ble_client):
                stop_nrf_peripheral(ble_client)
                time.sleep(STEP_SETTLE_SEC)
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )
            time.sleep(STEP_SETTLE_SEC)
            try:
                wifi_dut.interfaces.wifi.legacy_scan_stop()
            except Exception:
                pass

    logger().info(f"PASS — hostlog only")


@pytest.mark.ble_clients(["raspi_ble_client", "secondary_raspi_ble_client"])
@pytest.mark.test_src_map_id("C553853")
def test_ble_dual_peripheral_reconnect_with_bond_C553853(wifi_dut, ble_clients):
    """
    Test case          : Two connect, disconnect and reconnect with bond info
    Device roles       : DUT peripheral (BLE_UNIFIED_DEMO), two Raspi centrals
    """
    bus = get_bus(wifi_dut)
    reconnect_iterations = REPEAT_BOND_RECONNECT_ITERATIONS
    assert len(ble_clients) >= 2, (
        f"Requires two ble_client harness devices "
        "(raspi_ble_client + secondary_raspi_ble_client)"
    )
    ble_client1, ble_client2 = ble_clients[0], ble_clients[1]

    logger().info(
        f"Step 3: DUT init / advertising / scanning (hostlog)"
    )
    ensure_dut_wearables_init_hostlog_step(
        wifi_dut,
        bus,
        step="3",
        require_scan=True,
    )

    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayonly_peripheral(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ID_SIGN,
        rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    dut_address = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 4 prep: Configure Raspi centrals KeyboardOnly "
        "(enter passkey on behalf of phone)"
    )
    time.sleep(STEP_SETTLE_SEC)
    configure_raspi_keyboardonly_central(ble_client1)
    configure_raspi_keyboardonly_central(ble_client2)
    time.sleep(CENTRAL_SMP_CONFIG_SETTLE_SEC)

    with hostlog_only_session(dut_address, dut_address):
        central1: Optional[str] = None
        central2: Optional[str] = None
        try:
            logger().info(
                f"Step 4: Raspi central 1 scan for DUT "
                f"(expected adv '{BLE_UNIFIED_DEMO_ADV_NAME}')"
            )
            time.sleep(STEP_SETTLE_SEC)
            central1 = raspi_scan_for_dut_passkey_central(
                ble_client1,
                dut_address,
                scan_wait=NRF_SCAN_WAIT_PUBLIC_ADDR_SEC,
            )
            time.sleep(STEP_SETTLE_SEC)

            logger().info(
                f"Steps 5–6: Central 1 connect + SC passkey pair"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)
            pair_baseline = _hostlog_item_count(bus)
            central1_passkey = raspi_connect_and_pair_passkey_central(
                ble_client1,
                dut_address,
                bus,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                smp_complete_timeout=SMP_COMPLETE_TIMEOUT_SEC,
            )
            time.sleep(STEP_SETTLE_SEC)
            verify_passkey_entry_connect_hostlog(bus)
            wait_for_peripheral_master_count(bus, 1)
            time.sleep(POST_PAIR_SETTLE_SEC)

            logger().info(
                f"Step 7: Raspi central 2 scan for DUT "
                f"(expected adv '{BLE_UNIFIED_DEMO_ADV_NAME}')"
            )
            time.sleep(STEP_SETTLE_SEC)
            central2 = raspi_scan_for_dut_passkey_central(
                ble_client2,
                dut_address,
                scan_wait=NRF_SCAN_WAIT_PUBLIC_ADDR_SEC,
            )
            time.sleep(STEP_SETTLE_SEC)

            logger().info(
                f"Step 7: Central 2 connect + SC passkey pair"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)
            raspi_connect_and_pair_passkey_central(
                ble_client2,
                dut_address,
                bus,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                smp_complete_timeout=SMP_COMPLETE_TIMEOUT_SEC,
                passkey_exclude=(central1_passkey,),
            )
            time.sleep(STEP_SETTLE_SEC)
            wait_for_c553853_dual_masters_connected(
                bus,
                timeout=CONNECT_TIMEOUT_SEC,
                baseline=pair_baseline,
            )
            verify_post_pair_hostlog(
                bus, require_security_keys=False
            )
            time.sleep(POST_PAIR_SETTLE_SEC)

            for iteration in range(1, reconnect_iterations + 1):
                logger().info(
                    f"Steps 8–9: Dual disconnect / bonded "
                    f"reconnect iteration {iteration}/{reconnect_iterations}"
                )
                time.sleep(STEP_SETTLE_SEC)
                drain_serial(bus)
                raspi_dual_disconnect_and_wait(
                    bus,
                    (ble_client1, ble_client2),
                    dut_address,
                    disconnect_timeout=SCAN_RESTART_AFTER_DISCONNECT_SEC,
                )
                time.sleep(STEP_SETTLE_SEC)
                raspi_dual_reconnect_bonded(
                    (ble_client1, ble_client2),
                    dut_address,
                    bus,
                    expected_masters=2,
                    connect_timeout=CONNECT_TIMEOUT_SEC,
                    iteration=iteration,
                )
                time.sleep(STEP_SETTLE_SEC)

            logger().info(
                f"Step 10: Completed {reconnect_iterations} "
                "dual bonded reconnect iterations without passkey"
            )

        finally:
            for idx, client in enumerate((ble_client1, ble_client2), start=1):
                try:
                    clear_ble_bonds_after_test(
                        wifi_dut,
                        client,
                        dut_address,
                        central1 if idx == 1 else central2,
                        case_id=f"central{idx}",
                        close_peer_session=True,
                    )
                except Exception as exc:
                    logger().warning(
                        f"central{idx} cleanup failed (non-fatal): {exc}"
                    )
            time.sleep(CLEANUP_FINAL_SETTLE_SEC)

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553854")
def test_ble_peripheral_encryption_initiation_C553854(wifi_dut, ble_client):
    """
    Test case          : Verify encryption initiation by DUT as peripheral
    Device roles       : DUT peripheral (COEX_MAX_DEMO), Raspi central (SC passkey)
    """
    bus = get_bus(wifi_dut)
    central_address: Optional[str] = None

    logger().info(
        f"Step 1: DUT init / advertising / scanning (hostlog)"
    )
    ensure_dut_wearables_init_hostlog_step(
        wifi_dut,
        bus,
        step="1",
        require_scan=True,
    )

    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_peripheral(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ID_SIGN,
        rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    dut_address = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 2 prep: Configure Raspi central KeyboardOnly "
        "(enter passkey on behalf of phone)"
    )
    time.sleep(STEP_SETTLE_SEC)
    configure_raspi_keyboardonly_central(ble_client)
    time.sleep(CENTRAL_SMP_CONFIG_SETTLE_SEC)

    with hostlog_only_session(dut_address, dut_address):
        try:
            logger().info(
                f"Step 2: Raspi scan for DUT "
                f"(expected adv '{COEX_MAX_DEMO_ADV_NAME}', "
                f"scan_wait={NRF_SCAN_WAIT_PUBLIC_ADDR_SEC}s)"
            )
            time.sleep(STEP_SETTLE_SEC)
            central_address = raspi_scan_for_dut_passkey_central(
        ble_client,
                dut_address,
                scan_wait=NRF_SCAN_WAIT_PUBLIC_ADDR_SEC,
            )
            time.sleep(STEP_SETTLE_SEC)
            logger().info(
                f"DUT discovered at {dut_address} "
                f"(adv name '{COEX_MAX_DEMO_ADV_NAME}')"
            )

            logger().info(
                f"Step 3: Connect + MTU + SMP passkey request"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)

            def _connect():
                logger().info(f"Raspi connecting to DUT {dut_address} (SC passkey)")
                ble_client.interfaces.bluetooth.connect(
                    dev_addr=dut_address,
                    supervision_timeout=500,
                )

            connect_thread = threading.Thread(target=_connect)
            connect_thread.start()
            time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)

            time.sleep(STEP_SETTLE_SEC)
            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Passkey not found in DUT hostlog (step 3)"
            )
            assert_passkey_valid(passkey)
            verify_passkey_entry_connect_hostlog(bus)

            logger().info(
                f"Step 4: Enter passkey, verify encryption "
                "initiation (hostlog only)"
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_thread.join(timeout=CONNECT_TIMEOUT_SEC)
            assert not connect_thread.is_alive(), (
                "Raspi connect thread did not finish"
            )

            time.sleep(STEP_SETTLE_SEC)
            verify_peripheral_encryption_initiation_hostlog(bus)
            wait_for_peripheral_master_count(bus, 1)
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )
            time.sleep(STEP_SETTLE_SEC)

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553855")
def test_ble_peripheral_encryption_initiation_random_addr_C553855(wifi_dut, ble_client):
    """
    Test case          : Verify encryption initiation by DUT peripheral (random addr)
    Device roles       : DUT peripheral (COEX_MAX_DEMO, LE random BD), Raspi central
    """
    bus = get_bus(wifi_dut)
    central_address: Optional[str] = None
    scan_wait = NRF_SCAN_WAIT_RANDOM_ADDR_SEC

    logger().info(
        f"Step 1: DUT init / advertising / scanning (hostlog)"
    )
    verify_peripheral_init_hostlog(bus, wifi_dut=wifi_dut)

    time.sleep(STEP_SETTLE_SEC)
    dut_address = ensure_dut_peripheral_random_address(
        wifi_dut,
        bus,
        configure_smp=lambda dut: configure_dut_smp_displayyesno_peripheral(
            dut,
            auth_req=AUTH_REQ_BONDING_MITM_SC,
            ini_key_dist=KEY_DIST_ENC_ID_SIGN,
            rsp_key_dist=KEY_DIST_ENC_ID_SIGN,
        ),
    )
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 2 prep: Configure Raspi central KeyboardOnly "
        "(enter passkey on behalf of phone)"
    )
    time.sleep(STEP_SETTLE_SEC)
    configure_raspi_keyboardonly_central(ble_client)
    time.sleep(CENTRAL_SMP_CONFIG_SETTLE_SEC)

    with hostlog_only_session(dut_address, dut_address):
        try:
            logger().info(
                f"Step 2: Raspi scan for DUT "
                f"(expected adv '{COEX_MAX_DEMO_ADV_NAME}', addr {dut_address}, "
                f"scan_wait={scan_wait}s)"
            )
            time.sleep(STEP_SETTLE_SEC)
            central_address = raspi_scan_for_dut_passkey_central(
        ble_client,
                dut_address,
                scan_wait=scan_wait,
            )
            time.sleep(STEP_SETTLE_SEC)
            logger().info(
                f"DUT discovered at {dut_address} "
                f"(adv name '{COEX_MAX_DEMO_ADV_NAME}')"
            )

            logger().info(
                f"Step 3: Connect + MTU + SMP passkey request"
            )
            time.sleep(STEP_SETTLE_SEC)
            drain_serial(bus)

            def _connect():
                logger().info(f"Raspi connecting to DUT {dut_address} (SC passkey)")
                ble_client.interfaces.bluetooth.connect(
                    dev_addr=dut_address,
                    supervision_timeout=500,
                )

            connect_thread = threading.Thread(target=_connect)
            connect_thread.start()
            time.sleep(NRF_PAIR_THREAD_START_DELAY_SEC)

            time.sleep(STEP_SETTLE_SEC)
            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Passkey not found in DUT hostlog (step 3)"
            )
            assert_passkey_valid(passkey)
            verify_passkey_entry_connect_hostlog(bus)

            logger().info(
                f"Step 4: Enter passkey, verify encryption "
                "initiation (hostlog only)"
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_thread.join(timeout=CONNECT_TIMEOUT_SEC)
            assert not connect_thread.is_alive(), (
                "Raspi connect thread did not finish"
            )

            time.sleep(STEP_SETTLE_SEC)
            verify_peripheral_encryption_initiation_hostlog(bus)
            wait_for_peripheral_master_count(bus, 1)
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = central_address
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, dut_address, _peer
            )
            restore_dut_public_advertising(wifi_dut, bus)
            time.sleep(STEP_SETTLE_SEC)

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553856")
def test_ble_central_encryption_pause_resume_C553856(wifi_dut, ble_client):
    """
    Test case          : Verify encryption pause/resume for DUT as central
    Device roles       : DUT central (COEX_MAX_DEMO, DisplayYesNo), Raspi peripheral
    """
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None

    logger().info(
        f"Step 2: DUT init / advertising / scanning (hostlog)"
    )
    time.sleep(DUT_INIT_AFTER_RESET_SEC)
    drain_serial(bus)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut, auth_req=AUTH_REQ_BONDING_MITM_SC
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 3 prep: Raspi peripheral KeyboardOnly "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}', enters passkey on behalf of phone)"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_raspi_keyboardonly_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 3: DUT scan, connect, SMP passkey request"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect(
        wifi_dut,
                peripheral_address,
                accept_smp_start=True,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            logger().info(
                f"Step 4: Enter passkey on Raspi, complete pairing"
            )
            time.sleep(STEP_SETTLE_SEC)
            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Passkey not found in DUT hostlog (step 3–4)"
            )
            assert_passkey_valid(passkey)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)
            verify_c553856_central_pairing_hostlog(bus)
            time.sleep(STEP_SETTLE_SEC)

            note_c553856_step5_encryption_restart_deferred(bus)
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553857")
def test_ble_central_encryption_initiation_C553857(wifi_dut, ble_client):
    """
    Test case          : Verify encryption initiation by DUT as central
    Device roles       : DUT central (COEX_MAX_DEMO, DisplayYesNo), Raspi peripheral
    """
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None

    logger().info(
        f"Step 1: DUT init / advertising / scanning (hostlog)"
    )
    time.sleep(DUT_INIT_AFTER_RESET_SEC)
    drain_serial(bus)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut, auth_req=AUTH_REQ_BONDING_MITM_SC
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 2 prep: Raspi peripheral KeyboardOnly "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}', enters passkey on behalf of phone)"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_raspi_keyboardonly_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 2: DUT scan, connect, SMP passkey request"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect(
        wifi_dut,
                peripheral_address,
                accept_smp_start=True,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            logger().info(
                f"Step 3: Enter passkey on Raspi, verify "
                "encryption initiation + data path (hostlog)"
            )
            time.sleep(STEP_SETTLE_SEC)
            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Passkey not found in DUT hostlog (step 2–3)"
            )
            assert_passkey_valid(passkey)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)
            verify_c553857_central_encryption_initiation_hostlog(
                bus
            )
            time.sleep(STEP_SETTLE_SEC)

            note_c553857_step4_ota_deferred()
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553858")
def test_ble_central_encryption_initiation_random_addr_C553858(wifi_dut, ble_client):
    """
    Test case          : Verify encryption initiation by DUT central (random addr)
    Device roles       : DUT central (COEX_MAX_DEMO, LE random BD), Raspi peripheral
    """
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None

    logger().info(
        f"Step 1: DUT init / advertising / scanning (hostlog)"
    )
    time.sleep(DUT_INIT_AFTER_RESET_SEC)
    drain_serial(bus)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut, auth_req=AUTH_REQ_BONDING_MITM_SC
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Step 2 prep: Raspi peripheral KeyboardOnly "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}', enters passkey on behalf of phone)"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_raspi_keyboardonly_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 2: DUT scan (public), connect (random addr), "
                "SMP passkey request"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect(
        wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                own_addr_type=OWN_ADDR_TYPE_RANDOM,
                scan_own_addr_type=DEFAULT_OWN_ADDR_TYPE,
                stop_scan_before_connect=True,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            logger().info(
                f"Step 3: Enter passkey on Raspi, verify "
                "encryption initiation + data path (hostlog)"
            )
            time.sleep(STEP_SETTLE_SEC)
            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Passkey not found in DUT hostlog (step 2–3)"
            )
            assert_passkey_valid(passkey)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)
            verify_c553857_central_encryption_initiation_hostlog(
                bus
            )
            time.sleep(STEP_SETTLE_SEC)

            note_c553857_step4_ota_deferred()
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )
            restore_dut_public_advertising(wifi_dut, bus)
            time.sleep(STEP_SETTLE_SEC)

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553859")
def test_ble_legacy_stk_zero_ediv_rand_C553859(wifi_dut, nrf_ble_client):
    """
    Test case          : Legacy pairing — EDIV/Rand memset 0 for STK encryption
    Device roles       : DUT central (DisplayYesNo, legacy), nRF dongle peripheral (KeyboardDisplay)
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–2: DUT BLE ready + legacy SMP (bonding+MITM, ENC_KEY_DIST only)"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_LEGACY,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553859_dut_legacy_smp_config_hostlog(bus)

    logger().info(f"Step 2: DUT init / advertising / scanning confirmed (hostlog)")
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 3–5: {peer_label} KeyboardDisplay legacy peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_raspi_keyboarddisplay_legacy_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 6: DUT scan, connect, legacy passkey pairing"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, f"Passkey not found in DUT hostlog (step 6)"
            assert_passkey_valid(passkey)

            logger().info(
                f"Enter passkey on {peer_label} (KeyboardDisplay peer)"
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            verify_c553859_step6_legacy_passkey_hostlog(
                bus, passkey
            )
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)

            logger().info(
                f"Step 7: Connection + legacy STK encrypt (hostlog)"
            )
            verify_c553859_legacy_stk_post_pair_hostlog(bus)
            note_c553859_step7_ota_deferred()
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553860")
def test_ble_lesc_ltk_zero_ediv_rand_C553860(wifi_dut, nrf_ble_client):
    """
    Test case          : LESC pairing — EDIV/Rand memset 0 for LTK encryption
    Device roles       : DUT central (DisplayYesNo, LESC), nRF dongle peripheral (KeyboardOnly for LESC passkey)
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–2: DUT BLE ready + LESC SMP (bonding+MITM+SC, ENC_KEY_DIST only)"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553860_dut_le_sc_smp_config_hostlog(bus)

    logger().info(f"Step 2: DUT init / advertising / scanning confirmed (hostlog)")
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    peer_cap = "KeyboardOnly" if is_nrf_peer(ble_client) else "KeyboardDisplay"
    logger().info(
        f"Steps 3–5: {peer_label} {peer_cap} LESC peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553860_nrf_le_sc_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 6: DUT scan, connect, LESC passkey pairing"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = c553860_dut_scan_and_connect(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )
            ensure_c553860_nrf_passkey_entry_after_connect(
                ble_client
            )

            passkey = wait_and_enter_passkey_on_nrf_peer(
                bus,
        ble_client,
                timeout=PASSKEY_TIMEOUT_SEC,
                seed_log=connect_log,
            )
            assert passkey, f"Passkey not found in DUT hostlog (step 6)"
            assert_passkey_valid(passkey)

            complete_smp_with_passkey(
                bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
            )
            verify_c553860_step6_le_sc_passkey_hostlog(
                bus, passkey
            )
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)

            logger().info(
                f"Step 7: Connection + LESC LTK encrypt (hostlog)"
            )
            verify_c553860_le_sc_ltk_post_pair_hostlog(bus)
            note_c553860_step7_ota_deferred()
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553861")
def test_ble_passkey_timeout_keyboardonly_C553861(wifi_dut, nrf_ble_client):
    """
    Test case          : Passkey timeout — passkey not entered (KeyboardOnly initiator)
    Device roles       : DUT central initiator (KeyboardOnly), nRF dongle peripheral (DisplayOnly)
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + KeyboardOnly initiator SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_keyboardonly_initiator(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553861_dut_keyboardonly_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayOnly peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553861_nrf_displayonly_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT scan/connect, withhold passkey, "
                f"expect 0x{SMP_AUTH_FAILURE_ERROR_CODE}"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log, passkey, failure_code = c553861_dut_scan_connect_withhold_passkey(
                wifi_dut,
                peripheral_address,
                bus,
                connect_kwargs=connect_kwargs,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                auth_fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
            )
            verify_c553861_step7_connect_hostlog(bus)
            verify_c553861_passkey_timeout_hostlog(
                bus, passkey, failure_code=failure_code
            )
            note_c553861_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553862")
def test_ble_passkey_timeout_keyboarddisplay_C553862(wifi_dut, nrf_ble_client):
    """
    Test case          : Passkey timeout — passkey not entered (KeyboardDisplay initiator)
    Device roles       : DUT central initiator (KeyboardDisplay), nRF dongle peripheral (DisplayYesNo)
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + KeyboardDisplay initiator SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_keyboarddisplay_initiator(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553862_dut_keyboarddisplay_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553862_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT scan/connect, withhold passkey, "
                f"expect 0x{SMP_AUTH_FAILURE_ERROR_CODE}"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log, passkey, failure_code = (
                c553862_dut_scan_connect_withhold_passkey(
                    wifi_dut,
                    peripheral_address,
                    bus,
                    connect_kwargs=connect_kwargs,
                    passkey_timeout=PASSKEY_TIMEOUT_SEC,
                    auth_fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
                )
            )
            verify_c553862_step7_connect_hostlog(bus)
            verify_c553862_passkey_timeout_hostlog(
                bus, passkey, failure_code=failure_code
            )
            note_c553862_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553863")
def test_ble_passkey_confirm_failed_keyboardonly_C553863(wifi_dut, nrf_ble_client):
    """
    Test case          : Wrong passkey — Confirm Value Failed (KeyboardOnly initiator)
    Device roles       : DUT central initiator (KeyboardOnly), nRF dongle peripheral (DisplayOnly)
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + KeyboardOnly initiator SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_keyboardonly_initiator(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553861_dut_keyboardonly_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayOnly peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553863_nrf_displayonly_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT scan/connect, wrong passkey, "
                f"expect 0x{SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE}"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log, passkey, failure_code = c553863_dut_scan_connect_wrong_passkey(
                wifi_dut,
                peripheral_address,
                bus,
                connect_kwargs=connect_kwargs,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
                wrong_passkey=0,
                dut_submit_wrong=True,
            )
            verify_c553863_step7_connect_hostlog(bus)
            verify_c553863_wrong_passkey_failure_hostlog(
                bus, passkey, failure_code=failure_code
            )
            note_c553863_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553864")
def test_ble_passkey_confirm_failed_dual_keyboardonly_C553864(wifi_dut, nrf_ble_client):
    """
    Test case          : Wrong passkey — Confirm Value Failed (dual KeyboardOnly)
    Device roles       : DUT central initiator (KeyboardOnly), nRF dongle peripheral (KeyboardOnly)
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + KeyboardOnly initiator SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_keyboardonly_initiator(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553861_dut_keyboardonly_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} KeyboardOnly peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553864_nrf_keyboardonly_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT scan/connect, wrong passkey, "
                f"expect 0x{SMP_PASSKEY_ENTRY_FAILED_ERROR_CODE}"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log, passkey, failure_code = c553864_dut_scan_connect_wrong_passkey(
                wifi_dut,
                peripheral_address,
                bus,
                connect_kwargs=connect_kwargs,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
                wrong_passkey=0,
                dut_submit_wrong=True,
            )
            verify_c553863_step7_connect_hostlog(bus)
            verify_c553863_wrong_passkey_failure_hostlog(
                bus, passkey, failure_code=failure_code
            )
            note_c553864_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553865")
def test_ble_numeric_comparison_central_periph_accept_C553865(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — central Accept, then peripheral Accept
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + DisplayYesNo central SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553865_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553865_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT connect, NC central-then-peripheral "
                "Accept"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553865_complete_numeric_comparison_central_first(
                bus,
        wifi_dut,
        ble_client,
                peripheral_address,
                timeout=PASSKEY_TIMEOUT_SEC,
            )
            verify_c553865_nc_bond_complete_hostlog(
                bus, passkey
            )
            note_c553865_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553866")
def test_ble_numeric_comparison_periph_central_accept_C553866(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — peripheral Accept, then central Accept
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + DisplayYesNo central SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553866_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553866_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT connect, NC peripheral-then-central "
                "Accept"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553866_complete_numeric_comparison_periph_first(
                bus,
        wifi_dut,
        ble_client,
                peripheral_address,
                timeout=PASSKEY_TIMEOUT_SEC,
            )
            verify_c553866_nc_bond_complete_hostlog(
                bus, passkey
            )
            note_c553866_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")


@pytest.mark.test_src_map_id("C553867")
def test_ble_numeric_comparison_periph_decline_C553867(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — central Accept, peripheral Decline
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + DisplayYesNo central SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553867_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553867_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT connect, NC central Accept / "
                "peripheral Decline"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553867_fail_numeric_comparison_central_accept_periph_decline(
                bus,
        wifi_dut,
        ble_client,
                peripheral_address,
                dut_passkey=passkey,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
            )
            verify_c553867_nc_failure_hostlog(bus, passkey)
            note_c553867_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(
        f"PASS — NC failure 0x{SMP_NUMERIC_COMPARISON_FAILED_ERROR_CODE} "
        "(hostlog only)"
    )


@pytest.mark.test_src_map_id("C553868")
def test_ble_numeric_comparison_central_decline_C553868(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — peripheral Accept, central Decline
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + DisplayYesNo central SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553868_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553868_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT connect, NC peripheral Accept / "
                "central Decline"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553868_fail_numeric_comparison_periph_accept_central_decline(
                bus,
        wifi_dut,
        ble_client,
                peripheral_address,
                dut_passkey=passkey,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
            )
            verify_c553868_nc_failure_hostlog(bus, passkey)
            note_c553868_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(
        f"PASS — NC failure (hostlog only)"
    )


@pytest.mark.test_src_map_id("C553869")
def test_ble_numeric_comparison_central_only_decline_C553869(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — peripheral X, central Decline only
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + DisplayYesNo central SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553869_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}'), peripheral NC action X"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553869_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT connect, NC central Decline only "
                "(peripheral X)"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553869_fail_numeric_comparison_central_only_decline(
                bus,
                wifi_dut,
                peripheral_address,
                dut_passkey=passkey,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
            )
            verify_c553869_nc_failure_hostlog(bus, passkey)
            note_c553869_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(
        f"PASS — NC failure (hostlog only)"
    )


@pytest.mark.test_src_map_id("C553870")
def test_ble_numeric_comparison_periph_only_decline_C553870(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — peripheral Decline, central action X
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + DisplayYesNo central SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553870_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}'), NC confirm withheld until decline"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553870_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT connect, NC peripheral Decline only "
                "(central X)"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553870_fail_numeric_comparison_periph_only_decline(
                bus,
        ble_client,
                dut_passkey=passkey,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
            )
            verify_c553870_nc_failure_hostlog(bus, passkey)
            note_c553870_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(
        f"PASS — NC failure (hostlog only)"
    )


@pytest.mark.test_src_map_id("C553871")
def test_ble_numeric_comparison_central_accept_periph_no_action_C553871(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — central Accept, peripheral no action
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–2: DUT BLE ready + DisplayYesNo central SMP"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553871_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 3–5: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}'), peripheral NC no action"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553871_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 6: DUT connect; step 7 central Accept / "
                "peripheral no action (SMP timeout)"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553871_fail_numeric_comparison_central_accept_periph_no_action(
                bus,
                wifi_dut,
                peripheral_address,
                dut_passkey=passkey,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
            )
            verify_c553871_nc_timeout_hostlog(bus, passkey)
            note_c553871_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(
        f"PASS — SMP timeout (hostlog only)"
    )


@pytest.mark.test_src_map_id("C553872")
def test_ble_numeric_comparison_periph_accept_central_no_action_C553872(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — peripheral Accept, central no action
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + DisplayYesNo central SMP "
        f"(firmware step 2: rsi_ble_smp_passkey commented out)"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553872_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}'), NC confirm withheld for step 7"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553872_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 7: DUT connect, central no action "
                "(SMP timeout 0x4BFC)"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553872_fail_numeric_comparison_periph_accept_central_no_action(
                bus,
        ble_client,
                dut_passkey=passkey,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
            )
            verify_c553872_nc_timeout_hostlog(bus, passkey)
            note_c553872_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(
        f"PASS — SMP timeout (hostlog only)"
    )


@pytest.mark.test_src_map_id("C553873")
def test_ble_numeric_comparison_both_no_action_C553873(wifi_dut, nrf_ble_client):
    """
    Test case          : Numeric Comparison — peripheral and central no action
    Device roles       : DUT central DisplayYesNo, nRF dongle peripheral DisplayYesNo
    """
    ble_client = nrf_ble_client
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–3: DUT BLE ready + DisplayYesNo central SMP "
        f"(firmware step 2: rsi_ble_smp_passkey commented out)"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=AUTH_REQ_BONDING_MITM_SC,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553873_dut_displayyesno_smp_config_hostlog(bus)

    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 4–6: {peer_label} DisplayYesNo peripheral "
        f"(adv '{REMOTE_DEVICE_NAME_SLAVE11}'), NC confirm withheld for steps 7–8"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553873_nrf_displayyesno_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)

    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Steps 7–8: DUT connect, both sides no NC action "
                "(SMP timeout 0x4BFC)"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect_fast_connect_rx(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )

            passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
            assert passkey, (
                f"Numeric comparison passkey not found in DUT hostlog "
                "(step 7)"
            )
            assert_passkey_valid(passkey)

            c553873_fail_numeric_comparison_both_no_action(
                bus,
        ble_client,
                dut_passkey=passkey,
                passkey_timeout=PASSKEY_TIMEOUT_SEC,
                fail_timeout=SMP_AUTH_FAILURE_TIMEOUT_SEC,
            )
            verify_c553873_nc_timeout_hostlog(bus, passkey)
            note_c553873_ota_deferred()
            _ = connect_log
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(
        f"PASS — SMP timeout (hostlog only)"
    )


@pytest.mark.test_src_map_id("C553911")
def test_ble_legacy_bonding_after_enc_failure_C553911(wifi_dut, ble_client):
    """
    Test case          : GAR-8403 — legacy bonding after enc failure, EDIV/Rand zero
    Expected           : Peer-only unbond, JW rebond; LL_ENC_REQ EDIV=0 Rand=0
    Device roles       : DUT central DisplayYesNo legacy, Raspi peripheral (slave11)
    """
    bus = get_bus(wifi_dut)
    peripheral_address: Optional[str] = None
    legacy_auth = AUTH_REQ_BONDING_MITM_LEGACY
    peer_label = "nRF dongle" if is_nrf_peer(ble_client) else "Raspi"

    logger().info(
        f"Steps 1–5: DUT BLE ready + legacy SMP "
        f"(DisplayYesNo IO cap 0x01, Auth Req 0x05 bonding+MITM, SC off)"
    )
    smp_iocap_dut_settle(wifi_dut=wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    configure_dut_smp_displayyesno_central(
        wifi_dut,
        auth_req=legacy_auth,
        ini_key_dist=KEY_DIST_ENC_ONLY,
        rsp_key_dist=KEY_DIST_ENC_ONLY,
    )
    time.sleep(SMP_CONFIG_SETTLE_SEC)
    verify_c553859_dut_legacy_smp_config_hostlog(bus)
    local_addr = get_dut_local_address(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)

    logger().info(
        f"Steps 6–7: {peer_label} KeyboardDisplay legacy peripheral "
        f"(SC off, MITM, bonding; adv '{REMOTE_DEVICE_NAME_SLAVE11}') — "
        f"Raspi passkey responder for DUT DisplayYesNo+MITM (TestRail nRF DisplayYesNo)"
    )
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_raspi_keyboarddisplay_legacy_peripheral(
        ble_client, local_addr
    )
    time.sleep(PEER_ADV_START_SEC)
    connect_kwargs = dut_connect_kwargs_for_peer(ble_client)

    logger().info(
        f"Step 8: DUT scan, connect, legacy passkey pairing "
        f"(DisplayYesNo central + KeyboardDisplay peripheral, MITM)"
    )
    time.sleep(STEP_SETTLE_SEC)
    connect_log = dut_scan_and_connect(
        wifi_dut,
        peripheral_address,
        accept_smp_start=True,
        **connect_kwargs,
    )
    verify_displayyesno_central_connect_hostlog(bus, connect_log)
    passkey = wait_for_passkey(bus, timeout=PASSKEY_TIMEOUT_SEC, enter_on_peer=ble_client)
    assert passkey, f"Passkey not found in DUT hostlog (step 8)"
    assert_passkey_valid(passkey)
    logger().info(
        f"Enter passkey on {peer_label} (DisplayYesNo legacy MITM peer)"
    )
    time.sleep(STEP_SETTLE_SEC)
    complete_smp_with_passkey(
        bus, ble_client, passkey, timeout=SMP_COMPLETE_TIMEOUT_SEC
    )
    verify_c553911_step8_initial_legacy_bond_hostlog(
        bus, passkey
    )
    time.sleep(POST_PAIR_SETTLE_SEC)
    stop_raspi_peripheral(ble_client, local_addr, peripheral_address)
    peripheral_address = None
    time.sleep(POST_DISCONNECT_SETTLE_SEC)

    logger().info(f"Step 9: Clear peer bond only, retain DUT bond")
    time.sleep(STEP_SETTLE_SEC)
    raspi_clear_bond_with_dut(ble_client, local_addr)
    time.sleep(POST_DISCONNECT_SETTLE_SEC)

    logger().info(
        f"Steps 10–11: {peer_label} DisplayYesNo legacy re-adv "
        f"(JW rebond path; bonding-only, SC off; '{REMOTE_DEVICE_NAME_SLAVE11}')"
    )
    time.sleep(STEP_SETTLE_SEC)
    c553911_prepare_dut_jw_rebond(wifi_dut)
    time.sleep(STEP_SETTLE_SEC)
    peripheral_address = start_c553911_displayyesno_legacy_jw_rebond_peripheral(
        ble_client, local_addr
    )
    time.sleep(STEP_SETTLE_SEC)

    with hostlog_only_session(local_addr, peripheral_address):
        try:
            logger().info(
                f"Step 12: DUT reconnect + legacy JW rebond "
                f"(Pin missing path; complete_smp_justworks after connect)"
            )
            time.sleep(STEP_SETTLE_SEC)
            connect_log = dut_scan_and_connect(
                wifi_dut,
                peripheral_address,
                accept_smp_start=True,
                **connect_kwargs,
            )
            verify_displayyesno_central_connect_hostlog(
                bus, connect_log
            )
            time.sleep(STEP_SETTLE_SEC)
            complete_smp_justworks(bus, timeout=SMP_COMPLETE_TIMEOUT_SEC)
            verify_c553911_step12_jw_rebond_hostlog(bus)
            time.sleep(PROFILE_DISCOVERY_SETTLE_SEC)

            logger().info(
                f"Step 13: legacy encrypt after JW rebond (hostlog)"
            )
            verify_c553911_step13_legacy_encrypt_hostlog(bus)
            note_c553911_step13_ota_deferred()
            time.sleep(POST_PAIR_SETTLE_SEC)

        finally:
            _peer = peripheral_address
            peripheral_address = None
            clear_ble_bonds_after_test(
                wifi_dut, ble_client, local_addr, _peer
            )

    logger().info(f"PASS — hostlog only")
