"""
Raspberry Pi only: HTTP BLE API for scan / connect / passkey bonding / notifications.

Setup:
    1. Raspberry Pi with BlueZ (ble_client)
    2. External peer/DUT that advertises and displays a passkey during pairing
       (peer is NOT controlled by this test)

The server binds 0.0.0.0 inside a host-networked container, so it is reachable
at http://<raspberry-pi-ip>:<port> from any machine on the lab network.

The Pi registers a GATT server at startup (heart rate, immediate alert, health
thermometer, battery). The peer runs remote profile discovery immediately after
connecting and drops the link when those services are missing, which is why a
bare BlueZ central disconnects but a phone does not. Override the set withgatt_connect 
BLE_RASPI_SERVICE_CLASSES.

HTTP APIs (default port 5000):
    GET  /health
    GET  /ble/status
    POST /ble/scan                 {"timeout": 10, "address": optional MAC}
    POST /ble/connect              {"address": "AA:BB:CC:DD:EE:FF",
                                    "capability": "KeyboardOnly",
                                    "bond": true}   # false = plain connect, no SMP
    POST /ble/passkey              {"passkey": "123456"}  # only needed when bond=true
    POST /ble/unpair               {"address": "AA:BB:…"}  # clear prior BlueZ bond
    POST /ble/disconnect           {"address": "AA:BB:…"}  # phone disconnect (privacy)
    GET  /ble/services             # list the peer's GATT services/characteristics
    POST /ble/read                 {"service_uuid": "aabb", "char_uuid": "1aa1"}
                                   # GATT Read (long attr OK after MTU); short UUIDs OK
    POST /ble/notifications/enable {"service_uuid": "...", "char_uuid": "..."}
                                   # UUIDs optional (auto-picks a notify char) and
                                   # short forms like "2a37" are accepted
    GET  /ble/notifications
    POST /ble/notifications/clear
    POST /ble/peripheral/advertise              # Pi advertises (SILABS_DEV); DUT=central apps
    POST /ble/peripheral/advertise-and-connect  # advertise + wait for DUT central
    POST /ble/peripheral/expect-peer            # set DUT MAC when Pi is peripheral
    POST /ble/orchestration/complete   # host signals graceful shutdown (after stability)
    POST /ble/orchestration/abort      # force-stop server; pytest fails (stale-run teardown)

Roles (do not mix):
    Pi advertises  -> ble_central / ble_accept_list / ble_ae_central /
                      ble_longrange_2mbps / ble_datalength
    DUT advertises -> ble_ae_peripheral / ble_ibeacon / ble_heart_rate_profile /
                      gatt_long_read / ble_hid_on_gatt (Pi scans)

Typical flow with passkey (bond=true):
    1. POST /ble/scan
    2. POST /ble/connect  {"address":"...","bond":true}
    3. Read passkey shown on peer/DUT
    4. POST /ble/passkey
    5. POST /ble/notifications/enable
    6. GET  /ble/notifications

Typical flow WITHOUT SMP/passkey (bond=false):
    1. POST /ble/scan
    2. POST /ble/connect  {"address":"...","bond":false}
    3. POST /ble/notifications/enable
    4. GET  /ble/notifications
    (skip /ble/passkey entirely)

Stability rules enforced here:
    - Bluetooth adapter is never powered off
    - BlueZ / BT service is not restarted after the one-time init
    - glib mainloop stays up for the whole server lifetime
    - connect uses Trusted + link connect, then pair in a background thread
    - connection is polled after bond to confirm it stays up
"""

from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import pytest

from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils import mac_address_to_dbus_bt_path
from utf.interfaces.bluetooth.bluez.bluez_interfaces import BTDBusInterfaces


def logger():
    return get_logger(__name__)


DEFAULT_HTTP_PORT = int(os.environ.get("BLE_RASPI_HTTP_PORT", "5000"))
DEFAULT_SERVER_LIFETIME_SEC = int(os.environ.get("BLE_RASPI_HTTP_LIFETIME_SEC", "3600"))
DEFAULT_CAPABILITY = "KeyboardOnly"
# BlueZ agent pin sentinel: RequestPasskey waits up to ~30s for set_pin().
PASSKEY_WAIT_SENTINEL = "-8"
STABILITY_POLL_SEC = 30
STABILITY_INTERVAL_SEC = 5
POST_NOTIFY_STABILITY_SEC = int(os.environ.get("BLE_ORCHESTRATION_STABILITY_SEC", "300"))
ORCHESTRATION_FINISH_WAIT_SEC = int(
    os.environ.get("BLE_ORCHESTRATION_FINISH_WAIT_SEC", "180")
)

# The peer runs remote profile discovery right after connecting and drops the
# link when the expected services are absent, so the Pi must expose a GATT
# server. These cover 0x180D/0x2A37+0x2A38+0x2A39, 0x1802/0x2A06,
# 0x1809/0x2A1C and 0x180F/0x2A19 — same BlueZ demo services used by other
# UTF BLE peripheral testcases (e.g. ble_8p_2c / data-transfer style flows).
DEFAULT_SERVICE_CLASSES = [
    "HeartRateService",
    "ImmediateAlertService",
    "HealthThermometerService",
    "BatteryService",
]
if os.environ.get("BLE_RASPI_SERVICE_CLASSES"):
    DEFAULT_SERVICE_CLASSES = [
        name.strip()
        for name in os.environ["BLE_RASPI_SERVICE_CLASSES"].split(",")
        if name.strip()
    ]

# Heart Rate UUID in AD (normalized to 128-bit by BlueZ layer). Full GATT set
# above is still registered on the Pi for post-connect discovery. If AD UUID
# registration fails, utf_core falls back to LocalName-only advertising.
PERIPHERAL_ADVERTISE_UUIDS = ["0000180d-0000-1000-8000-00805f9b34fb"]

# Pi-as-peripheral orchestration kinds (DUT is the BLE central).
# ble_central / accept_list / longrange use legacy HCI ADV_IND; ae_central uses BlueZ LEAdvertisement.
PI_PERIPHERAL_KINDS = (
    "ae_central",
    "ble_central",
    "accept_list",
    "dut_central",
    "longrange",
    "datalength",
)
LEGACY_HCI_PERIPHERAL_KINDS = (
    "ble_central",
    "accept_list",
    "dut_central",
    "longrange",
    "datalength",
)
# Host marks connect via /ble/orchestration/ae-central-stability then /complete.
SIMPLE_CONNECT_HOST_MARK_KINDS = PI_PERIPHERAL_KINDS + (
    "ae_peripheral",
    "gatt_long_read",
    "testmodes",
    "stack_bypass",
    "secureconnection",
    "privacy",
    "hid_on_gatt",
)
# Quiet high-frequency HTTP polls in pytest reports.
QUIET_HTTP_KINDS = SIMPLE_CONNECT_HOST_MARK_KINDS
# Short readme-style console (manual tester) — no hciconfig / HTTP dumps.
MANUAL_CHECKLIST_KINDS = frozenset(
    {
        "datalength",
        "longrange",
        "testmodes",
        "stack_bypass",
        "secureconnection",
        "privacy",
        "gatt_long_read",
        "hid_on_gatt",
    }
)
# Phone-role apps: plain Connect then peer-initiated SMP (DUT shows passkey).
# hid_on_gatt is here too: with GATT_ROLE=SERVER the DUT never calls
# rsi_ble_smp_pair_request, so SMP starts when the peer reads an encrypted HID
# attribute (report map) — exactly what a phone does. Device.Pair() fails with
# org.bluez.Error.AuthenticationFailed on this stack.
PEER_INITIATED_SMP_KINDS = frozenset({"secureconnection", "privacy", "hid_on_gatt"})


def _json_bytes(payload: Dict[str, Any], status: int = 200) -> tuple[int, bytes, str]:
    body = json.dumps(payload, indent=2).encode("utf-8")
    return status, body, "application/json"


def _normalize_uuid(value: Optional[str]) -> Optional[str]:
    """Accept 2a37, 0x2A37 or the full 128-bit form and return BlueZ's format."""
    if value is None:
        return None
    uuid = str(value).strip().lower()
    if uuid.startswith("0x"):
        uuid = uuid[2:]
    if "-" in uuid:
        return uuid
    if len(uuid) == 4:
        return f"0000{uuid}-0000-1000-8000-00805f9b34fb"
    if len(uuid) == 8:
        return f"{uuid}-0000-1000-8000-00805f9b34fb"
    return uuid


class RaspiBleHttpController:
    """Owns BlueZ state for the HTTP handlers. RasPi / ble_client only."""

    def __init__(self, ble_client):
        self.ble_client = ble_client
        self.bt = ble_client.interfaces.bluetooth
        self.lock = threading.RLock()
        self.initialized = False
        self.local_address: Optional[str] = None
        self.target_address: Optional[str] = None
        self.capability = DEFAULT_CAPABILITY
        self.state = "idle"
        self.last_error: Optional[str] = None
        self.scanned_devices: Dict[str, Any] = {}
        self.connected = False
        self.bonded = False
        self.notifications_enabled = False
        self.service_uuid: Optional[str] = None
        self.char_uuid: Optional[str] = None
        self.char_path: Optional[str] = None
        self.pair_thread: Optional[threading.Thread] = None
        self.passkey_set = False
        self._stability_ok = False
        self._post_notify_stability_ok = False
        self._post_notify_stability_done = False
        self._orchestration_finish = threading.Event()
        self._orchestration_complete_requested = False
        self._orchestration_aborted = False
        self._abort_reason: Optional[str] = None
        self._http_server = None  # set by test runner for force-stop
        self.orchestration_kind: str = "gatt_connect"
        self._ibeacon_scan_stability_ok = False
        self._ibeacon_scan_stability_done = False
        self._ibeacon_scan_sample_count = 0
        self._ae_central_link_stability_ok = False
        self._ae_central_link_stability_done = False
        self._ae_central_link_sample_count = 0
        # Latched when BlueZ reports Connected for target_address (survives brief gaps).
        self._peer_link_seen = False
        self.peripheral_local_name: Optional[str] = None
        self.peripheral_mode = False
        self.advertising_on = False
        self.service_classes: list = []
        self.auto_enable_notifications = False
        self.auto_notify_service_uuid: Optional[str] = None
        self.auto_notify_char_uuid: Optional[str] = None
        # ble_testmodes (HCI LE Direct Test Mode on Pi = readme Linux dongle).
        self._testmodes_hci: str = "hci0"
        self._testmodes_active: Optional[str] = None  # "rx" | "tx" | None
        self._testmodes_last_packets: Optional[int] = None
        # bt_stack_bypass (DUT HCI UART attached on Pi).
        self._bypass_uart: Optional[str] = None
        self._bypass_adapter: Optional[str] = None
        self._bypass_bd_addr: Optional[str] = None
        self._bypass_attached: bool = False

    def _set_state(self, state: str, error: Optional[str] = None):
        self.state = state
        if error is not None:
            self.last_error = error
        if self.orchestration_kind in MANUAL_CHECKLIST_KINDS and not error:
            return
        logger().info(f"BleHttp state -> {state}" + (f" ({error})" if error else ""))

    def _hci_le_peer_connected(self, address: str) -> bool:
        """
        Controller-level LE link check via `hcitool con`.

        Needed for ble_central / dut_central: legacy HCI ADV_IND can complete a
        link that BlueZ Device1.Connected still reports as false.
        """
        if not address:
            return False
        needle = str(address).strip().upper().replace("-", ":")
        shell = getattr(self.bt, "shell", None)
        if shell is None:
            return False
        try:
            rc, stdout, stderr = shell.execute("sudo hcitool con")
        except Exception as exc:
            logger().warning(f"hcitool con failed: {exc}")
            return False
        if rc != 0:
            return False
        text = stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else str(stdout)
        for line in text.splitlines():
            if "LE" not in line.upper():
                continue
            # Normalize separators so D4:48… matches D4-48… forms.
            norm = line.upper().replace("-", ":")
            if needle in norm:
                return True
        return False

    def _hci_adapter(self) -> str:
        return (
            getattr(self, "_testmodes_hci", None)
            or getattr(self.bt, "adapter_name", None)
            or "hci0"
        )

    def _shell_exec(self, cmd: str) -> tuple[int, str, str]:
        shell = getattr(self.bt, "shell", None)
        if shell is None:
            raise RuntimeError("BlueZ shell not available for hcitool")
        rc, stdout, stderr = shell.execute(cmd)
        out = (
            stdout.decode("utf-8", errors="replace")
            if isinstance(stdout, (bytes, bytearray))
            else str(stdout or "")
        )
        err = (
            stderr.decode("utf-8", errors="replace")
            if isinstance(stderr, (bytes, bytearray))
            else str(stderr or "")
        )
        return int(rc), out, err

    @staticmethod
    def _parse_le_test_end_packets(hci_text: str) -> Optional[int]:
        """
        Parse Number_Of_Packets from LE Test End (OCF 0x001F) Command Complete.

        Typical hcitool dump:
          > HCI Event: 0x0e plen 6
            01 1F 20 00 2A 00
        → status=0x00, packets=0x002A (little-endian).
        """
        if not hci_text:
            return None
        # Opcode LE Test End = 0x201F → bytes 1F 20 in event payload.
        m = re.search(
            r"1[Ff]\s+20\s+([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})",
            hci_text,
        )
        if m:
            status = int(m.group(1), 16)
            lo = int(m.group(2), 16)
            hi = int(m.group(3), 16)
            if status != 0:
                return None
            return lo | (hi << 8)
        # Fallback: any "XX YY" after status near test end wording.
        m2 = re.search(
            r"[Tt]est\s*[Ee]nd[^\n]*?([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})\s*$",
            hci_text,
            re.M,
        )
        if m2:
            return int(m2.group(1), 16) | (int(m2.group(2), 16) << 8)
        return None

    def _hci_le_cmd(self, ocf: str, params: str = "") -> Dict[str, Any]:
        """Run `hcitool -i hciX cmd 0x08 <ocf> [params]` (LE controller OGF 0x08)."""
        adapter = self._hci_adapter()
        params = (params or "").strip()
        cmd = f"sudo hcitool -i {adapter} cmd 0x08 {ocf}"
        if params:
            cmd = f"{cmd} {params}"
        rc, out, err = self._shell_exec(cmd)
        text = (out or "") + ("\n" + err if err else "")
        return {
            "ok": rc == 0 and "Usage:" not in text,
            "rc": rc,
            "command": cmd,
            "output": text.strip(),
            "adapter": adapter,
        }

    def init_testmodes_stack(self) -> Dict[str, Any]:
        """
        Bring Pi HCI up for SDK ble_testmodes (Pi replaces Linux + BT dongle).

        No advertising / GATT connect — only raw LE test HCI commands.
        """
        with self.lock:
            self.orchestration_kind = "testmodes"
            self.peripheral_mode = False
            self.advertising_on = False
            adapter = self._hci_adapter()
            self._testmodes_hci = adapter
            # Best-effort: adapter up, no page/inquiry scan (RF test only).
            for prep in (
                f"sudo hciconfig {adapter} up",
                f"sudo hciconfig {adapter} noscan",
            ):
                try:
                    self._shell_exec(prep)
                except Exception as exc:
                    logger().warning(f"testmodes prep ignored ({prep}): {exc}")
            try:
                rc, out, _err = self._shell_exec(f"sudo hciconfig {adapter}")
                m = re.search(
                    r"BD\s*Address:\s*([0-9A-Fa-f:]{17})", out or "", re.I
                )
                if m:
                    self.local_address = m.group(1).upper()
            except Exception:
                pass
            if not self.local_address:
                try:
                    self.local_address = getattr(self.bt, "local_address", None) or ""
                except Exception:
                    self.local_address = ""
            self.initialized = True
            self._set_state("testmodes_ready")
            logger().info("=== BLE Testmodes (Pi = Linux HCI dongle in readme) ===")
            logger().info(f"  Adapter : {adapter}  addr={self.local_address or 'n/a'}")
            logger().info(
                "  DUT TX → Pi: hcitool cmd 0x08 0x001D <ch> then 0x001F (stop)"
            )
            logger().info(
                "  DUT RX → Pi: hcitool cmd 0x08 0x001E <ch> <len> <type> then 0x001F"
            )
            return {
                "ok": True,
                "message": "Pi HCI ready for LE testmodes (no advertising)",
                "local_address": self.local_address,
                "adapter": adapter,
                "orchestration_kind": "testmodes",
            }

    def testmodes_le_receiver_test(self, channel: int = 0x10) -> Dict[str, Any]:
        """
        Readme TX step 3: LE Receiver Test on Pi (dongle receives DUT TX).

        `hcitool -i hcix cmd 0x08 0x001D 0x10`
        """
        ch = int(channel) & 0xFF
        logger().info(
            f"[TX step 3] Pi LE Receiver Test — "
            f"hcitool cmd 0x08 0x001D 0x{ch:02X} (channel must match DUT TX)"
        )
        result = self._hci_le_cmd("0x001D", f"0x{ch:02X}")
        if result.get("ok"):
            self._testmodes_active = "rx"
            self._set_state("testmodes_rx_active")
            logger().info("[TX step 3] LE Receiver Test started on Pi (collecting packets)")
        else:
            logger().error(f"[TX step 3] LE Receiver Test FAILED: {result.get('output')}")
        result["channel"] = ch
        result["role"] = "le_receiver_test"
        result["status"] = self.status()
        return result

    def testmodes_le_transmitter_test(
        self,
        channel: int = 0x10,
        payload_len: int = 0x20,
        payload_type: int = 0x01,
    ) -> Dict[str, Any]:
        """
        Readme RX step 3: LE Transmitter Test on Pi (dongle TX → DUT RX).

        `hcitool -i hcix cmd 0x08 0x001E 0x10 0x20 0x01`
        """
        ch = int(channel) & 0xFF
        length = int(payload_len) & 0xFF
        ptype = int(payload_type) & 0xFF
        logger().info(
            f"[RX step 3] Pi LE Transmitter Test — "
            f"hcitool cmd 0x08 0x001E 0x{ch:02X} 0x{length:02X} 0x{ptype:02X}"
        )
        result = self._hci_le_cmd(
            "0x001E", f"0x{ch:02X} 0x{length:02X} 0x{ptype:02X}"
        )
        if result.get("ok"):
            self._testmodes_active = "tx"
            self._set_state("testmodes_tx_active")
            logger().info("[RX step 3] LE Transmitter Test started on Pi")
        else:
            logger().error(
                f"[RX step 3] LE Transmitter Test FAILED: {result.get('output')}"
            )
        result.update(
            {
                "channel": ch,
                "payload_len": length,
                "payload_type": ptype,
                "role": "le_transmitter_test",
                "status": self.status(),
            }
        )
        return result

    def testmodes_le_test_end(self) -> Dict[str, Any]:
        """
        Readme TX step 5 / RX stop: LE Test End.

        `hcitool -i hcix cmd 0x08 0x001F` → verify packet count (TX path).
        """
        logger().info(
            "[step 5] Pi LE Test End — hcitool cmd 0x08 0x001F (cease RX/TX test)"
        )
        result = self._hci_le_cmd("0x001F", "")
        packets = self._parse_le_test_end_packets(result.get("output") or "")
        self._testmodes_last_packets = packets
        self._testmodes_active = None
        self._set_state("testmodes_idle")
        if packets is not None:
            logger().info(
                f"[step 6] Packets reported by LE Test End: {packets}"
            )
        else:
            logger().info(
                "[step 6] Could not parse packet count from HCI output "
                "(see command dump below)"
            )
            if result.get("output"):
                for line in str(result["output"]).splitlines()[:12]:
                    logger().info(f"  | {line}")
        result["packets"] = packets
        result["role"] = "le_test_end"
        result["status"] = self.status()
        return result

    # ----- bt_stack_bypass (DUT HCI UART → Pi btattach; Linux BlueZ owns radio) -----

    def init_stack_bypass(self) -> Dict[str, Any]:
        """Pi ready to attach DUT HCI UART (readme Linux host). No onboard ADV/GATT."""
        with self.lock:
            self.orchestration_kind = "stack_bypass"
            self.peripheral_mode = False
            self.advertising_on = False
            self.initialized = True
            self._set_state("stack_bypass_ready")
            uart = os.environ.get("BLE_STACK_BYPASS_UART", "/dev/ttyUSB0")
            logger().info("=== BT Stack Bypass (SDK bt_stack_bypass) ===")
            logger().info("Pi = Linux host. DUT = raw HCI over UART (stack bypassed).")
            logger().info(f"Expected UART: {uart}  (env BLE_STACK_BYPASS_UART)")
            logger().info(
                "Flow: wait Wi-Fi init → btattach → hciconfig up → leadv → lescan → detach"
            )
            logger().info(
                "(Phone/SiConnect step replaced by BD_ADDR + leadv OK on Pi)"
            )
            return {
                "ok": True,
                "message": "Pi ready for bt_stack_bypass HCI UART attach",
                "orchestration_kind": "stack_bypass",
                "default_uart": uart,
            }

    def _list_hci_adapters(self) -> list:
        rc, out, _err = self._shell_exec("hciconfig -a || true")
        return re.findall(r"^(hci\d+):", out or "", re.M)

    def _parse_hciconfig_block(self, text: str, adapter: Optional[str] = None) -> dict:
        """Parse BD_ADDR / UP|DOWN from hciconfig -a output."""
        info: Dict[str, Any] = {
            "adapter": adapter,
            "bd_addr": None,
            "up": False,
            "raw": (text or "").strip(),
        }
        if not text:
            return info
        block = text
        if adapter:
            m = re.search(
                rf"^{re.escape(adapter)}:.*?(?=^hci\d+:|\Z)",
                text,
                re.M | re.S,
            )
            if m:
                block = m.group(0)
        addr = re.search(r"BD\s*Address:\s*([0-9A-Fa-f:]{17})", block, re.I)
        if addr:
            info["bd_addr"] = addr.group(1).upper()
        # First flags line after adapter name usually has UP RUNNING or DOWN.
        info["up"] = False
        for line in block.splitlines()[:5]:
            if re.search(r"\bUP\b", line) and "DOWN" not in line:
                info["up"] = True
                break
            if re.search(r"\bDOWN\b", line):
                info["up"] = False
                break
        return info

    def stack_bypass_attach(
        self,
        device: str = "/dev/ttyUSB0",
        baud: int = 115200,
    ) -> Dict[str, Any]:
        """
        Readme step 3: attach DUT HCI UART (same as hci_uart_attach.sh -d).

        Stops ModemManager/bluetooth, runs `btattach -P h4 -N` in background.
        """
        device = (device or "/dev/ttyUSB0").strip()
        baud = int(baud or 115200)
        logger().info(f"[3] Attach HCI UART on Pi: {device} @ {baud} (btattach H4)")
        before = set(self._list_hci_adapters())

        # Mirror SDK hci_uart_attach.sh (daemon mode).
        cmds = [
            "sudo systemctl stop ModemManager 2>/dev/null || true",
            "sudo systemctl stop bluetooth 2>/dev/null || true",
            f"sudo pkill -f 'btattach.*{device}' 2>/dev/null || true",
            "sudo pkill hciattach 2>/dev/null || true",
            f"sudo stty -F {device} {baud} raw -echo -ixon -ixoff cs8 -cstopb "
            f"-parenb -parodd crtscts",
            f"sudo sh -c 'nohup btattach -B {device} -S {baud} -P h4 -N "
            f">/tmp/btattach_bypass.log 2>&1 &'",
        ]
        logs = []
        for cmd in cmds:
            try:
                rc, out, err = self._shell_exec(cmd)
                logs.append({"cmd": cmd, "rc": rc, "out": (out or err or "")[:200]})
            except Exception as exc:
                logs.append({"cmd": cmd, "error": str(exc)})

        time.sleep(2.0)
        # Confirm device exists
        rc_dev, _o, _e = self._shell_exec(f"test -e {device} && echo OK || echo MISSING")
        if "MISSING" in (_o or ""):
            logger().error(
                f"[3] FAIL — serial device not found: {device}. "
                "Wire USB-UART (SoC: WSTK P35/P33) and set BLE_STACK_BYPASS_UART."
            )
            return {
                "ok": False,
                "error": f"serial device not found: {device}",
                "device": device,
                "hint": "USB-UART cable required; check dmesg for ttyUSB*",
                "logs": logs,
                "status": self.status(),
            }

        after = set(self._list_hci_adapters())
        new_adapters = sorted(after - before) or sorted(after)
        adapter = new_adapters[-1] if new_adapters else "hci0"
        # Prefer newly appeared adapter
        if after - before:
            adapter = sorted(after - before)[0]

        self._bypass_uart = device
        self._bypass_adapter = adapter
        self._bypass_attached = True
        self._testmodes_hci = adapter
        self._set_state("stack_bypass_attached")
        logger().info(f"[3] btattach running — HCI adapter: {adapter}")
        return {
            "ok": True,
            "device": device,
            "baud": baud,
            "adapter": adapter,
            "adapters_before": sorted(before),
            "adapters_after": sorted(after),
            "logs": logs,
            "status": self.status(),
        }

    def stack_bypass_hciconfig(self, adapter: Optional[str] = None) -> Dict[str, Any]:
        """Readme step 4: hciconfig — show BD_ADDR / UP|DOWN."""
        adapter = adapter or self._bypass_adapter or "hci0"
        logger().info(f"[4] hciconfig -a {adapter}")
        rc, out, err = self._shell_exec(f"sudo hciconfig -a {adapter}")
        text = (out or "") + ("\n" + err if err else "")
        info = self._parse_hciconfig_block(text, adapter)
        self._bypass_adapter = adapter
        if info.get("bd_addr"):
            self._bypass_bd_addr = info["bd_addr"]
            self.local_address = info["bd_addr"]
            logger().info(f"[4] BD_ADDR = {info['bd_addr']}  state={'UP' if info.get('up') else 'DOWN'}")
        else:
            logger().info(f"[4] hciconfig output (rc={rc}):")
            for line in text.splitlines()[:16]:
                logger().info(f"  | {line}")
        return {
            "ok": rc == 0 or bool(info.get("bd_addr")),
            "adapter": adapter,
            **info,
            "status": self.status(),
        }

    def stack_bypass_up(self, adapter: Optional[str] = None) -> Dict[str, Any]:
        """Readme step 5: hciconfig hciX up if DOWN."""
        adapter = adapter or self._bypass_adapter or "hci0"
        logger().info(f"[5] Bring interface UP: hciconfig -a {adapter} up")
        rc, out, err = self._shell_exec(f"sudo hciconfig -a {adapter} up")
        text = (out or "") + ("\n" + err if err else "")
        time.sleep(0.5)
        check = self.stack_bypass_hciconfig(adapter)
        ok = bool(check.get("up")) and bool(check.get("bd_addr"))
        if ok:
            logger().info(f"[5] {adapter} is UP  BD_ADDR={check.get('bd_addr')}")
        else:
            logger().error(f"[5] FAIL — {adapter} not UP after hciconfig up")
        return {
            "ok": ok,
            "adapter": adapter,
            "up_rc": rc,
            "up_output": text.strip(),
            "bd_addr": check.get("bd_addr"),
            "up": check.get("up"),
            "status": self.status(),
        }

    def stack_bypass_leadv(self, adapter: Optional[str] = None) -> Dict[str, Any]:
        """Readme step 6a: hciconfig -a hciX leadv."""
        adapter = adapter or self._bypass_adapter or "hci0"
        logger().info(f"[6a] Enable LE advertising: hciconfig -a {adapter} leadv")
        rc, out, err = self._shell_exec(f"sudo hciconfig -a {adapter} leadv")
        text = (out or "") + ("\n" + err if err else "")
        ok = rc == 0
        if ok:
            logger().info("[6a] LE advertising enabled (DUT radio via Linux HCI)")
        else:
            logger().error(f"[6a] leadv FAILED: {text[:300]}")
        return {
            "ok": ok,
            "adapter": adapter,
            "command": f"hciconfig -a {adapter} leadv",
            "output": text.strip(),
            "bd_addr": self._bypass_bd_addr,
            "status": self.status(),
        }

    def stack_bypass_lescan(
        self,
        adapter: Optional[str] = None,
        timeout_sec: int = 5,
    ) -> Dict[str, Any]:
        """Readme step 6b: hcitool -i hciX lescan (timed)."""
        adapter = adapter or self._bypass_adapter or "hci0"
        timeout_sec = max(2, int(timeout_sec or 5))
        logger().info(
            f"[6b] LE scan: timeout {timeout_sec}s hcitool -i {adapter} lescan"
        )
        # timeout kills lescan (runs until interrupted).
        rc, out, err = self._shell_exec(
            f"sudo timeout {timeout_sec} hcitool -i {adapter} lescan || true"
        )
        text = (out or "") + ("\n" + err if err else "")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        # Any output or clean timeout (124) counts as scan ran.
        ok = True
        logger().info(f"[6b] lescan finished — {len(lines)} line(s) of results")
        for line in lines[:12]:
            logger().info(f"  | {line}")
        if not lines:
            logger().info(
                "[6b] (no advertisers seen — OK for lab; scan command still ran)"
            )
        return {
            "ok": ok,
            "adapter": adapter,
            "timeout_sec": timeout_sec,
            "lines": lines[:40],
            "output": text.strip()[:2000],
            "status": self.status(),
        }

    def stack_bypass_detach(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Readme step 8: stop btattach."""
        device = (device or self._bypass_uart or "/dev/ttyUSB0").strip()
        logger().info(f"[8] Detach HCI UART: pkill btattach for {device}")
        self._shell_exec(f"sudo pkill -f 'btattach.*{device}' 2>/dev/null || true")
        self._shell_exec("sudo pkill hciattach 2>/dev/null || true")
        # Restore host bluetooth for later UTF apps (attach stopped it).
        self._shell_exec("sudo systemctl start bluetooth 2>/dev/null || true")
        self._bypass_attached = False
        self._set_state("stack_bypass_detached")
        logger().info("[8] btattach stopped (host bluetooth restarted)")
        return {"ok": True, "device": device, "status": self.status()}

    def _quiet_bluez_device_logs(self, *, manual_checklist: bool = False):
        """Silence DeviceManager / shell poll spam in simple-connect pytest reports."""
        import logging

        names = [
            "DeviceManager",
            "utf.interfaces.bluetooth.bluez.ble_device",
            "utf.interfaces.bluetooth.bluez.ble_device.DeviceManager",
        ]
        if manual_checklist:
            names.extend(
                (
                    "utf.interfaces.shell.shell",
                    "utf.interfaces.shell",
                    "dbus",
                    "dbus.connection",
                    "dbus.proxies",
                    "gi.repository.Gio",
                )
            )
        saved = []
        for name in names:
            lg = logging.getLogger(name)
            saved.append((lg, lg.level))
            lg.setLevel(logging.WARNING)
        return saved

    @staticmethod
    def _restore_log_levels(saved) -> None:
        for lg, level in saved or ():
            lg.setLevel(level)

    def status(self) -> Dict[str, Any]:
        conn = False
        conn_via = None
        manual = self.orchestration_kind in MANUAL_CHECKLIST_KINDS
        quiet = self.orchestration_kind in QUIET_HTTP_KINDS or manual
        saved_levels = self._quiet_bluez_device_logs(manual_checklist=manual) if quiet else []
        try:
            if self.target_address:
                if self._peer_link_seen:
                    conn = True
                    conn_via = "latched"
                else:
                    try:
                        conn = bool(self.bt.get_connection_status(self.target_address))
                        if conn:
                            conn_via = "bluez"
                    except Exception as exc:
                        logger().warning(f"get_connection_status failed: {exc}")
                        conn = False
                    # Legacy HCI ADV path: BlueZ may not flip Connected — check controller.
                    if not conn and self.orchestration_kind in LEGACY_HCI_PERIPHERAL_KINDS:
                        if self._hci_le_peer_connected(self.target_address):
                            conn = True
                            conn_via = "hcitool"
                if conn:
                    if not self._peer_link_seen:
                        if self.orchestration_kind in MANUAL_CHECKLIST_KINDS:
                            logger().info(
                                f"[4] Connection established (DUT {self.target_address})"
                            )
                        else:
                            logger().info(
                                f"Incoming DUT central link seen: {self.target_address}"
                                + (f" via {conn_via}" if conn_via else "")
                            )
                    self._peer_link_seen = True
        finally:
            self._restore_log_levels(saved_levels)
        self.connected = conn
        notifications = []
        if self.char_uuid and hasattr(self.bt, "gatt_adapter"):
            try:
                notifications = list(
                    self.bt.gatt_adapter.notifications.get(self.char_uuid, [])
                )
            except Exception as exc:
                logger().warning(f"notification read failed: {exc}")
        return {
            "state": self.state,
            "initialized": self.initialized,
            "local_address": self.local_address,
            "target_address": self.target_address,
            "connected": self.connected,
            "bonded": self.bonded,
            "passkey_set": self.passkey_set,
            "notifications_enabled": self.notifications_enabled,
            "service_uuid": self.service_uuid,
            "char_uuid": self.char_uuid,
            "notification_count": len(notifications),
            "stability_ok": self._stability_ok,
            "post_notify_stability_ok": self._post_notify_stability_ok,
            "post_notify_stability_done": self._post_notify_stability_done,
            "orchestration_complete_requested": self._orchestration_complete_requested,
            "orchestration_aborted": self._orchestration_aborted,
            "abort_reason": self._abort_reason,
            "orchestration_kind": self.orchestration_kind,
            "ibeacon_scan_stability_ok": self._ibeacon_scan_stability_ok,
            "ibeacon_scan_stability_done": self._ibeacon_scan_stability_done,
            "ibeacon_scan_sample_count": self._ibeacon_scan_sample_count,
            "ae_central_link_stability_ok": self._ae_central_link_stability_ok,
            "ae_central_link_stability_done": self._ae_central_link_stability_done,
            "ae_central_link_sample_count": self._ae_central_link_sample_count,
            "peer_link_seen": self._peer_link_seen,
            "connection_via": conn_via,
            "peripheral_mode": self.peripheral_mode,
            "peripheral_local_name": self.peripheral_local_name,
            "advertising_on": self._is_advertising(),
            "service_classes": self.service_classes,
            "scanned_devices": self.scanned_devices,
            "last_error": self.last_error,
        }

    def _is_advertising(self) -> bool:
        try:
            if getattr(self.bt, "advertisement_on", False):
                return True
            adv_mgr = getattr(self.bt, "adv_manager", None)
            if adv_mgr is not None and getattr(adv_mgr, "advertisement_on", False):
                return True
        except Exception:
            pass
        return bool(self.advertising_on)

    def _log_advertising_banner(self, local_name: str, local_address: str):
        """Confirm Pi LE advertising (short for manual-checklist apps)."""
        if self.orchestration_kind in MANUAL_CHECKLIST_KINDS:
            logger().info(
                f"[1] Pi advertising: name={local_name!r} addr={local_address} "
                "(connectable + local name + scan response)"
            )
            return
        logger().info("=" * 72)
        logger().info("*** RASPBERRY PI IS ADVERTISING (LE peripheral) ***")
        logger().info(f"  LocalName     : {local_name}")
        logger().info(f"  Local address : {local_address}")
        logger().info(f"  advertising_on: {self._is_advertising()}")
        logger().info(
            "  DUT should scan and find this name/address "
            "(RSI_REMOTE_DEVICE_NAME / RSI_BLE_DEV_ADDR)"
        )
        logger().info("=" * 72)
        # Best-effort HCI dump for operators watching UTF / docker logs.
        try:
            adapter = getattr(self.bt, "adapter_name", "hci0")
            shell = getattr(self.bt, "shell", None)
            if shell is not None:
                rc, stdout, stderr = shell.execute(f"sudo hciconfig {adapter}")
                out = (stdout or b"").decode(errors="replace").strip()
                err = (stderr or b"").decode(errors="replace").strip()
                if out:
                    logger().info(f"hciconfig {adapter}:\n{out}")
                if rc != 0 and err:
                    logger().warning(f"hciconfig {adapter} rc={rc}: {err}")
        except Exception as exc:
            logger().warning(f"hciconfig advertising check ignored: {exc}")

    @staticmethod
    def _legacy_hci_adv_data_params(local_name: str, *, include_hr_uuid: bool = False) -> str:
        """Build HCI LE Set Advertising Data params: length + 31-byte AD payload."""
        name = (local_name or "SILABS_DEV").encode("ascii", errors="ignore")[:18]
        payload = bytearray([0x02, 0x01, 0x06])  # Flags: LE General Discoverable
        payload.extend([len(name) + 1, 0x09])  # Complete Local Name
        payload.extend(name)
        if include_hr_uuid:
            payload.extend([0x03, 0x03, 0x0D, 0x18])  # Complete 16-bit UUID: Heart Rate
        if len(payload) > 31:
            payload = payload[:31]
        padded = bytes(payload) + bytes(31 - len(payload))
        return " ".join(f"0x{b:02X}" for b in bytes([len(payload)]) + padded)

    @staticmethod
    def _legacy_hci_scan_resp_params(local_name: str) -> str:
        """HCI LE Set Scan Response Data: Complete Local Name (readme requirement)."""
        scan_name = (local_name or "SILABS_DEV").encode("ascii", errors="ignore")[:29]
        scan_payload = bytearray([len(scan_name) + 1, 0x09]) + bytearray(scan_name)
        scan_padded = bytes(scan_payload) + bytes(31 - len(scan_payload))
        return " ".join(f"0x{b:02X}" for b in bytes([len(scan_payload)]) + scan_padded)

    @staticmethod
    def _legacy_hci_adv_params() -> str:
        """
        HCI LE Set Advertising Parameters: ADV_IND, public own address.

        Interval matches UTF advertise_remote_device (~20–40 ms) so rsi_ble_connect
        has a better chance before the sample app's 10 s connect cancel.
        """
        return (
            "0x20 0x00 "  # Advertising_Interval_Min (~20 ms)
            "0x40 0x00 "  # Advertising_Interval_Max (~40 ms)
            "0x00 "  # ADV_IND connectable undirected
            "0x00 "  # Own_Address_Type = Public
            "0x00 "  # Peer_Address_Type
            "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
            "0x07 "  # Channel map
            "0x00"  # Filter policy
        )

    def _enable_legacy_hci_advertising(self, local_name: str) -> None:
        """
        Switch controller to legacy ADV_IND after BlueZ GATT/adv bring-up.

        Matches utf_core start_smp_adv_with_hci_tool: HCI disable → set params/data
        → enable. Do NOT UnregisterAdvertisement first (that fights BlueZ/HCI).
        """
        quiet = self.orchestration_kind in MANUAL_CHECKLIST_KINDS
        if not quiet:
            logger().info(
                f"Switching Pi to LEGACY HCI advertising (ADV_IND) name={local_name!r}"
            )
        include_hr = bool(self.service_classes) and "HeartRateService" in (
            self.service_classes or []
        )
        adv_data = self._legacy_hci_adv_data_params(
            local_name, include_hr_uuid=include_hr
        )
        scan_resp = self._legacy_hci_scan_resp_params(local_name)
        try:
            self.bt.disable_advertisement()
        except Exception:
            pass
        self.bt.set_advertising_parameters(hci_adv_params=self._legacy_hci_adv_params())
        self.bt.set_advertising_data(hci_adv_data=adv_data)
        try:
            self.bt.set_scan_response_data(scan_resp_data=scan_resp)
        except Exception as exc:
            if not quiet:
                logger().warning(f"set_scan_response_data ignored: {exc}")
        self.bt.enable_advertisement()
        self.advertising_on = True
        if not quiet:
            logger().info(
                "Legacy HCI ADV_IND enabled "
                "(Complete Local Name in AD + scan response; GATT still registered)"
            )

    def init_stack(
        self,
        capability: str = DEFAULT_CAPABILITY,
        address: Optional[str] = None,
        service_classes: Optional[list] = None,
    ):
        """
        One-time BlueZ bring-up.

        BT service restart is allowed only here. After this returns, nothing in
        this controller will restart or power-cycle Bluetooth.
        """
        with self.lock:
            if self.initialized:
                return {
                    "ok": True,
                    "message": "already initialized",
                    "local_address": self.local_address,
                }

            self.capability = capability or DEFAULT_CAPABILITY
            target = (address or "00:00:00:00:00:00").upper()
            remove = address is not None
            self.service_classes = list(
                service_classes
                if service_classes is not None
                else DEFAULT_SERVICE_CLASSES
            )

            logger().info(
                "Initializing BlueZ once "
                f"(capability={self.capability}, restart_bt_service=True only here)"
            )
            logger().info(f"Registering GATT services on Pi: {self.service_classes}")
            self.local_address = self.bt.start_smp_scan(
                bt_dut_address=target,
                capability=self.capability,
                pin_code=PASSKEY_WAIT_SENTINEL,
                service_classes=self.service_classes,
                restart_bt_service=True,
                register_agent=True,
                remove_device=remove,
                discoverable=False,
            )
            assert self.local_address, "failed to init BlueZ on Raspberry Pi"
            # Keep adapter powered; never call power_off / restart after this.
            self.bt.set_power()
            self.initialized = True
            self._set_state("ready")
            return {
                "ok": True,
                "message": "BlueZ initialized",
                "local_address": self.local_address,
                "service_classes": self.service_classes,
            }

    def _resolve_peripheral_service_classes(
        self, service_classes: Optional[list]
    ) -> list:
        """
        GATT services for Pi peripheral.

        Explicit [] = LocalName-only simple connect (AE / BLE central readme demo —
        no Heart Rate / data-transfer profiles in the log).
        """
        if service_classes is not None and len(service_classes) == 0:
            return []
        classes = list(
            service_classes if service_classes is not None else DEFAULT_SERVICE_CLASSES
        )
        if "HeartRateService" not in classes:
            classes.insert(0, "HeartRateService")
        return classes

    def _start_local_heart_rate_notifications(self) -> bool:
        """
        Start Heart Rate Measurement notifies on the Pi GATT server so the link
        has active data transfer after the DUT connects (avoids idle disconnects
        when the central enabled CCCD / expects HRS traffic).
        """
        started = False
        try:
            apps = getattr(self.bt, "_gatt_applications", None) or []
            for app in apps:
                for service in getattr(app, "services", []) or []:
                    svc_name = type(service).__name__
                    svc_uuid = str(getattr(service, "uuid", "")).lower()
                    is_hrs = svc_name == "HeartRateService" or "180d" in svc_uuid
                    if not is_hrs:
                        continue
                    for char in getattr(service, "characteristics", []) or []:
                        char_name = type(char).__name__
                        char_uuid = str(getattr(char, "uuid", "")).lower()
                        if (
                            "HeartRateMeasurement" in char_name
                            or "2a37" in char_uuid
                            or "notify" in (getattr(char, "flags", None) or [])
                        ):
                            if hasattr(char, "StartNotify"):
                                char.StartNotify()
                                started = True
                                logger().info(
                                    "Started Pi Heart Rate Measurement notifications "
                                    f"(char={char_name}, uuid={char_uuid})"
                                )
        except Exception as exc:
            logger().warning(f"Could not start local HR notifications: {exc}")
        return started

    def init_peripheral_stack(
        self,
        local_name: str = "SILABS_DEV",
        capability: str = "NoInputNoOutput",
        service_classes: Optional[list] = None,
    ) -> Dict[str, Any]:
        """
        Pi as connectable peripheral (AE / central / longrange: DUT scans + connects).

        service_classes=[] → LocalName-only advertise (simple connect demo).
        Otherwise registers Heart Rate + demo GATT for apps that need profiles.
        """
        with self.lock:
            if self.initialized and self.peripheral_mode and self._is_advertising():
                self._log_advertising_banner(
                    self.peripheral_local_name or local_name,
                    self.local_address or "",
                )
                return {
                    "ok": True,
                    "message": "already initialized and advertising",
                    "local_address": self.local_address,
                    "peripheral_local_name": self.peripheral_local_name,
                    "advertising_on": True,
                    "service_classes": self.service_classes,
                    "advertise_uuids": list(PERIPHERAL_ADVERTISE_UUIDS),
                }

            self.peripheral_mode = True
            self.peripheral_local_name = local_name
            self.capability = capability or "NoInputNoOutput"
            self.service_classes = self._resolve_peripheral_service_classes(
                service_classes
            )
            simple_adv = len(self.service_classes) == 0
            adv_uuids = [] if simple_adv else list(PERIPHERAL_ADVERTISE_UUIDS)

            if simple_adv:
                logger().info(
                    f"Pi peripheral (simple connect): LocalName={local_name!r} only — "
                    "no Heart Rate / data-transfer GATT (SDK readme demo)"
                )
            else:
                logger().info(
                    f"Initializing Pi peripheral stack (local_name={local_name!r}, "
                    f"capability={self.capability}, "
                    f"gatt={self.service_classes}, ad_uuids={adv_uuids})"
                )
            # Keep for the whole run — BlueZ / re-advertise paths re-read this.
            os.environ["BLE_RASPI_ADV_LOCAL_NAME"] = local_name
            start_kwargs = dict(
                bt_dut_address="00:00:00:00:00:00",
                capability=self.capability,
                pin_code=PASSKEY_WAIT_SENTINEL,
                service_classes=self.service_classes,
                restart_bt_service=True,
                register_agent=True,
                remove_device=False,
                discoverable=True,
            )
            try:
                self.local_address = self.bt.start_smp_adv(
                    **start_kwargs,
                    advertise_gatt_uuids=False,
                    local_name=local_name,
                    advertise_uuids=adv_uuids,
                )
            except TypeError:
                # Older utf_core without new kwargs — still set env LocalName.
                logger().warning(
                    "start_smp_adv lacks advertise_uuids/local_name; "
                    "falling back (update utf_core on Pi for reliable AD + GATT)"
                )
                try:
                    self.local_address = self.bt.start_smp_adv(
                        **start_kwargs,
                        advertise_gatt_uuids=False,
                        local_name=local_name,
                    )
                except TypeError:
                    self.local_address = self.bt.start_smp_adv(**start_kwargs)

            assert self.local_address, "failed to init Pi peripheral stack"
            self.bt.set_power()
            # Give glib a moment; then require a real LE advertisement.
            time.sleep(1.0)
            self.advertising_on = self._is_advertising()
            if not self.advertising_on:
                raise RuntimeError(
                    "Pi peripheral stack initialized but LE advertising is OFF "
                    f"(name={local_name!r}, addr={self.local_address}). "
                    "Check BlueZ RegisterAdvertisement / experimental flags."
                )
            # Legacy central (dut_central / longrange) cannot complete connect to
            # BlueZ extended LEAdvertisement; switch to HCI ADV_IND.
            # ble_central uses dedicated init_ble_central_peripheral().
            # AE central keeps BlueZ LEAdvertisement (extended path works).
            legacy_hci = self.orchestration_kind == "dut_central"
            if legacy_hci:
                self._enable_legacy_hci_advertising(local_name)

            self.initialized = True
            self._set_state("peripheral_advertising")
            self._log_advertising_banner(local_name, self.local_address)
            if simple_adv:
                mode = "legacy HCI ADV_IND" if legacy_hci else "BlueZ LEAdvertisement"
                logger().info(f"Pi advertising ready ({mode}) — waiting for DUT connect")
            else:
                logger().info(
                    f"Pi GATT services ready for DUT discovery: {self.service_classes}"
                    + (
                        " [legacy HCI ADV_IND]"
                        if legacy_hci
                        else " [BlueZ LEAdvertisement]"
                    )
                )
            return {
                "ok": True,
                "message": (
                    "Pi peripheral LocalName-only advertising (simple connect)"
                    if simple_adv
                    else (
                        "Pi peripheral advertising with GATT (Heart Rate + demo services)"
                        + (" via legacy HCI ADV_IND" if legacy_hci else "")
                    )
                ),
                "local_address": self.local_address,
                "peripheral_local_name": self.peripheral_local_name,
                "advertising_on": True,
                "legacy_hci_adv": legacy_hci,
                "service_classes": self.service_classes,
                "advertise_uuids": adv_uuids,
                "simple_connect_adv": simple_adv,
            }

    def init_ble_central_peripheral(
        self,
        local_name: str = "SILABS_DEV",
        capability: str = "NoInputNoOutput",
    ) -> Dict[str, Any]:
        """
        Pi peripheral for SDK ble_central / siwx91x_bluetooth_le_central readme.

        Not the AE-central path. Phone/readme requirements:
          - connectable advertising
          - Complete Local Name in advertising data AND scan response
          - name = RSI_REMOTE_DEVICE_NAME (SILABS_DEV)

        Uses utf_core start_smp_adv_with_hci_tool (legacy ADV_IND) so
        rsi_ble_connect can complete (BlueZ LEAdvertisement is often extended).
        """
        with self.lock:
            local_name = local_name or "SILABS_DEV"
            # Keep caller's kind (datalength / longrange / ble_central); never force ble_central.
            if self.orchestration_kind not in LEGACY_HCI_PERIPHERAL_KINDS:
                self.orchestration_kind = "ble_central"
            quiet = self.orchestration_kind in MANUAL_CHECKLIST_KINDS
            if (
                self.initialized
                and self.peripheral_mode
                and self.orchestration_kind in LEGACY_HCI_PERIPHERAL_KINDS
                and self._is_advertising()
            ):
                self._log_advertising_banner(
                    self.peripheral_local_name or local_name,
                    self.local_address or "",
                )
                return {
                    "ok": True,
                    "message": f"already initialized ({self.orchestration_kind} legacy HCI)",
                    "local_address": self.local_address,
                    "peripheral_local_name": self.peripheral_local_name,
                    "advertising_on": True,
                    "legacy_hci_adv": True,
                    "service_classes": self.service_classes,
                }

            self.peripheral_mode = True
            self.peripheral_local_name = local_name
            self.capability = capability or "NoInputNoOutput"
            # Minimal GATT so BlueZ owns the ACL after connect; AD is LocalName-only.
            self.service_classes = ["BatteryService"]
            os.environ["BLE_RASPI_ADV_LOCAL_NAME"] = local_name

            adv_data = self._legacy_hci_adv_data_params(
                local_name, include_hr_uuid=False
            )
            scan_resp = self._legacy_hci_scan_resp_params(local_name)
            hci_adv_params = self._legacy_hci_adv_params()

            if not quiet:
                logger().info(
                    f"Initializing BLE Central peripheral (SDK readme): "
                    f"LocalName={local_name!r} in AD + scan response, "
                    f"ADV_IND via start_smp_adv_with_hci_tool"
                )
            if not hasattr(self.bt, "start_smp_adv_with_hci_tool"):
                raise RuntimeError(
                    "utf_core BlueZ lacks start_smp_adv_with_hci_tool — "
                    "update utf_core on the Pi for ble_central"
                )

            saved_levels = self._quiet_bluez_device_logs(manual_checklist=quiet) if quiet else []
            try:
                self.local_address = self.bt.start_smp_adv_with_hci_tool(
                    bt_dut_address="00:00:00:00:00:00",
                    pin_code=PASSKEY_WAIT_SENTINEL,
                    capability=self.capability,
                    service_classes=self.service_classes,
                    restart_bt_service=True,
                    register_agent=True,
                    hci_adv_params=hci_adv_params,
                    hci_adv_data=adv_data,
                    scan_resp_data=scan_resp,
                )
            finally:
                self._restore_log_levels(saved_levels)
            assert self.local_address, "failed to init ble_central Pi peripheral"
            self.bt.set_power()
            time.sleep(0.5)
            # Re-assert HCI ADV in case BlueZ briefly reclaimed advertising.
            saved_levels = self._quiet_bluez_device_logs(manual_checklist=quiet) if quiet else []
            try:
                self._enable_legacy_hci_advertising(local_name)
            except Exception as exc:
                logger().warning(f"HCI ADV re-assert after init: {exc}")
            finally:
                self._restore_log_levels(saved_levels)
            self.advertising_on = True
            self.initialized = True
            self._set_state("peripheral_advertising")
            self._log_advertising_banner(local_name, self.local_address)
            if not quiet:
                logger().info(
                    "Pi ready for ble_central: legacy ADV_IND + Complete Local Name "
                    f"(addr={self.local_address}) — waiting for DUT rsi_ble_connect"
                )
                logger().info(
                    "Firmware tip: set RSI_REMOTE_DEVICE_NAME=\"SILABS_DEV\" or "
                    f"RSI_BLE_DEV_ADDR=\"{self.local_address}\" (LE_PUBLIC_ADDRESS). "
                    "SDK sample ENABLE_NWP_POWER_SAVE=1 often blocks connect — "
                    "prefer 0 for lab automation (AE central sample uses 0)."
                )
            return {
                "ok": True,
                "message": (
                    f"Pi {self.orchestration_kind} peripheral: legacy HCI ADV_IND with "
                    "Complete Local Name in AD + scan response"
                ),
                "local_address": self.local_address,
                "peripheral_local_name": self.peripheral_local_name,
                "advertising_on": True,
                "legacy_hci_adv": True,
                "service_classes": self.service_classes,
                "simple_connect_adv": True,
            }

    def set_expected_peer(self, address: str) -> Dict[str, Any]:
        """Host sets DUT MAC to poll for incoming central connection."""
        with self.lock:
            if not address:
                return {"ok": False, "error": "address is required"}
            new_addr = str(address).upper()
            if self.target_address != new_addr:
                self._peer_link_seen = False
            self.target_address = new_addr
            self._set_state("awaiting_dut_central")
            # status() may latch peer_link_seen if already connected.
            st = self.status()
            return {
                "ok": True,
                "target_address": self.target_address,
                "peer_link_seen": self._peer_link_seen,
                "status": st,
            }

    def start_advertise(
        self,
        local_name: str = "SILABS_DEV",
        capability: str = "NoInputNoOutput",
        service_classes: Optional[list] = None,
        legacy_hci: bool = True,
    ) -> Dict[str, Any]:
        """
        Start Pi LE peripheral advertising only (does not wait for DUT connect).

        Default legacy_hci=True uses the ble_central readme path (HCI ADV_IND).
        Not used for ble_ae_peripheral (DUT advertises; Pi scans/connects).
        """
        local_name = local_name or "SILABS_DEV"
        try:
            if legacy_hci:
                result = self.init_ble_central_peripheral(
                    local_name=local_name,
                    capability=capability or "NoInputNoOutput",
                )
            else:
                result = self.init_peripheral_stack(
                    local_name=local_name,
                    capability=capability or "NoInputNoOutput",
                    service_classes=service_classes,
                )
        except Exception as exc:
            logger().exception("start_advertise: peripheral init failed")
            return {"ok": False, "error": f"peripheral advertise failed: {exc}"}

        if not result.get("ok"):
            return result

        result["status"] = self.status()
        return result

    def advertise_and_wait_dut_connect(
        self,
        address: str,
        local_name: str = "SILABS_DEV",
        timeout_sec: int = 180,
        capability: str = "NoInputNoOutput",
        service_classes: Optional[list] = None,
        start_hr_notify: bool = True,
    ) -> Dict[str, Any]:
        """
        One-shot API: Pi advertises as peripheral (with Heart Rate + demo GATT),
        then waits for DUT (central) to connect.

        Roles: Raspberry Pi = advertiser/peripheral, DUT = scanner/central initiator.
        """
        if not address:
            return {"ok": False, "error": "address is required"}
        dut = str(address).upper()
        timeout_sec = max(1, int(timeout_sec))
        local_name = local_name or "SILABS_DEV"

        try:
            init = self.init_peripheral_stack(
                local_name=local_name,
                capability=capability or "NoInputNoOutput",
                service_classes=service_classes,
            )
        except Exception as exc:
            logger().exception("advertise_and_wait_dut_connect: peripheral init failed")
            return {"ok": False, "error": f"peripheral advertise failed: {exc}"}

        if not init.get("ok"):
            return {
                "ok": False,
                "error": init.get("error") or init.get("message") or "advertise failed",
                "init": init,
            }
        if not init.get("advertising_on", True) and not self._is_advertising():
            return {
                "ok": False,
                "error": "Pi LE advertising is not active",
                "init": init,
                "status": self.status(),
            }

        peer = self.set_expected_peer(dut)
        if not peer.get("ok"):
            return peer

        logger().info(
            f"Waiting up to {timeout_sec}s for DUT {dut} to connect to "
            f"advertising Pi name={local_name!r} addr={self.local_address} "
            f"gatt={self.service_classes}"
        )
        self._log_advertising_banner(local_name, self.local_address or "")

        sw = Stopwatch()
        while sw.elapsed_sec < timeout_sec:
            st = self.status()
            if st.get("connected"):
                hr_notify = False
                if start_hr_notify:
                    hr_notify = self._start_local_heart_rate_notifications()
                self._set_state("connected")
                logger().info(
                    f"DUT {dut} connected to advertising Pi "
                    f"(elapsed={sw.elapsed_sec:.1f}s, hr_notify={hr_notify})"
                )
                return {
                    "ok": True,
                    "message": (
                        "Pi advertising with GATT; DUT connected"
                        + (" (Heart Rate notify started)" if hr_notify else "")
                    ),
                    "local_address": self.local_address,
                    "peripheral_local_name": self.peripheral_local_name,
                    "target_address": self.target_address,
                    "advertising_on": self._is_advertising(),
                    "connected": True,
                    "service_classes": self.service_classes,
                    "advertise_uuids": list(PERIPHERAL_ADVERTISE_UUIDS),
                    "heart_rate_notify_started": hr_notify,
                    "waited_sec": round(sw.elapsed_sec, 1),
                    "status": self.status(),
                }
            time.sleep(1.0)

        self._set_state(
            "connect_timeout",
            f"DUT {dut} did not connect within {timeout_sec}s",
        )
        return {
            "ok": False,
            "error": (
                f"timeout: DUT {dut} did not connect within {timeout_sec}s "
                f"(Pi advertising as {local_name!r} / {self.local_address})"
            ),
            "local_address": self.local_address,
            "peripheral_local_name": self.peripheral_local_name,
            "target_address": self.target_address,
            "advertising_on": self._is_advertising(),
            "connected": False,
            "service_classes": self.service_classes,
            "advertise_uuids": list(PERIPHERAL_ADVERTISE_UUIDS),
            "waited_sec": timeout_sec,
            "status": self.status(),
        }

    def scan(
        self,
        timeout: int = 10,
        address: Optional[str] = None,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Discover peers. Optional filters:
          - address: MAC must appear in the scan cache
          - name: Alias/LocalName substring match (e.g. AE_PERIPHERAL)
        """
        with self.lock:
            if not self.initialized:
                self.init_stack(address=address)

            self._set_state("scanning")
            # Do not restart BT — only (re)start discovery.
            try:
                self.bt.stop_scanning()
            except Exception:
                pass

            # Do NOT RemoveDevice before scan for connect flows: that deletes the
            # BlueZ Device1 and leaves Trusted/Connect with UnknownObject if the
            # peer is not immediately rediscovered (common for AE peripherals).

            scan_kwargs = {}
            if self.orchestration_kind == "ae_peripheral":
                # Extended advertisers: force LE transport + keep duplicate reports.
                scan_kwargs = {"transport": "le", "duplicate_data": False}
            try:
                self.bt.start_scanning(**scan_kwargs)
            except TypeError:
                # Older utf_core without duplicate_data kwarg.
                self.bt.start_scanning(transport=scan_kwargs.get("transport"))
            time.sleep(max(1, int(timeout)))
            self.bt.stop_scanning()
            devices = self.bt.get_devices() or {}
            self.scanned_devices = {str(k).upper(): v for k, v in devices.items()}
            self._set_state("ready")

            found = None
            matched_address = None
            name_matches: list = []
            if address:
                addr_u = address.upper()
                found = addr_u in self.scanned_devices
                if found:
                    matched_address = addr_u
                    # Confirm a live D-Bus Device1 (not a stale Alias cache).
                    exists = getattr(self.bt, "device_object_exists", None)
                    if callable(exists) and not exists(addr_u):
                        found = False
                        matched_address = None
            if name:
                needle = str(name).strip().upper()
                for mac, alias in self.scanned_devices.items():
                    alias_s = str(alias or "").upper()
                    if needle and needle in alias_s:
                        name_matches.append(mac)
                if name_matches and not matched_address:
                    matched_address = name_matches[0]
                    found = True
                elif name_matches and found is None:
                    found = True
                elif found is None:
                    found = False

            if self.orchestration_kind == "ae_peripheral":
                logger().info(
                    f"Scan done: devices={len(self.scanned_devices)} "
                    f"name={name!r} matched={matched_address} "
                    f"address_found={found}"
                )

            return {
                "ok": True,
                "devices": self.scanned_devices,
                "address_requested": address.upper() if address else None,
                "name_requested": name,
                "name_matches": name_matches,
                "matched_address": matched_address,
                "address_found": found,
            }

    def _ensure_device1(self, address: str, *, timeout_sec: float = 12.0) -> bool:
        """Make sure BlueZ has a live Device1 before Pair/Connect (scan if needed)."""
        exists_fn = getattr(self.bt, "device_object_exists", None)
        rediscover = getattr(self.bt, "_rediscover_device", None)
        if callable(exists_fn) and exists_fn(address):
            return True
        if callable(rediscover):
            logger().info(
                f"Device1 missing for {address} — rediscover (≤{timeout_sec:.0f}s) …"
            )
            try:
                rediscover(address, timeout_sec=timeout_sec)
            except Exception as exc:
                logger().warning(f"rediscover {address}: {exc}")
        return bool(callable(exists_fn) and exists_fn(address))

    def _device_is_paired(self, address: str) -> bool:
        """Read org.bluez.Device1.Paired (True after successful SMP)."""
        try:
            path = mac_address_to_dbus_bt_path(
                self.bt.adapter_path, mac_address=address
            )
            mgr = getattr(self.bt, "_dev_manager", None)
            if mgr is None:
                return False
            return bool(mgr.get_property(self.bt.bus, path, prop="Paired"))
        except Exception:
            return False

    def _wait_peer_smp_bond(self, address: str, timeout_sec: float = 120.0) -> None:
        """
        After plain Connect: DUT ble_secureconnection initiates SMP; BlueZ agent
        handles RequestPasskey when host POSTs /ble/passkey.
        """
        logger().info(
            f"Waiting for peer-initiated SMP bond on {address} (≤{timeout_sec:.0f}s)"
        )
        sw = Stopwatch()
        while sw.elapsed_sec < timeout_sec:
            if self.state in ("pair_failed", "orchestration_aborted"):
                return
            try:
                connected = bool(self.bt.get_connection_status(address))
            except Exception:
                connected = False
            self.connected = connected
            paired = self._device_is_paired(address)
            if paired and connected:
                self.bonded = True
                self._set_state("bonded")
                logger().info(f"Peer SMP bond complete for {address}")
                self._verify_stable_connection(address)
                return
            if not connected and sw.elapsed_sec > 8:
                # Brief gaps OK right after connect; persistent drop is failure.
                # HoG is exempt: the DUT drops and re-pairs repeatedly while the agent
                # is still blocked inside RequestPasskey, and moving to pair_failed
                # here stops the host from ever submitting the passkey.
                if (
                    sw.elapsed_sec > 25
                    and not self.passkey_set
                    and self.orchestration_kind != "hid_on_gatt"
                ):
                    self._set_state(
                        "pair_failed",
                        "link dropped before passkey (peer SMP)",
                    )
                    return
            time.sleep(1.0)
        if not self.bonded:
            self._set_state(
                "pair_failed",
                "peer SMP / passkey timed out (DUT should initiate SMP after connect)",
            )

    def _pair_worker(self, address: str):
        """
        Background pair+connect so /ble/passkey can be accepted concurrently.

        pair_and_connect() does Pair() first and only issues Connect() from the
        pairing reply handler. Calling Connect() before Pair() makes BlueZ open a
        second link and then tear one down mid-SMP, which the peer reports as
        HCI 0x13 (remote user terminated).

        Note: ble_secureconnection uses _wait_peer_smp_bond instead (phone flow).
        """
        try:
            if not self._ensure_device1(address, timeout_sec=15.0):
                self._set_state(
                    "pair_failed",
                    f"Device1 missing for {address} (scan/rediscover failed)",
                )
                return
            logger().info(f"Pair worker: pair_and_connect to {address}")
            self._set_state("pairing")
            ok = self.bt.pair_and_connect(dev_addr=address, timeout=120)
            if ok:
                self.bonded = True
                self._set_state("bonded")
                logger().info(f"Pair worker: bonding complete for {address}")
                self._verify_stable_connection(address)
            else:
                err = getattr(self.bt, "_last_pair_error", None) or (
                    "pair_and_connect() returned False"
                )
                self._set_state("pair_failed", str(err))
        except Exception as exc:
            logger().error(f"Pair worker failed: {exc}")
            self._set_state("pair_failed", str(exc))

    def _verify_stable_connection(self, address: str):
        """
        Poll connection for STABILITY_POLL_SEC so immediate remote disconnects
        are detected instead of treating a momentary connect as success.
        """
        logger().info(
            f"Stability check: polling connection to {address} "
            f"for {STABILITY_POLL_SEC}s (interval={STABILITY_INTERVAL_SEC}s)"
        )
        sw = Stopwatch()
        samples = []
        while sw.elapsed_sec < STABILITY_POLL_SEC:
            try:
                connected = bool(self.bt.get_connection_status(address))
            except Exception as exc:
                logger().warning(f"stability poll error: {exc}")
                connected = False
            samples.append(connected)
            self.connected = connected
            if not connected:
                self._stability_ok = False
                self._set_state(
                    "disconnected",
                    "connection dropped during stability poll — "
                    "immediate disconnect observed",
                )
                return
            time.sleep(STABILITY_INTERVAL_SEC)

        self._stability_ok = all(samples) and len(samples) > 0
        if self._stability_ok:
            self._set_state("stable")
            logger().info("Stability check PASSED — connection remained up")
        else:
            self._set_state("unstable", "connection not consistently up")

    def run_post_notify_stability(self, duration_sec: int = POST_NOTIFY_STABILITY_SEC) -> bool:
        """
        After notifications are enabled, keep the link up for duration_sec (Build Studio).

        Does not power off BT or stop the HTTP server; pytest exits only after
        POST /ble/orchestration/complete.
        """
        address = self.target_address
        if not address:
            self._post_notify_stability_done = True
            self._post_notify_stability_ok = False
            return False
        logger().info(
            f"Post-notify stability: polling connection to {address} "
            f"for {duration_sec}s (interval={STABILITY_INTERVAL_SEC}s)"
        )
        self._set_state("post_notify_stability")
        sw = Stopwatch()
        samples = []
        while sw.elapsed_sec < duration_sec:
            try:
                connected = bool(self.bt.get_connection_status(address))
            except Exception as exc:
                logger().warning(f"post-notify stability poll error: {exc}")
                connected = False
            samples.append(connected)
            self.connected = connected
            if not connected:
                self._post_notify_stability_ok = False
                self._post_notify_stability_done = True
                self._set_state(
                    "disconnected",
                    "connection dropped during post-notify stability",
                )
                return False
            time.sleep(STABILITY_INTERVAL_SEC)

        self._post_notify_stability_ok = all(samples) and len(samples) > 0
        self._post_notify_stability_done = True
        if self._post_notify_stability_ok:
            self._set_state("post_notify_stable")
            logger().info("Post-notify stability PASSED — connection remained up")
        else:
            self._set_state("post_notify_unstable", "connection not consistently up")
        return self._post_notify_stability_ok

    def complete_orchestration(self) -> Dict[str, Any]:
        """Host-requested graceful end: stop HTTP server; pytest completes normally."""
        with self.lock:
            if self.orchestration_kind == "ibeacon_scan":
                if not self._ibeacon_scan_stability_done:
                    return {
                        "ok": False,
                        "error": (
                            "iBeacon scan stability not finished on host; "
                            "complete POST /ble/orchestration/complete only after "
                            "5 min scan stability passes"
                        ),
                        "status": self.status(),
                    }
                if not self._ibeacon_scan_stability_ok:
                    return {
                        "ok": False,
                        "error": "iBeacon scan stability failed (DUT missing from a scan sample)",
                        "status": self.status(),
                    }
                self._orchestration_complete_requested = True
                self._orchestration_finish.set()
                self._set_state("orchestration_complete")
                return {
                    "ok": True,
                    "message": (
                        "iBeacon scan orchestration complete; HTTP server will stop"
                    ),
                    "status": self.status(),
                }

            if self.orchestration_kind in SIMPLE_CONNECT_HOST_MARK_KINDS:
                if not self._ae_central_link_stability_done:
                    return {
                        "ok": False,
                        "error": (
                            "Simple-connect mark not finished; complete only after "
                            "host marks connect OK"
                        ),
                        "status": self.status(),
                    }
                if not self._ae_central_link_stability_ok:
                    return {
                        "ok": False,
                        "error": "Simple-connect mark failed (connection / stability)",
                        "status": self.status(),
                    }
                self._orchestration_complete_requested = True
                self._orchestration_finish.set()
                self._set_state("orchestration_complete")
                return {
                    "ok": True,
                    "message": "Simple-connect orchestration complete; HTTP server will stop",
                    "status": self.status(),
                }

            if not self._post_notify_stability_done:
                return {
                    "ok": False,
                    "error": (
                        "post-notify stability still running; wait until "
                        "post_notify_stability_done is true in GET /ble/status"
                    ),
                    "status": self.status(),
                }
            if not self._post_notify_stability_ok:
                return {
                    "ok": False,
                    "error": "post-notify stability failed; cannot complete orchestration",
                    "status": self.status(),
                }
            self._orchestration_complete_requested = True
            self._orchestration_finish.set()
            self._set_state("orchestration_complete")
            return {
                "ok": True,
                "message": (
                    "orchestration complete; HTTP server will stop and pytest will finish"
                ),
                "status": self.status(),
            }

    def abort_orchestration(self, reason: str = "aborted by host") -> Dict[str, Any]:
        """
        Force-stop BLE HTTP server and end the pytest (failed report).

        Unlike /ble/orchestration/complete, this skips stability gates so Build
        Studio can tear down a stale or failed run before relaunching UTF.
        """
        with self.lock:
            reason = (reason or "aborted by host").strip() or "aborted by host"
            self._orchestration_aborted = True
            self._abort_reason = reason
            self._orchestration_complete_requested = True
            self._orchestration_finish.set()
            self._set_state("orchestration_aborted", reason)
            logger().warning(f"Orchestration ABORT requested: {reason}")

            server = self._http_server
            if server is not None:

                def _stop_httpd():
                    try:
                        server.stop()
                    except Exception as exc:
                        logger().warning(f"abort httpd stop: {exc}")

                threading.Thread(target=_stop_httpd, daemon=True).start()

            return {
                "ok": True,
                "aborted": True,
                "message": f"BLE HTTP server stopping; pytest will fail: {reason}",
                "reason": reason,
                "status": self.status(),
            }

    def mark_ibeacon_scan_stability(
        self, *, ok: bool, sample_count: int
    ) -> Dict[str, Any]:
        """Host reports iBeacon scan stability result (advertiser visible every interval)."""
        with self.lock:
            self._ibeacon_scan_stability_ok = bool(ok)
            self._ibeacon_scan_stability_done = True
            self._ibeacon_scan_sample_count = int(sample_count)
            if ok:
                self._set_state("ibeacon_scan_stable")
            else:
                self._set_state("ibeacon_scan_unstable", "DUT not seen in all scan samples")
            return {
                "ok": ok,
                "sample_count": sample_count,
                "status": self.status(),
            }

    def mark_ae_central_link_stability(
        self, *, ok: bool, sample_count: int
    ) -> Dict[str, Any]:
        """Host reports DUT-central → Pi-peripheral link stability (connected each sample)."""
        with self.lock:
            self._ae_central_link_stability_ok = bool(ok)
            self._ae_central_link_stability_done = True
            self._ae_central_link_sample_count = int(sample_count)
            if ok:
                self._set_state("ae_central_link_stable")
            else:
                self._set_state(
                    "ae_central_link_unstable", "DUT central link dropped during stability"
                )
            return {
                "ok": ok,
                "sample_count": sample_count,
                "status": self.status(),
            }

    def _maybe_auto_enable_notifications(self) -> Optional[Dict[str, Any]]:
        """Orchestrated apps: subscribe to notify char after link is up (no extra HTTP step)."""
        if not self.auto_enable_notifications or self.notifications_enabled:
            return None
        if not self.target_address:
            return None
        try:
            if not self.bt.get_connection_status(self.target_address):
                return None
        except Exception:
            return None
        result = self.enable_notifications(
            service_uuid=self.auto_notify_service_uuid,
            char_uuid=self.auto_notify_char_uuid,
        )
        if result.get("ok"):
            logger().info(
                "Auto-enabled notifications on "
                f"service={self.service_uuid} char={self.char_uuid}"
            )
        else:
            logger().info(f"Auto-enable notifications deferred/failed: {result}")
        return result

    def connect(
        self,
        address: str,
        capability: Optional[str] = None,
        bond: bool = True,
        conn_params: Optional[Dict[str, Any]] = None,
        address_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Connect to a peer.

        bond=True  -> pair_and_connect (SMP / passkey flow; use /ble/passkey next)
        bond=False -> plain Connect only (no SMP, no passkey)

        conn_params keys (hcitool lecup units: interval 1.25ms, timeout 10ms):
            min_conn_interval, max_conn_interval, conn_latency, supervision_timeout
        address_type: optional 'public' or 'random' (AE SET2 / SET1)
        """
        address = address.upper()
        conn_params = conn_params or {}
        with self.lock:
            if self.orchestration_kind == "testmodes":
                return {
                    "ok": False,
                    "error": (
                        "ble_testmodes does not use GATT connect. "
                        "Use POST /ble/testmodes/le-receiver-test (DUT TX) or "
                        "/ble/testmodes/le-transmitter-test (DUT RX), then "
                        "/ble/testmodes/le-test-end — same as readme hcitool steps."
                    ),
                    "hint": "Host must use orchestration_kind=testmodes (restart Build Studio)",
                    "status": self.status(),
                }
            if self.orchestration_kind == "stack_bypass":
                return {
                    "ok": False,
                    "error": (
                        "bt_stack_bypass does not use GATT connect. "
                        "Use /ble/stack-bypass/attach → up → leadv → lescan → detach "
                        "(HCI UART on Pi, same as readme btattach/hciconfig)."
                    ),
                    "hint": "Host must use orchestration_kind=stack_bypass",
                    "status": self.status(),
                }
            if not self.initialized:
                # NoInputNoOutput is enough when bonding is disabled.
                cap = capability or (
                    self.capability if bond else "NoInputNoOutput"
                )
                self.init_stack(capability=cap, address=address)
            elif capability:
                self.capability = capability

            if self.pair_thread and self.pair_thread.is_alive():
                return {
                    "ok": False,
                    "error": "pair already in progress; POST /ble/passkey or wait",
                    "status": self.status(),
                }

            self.target_address = address
            self.bonded = False
            self.passkey_set = False
            self._stability_ok = False
            self.notifications_enabled = False
            self.char_path = None

            try:
                self.bt.stop_scanning()
            except Exception:
                pass

            if not bond:
                self._set_state("connecting")
                logger().info(
                    f"Plain connect (no SMP) to {address}"
                    + (f" address_type={address_type}" if address_type else "")
                )
                # Require a live Device1 from scan first. Blind ConnectDevice on
                # Pi BlueZ NoReply/segfaults when AE DUT is not in the cache
                # (that took down the HTTP server and broke AE peripheral runs).
                exists_fn = getattr(self.bt, "device_object_exists", None)
                rediscover = getattr(self.bt, "_rediscover_device", None)
                if callable(exists_fn) and not exists_fn(address):
                    if callable(rediscover):
                        logger().info(
                            f"Device1 missing for {address} — short rediscover …"
                        )
                        rediscover(address, timeout_sec=8)
                    if not exists_fn(address):
                        self._set_state(
                            "connect_failed",
                            "peer not discovered yet",
                        )
                        return {
                            "ok": False,
                            "error": (
                                f"BLE connect deferred: {address} not in BlueZ "
                                "scan cache (scan again; do not ConnectDevice blind)"
                            ),
                            "status": self.status(),
                        }
                connect_kwargs = {
                    "dev_addr": address,
                    "min_conn_interval": conn_params.get("min_conn_interval"),
                    "max_conn_interval": conn_params.get("max_conn_interval"),
                    "conn_latency": conn_params.get("conn_latency"),
                    "supervision_timeout": conn_params.get("supervision_timeout"),
                }
                if address_type:
                    connect_kwargs["addr_type"] = address_type
                try:
                    connected = bool(self.bt.connect(**connect_kwargs))
                except TypeError:
                    connect_kwargs.pop("addr_type", None)
                    try:
                        connected = bool(self.bt.connect(**connect_kwargs))
                    except Exception as exc:
                        self._set_state("connect_failed", str(exc))
                        return {
                            "ok": False,
                            "error": f"BLE connect failed: {exc}",
                            "status": self.status(),
                        }
                except Exception as exc:
                    err = str(exc)
                    if (
                        ("UnknownObject" in err or "doesn't exist" in err)
                        and callable(rediscover)
                    ):
                        logger().warning(
                            f"Connect UnknownObject for {address}; rediscover + retry"
                        )
                        try:
                            rediscover(address, timeout_sec=8)
                            if callable(exists_fn) and not exists_fn(address):
                                raise RuntimeError(
                                    f"{address} still not in BlueZ cache after scan"
                                )
                            connected = bool(self.bt.connect(**connect_kwargs))
                        except Exception as exc2:
                            self._set_state("connect_failed", str(exc2))
                            return {
                                "ok": False,
                                "error": f"BLE connect failed: {exc2}",
                                "status": self.status(),
                            }
                    else:
                        self._set_state("connect_failed", err)
                        return {
                            "ok": False,
                            "error": f"BLE connect failed: {exc}",
                            "status": self.status(),
                        }

                self.connected = connected
                if not connected:
                    self._set_state("connect_failed", "connect() returned False")
                    return {
                        "ok": False,
                        "error": "BLE connect failed",
                        "status": self.status(),
                    }

                # Confirm the link is still up before enabling notifications.
                time.sleep(2)
                if not self.bt.get_connection_status(address):
                    self._set_state(
                        "disconnected",
                        "immediate disconnect after plain connect",
                    )
                    return {
                        "ok": False,
                        "error": "immediate disconnect after connect",
                        "status": self.status(),
                    }

                self._set_state("connected")
                # Stability poll in background so the HTTP response returns quickly.
                self.pair_thread = threading.Thread(
                    target=self._verify_stable_connection,
                    args=(address,),
                    name="ble-stability-worker",
                    daemon=True,
                )
                self.pair_thread.start()

                auto = self._maybe_auto_enable_notifications()
                return {
                    "ok": True,
                    "message": (
                        "Connected without SMP/passkey."
                        + (
                            " Notifications auto-enabled."
                            if auto and auto.get("ok")
                            else " Call /ble/notifications/enable if not auto-enabled."
                        )
                    ),
                    "bonded": False,
                    "notifications_auto_enable": auto,
                    "status": self.status(),
                }

            # ---- SMP / passkey path ----
            # Require a live Device1 first (same as plain connect). Blind Pair on a
            # missing object returns UnknownObject and the DUT never shows a passkey.
            if not self._ensure_device1(address, timeout_sec=15.0):
                self._set_state(
                    "connect_failed",
                    "peer not discovered yet",
                )
                return {
                    "ok": False,
                    "error": (
                        f"BLE pair deferred: {address} not in BlueZ scan cache "
                        "(POST /ble/scan first, or use secureconnection host path)"
                    ),
                    "status": self.status(),
                }

            self.bt.set_pin(pin_code=PASSKEY_WAIT_SENTINEL)

            # Phone-role apps (secureconnection / privacy): Connect first; DUT then
            # initiates SMP. Pi Pair() alone often fails on this BlueZ stack.
            if self.orchestration_kind in PEER_INITIATED_SMP_KINDS:
                self._set_state("connecting")
                logger().info(
                    f"{self.orchestration_kind}: plain Connect then peer SMP to {address}"
                )
                connect_kwargs = {
                    "dev_addr": address,
                    "min_conn_interval": conn_params.get("min_conn_interval"),
                    "max_conn_interval": conn_params.get("max_conn_interval"),
                    "conn_latency": conn_params.get("conn_latency"),
                    "supervision_timeout": conn_params.get("supervision_timeout"),
                }
                if address_type:
                    connect_kwargs["addr_type"] = address_type
                try:
                    connected = bool(self.bt.connect(**connect_kwargs))
                except TypeError:
                    connect_kwargs.pop("addr_type", None)
                    try:
                        connected = bool(self.bt.connect(**connect_kwargs))
                    except Exception as exc:
                        self._set_state("connect_failed", str(exc))
                        return {
                            "ok": False,
                            "error": f"BLE connect failed: {exc}",
                            "status": self.status(),
                        }
                except Exception as exc:
                    self._set_state("connect_failed", str(exc))
                    return {
                        "ok": False,
                        "error": f"BLE connect failed: {exc}",
                        "status": self.status(),
                    }
                self.connected = connected
                if not connected or not self.bt.get_connection_status(address):
                    self._set_state("connect_failed", "connect() returned False")
                    return {
                        "ok": False,
                        "error": "BLE connect failed before peer SMP",
                        "status": self.status(),
                    }
                self._set_state("awaiting_passkey")
                self.pair_thread = threading.Thread(
                    target=self._wait_peer_smp_bond,
                    args=(address,),
                    name="ble-peer-smp-worker",
                    daemon=True,
                )
                self.pair_thread.start()
                return {
                    "ok": True,
                    "message": (
                        "Connected; DUT should initiate SMP and display passkey. "
                        "POST /ble/passkey promptly (agent waits up to ~90s)."
                    ),
                    "bonded": False,
                    "peer_initiated_smp": True,
                    "status": self.status(),
                }

            self._set_state("connecting")
            self.pair_thread = threading.Thread(
                target=self._pair_worker,
                args=(address,),
                name="ble-pair-worker",
                daemon=True,
            )
            self.pair_thread.start()

            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                if self.state == "pair_failed":
                    break
                try:
                    if self.bt.get_connection_status(address):
                        self.connected = True
                        break
                except Exception:
                    pass
                time.sleep(1)

            if self.state == "pair_failed":
                return {
                    "ok": False,
                    "error": self.last_error or "pair_and_connect failed",
                    "bonded": False,
                    "status": self.status(),
                }

            self._set_state("awaiting_passkey")
            return {
                "ok": True,
                "message": (
                    "pair_and_connect started. Peer should display a passkey. "
                    "POST /ble/passkey with that value promptly "
                    "(BlueZ agent waits ~90s for RequestPasskey)."
                ),
                "bonded": False,
                "status": self.status(),
            }

    def submit_passkey(self, passkey: str) -> Dict[str, Any]:
        passkey = str(passkey).strip()
        if not passkey.isdigit() or len(passkey) != 6:
            return {"ok": False, "error": "passkey must be a 6-digit numeric string"}

        with self.lock:
            if not self.target_address:
                return {"ok": False, "error": "no active target; call /ble/connect first"}

            if self.bonded and self.connected:
                return {
                    "ok": True,
                    "message": "already bonded",
                    "status": self.status(),
                }

            logger().info(f"Submitting runtime passkey to BlueZ agent: {passkey}")
            self.bt.set_pin(pin_code=passkey)
            self.passkey_set = True
            self._set_state("passkey_submitted")

        # Wait for the bond only (outside the lock so the worker can progress).
        # The stability poll keeps running in the background; watch /ble/status.
        sw = Stopwatch()
        while sw.elapsed_sec < 120:
            if self.bonded or self.state == "pair_failed":
                break
            time.sleep(1)

        status = self.status()
        ok = bool(self.bonded and self.connected)
        auto = None
        if ok:
            auto = self._maybe_auto_enable_notifications()
        return {
            "ok": ok,
            "message": "passkey submitted" + (" and bond complete" if ok else ""),
            "status": status,
        }

    def clear_bond(self, address: str) -> Dict[str, Any]:
        """
        Delete prior BlueZ bond / Device1 for address (readme: clear bonded tab).

        Safe when the device was never bonded — returns ok with a note.
        Caller should scan again before connect (RemoveDevice drops Device1).
        """
        address = str(address or "").strip().upper()
        if not address:
            return {"ok": False, "error": "address is required"}
        with self.lock:
            if not self.initialized:
                init = self.init_stack(capability=self.capability or DEFAULT_CAPABILITY)
                if not init.get("ok"):
                    return {"ok": False, "error": f"BlueZ init failed: {init}", "address": address}
            removed = False
            detail = "no prior Device1 / bond"
            try:
                remove_fn = getattr(self.bt, "remove_device", None)
                if callable(remove_fn):
                    remove_fn(address)
                    removed = True
                    detail = "RemoveDevice OK"
            except Exception as exc:
                detail = f"remove skipped ({exc})"
            if self.orchestration_kind not in MANUAL_CHECKLIST_KINDS:
                logger().info(f"clear_bond {address}: {detail}")
            return {
                "ok": True,
                "address": address,
                "removed": removed,
                "message": detail,
                "status": self.status(),
            }

    def disconnect(self, address: Optional[str] = None) -> Dict[str, Any]:
        """Disconnect from peer (ble_privacy readme step: disconnect remote)."""
        address = str(address or self.target_address or "").strip().upper()
        if not address:
            return {"ok": False, "error": "address is required"}
        with self.lock:
            try:
                self.bt.disconnect(address)
                self.connected = False
                self._set_state("disconnected", "host requested disconnect")
                if self.orchestration_kind not in MANUAL_CHECKLIST_KINDS:
                    logger().info(f"Disconnected from {address}")
                return {
                    "ok": True,
                    "address": address,
                    "message": "disconnected",
                    "status": self.status(),
                }
            except Exception as exc:
                self._set_state("disconnect_failed", str(exc))
                return {
                    "ok": False,
                    "address": address,
                    "error": str(exc),
                    "status": self.status(),
                }

    def _device_path(self) -> str:
        return mac_address_to_dbus_bt_path(
            self.bt.adapter_path, mac_address=self.target_address
        )

    def _wait_services_resolved(self, timeout: int = 30) -> bool:
        """BlueZ exposes the peer's GATT objects only once discovery finishes."""
        sw = Stopwatch()
        while sw.elapsed_sec < timeout:
            try:
                resolved = self.bt.get_remote_device_property(
                    self.target_address, prop="ServicesResolved"
                )
                if resolved:
                    logger().info("ServicesResolved is true")
                    return True
            except Exception as exc:
                logger().debug(f"ServicesResolved poll: {exc}")
            time.sleep(1)
        logger().warning(f"ServicesResolved still false after {timeout}s")
        return False

    def _remote_services(self):
        """
        Service entries belonging to the connected peer only.

        The Pi runs its own GATT server (which also has 0x180D), so an
        unfiltered lookup can match the local service instead of the peer's.
        """
        device_path = self._device_path()
        servs, chars = self.bt.gatt_adapter.resolve_all_services_characteristics()
        remote_servs = [
            (path, char_paths)
            for path, char_paths in (servs or [])
            if str(path).startswith(device_path + "/")
        ]
        remote_chars = [c for c in (chars or []) if str(c).startswith(device_path + "/")]
        logger().info(
            f"GATT under {device_path}: {len(remote_servs)} services, "
            f"{len(remote_chars)} characteristics "
            f"(total on bus: {len(servs or [])}/{len(chars or [])})"
        )
        return remote_servs, remote_chars

    def discover_services(self, timeout: int = 30) -> Dict[str, Any]:
        """List the peer's GATT services/characteristics with UUIDs and flags."""
        with self.lock:
            if not self.target_address:
                return {"ok": False, "error": "no active target; connect first"}
            if not self.bt.get_connection_status(self.target_address):
                return {"ok": False, "error": "not connected"}

            self._wait_services_resolved(timeout)
            device_path = self._device_path()
            remote_servs, remote_chars = self._remote_services()

            details = {}
            try:
                resolved = (
                    self.bt.gatt_adapter.get_resolved_services_and_characteristics()
                    or {}
                )
                details = {
                    uuid: info
                    for uuid, info in resolved.items()
                    if str(info.get("service_path", "")).startswith(device_path + "/")
                }
            except Exception as exc:
                logger().warning(f"resolved service details failed: {exc}")

            return {
                "ok": bool(remote_servs),
                "device_path": device_path,
                "service_count": len(remote_servs),
                "characteristic_count": len(remote_chars),
                "services": details,
                "service_paths": [p for p, _ in remote_servs],
                "characteristic_paths": remote_chars,
            }

    def enable_notifications(
        self,
        service_uuid: Optional[str] = None,
        char_uuid: Optional[str] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        with self.lock:
            if not self.target_address:
                return {"ok": False, "error": "no active target; connect+bond first"}
            if not self.bt.get_connection_status(self.target_address):
                return {"ok": False, "error": "not connected; cannot enable notifications"}

            service_uuid = _normalize_uuid(service_uuid)
            char_uuid = _normalize_uuid(char_uuid)
            self._set_state("resolving_gatt")
            self._wait_services_resolved(timeout)

            remote_servs, remote_chars = self._remote_services()
            if not remote_servs:
                self._set_state("gatt_failed", "peer exposed no GATT services")
                return {
                    "ok": False,
                    "error": (
                        "no GATT services found on the peer. The peer must expose a "
                        "GATT server; check GET /ble/services"
                    ),
                    "device_path": self._device_path(),
                }

            # No UUIDs given: pick the first notify/indicate capable characteristic.
            if not service_uuid or not char_uuid:
                picked = self._auto_pick_notify_char()
                if not picked:
                    self._set_state("gatt_failed", "no notify-capable characteristic")
                    return {
                        "ok": False,
                        "error": (
                            "no notify/indicate characteristic found; "
                            "inspect GET /ble/services and pass explicit UUIDs"
                        ),
                    }
                service_uuid, char_uuid = picked
                logger().info(
                    f"Auto-selected service={service_uuid} char={char_uuid}"
                )

            self.service_uuid = service_uuid
            self.char_uuid = char_uuid

            char_path, char_props = self.bt.gatt_adapter.resolve_characteristic(
                services=remote_servs,
                service_uid=service_uuid,
                char_uid=char_uuid,
            )
            if not char_path:
                self._set_state("gatt_failed", "characteristic not found")
                return {
                    "ok": False,
                    "error": (
                        f"characteristic not found on peer for "
                        f"service={service_uuid} char={char_uuid}"
                    ),
                    "hint": "call GET /ble/services to see what the peer exposes",
                }

            logger().info(f"Enabling notifications on {char_path}")
            self.bt.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uuid
            )
            self.bt.gatt_adapter.enable_notifications(char_path=char_path)
            self.char_path = char_path
            self.notifications_enabled = True
            self._set_state("notifications_ready")

            # Confirm the CCCD write landed; StartNotify can return without the
            # peer actually enabling the subscription.
            notifying = None
            try:
                _, fresh_props = self.bt.gatt_adapter.resolve_characteristic(
                    services=remote_servs,
                    service_uid=service_uuid,
                    char_uid=char_uuid,
                )
                notifying = bool(dict(fresh_props or {}).get("Notifying", False))
            except Exception as exc:
                logger().warning(f"could not read Notifying property: {exc}")
            logger().info(f"Notifying={notifying} on {char_path}")

            flags = [str(f).lower() for f in (char_props or {}).get("Flags", [])]
            return {
                "ok": True,
                "message": "notifications enabled; ready to receive",
                "service_uuid": service_uuid,
                "char_uuid": char_uuid,
                "char_path": char_path,
                "flags": flags,
                "notifying": notifying,
                "char_props": {
                    key: str(value) for key, value in dict(char_props or {}).items()
                },
                "status": self.status(),
            }

    def read_characteristic(
        self,
        service_uuid: Optional[str] = None,
        char_uuid: Optional[str] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """
        GATT Read on the connected peer (BlueZ ReadValue — long reads after MTU).

        Used by gatt_long_read SERVER: service 0xAABB / char 0x1AA1.
        """
        with self.lock:
            if not self.target_address:
                return {"ok": False, "error": "no active target; connect first"}
            if not self.bt.get_connection_status(self.target_address):
                return {"ok": False, "error": "not connected; cannot read characteristic"}

            service_uuid = _normalize_uuid(service_uuid)
            char_uuid = _normalize_uuid(char_uuid)
            if not service_uuid or not char_uuid:
                return {
                    "ok": False,
                    "error": "service_uuid and char_uuid are required for GATT read",
                }

            self._set_state("resolving_gatt")
            self._wait_services_resolved(timeout)

            remote_servs, _remote_chars = self._remote_services()
            if not remote_servs:
                self._set_state("gatt_failed", "peer exposed no GATT services")
                return {
                    "ok": False,
                    "error": (
                        "no GATT services found on the peer; "
                        "check GET /ble/services"
                    ),
                    "device_path": self._device_path(),
                }

            char_path, char_props = self.bt.gatt_adapter.resolve_characteristic(
                services=remote_servs,
                service_uid=service_uuid,
                char_uid=char_uuid,
            )
            if not char_path:
                self._set_state("gatt_failed", "characteristic not found")
                return {
                    "ok": False,
                    "error": (
                        f"characteristic not found on peer for "
                        f"service={service_uuid} char={char_uuid}"
                    ),
                    "hint": "call GET /ble/services to see what the peer exposes",
                }

            flags = [str(f).lower() for f in (char_props or {}).get("Flags", [])]
            logger().info(f"GATT Read on {char_path} flags={flags}")
            value_bytes: Optional[bytes] = None
            last_err: Optional[Exception] = None
            for attempt in range(1, 6):
                try:
                    # Full byte array (long read after MTU). Do not use
                    # read_charac_value(..., type!=str) — that returns only int(first).
                    characteristic = self.bt.gatt_adapter.bus.get_object(
                        BTDBusInterfaces.ORG_BLUEZ, char_path
                    )
                    data = characteristic.ReadValue(
                        {},
                        dbus_interface=BTDBusInterfaces.ORG_BLUEZ_GATTCHARACTERISTIC,
                    )
                    value_bytes = bytes(int(b) for b in data)
                    last_err = None
                    break
                except Exception as exc:
                    last_err = exc
                    logger().warning(f"GATT Read attempt {attempt}/5 failed: {exc}")
                    time.sleep(1.0)
            if value_bytes is None:
                self._set_state("gatt_failed", str(last_err))
                return {
                    "ok": False,
                    "error": f"GATT Read failed: {last_err}",
                    "service_uuid": service_uuid,
                    "char_uuid": char_uuid,
                    "char_path": char_path,
                }

            self.service_uuid = service_uuid
            self.char_uuid = char_uuid
            self.char_path = char_path
            self._set_state("gatt_read_ok")
            value_list = list(value_bytes)
            return {
                "ok": True,
                "message": "GATT Read OK",
                "service_uuid": service_uuid,
                "char_uuid": char_uuid,
                "char_path": char_path,
                "flags": flags,
                "length": len(value_bytes),
                "value_hex": value_bytes.hex(),
                "value_bytes": value_list[:128],
                "value_preview": value_list[:16],
                "status": self.status(),
            }

    def _auto_pick_notify_char(self):
        """
        Pick a (service_uuid, char_uuid) on the peer that can push data.

        Prefer 'notify' over 'indicate': peers commonly expose both, and the
        notify characteristic is the one that carries the data stream, while the
        indicate one is often only used for confirmed one-off updates.
        """
        device_path = self._device_path()
        try:
            resolved = (
                self.bt.gatt_adapter.get_resolved_services_and_characteristics() or {}
            )
        except Exception as exc:
            logger().warning(f"auto-pick failed to read services: {exc}")
            return None

        candidates = {"notify": None, "indicate": None}
        for svc_uuid, info in resolved.items():
            if not str(info.get("service_path", "")).startswith(device_path + "/"):
                continue
            for c_uuid, c_info in (info.get("characteristics") or {}).items():
                flags = [str(f).lower() for f in (c_info.get("flags") or [])]
                for flag in ("notify", "indicate"):
                    if flag in flags and candidates[flag] is None:
                        candidates[flag] = (str(svc_uuid), str(c_uuid))

        picked = candidates["notify"] or candidates["indicate"]
        if picked:
            logger().info(f"Notify candidates on peer: {candidates}")
        return picked

    def get_notifications(self) -> Dict[str, Any]:
        notifications = []
        if self.char_uuid:
            try:
                notifications = list(
                    self.bt.gatt_adapter.notifications.get(self.char_uuid, [])
                )
            except Exception as exc:
                return {"ok": False, "error": str(exc), "status": self.status()}
        return {
            "ok": True,
            "char_uuid": self.char_uuid,
            "notifications": notifications,
            "count": len(notifications),
            "status": self.status(),
        }

    def clear_notifications(self) -> Dict[str, Any]:
        if self.char_uuid:
            try:
                self.bt.gatt_adapter.notifications[self.char_uuid] = []
            except Exception as exc:
                return {"ok": False, "error": str(exc)}
        return {"ok": True, "message": "notification buffer cleared"}


class BleHttpRequestHandler(BaseHTTPRequestHandler):
    controller: RaspiBleHttpController = None  # set on server

    def log_message(self, fmt, *args):
        # Quiet high-frequency polls so AE/BLE central reports look like the DUT serial checklist.
        msg = fmt % args if args else str(fmt)
        ctrl = getattr(self.server, "controller", None)
        kind = getattr(ctrl, "orchestration_kind", "") if ctrl else ""
        if kind in QUIET_HTTP_KINDS:
            low = msg.lower()
            if " /ble/status" in low or " /health" in low or ' "/" ' in low:
                return
            # Manual checklist apps: hide host plumbing HTTP noise entirely.
            if kind in MANUAL_CHECKLIST_KINDS:
                return
        logger().info("HTTP " + msg)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON body: {exc}") from exc

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str):
        ctrl: RaspiBleHttpController = self.server.controller  # type: ignore[attr-defined]
        path = urlparse(self.path).path.rstrip("/") or "/"

        try:
            if method == "GET" and path in ("/health", "/"):
                status, body, ctype = _json_bytes(
                    {"ok": True, "service": "ble-raspi-http", "status": ctrl.status()}
                )
            elif method == "GET" and path == "/ble/status":
                status, body, ctype = _json_bytes({"ok": True, "status": ctrl.status()})
            elif method == "GET" and path == "/ble/notifications":
                status, body, ctype = _json_bytes(ctrl.get_notifications())
            elif method == "GET" and path == "/ble/services":
                result = ctrl.discover_services()
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/scan":
                data = self._read_json()
                name = data.get("name") or data.get("local_name")
                result = ctrl.scan(
                    timeout=int(data.get("timeout", 10)),
                    address=data.get("address"),
                    name=str(name) if name else None,
                )
                status, body, ctype = _json_bytes(result, 200 if result.get("ok") else 400)
            elif method == "POST" and path == "/ble/connect":
                data = self._read_json()
                address = data.get("address")
                if not address:
                    status, body, ctype = _json_bytes(
                        {"ok": False, "error": "address is required"}, 400
                    )
                else:
                    # bond defaults to True; pass bond=false for plain connect (no SMP).
                    bond = data.get("bond", data.get("pair", True))
                    if isinstance(bond, str):
                        bond = bond.strip().lower() in ("1", "true", "yes", "on")
                    conn_params = {
                        key: data[key]
                        for key in (
                            "min_conn_interval",
                            "max_conn_interval",
                            "conn_latency",
                            "supervision_timeout",
                        )
                        if data.get(key) is not None
                    }
                    result = ctrl.connect(
                        address=address,
                        capability=data.get("capability"),
                        bond=bool(bond),
                        conn_params=conn_params,
                        address_type=data.get("address_type")
                        or data.get("addr_type"),
                    )
                    status, body, ctype = _json_bytes(
                        result, 200 if result.get("ok") else 400
                    )
            elif method == "POST" and path == "/ble/passkey":
                data = self._read_json()
                passkey = data.get("passkey") or data.get("pin") or data.get("pin_code")
                if passkey is None:
                    status, body, ctype = _json_bytes(
                        {"ok": False, "error": "passkey is required"}, 400
                    )
                else:
                    result = ctrl.submit_passkey(str(passkey))
                    status, body, ctype = _json_bytes(
                        result, 200 if result.get("ok") else 400
                    )
            elif method == "POST" and path == "/ble/unpair":
                # Readme secureconnection/privacy — delete prior bond before re-pair.
                data = self._read_json()
                addr = data.get("address") or data.get("mac")
                result = ctrl.clear_bond(str(addr) if addr else "")
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/disconnect":
                # ble_privacy readme step 11 — remote disconnect → DUT re-advertises.
                data = self._read_json()
                addr = data.get("address") or data.get("mac")
                result = ctrl.disconnect(str(addr) if addr else None)
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/notifications/enable":
                data = self._read_json()
                result = ctrl.enable_notifications(
                    service_uuid=data.get("service_uuid"),
                    char_uuid=data.get("char_uuid"),
                    timeout=int(data.get("timeout", 30)),
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/read":
                data = self._read_json()
                result = ctrl.read_characteristic(
                    service_uuid=data.get("service_uuid"),
                    char_uuid=data.get("char_uuid"),
                    timeout=int(data.get("timeout", 30)),
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/notifications/clear":
                status, body, ctype = _json_bytes(ctrl.clear_notifications())
            elif method == "POST" and path == "/ble/orchestration/ibeacon-stability":
                data = self._read_json()
                result = ctrl.mark_ibeacon_scan_stability(
                    ok=bool(data.get("ok", False)),
                    sample_count=int(data.get("sample_count") or 0),
                )
                # Always 200 once mark is recorded; body "ok" is pass/fail.
                # (HTTP 409 made host retries treat a failed mark as transient.)
                status, body, ctype = _json_bytes({**result, "accepted": True}, 200)
            elif method == "POST" and path == "/ble/peripheral/expect-peer":
                data = self._read_json()
                address = data.get("address")
                if not address:
                    status, body, ctype = _json_bytes(
                        {"ok": False, "error": "address is required"}, 400
                    )
                else:
                    result = ctrl.set_expected_peer(str(address))
                    status, body, ctype = _json_bytes(
                        result, 200 if result.get("ok") else 400
                    )
            elif method == "POST" and path == "/ble/peripheral/start-hr-notify":
                started = ctrl._start_local_heart_rate_notifications()
                status, body, ctype = _json_bytes(
                    {
                        "ok": True,
                        "heart_rate_notify_started": started,
                        "service_classes": ctrl.service_classes,
                        "status": ctrl.status(),
                    },
                    200,
                )
            elif method == "POST" and path == "/ble/peripheral/advertise":
                # Pi advertises only (DUT=central apps). Does not wait for connect.
                data = self._read_json()
                svc = data.get("service_classes")
                if isinstance(svc, str):
                    svc = [s.strip() for s in svc.split(",") if s.strip()]
                legacy = data.get("legacy_hci", data.get("legacy", True))
                if isinstance(legacy, str):
                    legacy = legacy.strip().lower() in ("1", "true", "yes", "on")
                result = ctrl.start_advertise(
                    local_name=str(
                        data.get("local_name") or data.get("name") or "SILABS_DEV"
                    ),
                    capability=str(data.get("capability") or "NoInputNoOutput"),
                    service_classes=svc,
                    legacy_hci=bool(legacy),
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/peripheral/advertise-and-connect":
                # Pi advertises + GATT (Heart Rate…); wait for DUT central connect.
                data = self._read_json()
                address = data.get("address") or data.get("dut_address")
                if not address:
                    status, body, ctype = _json_bytes(
                        {
                            "ok": False,
                            "error": "address is required (DUT MAC)",
                        },
                        400,
                    )
                else:
                    svc = data.get("service_classes")
                    if isinstance(svc, str):
                        svc = [s.strip() for s in svc.split(",") if s.strip()]
                    start_hr = data.get("start_hr_notify", data.get("hr_notify", True))
                    if isinstance(start_hr, str):
                        start_hr = start_hr.strip().lower() in (
                            "1",
                            "true",
                            "yes",
                            "on",
                        )
                    result = ctrl.advertise_and_wait_dut_connect(
                        address=str(address),
                        local_name=str(
                            data.get("local_name")
                            or data.get("name")
                            or "SILABS_DEV"
                        ),
                        timeout_sec=int(data.get("timeout", data.get("timeout_sec", 180))),
                        capability=str(
                            data.get("capability") or "NoInputNoOutput"
                        ),
                        service_classes=svc,
                        start_hr_notify=bool(start_hr),
                    )
                    status, body, ctype = _json_bytes(
                        result, 200 if result.get("ok") else 408 if "timeout" in str(
                            result.get("error", "")
                        ).lower() else 400
                    )
            elif method == "POST" and path == "/ble/orchestration/ae-central-stability":
                data = self._read_json()
                result = ctrl.mark_ae_central_link_stability(
                    ok=bool(data.get("ok", False)),
                    sample_count=int(data.get("sample_count") or 0),
                )
                # Always 200 once mark is recorded; body "ok" is pass/fail.
                status, body, ctype = _json_bytes({**result, "accepted": True}, 200)
            elif method == "POST" and path == "/ble/testmodes/le-receiver-test":
                # Readme TX: Pi receives DUT TX packets (OCF 0x001D).
                data = self._read_json()
                ch = data.get("channel", data.get("rx_channel", 0x10))
                result = ctrl.testmodes_le_receiver_test(channel=int(ch))
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/testmodes/le-transmitter-test":
                # Readme RX: Pi transmits to DUT RX (OCF 0x001E).
                data = self._read_json()
                result = ctrl.testmodes_le_transmitter_test(
                    channel=int(data.get("channel", data.get("tx_channel", 0x10))),
                    payload_len=int(
                        data.get("payload_len", data.get("length", 0x20))
                    ),
                    payload_type=int(
                        data.get("payload_type", data.get("type", 0x01))
                    ),
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/testmodes/le-test-end":
                # Readme: stop LE test (OCF 0x001F) and read packet count.
                result = ctrl.testmodes_le_test_end()
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/stack-bypass/attach":
                data = self._read_json()
                result = ctrl.stack_bypass_attach(
                    device=str(
                        data.get("device")
                        or data.get("uart")
                        or os.environ.get("BLE_STACK_BYPASS_UART", "/dev/ttyUSB0")
                    ),
                    baud=int(data.get("baud") or data.get("speed") or 115200),
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/stack-bypass/hciconfig":
                data = self._read_json()
                result = ctrl.stack_bypass_hciconfig(
                    adapter=data.get("adapter") or data.get("hci")
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/stack-bypass/up":
                data = self._read_json()
                result = ctrl.stack_bypass_up(
                    adapter=data.get("adapter") or data.get("hci")
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/stack-bypass/leadv":
                data = self._read_json()
                result = ctrl.stack_bypass_leadv(
                    adapter=data.get("adapter") or data.get("hci")
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/stack-bypass/lescan":
                data = self._read_json()
                result = ctrl.stack_bypass_lescan(
                    adapter=data.get("adapter") or data.get("hci"),
                    timeout_sec=int(
                        data.get("timeout")
                        or data.get("timeout_sec")
                        or 5
                    ),
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/stack-bypass/detach":
                data = self._read_json()
                result = ctrl.stack_bypass_detach(
                    device=data.get("device") or data.get("uart")
                )
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 400
                )
            elif method == "POST" and path == "/ble/orchestration/complete":
                result = ctrl.complete_orchestration()
                status, body, ctype = _json_bytes(
                    result, 200 if result.get("ok") else 409
                )
            elif method == "POST" and path == "/ble/orchestration/abort":
                data = self._read_json()
                reason = str(
                    data.get("reason")
                    or data.get("error")
                    or data.get("message")
                    or "aborted by host"
                )
                result = ctrl.abort_orchestration(reason=reason)
                status, body, ctype = _json_bytes(result, 200)
            else:
                status, body, ctype = _json_bytes(
                    {
                        "ok": False,
                        "error": f"unsupported {method} {path}",
                        "endpoints": [
                            "GET /health",
                            "GET /ble/status",
                            "POST /ble/scan",
                            "POST /ble/connect",
                            "POST /ble/passkey",
                            "GET /ble/services",
                            "POST /ble/read",
                            "POST /ble/notifications/enable",
                            "GET /ble/notifications",
                            "POST /ble/notifications/clear",
                            "POST /ble/orchestration/ibeacon-stability",
                            "POST /ble/peripheral/expect-peer",
                            "POST /ble/peripheral/advertise",
                            "POST /ble/peripheral/advertise-and-connect",
                            "POST /ble/peripheral/start-hr-notify",
                            "POST /ble/orchestration/ae-central-stability",
                            "POST /ble/unpair",
                            "POST /ble/disconnect",
                            "POST /ble/testmodes/le-receiver-test",
                            "POST /ble/testmodes/le-transmitter-test",
                            "POST /ble/testmodes/le-test-end",
                            "POST /ble/stack-bypass/attach",
                            "POST /ble/stack-bypass/hciconfig",
                            "POST /ble/stack-bypass/up",
                            "POST /ble/stack-bypass/leadv",
                            "POST /ble/stack-bypass/lescan",
                            "POST /ble/stack-bypass/detach",
                            "POST /ble/orchestration/complete",
                            "POST /ble/orchestration/abort",
                        ],
                    },
                    404,
                )
        except Exception as exc:
            logger().exception(f"HTTP handler error on {method} {path}")
            status, body, ctype = _json_bytes({"ok": False, "error": str(exc)}, 500)

        self._send(status, body, ctype)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


class BleHttpServerThread(ThreadBase):
    def __init__(self, controller: RaspiBleHttpController, host: str, port: int):
        super().__init__()
        self.controller = controller
        self.host = host
        self.port = port
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.ready = threading.Event()

    def run(self):
        handler = BleHttpRequestHandler
        self.httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self.httpd.controller = self.controller  # type: ignore[attr-defined]
        self.httpd.daemon_threads = True
        logger().info(f"BLE RasPi HTTP API listening on http://{self.host}:{self.port}")
        self.ready.set()
        self.httpd.serve_forever(poll_interval=0.5)

    def stop(self):
        super().stop()
        if self.httpd is not None:
            logger().info("Stopping BLE RasPi HTTP API server")
            try:
                self.httpd.shutdown()
            except Exception as exc:
                logger().warning(f"httpd.shutdown: {exc}")
            try:
                self.httpd.server_close()
            except Exception as exc:
                logger().warning(f"httpd.server_close: {exc}")
            self.httpd = None


def _local_ipv4_addresses() -> list:
    """
    All non-loopback IPv4 addresses of this host.

    The container runs with network_mode=host, so these are the Raspberry Pi's
    own addresses. Link-local (169.254.x.x) entries are listed last since they
    are usually not the address a remote client should use.
    """
    addresses = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        addresses.append(sock.getsockname()[0])
        sock.close()
    except Exception:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in addresses and not ip.startswith("127."):
                addresses.append(ip)
    except Exception:
        pass

    addresses.sort(key=lambda ip: ip.startswith("169.254."))
    return addresses or ["<raspberry-pi-ip>"]


@pytest.mark.test_src_map_id("C_RASPI_HTTP_PASSKEY_NOTIFY")
def test_ble_raspi_http_scan_connect_passkey_notify(ble_client):
    """
    Raspberry Pi only: run HTTP BLE APIs for scan, connect+bond (runtime passkey),
    and notification enable/receive. Does not control or import any DUT.s

    Keepalive: server runs for BLE_RASPI_HTTP_LIFETIME_SEC (default 3600).
    Bluetooth is not powered off or killed on exit.
    """
    port = DEFAULT_HTTP_PORT
    lifetime = DEFAULT_SERVER_LIFETIME_SEC
    host = "0.0.0.0"
    advertise_ips = _local_ipv4_addresses()

    controller = RaspiBleHttpController(ble_client)
    # One-time init up front so /ble/scan|/ble/connect do not surprise-restart BT later.
    init_result = controller.init_stack(capability=DEFAULT_CAPABILITY)
    assert init_result.get("ok"), f"BlueZ init failed: {init_result}"

    server = BleHttpServerThread(controller=controller, host=host, port=port)
    controller._http_server = server
    server.start()
    assert server.ready.wait(timeout=15), "HTTP server failed to start"

    logger().info("=" * 72)
    logger().info("BLE RasPi HTTP API is ready (Raspberry Pi / BlueZ only)")
    logger().info(f"  Bound to : {host}:{port} (container uses host networking)")
    for ip in advertise_ips:
        logger().info(f"  Base URL : http://{ip}:{port}")
    logger().info(
        "  Reach it from your PC using the Raspberry Pi IP, not localhost"
    )
    logger().info(f"  Lifetime : {lifetime}s  (env BLE_RASPI_HTTP_LIFETIME_SEC)")
    logger().info("  Flow     :")
    logger().info('    POST /ble/scan  {"timeout": 10, "address": "<PEER_MAC>"}')
    logger().info('    POST /ble/connect  {"address": "<PEER_MAC>"}')
    logger().info('    POST /ble/passkey  {"passkey": "<6-digit from peer display>"}')
    logger().info(
        '    POST /ble/notifications/enable  '
        '{"service_uuid": "<uuid>", "char_uuid": "<uuid>"}'
    )
    logger().info("    GET  /ble/notifications")
    logger().info("  Notes    : no bluetooth power-off / service kill in this test")
    logger().info("=" * 72)

    try:
        # Stay alive so external tools can drive the full bond + notify flow.
        sw = Stopwatch()
        last_keepalive_bucket = -1
        while sw.elapsed_sec < lifetime and not server.stop_requested:
            time.sleep(1)
            # Soft health: confirm link without touching adapter power.
            bucket = int(sw.elapsed_sec) // 60
            if bucket != last_keepalive_bucket and controller.target_address:
                last_keepalive_bucket = bucket
                try:
                    connected = controller.bt.get_connection_status(
                        controller.target_address
                    )
                    logger().info(
                        f"keepalive status: connected={connected} state={controller.state}"
                    )
                except Exception as exc:
                    logger().warning(f"keepalive status check: {exc}")
    finally:
        # Stop HTTP only. Do NOT power_off, restart BT, or kill bluetoothd.
        # Do NOT call bluetooth.close() — that tears down the agent/glib loop.
        server.stop()
        server.wait_for_exit(raise_exceptions=False)
        try:
            controller.bt.stop_scanning()
        except Exception:
            pass
        logger().info(
            "HTTP server stopped. Bluetooth left running "
            "(no power_off / service restart / close)."
        )


def _run_app_ble_http_flow(ble_client, app_id: str) -> None:
    """
    Per-application HTTP server for Build Studio orchestration.

    The host PC drives /ble/scan, /ble/connect, /ble/passkey via HTTP while this
    test keeps the Pi-side BlueZ stack and HTTP server alive. When
    BLE_APP_ORCHESTRATED=1 (default), gatt_connect apps pass after link stability
    (and notifications when require_notifications is True).
    """
    from ble_app_http_configs import get_app_config

    cfg = get_app_config(app_id)
    port = DEFAULT_HTTP_PORT
    host = "0.0.0.0"
    orchestrated = os.environ.get("BLE_APP_ORCHESTRATED", "1").strip() not in ("0", "false", "no")
    enable_wait_sec = int(
        os.environ.get("BLE_ORCHESTRATION_TIMEOUT_SEC", str(cfg.orchestration_timeout_sec))
    )
    ibeacon_scan_duration = int(
        os.environ.get(
            "BLE_IBEACON_SCAN_DURATION_SEC", str(cfg.ibeacon_scan_duration_sec)
        )
    )
    ibeacon_scan_interval = int(
        os.environ.get(
            "BLE_IBEACON_SCAN_INTERVAL_SEC", str(cfg.ibeacon_scan_interval_sec)
        )
    )
    stability_sec = int(
        os.environ.get("BLE_ORCHESTRATION_STABILITY_SEC", str(cfg.post_notify_stability_sec))
    )
    finish_wait_sec = int(
        os.environ.get("BLE_ORCHESTRATION_FINISH_WAIT_SEC", str(ORCHESTRATION_FINISH_WAIT_SEC))
    )
    lifetime = int(os.environ.get("BLE_RASPI_HTTP_LIFETIME_SEC", str(DEFAULT_SERVER_LIFETIME_SEC)))
    is_ibeacon = cfg.orchestration_kind == "ibeacon_scan"
    # Pi advertises; DUT connects — kinds must not share init (AE vs legacy).
    is_ae_central = cfg.orchestration_kind == "ae_central"
    is_ble_central = cfg.orchestration_kind == "ble_central"
    is_accept_list = cfg.orchestration_kind == "accept_list"
    is_longrange = cfg.orchestration_kind == "longrange"
    is_datalength = cfg.orchestration_kind == "datalength"
    is_testmodes = cfg.orchestration_kind == "testmodes"
    is_stack_bypass = cfg.orchestration_kind == "stack_bypass"
    is_secureconnection = cfg.orchestration_kind == "secureconnection"
    is_privacy = cfg.orchestration_kind == "privacy"
    is_dut_central_soak = cfg.orchestration_kind == "dut_central"
    is_ae_peripheral = cfg.orchestration_kind == "ae_peripheral"
    is_gatt_long_read = cfg.orchestration_kind == "gatt_long_read"
    is_hid_on_gatt = cfg.orchestration_kind == "hid_on_gatt"
    is_pi_peripheral = cfg.orchestration_kind in PI_PERIPHERAL_KINDS
    require_notifications = bool(getattr(cfg, "require_notifications", True))
    peripheral_name = os.environ.get(
        "BLE_AE_CENTRAL_PERIPHERAL_NAME", cfg.ae_central_peripheral_name
    )
    dut_adv_name = (
        os.environ.get("BLE_AE_PERIPHERAL_NAME")
        or getattr(cfg, "dut_advertising_name", "")
        or "AE_PERIPHERAL"
    )
    if is_secureconnection:
        dut_adv_name = (
            os.environ.get("BLE_SECURECONNECTION_NAME")
            or getattr(cfg, "dut_advertising_name", "")
            or "BLE_SMP_SC"
        )
    if is_privacy:
        dut_adv_name = (
            os.environ.get("BLE_PRIVACY_NAME")
            or getattr(cfg, "dut_advertising_name", "")
            or "SIMPLE_PRIVACY"
        )
    if is_gatt_long_read:
        dut_adv_name = (
            os.environ.get("BLE_GATT_LONG_READ_NAME")
            or getattr(cfg, "dut_advertising_name", "")
            or "LONG_READ_TEST"
        )
    if is_hid_on_gatt:
        dut_adv_name = (
            os.environ.get("BLE_HID_ON_GATT_NAME")
            or getattr(cfg, "dut_advertising_name", "")
            or "HID_OVER_GATT"
        )
    if is_ibeacon:
        scan_stability_sec = ibeacon_scan_duration
    elif is_testmodes:
        scan_stability_sec = int(getattr(cfg, "testmodes_collect_sec", 8) or 8) + 60
    elif is_stack_bypass:
        scan_stability_sec = 120
    elif is_secureconnection or is_privacy:
        # Host marks SMP (+ privacy disconnect); no post-notify soak.
        scan_stability_sec = int(cfg.ae_central_connect_timeout_sec) + 120
    elif is_hid_on_gatt:
        # Connect + SMP + HID subscribe + report collection window (no soak).
        scan_stability_sec = int(cfg.ae_central_connect_timeout_sec) + 240
    elif is_gatt_long_read:
        # Connect + MTU settle + long GATT Read retries (no soak).
        scan_stability_sec = int(cfg.ae_central_connect_timeout_sec) + 120
    elif is_pi_peripheral or is_ae_peripheral:
        # Simple connect: duration 0 → budget is just connect wait.
        scan_stability_sec = (
            ibeacon_scan_duration
            if ibeacon_scan_duration > 0
            else int(cfg.ae_central_connect_timeout_sec)
        )
    else:
        scan_stability_sec = stability_sec
    run_for = lifetime if not orchestrated else (
        enable_wait_sec + scan_stability_sec + finish_wait_sec + 120
    )

    controller = RaspiBleHttpController(ble_client)
    controller.orchestration_kind = cfg.orchestration_kind
    auto_notify_env = os.environ.get("BLE_ORCHESTRATION_AUTO_ENABLE_NOTIFY", "1").strip()
    if orchestrated and cfg.orchestration_kind == "gatt_connect":
        if require_notifications:
            controller.auto_enable_notifications = auto_notify_env not in (
                "0",
                "false",
                "no",
            )
            controller.auto_notify_service_uuid = cfg.service_uuid
            controller.auto_notify_char_uuid = cfg.char_uuid
        else:
            controller.auto_enable_notifications = False
    simple_connect = (is_pi_peripheral or is_ae_peripheral) and ibeacon_scan_duration <= 0
    if is_testmodes:
        # Pi = Linux + BT dongle in SDK readme (raw HCI LE test; no ADV/GATT).
        init_result = controller.init_testmodes_stack()
    elif is_stack_bypass:
        # Pi = Linux host attaching DUT HCI UART (btattach).
        init_result = controller.init_stack_bypass()
    elif is_ble_central or is_accept_list or is_longrange or is_datalength:
        # Readme peripheral: connectable + Complete Local Name in AD + scan rsp.
        # accept_list / longrange / datalength: same legacy ADV_IND path.
        init_result = controller.init_ble_central_peripheral(
            local_name=peripheral_name,
        )
    elif is_ae_central:
        # Extended advertising OK for AE central.
        init_result = controller.init_peripheral_stack(
            local_name=peripheral_name,
            service_classes=[] if simple_connect else None,
        )
    elif is_dut_central_soak:
        # Generic DUT-central soak: GATT + legacy HCI ADV_IND.
        init_result = controller.init_peripheral_stack(
            local_name=peripheral_name,
            service_classes=None,
        )
    elif is_ae_peripheral:
        # Pi is central (phone in SDK readme); DUT advertises AE_PERIPHERAL.
        init_result = controller.init_stack(capability="NoInputNoOutput")
    elif is_gatt_long_read:
        # Pi is central (phone); DUT SERVER advertises LONG_READ_TEST.
        init_result = controller.init_stack(capability="NoInputNoOutput")
        controller.auto_enable_notifications = False
    elif is_hid_on_gatt:
        # Pi is central (phone); DUT is the HOGP keyboard and displays the passkey.
        # Host picks the notify-capable 0x2A4D instance, so no auto CCCD write here.
        init_result = controller.init_stack(capability=DEFAULT_CAPABILITY)
        controller.auto_enable_notifications = False
    elif is_secureconnection or is_privacy:
        # Pi enters passkey (KeyboardOnly); DUT displays passkey (IO cap DisplayOnly).
        init_result = controller.init_stack(capability=DEFAULT_CAPABILITY)
        controller.auto_enable_notifications = False
    else:
        init_result = controller.init_stack(capability=DEFAULT_CAPABILITY)
    assert init_result.get("ok"), f"BlueZ init failed: {init_result}"

    server = BleHttpServerThread(controller=controller, host=host, port=port)
    controller._http_server = server
    server.start()
    assert server.ready.wait(timeout=15), "HTTP server failed to start"

    if is_datalength:
        logger().info("=== Data Length (SDK ble_datalength) ===")
        logger().info(
            f"Pi peripheral: {peripheral_name!r} @ {init_result.get('local_address')}"
        )
        logger().info("DUT will: scan → connect → set data length → length change")
        logger().info("(No Heart Rate / notifications)")
    elif is_longrange:
        logger().info("=== Long Range / 2Mbps (SDK ble_longrange_2mbps) ===")
        logger().info(
            f"Pi peripheral: {peripheral_name!r} @ {init_result.get('local_address')}"
        )
        logger().info("DUT will: scan → connect → PHY update (2Mbps; Coded skipped on Pi)")
    elif is_testmodes:
        mode = str(getattr(cfg, "testmodes_mode", "tx") or "tx").lower()
        ch = int(getattr(cfg, "testmodes_channel", 0x10) or 0x10)
        logger().info("=== BLE Testmodes (SDK ble_testmodes) ===")
        logger().info(f"Pi = Linux HCI dongle ({init_result.get('adapter', 'hci0')})")
        if mode == "rx":
            logger().info(
                f"Mode RX: DUT receives; Pi will TX on channel 0x{ch:02X} "
                "(hcitool 0x001E) then stop (0x001F)"
            )
        else:
            logger().info(
                f"Mode TX: DUT transmits; Pi will RX on channel 0x{ch:02X} "
                "(hcitool 0x001D) then stop (0x001F) and check packets"
            )
    elif is_stack_bypass:
        uart = (
            os.environ.get("BLE_STACK_BYPASS_UART")
            or getattr(cfg, "stack_bypass_uart", None)
            or "/dev/ttyUSB0"
        )
        logger().info("=== BT Stack Bypass (SDK bt_stack_bypass) ===")
        logger().info("Pi = Linux host; DUT = HCI over UART (no on-chip BLE stack app)")
        logger().info(f"UART: {uart}  (USB-UART cable required — SoC: WSTK P35/P33)")
        logger().info(
            "Host will: wait Wi-Fi init → btattach → up → leadv → lescan → detach"
        )
    elif is_secureconnection:
        logger().info("=== BLE Secure Connection (SDK ble_secureconnection) ===")
        logger().info(
            f"DUT advertises as {dut_adv_name!r} (peripheral + SMP SC)"
        )
        logger().info(
            "Pi = central (phone role): unpair → scan → connect bond → passkey → encrypt"
        )
        logger().info("No GATT notifications / no Heart Rate path")
    elif is_privacy:
        logger().info("=== BLE Privacy (SDK ble_privacy — PERIPHERAL_ROLE) ===")
        logger().info(f"DUT advertises as {dut_adv_name!r}")
        logger().info(
            "Pi = central (phone): scan → connect → SMP → keys/resolve → disconnect"
        )
        logger().info("DUT then Start Advertising again (readme step 11)")
        logger().info("No GATT notifications / no Heart Rate path")
    elif is_hid_on_gatt:
        logger().info("=== HID over GATT (SDK ble_hid_on_gatt GATT_ROLE=SERVER) ===")
        logger().info(f"DUT advertises as {dut_adv_name!r} (HOGP keyboard)")
        logger().info(
            "Pi = central (phone): unpair → scan → connect bond → passkey → encrypt"
        )
        logger().info(
            f"Then subscribe HID report service={cfg.service_uuid} "
            f"char={cfg.char_uuid} and collect the 'hog_' keystroke reports"
        )
        logger().info(
            "If BlueZ keeps HoG in its own input plugin, the DUT print "
            "'Input report notify val: 1' is the HID evidence"
        )
    elif is_gatt_long_read:
        logger().info("=== GATT Long Read SERVER (SDK gatt_long_read) ===")
        logger().info(f"DUT advertises as {dut_adv_name!r} (GATT_ROLE=SERVER)")
        logger().info(
            f"Pi = central: scan → connect → GATT Read "
            f"service={cfg.service_uuid} char={cfg.char_uuid} "
            f"(min_len={getattr(cfg, 'min_gatt_read_len', 21)})"
        )
        logger().info("No notify soak — pass on long attribute read")
    else:
        logger().info("=" * 72)
        logger().info(f"BLE RasPi HTTP API ready for app: {app_id} ({cfg.label})")
        logger().info(f"  Orchestrated : {orchestrated}  max_runtime={run_for}s")
        if orchestrated:
            if is_ibeacon:
                logger().info(
                    f"  Phases       : enable_wait={enable_wait_sec}s  "
                    f"ibeacon_scan={ibeacon_scan_duration}s every {ibeacon_scan_interval}s  "
                    f"finish_wait={finish_wait_sec}s"
                )
                logger().info(
                    "  Host flow    : POST /ble/scan (filter DUT MAC) every 30s for 5 min → "
                    "POST /ble/orchestration/ibeacon-stability → POST /ble/orchestration/complete"
                )
            elif is_ae_peripheral:
                logger().info(
                    f"  Mode         : ae_peripheral (SDK readme — DUT advertises, Pi central)"
                )
                logger().info(
                    f"  DUT LocalName: {dut_adv_name!r}  "
                    f"(SET1 random / SET2 public from UI or serial)"
                )
                logger().info(
                    f"  Host flow    : scan → connect (bond=false) "
                    f"(≤{cfg.ae_central_connect_timeout_sec}s) → PASS → complete"
                )
                logger().info(
                    "  Firmware tip : ENABLE_NWP_POWER_SAVE=0 recommended "
                    "(sample often ships with 1)"
                )
            elif is_pi_peripheral:
                simple_connect = ibeacon_scan_duration <= 0
                logger().info(
                    f"  Pi peripheral: local_name={peripheral_name!r}  "
                    f"local_address={init_result.get('local_address')}  "
                    f"advertising_on={init_result.get('advertising_on')}  "
                    f"kind={cfg.orchestration_kind}"
                )
                if is_ble_central or is_accept_list:
                    mode_label = (
                        "accept_list (SDK ble_accept_list — legacy ADV_IND + "
                        "controller accept list; NOT ae_central)"
                        if is_accept_list
                        else "ble_central (SDK readme — legacy ADV_IND, "
                        "LocalName in AD + scan response; NOT ae_central)"
                    )
                    logger().info(f"  Mode         : {mode_label}")
                    logger().info(
                        f"  Host flow    : expect-peer → wait DUT 'Module connected' "
                        f"(≤{cfg.ae_central_connect_timeout_sec}s) → PASS → complete"
                    )
                    logger().info(
                        "  Firmware tip : ENABLE_NWP_POWER_SAVE=0 recommended "
                        "(sample often ships with 1; AE central uses 0)"
                    )
                    if is_accept_list:
                        pi_mac = init_result.get("local_address")
                        logger().info(
                            "  Accept list  : flash with Pi MAC in ble_acceptlist_addr1 "
                            f"(big-endian) AND RSI_BLE_DEV_ADDR / name "
                            f"({peripheral_name!r} / {pi_mac}) — name alone is not enough"
                        )
                elif simple_connect:
                    logger().info(
                        "  Mode         : AE central simple connect "
                        "(extended adv OK — no data transfer, no soak)"
                    )
                    logger().info(
                        f"  Host flow    : expect-peer → wait connect "
                        f"(≤{cfg.ae_central_connect_timeout_sec}s) → PASS → complete"
                    )
                else:
                    logger().info(
                        f"  Phases       : connect_wait={cfg.ae_central_connect_timeout_sec}s  "
                        f"link_stability={ibeacon_scan_duration}s every {ibeacon_scan_interval}s"
                    )
                    logger().info(
                        "  Host flow    : expect-peer → connect → link soak → complete"
                    )
                logger().info(
                    "  DUT firmware : RSI_REMOTE_DEVICE_NAME / Pi MAC must match Pi "
                    f"({peripheral_name!r} / {init_result.get('local_address')})"
                )
            else:
                logger().info(
                    f"  Phases       : enable_wait={enable_wait_sec}s  "
                    f"stability={stability_sec}s  finish_wait={finish_wait_sec}s"
                )
                if cfg.orchestration_kind == "gatt_connect" and not require_notifications:
                    dut_name = getattr(cfg, "dut_advertising_name", "") or "n/a"
                    logger().info(
                        f"  Connect-only : require_notifications=false  "
                        f"DUT LocalName hint={dut_name!r} "
                        "(SDK AE / peripheral connect — no GATT notify)"
                    )
                    logger().info(
                        "  Host flow    : scan → connect (bond=false) → link stability → "
                        "POST /ble/orchestration/complete"
                    )
                else:
                    if (
                        cfg.orchestration_kind == "gatt_connect"
                        and controller.auto_enable_notifications
                    ):
                        logger().info(
                            f"  Auto-notify  : service={cfg.service_uuid} char={cfg.char_uuid} "
                            "(Pi enables CCCD after connect; "
                            "BLE_ORCHESTRATION_AUTO_ENABLE_NOTIFY=0 to disable)"
                        )
                    logger().info(
                        "  Host flow    : connect → passkey (if used) → stability → "
                        "POST /ble/orchestration/complete"
                    )
        for ip in _local_ipv4_addresses():
            logger().info(f"  Base URL     : http://{ip}:{port}")
        logger().info("=" * 72)

    try:
        sw = Stopwatch()
        if orchestrated and is_ibeacon:
            while sw.elapsed_sec < run_for and not server.stop_requested:
                time.sleep(1)
                if controller._orchestration_finish.is_set():
                    logger().info("iBeacon orchestration complete — host signaled finish")
                    break
            if controller._orchestration_aborted:
                pytest.fail(
                    f"Test aborted by host: {controller._abort_reason or 'aborted'}"
                )
            assert controller._ibeacon_scan_stability_done, (
                f"Timed out waiting for host iBeacon scan stability for {app_id}"
            )
            assert controller._ibeacon_scan_stability_ok, (
                "iBeacon scan stability failed — DUT not in every scan sample"
            )
            assert controller._orchestration_finish.is_set(), (
                f"Timed out waiting for POST /ble/orchestration/complete ({finish_wait_sec}s)"
            )
        elif orchestrated and (
            is_pi_peripheral
            or is_ae_peripheral
            or is_gatt_long_read
            or is_testmodes
            or is_stack_bypass
            or is_secureconnection
            or is_privacy
            or is_hid_on_gatt
        ):
            last_adv_heartbeat = 0.0
            # Simple connect: rare heartbeats (keep report close to DUT serial checklist).
            hb_interval = (
                60.0
                if (
                    simple_connect
                    or is_gatt_long_read
                    or is_testmodes
                    or is_stack_bypass
                    or is_secureconnection
                    or is_privacy
                    or is_hid_on_gatt
                )
                else 30.0
            )
            while sw.elapsed_sec < run_for and not server.stop_requested:
                time.sleep(1)
                if (sw.elapsed_sec - last_adv_heartbeat) >= hb_interval:
                    last_adv_heartbeat = sw.elapsed_sec
                    if (
                        is_testmodes
                        or is_stack_bypass
                        or is_secureconnection
                        or is_privacy
                        or is_gatt_long_read
                        or is_hid_on_gatt
                    ):
                        # Quiet — host drives GATT-client / SMP steps; no ADV heartbeat.
                        pass
                    else:
                        connected = bool(controller.status().get("connected"))
                        if is_ae_peripheral:
                            if connected:
                                logger().info(
                                    f"Pi central: connected to DUT "
                                    f"(peer={controller.target_address})"
                                )
                        else:
                            adv = controller._is_advertising()
                            if simple_connect:
                                if connected:
                                    if cfg.orchestration_kind not in MANUAL_CHECKLIST_KINDS:
                                        logger().info(
                                            f"Pi: DUT connected (peer={controller.target_address})"
                                        )
                                elif not adv:
                                    logger().error(
                                        "LE advertising is OFF — DUT cannot discover the Pi"
                                    )
                                    if is_ble_central or is_accept_list or is_datalength or is_longrange:
                                        try:
                                            controller._enable_legacy_hci_advertising(
                                                peripheral_name
                                            )
                                        except Exception as exc:
                                            logger().warning(
                                                f"legacy ADV re-enable: {exc}"
                                            )
                            else:
                                logger().info(
                                    f"[Pi advertising heartbeat] name={peripheral_name!r} "
                                    f"addr={controller.local_address} advertising_on={adv} "
                                    f"connected={connected}"
                                )
                                if not adv and not connected:
                                    logger().error(
                                        "LE advertising is OFF while waiting for DUT central — "
                                        "DUT cannot discover the Pi"
                                    )
                if controller._orchestration_finish.is_set():
                    logger().info(
                        "Orchestration complete — host signaled finish"
                        if (
                            is_testmodes
                            or is_secureconnection
                            or is_privacy
                            or is_gatt_long_read
                            or is_hid_on_gatt
                        )
                        else "Simple-connect orchestration complete — host signaled finish"
                    )
                    break
            if controller._orchestration_aborted:
                pytest.fail(
                    f"Test aborted by host: {controller._abort_reason or 'aborted'}"
                )
            assert controller._ae_central_link_stability_done, (
                f"Timed out waiting for host HID mark for {app_id} "
                "(bond → HID report subscribe → reports)"
                if is_hid_on_gatt
                else f"Timed out waiting for host GATT long-read mark for {app_id}"
                if is_gatt_long_read
                else (
                    f"Timed out waiting for host SMP/privacy mark for {app_id}"
                    if (is_secureconnection or is_privacy)
                    else f"Timed out waiting for host testmodes/connect mark for {app_id}"
                )
            )
            assert controller._ae_central_link_stability_ok, (
                "HID over GATT mark failed (bond, HID subscribe, or no HID reports)"
                if is_hid_on_gatt
                else "GATT long-read mark failed (connect or long Read)"
                if is_gatt_long_read
                else (
                    "Privacy SMP mark failed"
                    if is_privacy
                    else (
                        "Secureconnection SMP mark failed"
                        if is_secureconnection
                        else (
                            "Testmodes/simple-connect mark failed"
                            if is_testmodes
                            else "Simple-connect mark failed — connection not established"
                        )
                    )
                )
            )
            assert controller._orchestration_finish.is_set(), (
                f"Timed out waiting for POST /ble/orchestration/complete ({finish_wait_sec}s)"
            )
        elif orchestrated:
            stability_started = False
            last_auto_notify_try = 0.0
            while sw.elapsed_sec < run_for and not server.stop_requested:
                time.sleep(1)

                st = controller.status()
                if (
                    cfg.orchestration_kind == "gatt_connect"
                    and require_notifications
                    and controller.auto_enable_notifications
                    and st.get("connected")
                    and not st.get("notifications_enabled")
                    and (sw.elapsed_sec - last_auto_notify_try) >= 5
                ):
                    last_auto_notify_try = sw.elapsed_sec
                    controller._maybe_auto_enable_notifications()

                ready_for_stability = bool(st.get("connected")) and (
                    (not require_notifications) or bool(st.get("notifications_enabled"))
                )
                if not stability_started and ready_for_stability:
                    stability_started = True

                    def _stability_worker() -> None:
                        controller.run_post_notify_stability(stability_sec)

                    threading.Thread(target=_stability_worker, daemon=True).start()
                    label = "Connect link" if not require_notifications else "Post-notify"
                    logger().info(
                        f"{label} stability started in background ({stability_sec}s)"
                    )

                if controller._orchestration_aborted:
                    logger().info("Orchestration aborted by host — leaving wait loop")
                    break

                if (
                    stability_started
                    and controller._post_notify_stability_done
                    and controller._orchestration_finish.is_set()
                ):
                    logger().info(
                        "Orchestration complete — stability passed and host signaled finish"
                    )
                    break

            if controller._orchestration_aborted:
                pytest.fail(
                    f"Test aborted by host: {controller._abort_reason or 'aborted'}"
                )
            if require_notifications:
                assert stability_started, (
                    f"Timed out after {enable_wait_sec}s waiting for notifications to be "
                    f"enabled for {app_id}"
                )
            else:
                assert stability_started, (
                    f"Timed out after {enable_wait_sec}s waiting for BLE connect "
                    f"for {app_id}"
                )
            assert controller._post_notify_stability_ok, (
                "Link stability failed (connection dropped)"
                if not require_notifications
                else "Post-notify stability failed (connection dropped)"
            )
            assert controller._orchestration_finish.is_set(), (
                f"Timed out after stability waiting for POST /ble/orchestration/complete "
                f"({finish_wait_sec}s window)"
            )
        else:
            while sw.elapsed_sec < run_for and not server.stop_requested:
                time.sleep(1)
                if controller._orchestration_aborted:
                    break
            if controller._orchestration_aborted:
                pytest.fail(
                    f"Test aborted by host: {controller._abort_reason or 'aborted'}"
                )
    finally:
        server.stop()
        server.wait_for_exit(raise_exceptions=False)
        try:
            controller.bt.stop_scanning()
        except Exception:
            pass


def _register_app_http_tests() -> None:
    from ble_app_http_configs import BLE_APP_HTTP_CONFIGS

    def _make(app_id: str):
        @pytest.mark.test_src_map_id(f"C_RASPI_HTTP_{app_id.upper()}")
        def _test(ble_client):
            _run_app_ble_http_flow(ble_client, app_id)

        _test.__name__ = f"test_{app_id}_http_flow"
        _test.__doc__ = f"Raspberry Pi HTTP BLE flow for {app_id} (Build Studio orchestration)."
        return _test

    for app_id in BLE_APP_HTTP_CONFIGS:
        globals()[f"test_{app_id}_http_flow"] = _make(app_id)


_register_app_http_tests()
