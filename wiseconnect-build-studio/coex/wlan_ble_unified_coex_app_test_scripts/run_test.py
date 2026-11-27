#!/usr/bin/env python3
"""Build, flash, and validate WLAN BLE Unified Coex App."""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_COEX_ROOT = Path(__file__).resolve().parents[1]
if str(_COEX_ROOT) not in sys.path:
    sys.path.insert(0, str(_COEX_ROOT))
from _common.studio_config import load_json_config, missing_nested_keys  # noqa: E402

APP_ID = "wlan_ble_unified_coex_app"
PRIVATE_IP_RE = re.compile(
    r"(?<!\d)(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)"
)
BLE_ADDR_RE = re.compile(r"(?<![0-9A-F])(?:[0-9A-F]{2}:){5}[0-9A-F]{2}(?![0-9A-F])", re.I)

_BLE_AUTOMATION_MACROS = {
    "RSI_BLE_MAX_NBR_PERIPHERALS": "1",
    "RSI_BLE_MAX_NBR_CENTRALS": "1",
    "SMP_ENABLE_C1": "0",
    "SMP_ENABLE_P1": "0",
}


class _SafeStream:
    def __init__(self, stream):
        self.stream = stream

    def write(self, value):
        try:
            return self.stream.write(value)
        except UnicodeEncodeError:
            enc = getattr(self.stream, "encoding", None) or "ascii"
            return self.stream.write(value.encode(enc, "backslashreplace").decode(enc))

    def __getattr__(self, name):
        return getattr(self.stream, name)


for _stream_name in ("stdout", "stderr"):
    _stream = getattr(sys, _stream_name)
    try:
        _stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, OSError, ValueError):
        setattr(sys, _stream_name, _SafeStream(_stream))


@dataclass
class UnifiedState:
    wifi_init: bool = False
    wifi_connected: bool = False
    ip_address: Optional[str] = None
    ble_advertising: bool = False
    ble_scanning: bool = False
    connected_addresses: list[str] = field(default_factory=list)
    connection_event_count: int = 0
    initiated_roles: list[int] = field(default_factory=list)
    mtu_exchange: bool = False
    profile_discovery: bool = False
    notification_activity: bool = False
    mqtt_connected: bool = False
    mqtt_publish_count: int = 0
    disconnect_count: int = 0
    wlan_retry_count: int = 0
    last_wlan_retry: Optional[str] = None
    failure: Optional[str] = None

    @property
    def ble_connection_count(self) -> int:
        return max(len(self.connected_addresses), len(self.initiated_roles))


def _append_unique(items, value):
    if value not in items:
        items.append(value)


def parse_serial_line(state: UnifiedState, line: str) -> None:
    raw = line.strip()
    low = raw.lower()
    if not low:
        return
    if "wi-fi initialization success" in low or "wi-fi initialization is successful" in low:
        state.wifi_init = True
    if (
        "wlan connection is successful" in low
        or "wlan connection success" in low
        or "wlan connected" in low
        or "ip config" in low and "success" in low
    ):
        state.wifi_connected = True
    if "wlan connection failed" in low:
        # The SDK Wi-Fi task automatically retries.  Error 0x10003/10003 is
        # commonly followed by WLAN connected + DHCP success, so recording it
        # as an immediate fatal error aborts an otherwise healthy run.
        state.wlan_retry_count += 1
        state.last_wlan_retry = raw
    ip_match = PRIVATE_IP_RE.search(raw)
    if ip_match and ("ip" in low or state.wifi_init or state.wifi_connected):
        state.ip_address = ip_match.group(1)
        state.wifi_connected = True
    if "advertising started" in low:
        state.ble_advertising = True
    if "scanning started" in low:
        state.ble_scanning = True

    if (
        "connected address" in low
        or "remote device address" in low
        or "remote_dev_addr" in low
    ) and "disconnect" not in low:
        if "connected address" in low:
            state.connection_event_count += 1
        for address in BLE_ADDR_RE.findall(raw):
            _append_unique(state.connected_addresses, address.upper())
    role_match = re.search(r"initiated\s+role\s*:\s*0x([0-9a-f]+)", low)
    if role_match:
        _append_unique(state.initiated_roles, int(role_match.group(1), 16))
    if "mtu exchange" in low or "remotemtu" in low or "mtu size from remote" in low:
        state.mtu_exchange = True
    if "profile discovery" in low or "profile list" in low or "characteristic" in low:
        state.profile_discovery = True
    if "notification" in low and ("received" in low or "sent" in low or "success" in low):
        state.notification_activity = True
    if "mqtt" in low and ("connected" in low or "connection" in low) and (
        "success" in low or "established" in low or "done" in low
    ):
        state.mqtt_connected = True
    if (
        "qos1 publish is successful" in low
        or "mqtt publish is successful" in low
        or "publish message success" in low
        or "published successfully" in low
    ):
        state.mqtt_connected = True
        state.mqtt_publish_count += 1
    if "disconnected" in low or "dis-conn evt" in low:
        state.disconnect_count += 1

    fatal = (
        "wi-fi initialization failed",
        "mqtt connection failed",
        "failed to connect mqtt",
        "ble dual role init failed",
        "ble task excution fails",
        "number of ble centrals or ble peripherals given wrong",
        "smp failed",
    )
    if any(marker in low for marker in fatal):
        state.failure = raw


class StudioApi:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise RuntimeError(f"{method} {path} failed ({exc.code}): {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Cannot reach Build Studio at {self.base_url}: {exc}") from exc

    def build_flash(self, cfg):
        studio = cfg["studio"]
        wifi = cfg["wifi"]
        payload = {
            "app_id": APP_ID,
            "target": "soc",
            "board": studio.get("board", "brd4338a"),
            "toolchain": studio.get("toolchain", "gcc"),
            "sdk_root": studio["sdk_root"],
            "ble_root": studio["examples_root"],
            "wifi_ssid": wifi["ssid"],
            "wifi_psk": wifi.get("password", ""),
        }
        if studio.get("adapter_serial"):
            payload["adapter_serial"] = studio["adapter_serial"]
        started = self.request("POST", "/api/build-flash", payload)
        job_id = str(started["job_id"])
        seen = 0
        while True:
            job = self.request("GET", f"/api/build/{job_id}")
            logs = list(job.get("logs") or [])
            for item in logs[seen:]:
                print(f"[build] {item}", flush=True)
            seen = len(logs)
            if job.get("status") in ("success", "failed"):
                if job["status"] != "success":
                    raise RuntimeError(job.get("error") or "Build/flash failed")
                return job
            time.sleep(1)


def _find_example_dir(config: dict[str, Any]) -> Path:
    """Resolve the SDK example without depending on Build Studio internals."""
    studio = config["studio"]
    roots = []
    for raw in (studio.get("examples_root"), studio.get("sdk_root")):
        if not raw:
            continue
        root = Path(str(raw))
        roots.extend(
            (
                root / APP_ID,
                root / "examples" / "snippets" / "wlan_ble" / APP_ID,
            )
        )
        if root.name == APP_ID:
            roots.append(root)
    seen = set()
    for candidate in roots:
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        if (candidate / "ble_config.h").is_file():
            return candidate
    checked = "\n  ".join(str(path) for path in roots)
    raise FileNotFoundError(
        f"Cannot locate {APP_ID}/ble_config.h. Checked:\n  {checked}"
    )


def patch_and_verify_app_sources(config: dict[str, Any]) -> tuple[Path, Path]:
    """Enable WLAN/MQTT and make BLE non-interactive before generation.

    This is deliberately performed by the isolated runner as well as by
    build_engine.py.  It prevents an older/stale Build Studio process from
    compiling the stock SMP_ENABLE_C1=1 setting and dropping the BLE link when
    BlueZ cannot satisfy the demo's MITM pairing policy.
    """
    example_dir = _find_example_dir(config)
    header = example_dir / "ble_config.h"
    text = header.read_text(encoding="utf-8", errors="strict")
    updated = text
    for macro, value in _BLE_AUTOMATION_MACROS.items():
        pattern = re.compile(
            rf"(^[ \t]*#[ \t]*define[ \t]+{re.escape(macro)}[ \t]+)"
            rf"(\d+)([ \t]*(?://.*)?)$",
            re.MULTILINE,
        )
        updated, count = pattern.subn(rf"\g<1>{value}\g<3>", updated, count=1)
        if count != 1:
            raise RuntimeError(f"Required macro {macro} not found in {header}")

    remote_name = str(
        (config.get("ble") or {}).get("pi_advertising_name") or "SILABS_DEV"
    )
    remote_pattern = re.compile(
        r'(^\s*#\s*define\s+RSI_REMOTE_DEVICE_NAME1\s+)"[^"]*"',
        re.MULTILINE,
    )
    updated, count = remote_pattern.subn(
        lambda match: match.group(1) + json.dumps(remote_name), updated, count=1
    )
    if count != 1:
        raise RuntimeError(f"RSI_REMOTE_DEVICE_NAME1 not found in {header}")

    if updated != text:
        header.write_text(updated, encoding="utf-8")

    verify = header.read_text(encoding="utf-8", errors="strict")
    for macro, value in _BLE_AUTOMATION_MACROS.items():
        if not re.search(
            rf"^\s*#\s*define\s+{re.escape(macro)}\s+{re.escape(value)}(?:\s|$)",
            verify,
            re.MULTILINE,
        ):
            raise RuntimeError(f"Pre-build verification failed: {macro} != {value}")
    expected_name = json.dumps(remote_name)
    if not re.search(
        rf"^\s*#\s*define\s+RSI_REMOTE_DEVICE_NAME1\s+{re.escape(expected_name)}(?:\s|$)",
        verify,
        re.MULTILINE,
    ):
        raise RuntimeError("Pre-build verification failed: remote BLE name mismatch")
    common_candidates = [example_dir / "inc" / "rsi_common_app.h"]
    common_candidates.extend(example_dir.glob("**/rsi_common_app.h"))
    common = next(
        (
            path
            for path in common_candidates
            if path.is_file()
            and not any(part.startswith("output_") for part in path.parts)
        ),
        None,
    )
    if common is None:
        raise FileNotFoundError(f"Cannot locate rsi_common_app.h under {example_dir}")
    common_text = common.read_text(encoding="utf-8", errors="strict")
    wlan_pattern = re.compile(
        r"(^[ \t]*#[ \t]*define[ \t]+WLAN_TASK_ENABLE[ \t]+)(\d+)([ \t]*(?://.*)?)$",
        re.MULTILINE,
    )
    common_updated, wlan_count = wlan_pattern.subn(
        r"\g<1>1\g<3>", common_text, count=1
    )
    if wlan_count != 1:
        raise RuntimeError(f"WLAN_TASK_ENABLE not found in {common}")

    # Some SDK revisions expose a Wi-Fi application selector; others only
    # compile the MQTT application and omit this macro.
    app_pattern = re.compile(
        r"(^[ \t]*#[ \t]*define[ \t]+WIFI_APP[ \t]+)([A-Za-z_][A-Za-z0-9_]*)([ \t]*(?://.*)?)$",
        re.MULTILINE,
    )
    common_updated, app_count = app_pattern.subn(
        r"\g<1>MQTT_APP\g<3>", common_updated, count=1
    )
    if common_updated != common_text:
        common.write_text(common_updated, encoding="utf-8")

    common_verify = common.read_text(encoding="utf-8", errors="strict")
    if not re.search(
        r"^\s*#\s*define\s+WLAN_TASK_ENABLE\s+1(?:\s|$)",
        common_verify,
        re.MULTILINE,
    ):
        raise RuntimeError("Pre-build verification failed: WLAN_TASK_ENABLE != 1")
    if app_count and not re.search(
        r"^\s*#\s*define\s+WIFI_APP\s+MQTT_APP(?:\s|$)",
        common_verify,
        re.MULTILINE,
    ):
        raise RuntimeError("Pre-build verification failed: WIFI_APP != MQTT_APP")

    print(
        "[prebuild] Verified WLAN task enabled"
        + (", MQTT mode" if app_count else "")
        + f" ({common})",
        flush=True,
    )
    print(
        "[prebuild] Verified ble_config.h: 1 peripheral, 1 central, "
        f"SMP C1/P1 disabled, peer={remote_name!r} ({header})",
        flush=True,
    )
    return header, common


def serial_cursor(api: StudioApi) -> int:
    return int(api.request("GET", "/api/serial/lines?since=999999999").get("total", 0))


class SerialWatcher:
    def __init__(self, api: StudioApi, since: int):
        self.api = api
        self.since = since
        self.state = UnifiedState()
        self.stop_event = threading.Event()
        self.error = None
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        since = self.since
        try:
            while not self.stop_event.is_set():
                data = self.api.request("GET", f"/api/serial/lines?since={since}")
                lines = list(data.get("lines") or [])
                since = int(data.get("total", since + len(lines)))
                for line in lines:
                    print(f"[dut] {line}", flush=True)
                    parse_serial_line(self.state, str(line))
                time.sleep(0.25)
        except Exception as exc:
            self.error = exc

    def wait_for(self, label, predicate, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.error:
                raise RuntimeError(f"Serial polling failed: {self.error}")
            if self.state.failure:
                raise RuntimeError(f"DUT reported failure: {self.state.failure}")
            if predicate(self.state):
                print(f"[pass] {label}", flush=True)
                return
            time.sleep(0.25)
        raise TimeoutError(f"Timed out waiting for {label}: {asdict(self.state)}")

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)


class PeerWorker:
    def __init__(self, config, section, mode, name, label):
        self.config = config
        self.section = section
        self.mode = mode
        self.name = name
        self.label = label
        self.result = None
        self.error = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            from pi_ble import run_peer
            self.result = run_peer(
                self.config,
                section=self.section,
                mode=self.mode,
                name=self.name,
                label=self.label,
            )
        except BaseException as exc:
            self.error = exc
        finally:
            self.done.set()

    def start(self):
        self.thread.start()

    def stop(self):
        try:
            from pi_ble import stop_peer
            stop_peer(self.config, section=self.section, mode=self.mode)
        except Exception as exc:
            print(f"[{self.label}] cleanup note: {exc}", flush=True)


def load_config(path: Path):
    config = load_json_config(path)
    required = (
        ("studio", "sdk_root"),
        ("studio", "examples_root"),
        ("wifi", "ssid"),
        ("pi", "host"),
    )
    missing = missing_nested_keys(config, required)
    if missing:
        raise ValueError("Missing config values: " + ", ".join(missing))
    placeholders = {
        "C:/path/to/simplicity_sdk",
        "C:/path/to/wiseconnect/examples/snippets/wlan_ble",
        "YOUR_SSID",
        "YOUR_WIFI_PASSWORD",
    }
    unresolved = []
    for section, key in (
        ("studio", "sdk_root"),
        ("studio", "examples_root"),
        ("wifi", "ssid"),
        ("wifi", "password"),
    ):
        if str(config.get(section, {}).get(key, "")) in placeholders:
            unresolved.append(f"{section}.{key}")
    if unresolved:
        raise ValueError("Replace config placeholders: " + ", ".join(unresolved))

    central = config.get("central_pi") or {}
    if central.get("enabled"):
        primary_host = str(config["pi"].get("host") or "").strip()
        central_host = str(central.get("host") or "").strip()
        if not central_host:
            raise ValueError("central_pi.host is required when central_pi.enabled=true")
        if central_host == primary_host:
            raise ValueError(
                "Full dual-role testing requires two distinct Bluetooth controllers; "
                "pi.host and central_pi.host must differ"
            )
    return config


def run(config, skip_build=False):
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")
    before = serial_cursor(api)
    if not skip_build:
        patch_and_verify_app_sources(config)
    build = None if skip_build else api.build_flash(config)
    after = serial_cursor(api)
    cursor = 0 if skip_build or after < before else before
    watcher = SerialWatcher(api, cursor)
    watcher.start()

    ble = config.get("ble") or {}
    full_dual = bool((config.get("central_pi") or {}).get("enabled"))
    expected_connections = 2 if full_dual else 1
    peers = [
        PeerWorker(
            config,
            "pi",
            "advertise",
            str(ble.get("pi_advertising_name") or "SILABS_DEV"),
            "pi-peripheral",
        )
    ]
    if full_dual:
        peers.append(
            PeerWorker(
                config,
                "central_pi",
                "connect",
                str(ble.get("dut_advertising_name") or "BLE_8S2M_COEX_DEMO"),
                "pi-central",
            )
        )
    for peer in peers:
        peer.start()

    timeouts = config.get("timeouts") or {}
    try:
        watcher.wait_for(
            "Wi-Fi initialization",
            lambda s: s.wifi_init,
            float(timeouts.get("wifi_s", 120)),
        )
        watcher.wait_for(
            "BLE advertising + scanning",
            lambda s: s.ble_advertising and s.ble_scanning,
            float(timeouts.get("ble_s", 150)),
        )
        watcher.wait_for(
            f"BLE connection count {expected_connections}",
            lambda s: s.ble_connection_count >= expected_connections,
            float(timeouts.get("ble_s", 150)),
        )
        connected_at = time.monotonic()
        disconnect_baseline = watcher.state.disconnect_count
        connection_baseline = watcher.state.connection_event_count
        watcher.wait_for(
            "WLAN connection and IPv4 address",
            lambda s: s.wifi_connected and bool(s.ip_address),
            float(timeouts.get("wifi_connect_s", 120)),
        )
        min_publish = max(1, int((config.get("mqtt") or {}).get("min_publish_count", 2)))
        publish_baseline = watcher.state.mqtt_publish_count
        publish_target = publish_baseline + min_publish
        stability = max(1.0, float(ble.get("stability_s", 60)))
        max_reconnects = max(0, int(ble.get("max_establishment_retries", 2)))
        reconnects = 0
        awaiting_reconnect = False
        require_profile = bool(ble.get("require_profile_evidence", True))
        deadline = time.monotonic() + float(timeouts.get("mqtt_s", 210))
        while time.monotonic() < deadline:
            if watcher.error:
                raise RuntimeError(f"Serial polling failed: {watcher.error}")
            if watcher.state.failure:
                raise RuntimeError(f"DUT reported failure: {watcher.state.failure}")
            if watcher.state.disconnect_count > disconnect_baseline:
                reconnects += watcher.state.disconnect_count - disconnect_baseline
                disconnect_baseline = watcher.state.disconnect_count
                if reconnects > max_reconnects:
                    raise RuntimeError(
                        f"BLE exceeded {max_reconnects} establishment retries"
                    )
                awaiting_reconnect = True
                print(
                    f"[retry] BLE establishment drop {reconnects}/{max_reconnects}; "
                    "waiting for reconnect before restarting the 60-second window",
                    flush=True,
                )
            if awaiting_reconnect:
                if watcher.state.connection_event_count > connection_baseline:
                    connection_baseline = watcher.state.connection_event_count
                    connected_at = time.monotonic()
                    publish_baseline = watcher.state.mqtt_publish_count
                    publish_target = publish_baseline + min_publish
                    awaiting_reconnect = False
                    print(
                        "[retry] BLE reconnected; stability and MQTT counters restarted",
                        flush=True,
                    )
                else:
                    time.sleep(0.25)
                    continue
            for peer in peers:
                if peer.done.is_set() and peer.error:
                    raise RuntimeError(f"{peer.label} failed: {peer.error}")
            profile_ok = (
                not require_profile
                or watcher.state.mtu_exchange
                or watcher.state.profile_discovery
            )
            if (
                watcher.state.mqtt_publish_count >= publish_target
                and profile_ok
                and time.monotonic() - connected_at >= stability
            ):
                break
            time.sleep(0.25)
        else:
            raise TimeoutError(
                "Coexistence acceptance not reached: " + json.dumps(asdict(watcher.state))
            )

        print(
            f"[pass] {min_publish} new MQTT publish confirmations while "
            f"{expected_connections} BLE link(s) remained stable for {stability:.0f}s",
            flush=True,
        )
        return {
            "ok": True,
            "app_id": APP_ID,
            "scope": "full_dual_role" if full_dual else "dut_central_role",
            "build_job_id": None if build is None else build.get("id"),
            "serial": asdict(watcher.state),
        }
    finally:
        for peer in peers:
            peer.stop()
        for peer in peers:
            peer.thread.join(timeout=15)
        watcher.stop()


def parser_self_test():
    state = UnifiedState()
    lines = (
        "Wi-Fi Initialization Success",
        "IP Address: 192.168.50.22",
        "Advertising started, local device name : BLE_8S2M_COEX_DEMO",
        "Scanning started",
        "Connected Address: C2:9E:DA:33:B0:DF",
        "Initiated Role : 0x2",
        "RemoteMTU : 232",
        "Remote device profile discovery started",
        "QoS1 publish is successful",
        "QoS1 publish is successful",
    )
    for line in lines:
        parse_serial_line(state, line)
    assert state.wifi_init and state.wifi_connected
    assert state.ip_address == "192.168.50.22"
    assert state.ble_advertising and state.ble_scanning
    assert state.ble_connection_count == 1 and state.initiated_roles == [2]
    assert state.connection_event_count == 1
    assert state.mtu_exchange and state.profile_discovery
    assert state.mqtt_publish_count == 2 and state.disconnect_count == 0
    parse_serial_line(state, "Central is disconnected, reason : 0x4e13")
    assert state.disconnect_count == 1
    retry = UnifiedState()
    parse_serial_line(retry, "WLAN connection failed 10003")
    parse_serial_line(retry, "WLAN connected state")
    parse_serial_line(retry, "192.168.50.22")
    assert retry.failure is None and retry.wlan_retry_count == 1
    assert retry.wifi_connected and retry.ip_address == "192.168.50.22"
    print("Parser self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path(__file__).with_name("config.local.json")
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        parser_self_test()
        return 0
    try:
        config = load_config(args.config)
        result = run(config, skip_build=args.skip_build)
        result_path = Path(__file__).with_name("last_result.json")
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nPASS: WLAN BLE Unified Coex App ({result_path})")
        return 0
    except Exception as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
