#!/usr/bin/env python3
"""Build, flash, and validate the complete WLAN BLE Unified AE Coex app."""

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
from _common.studio_config import load_json_config, missing_nested_keys_or  # noqa: E402

APP_ID = "wlan_ble_unified_ae_coex_app"
PRIVATE_IP_RE = re.compile(
    r"(?<!\d)(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)"
)
CONN_RE = re.compile(r"(?:-|\b)conn\s*(\d+)\b", re.I)
BLE_ADDR_RE = re.compile(r"(?<![0-9A-F])(?:[0-9A-F]{2}:){5}[0-9A-F]{2}(?![0-9A-F])", re.I)


@dataclass
class AeState:
    wifi_init: bool = False
    wifi_scan: bool = False
    wifi_connected: bool = False
    ip_address: Optional[str] = None
    socket_connected: bool = False
    throughput_started: bool = False
    throughput_complete: bool = False
    total_bytes: int = 0
    throughput_mbps: float = 0.0
    ae_set1: bool = False
    ae_set2: bool = False
    ae_scan: bool = False
    local_ble_address: Optional[str] = None
    remote_central_links: int = 0
    remote_peripheral_links: int = 0
    connection_ids: set[int] = field(default_factory=set)
    mtu_connections: set[int] = field(default_factory=set)
    smp_connections: set[int] = field(default_factory=set)
    encrypted_connections: set[int] = field(default_factory=set)
    security_connections: set[int] = field(default_factory=set)
    passkeys: list[str] = field(default_factory=list)
    profile_connections: set[int] = field(default_factory=set)
    receive_connections: set[int] = field(default_factory=set)
    transmit_connections: set[int] = field(default_factory=set)
    disconnect_count: int = 0
    last_warning: Optional[str] = None
    failure: Optional[str] = None


def _conn_ids(line: str) -> set[int]:
    return {int(match) for match in CONN_RE.findall(line)}


def parse_serial_line(state: AeState, line: str) -> None:
    raw = line.rstrip("\r\n")
    low = raw.strip().lower()
    if not low:
        return

    state.wifi_init |= (
        "wi-fi initialization success" in low
        or "wi-fi initialization is successful" in low
    )
    state.wifi_scan |= "scan results" in low or "scan done state" in low
    state.wifi_connected |= (
        "wlan connected state" in low
        or "wlan connection is successful" in low
        or "wlan connection success" in low
    )
    ip_match = PRIVATE_IP_RE.search(raw)
    if ip_match and ("ip" in low or state.wifi_connected):
        state.ip_address = ip_match.group(1)
        state.wifi_connected = True
    state.socket_connected |= (
        "socket connected to tcp server" in low
        or "tcp socket connect success" in low
    )
    state.throughput_started |= "tcp_tx throughput test start" in low
    if "total bytes sent" in low:
        match = re.search(r"total bytes sent\s*:\s*(\d+)", low)
        if match:
            state.total_bytes = max(state.total_bytes, int(match.group(1)))
    if "throughput achieved" in low and "success" in low:
        state.throughput_complete = True
        match = re.search(r"throughput achieved\s*@?\s*([0-9.]+)\s*mbps", low)
        if match:
            state.throughput_mbps = max(state.throughput_mbps, float(match.group(1)))

    state.ae_set1 |= (
        "set 1 ae adv enable success" in low
        or "set ae params of set 1 successful" in low
    )
    state.ae_set2 |= (
        "set 2 ae adv enable success" in low
        or "set ae params of set 2 successful" in low
    )
    state.ae_scan |= (
        "set ae scan enable success" in low
        or "set ae scan params success" in low
        or "scanning started" in low
    )
    if "local device address" in low:
        address = BLE_ADDR_RE.search(raw)
        if address:
            state.local_ble_address = address.group(0).upper()
    match = re.search(r"number of central devices connected\s*:\s*(\d+)", low)
    if match:
        state.remote_central_links = max(state.remote_central_links, int(match.group(1)))
    match = re.search(r"number of peripheral devices connected\s*:\s*(\d+)", low)
    if match:
        state.remote_peripheral_links = max(state.remote_peripheral_links, int(match.group(1)))

    ids = _conn_ids(low)
    if "ble conn id" in low:
        match = re.search(r"ble conn id\s*:\s*(\d+)", low)
        if match:
            ids.add(int(match.group(1)))
    if "enhance connect event" in low or "connected address" in low:
        state.connection_ids.update(ids)
    if "mtu exchange" in low or "mtu size from remote" in low:
        state.mtu_connections.update(ids)
    if "smp pairing request" in low or "in smp response" in low or "passkey event" in low:
        state.smp_connections.update(ids)
    if "smp encrypt event" in low:
        state.encrypted_connections.update(ids)
    if "smp security keys event" in low or "le ltk" in low:
        state.security_connections.update(ids)
    passkey = re.search(r"passkey\s*:\s*(\d{6})", low)
    if passkey:
        state.passkeys.append(passkey.group(1))
    if "profiles discovery completed" in low:
        state.profile_connections.update(ids)
    if "receiving notifications from remote device" in low or "receive notification event" in low:
        state.receive_connections.update(ids)
    if "remote device enabled the notification" in low or "start transmitting data to" in low:
        state.transmit_connections.update(ids)
    if "disconnected" in low or "disconnect event" in low or "dis-conn evt" in low:
        state.disconnect_count += 1

    if any(token in low for token in ("wlan connection failed", "socket connect failed")):
        state.last_warning = raw.strip()
    fatal = (
        "wi-fi initialization failed",
        "ble task excution fails",
        "number of ble centrals or ble peripherals given wrong",
        "throughput test failed",
        "smp failed",
    )
    if any(token in low for token in fatal):
        state.failure = raw.strip()


def _state_dict(state: AeState) -> dict[str, Any]:
    result = asdict(state)
    for key, value in tuple(result.items()):
        if isinstance(value, set):
            result[key] = sorted(value)
    return result


class StudioApi:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path, data=body, method=method,
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

    def build_flash(self, cfg, server):
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
            "throughput_server_ip": server["host"],
            "throughput_server_port": int(server["port"]),
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


def serial_cursor(api: StudioApi) -> int:
    return int(api.request("GET", "/api/serial/lines?since=999999999").get("total", 0))


class SerialWatcher:
    def __init__(self, api: StudioApi, since: int):
        self.api = api
        self.since = max(0, since)
        self.state = AeState()
        self.stop_event = threading.Event()
        self.error: Optional[Exception] = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
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
        except Exception as exc:  # noqa: BLE001
            self.error = exc

    def check(self):
        if self.error:
            raise RuntimeError(f"Serial polling failed: {self.error}")
        if self.state.failure:
            raise RuntimeError(f"DUT reported failure: {self.state.failure}")

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=3)


def load_config(path: Path) -> dict[str, Any]:
    cfg = load_json_config(path)
    required = (
        ("studio", "sdk_root"), ("studio", "examples_root"),
        ("wifi", "ssid"), ("nuc", "host"),
        ("pi", "host"), ("central_pi", "host"),
    )
    missing = missing_nested_keys_or(cfg, required)
    if missing:
        raise ValueError("Missing full-validation settings: " + ", ".join(missing))
    if str(cfg["pi"]["host"]) == str(cfg["central_pi"]["host"]):
        raise ValueError("pi and central_pi must be different BLE controllers")
    return cfg


def _peer_worker(config, section, mode, label, outcome):
    try:
        from pi_ble import run_peer
        outcome["result"] = run_peer(config, section=section, mode=mode, label=label)
    except BaseException as exc:  # noqa: BLE001
        outcome["error"] = exc
    finally:
        outcome["done"] = True


def _check_peers(outcomes, *, allow_central_pending=True):
    for mode, outcome in outcomes.items():
        if allow_central_pending and mode == "central" and not outcome:
            continue
        if outcome.get("done"):
            raise RuntimeError(
                f"{mode} BLE peer ended early: {outcome.get('error') or 'unexpected exit'}"
            )


def _wait(label, watcher, outcomes, predicate, timeout, pump=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        watcher.check()
        _check_peers(outcomes)
        if pump:
            pump()
        if predicate(watcher.state):
            print(f"[pass] {label}", flush=True)
            return
        time.sleep(0.25)
    raise TimeoutError(f"Timed out waiting for {label}: {_state_dict(watcher.state)}")


def run(config: dict[str, Any], *, skip_build: bool = False) -> dict[str, Any]:
    from nuc_tcp import start_tcp_sink, stop_tcp_sink
    from pi_ble import stop_peer, supply_passkey

    print("\n=== WLAN BLE Unified AE complete validation ===", flush=True)
    server = start_tcp_sink(config)
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")
    before = serial_cursor(api)
    outcomes = {"peripheral": {}, "central": {}}
    threads = []
    watcher = None

    peripheral = threading.Thread(
        target=_peer_worker,
        args=(config, "pi", "peripheral", "pi-peripheral", outcomes["peripheral"]),
        daemon=True,
    )
    peripheral.start()
    threads.append(peripheral)
    time.sleep(float((config.get("ble") or {}).get("peripheral_ready_wait_s", 5)))
    if outcomes["peripheral"].get("done"):
        raise RuntimeError(
            f"peripheral BLE peer failed before flash: {outcomes['peripheral'].get('error')}"
        )

    try:
        build = None if skip_build else api.build_flash(config, server)
        after = serial_cursor(api)
        cursor = 0 if skip_build or after < before else before
        watcher = SerialWatcher(api, cursor)
        watcher.start()

        timeouts = config.get("timeouts") or {}
        relayed = 0

        def relay_passkeys():
            nonlocal relayed
            while relayed < len(watcher.state.passkeys):
                value = watcher.state.passkeys[relayed]
                supply_passkey(config, value)
                relayed += 1

        _wait("Wi-Fi initialized", watcher, outcomes, lambda s: s.wifi_init, float(timeouts.get("wifi_s", 150)), relay_passkeys)
        _wait(
            "Wi-Fi connected with IPv4",
            watcher, outcomes,
            lambda s: s.wifi_connected and bool(s.ip_address),
            float(timeouts.get("wifi_connect_s", 150)),
            relay_passkeys,
        )
        _wait(
            "AE advertising set 1, set 2, and scan enabled",
            watcher, outcomes,
            lambda s: s.ae_set1 and s.ae_set2 and s.ae_scan,
            float(timeouts.get("ble_s", 180)),
            relay_passkeys,
        )
        _wait(
            "DUT public BLE address",
            watcher, outcomes,
            lambda s: bool(s.local_ble_address),
            float(timeouts.get("ble_s", 180)),
            relay_passkeys,
        )
        _wait(
            "DUT-central/Pi-peripheral link paired and encrypted",
            watcher, outcomes,
            lambda s: (
                s.remote_central_links >= 1
                and len(s.encrypted_connections | s.security_connections) >= 1
            ),
            float(timeouts.get("smp_s", 180)),
            relay_passkeys,
        )
        # AE payloads here are application bytes, not a guaranteed Local Name
        # AD structure. Connect using the public address reported by the DUT.
        config.setdefault("ble", {})["dut_address"] = watcher.state.local_ble_address
        central = threading.Thread(
            target=_peer_worker,
            args=(config, "central_pi", "central", "pi-central", outcomes["central"]),
            daemon=True,
        )
        central.start()
        threads.append(central)
        _wait(
            "both BLE roles connected",
            watcher, outcomes,
            lambda s: s.remote_central_links >= 1 and s.remote_peripheral_links >= 1,
            float(timeouts.get("ble_s", 180)),
            relay_passkeys,
        )
        _wait(
            "authenticated SMP on both BLE links",
            watcher, outcomes,
            lambda s: len(s.encrypted_connections | s.security_connections) >= 2,
            float(timeouts.get("smp_s", 180)),
            relay_passkeys,
        )
        _wait(
            "profile discovery and bidirectional notifications",
            watcher, outcomes,
            lambda s: (
                len(s.profile_connections) >= 2
                and bool(s.receive_connections)
                and bool(s.transmit_connections)
            ),
            float(timeouts.get("ble_data_s", 240)),
            relay_passkeys,
        )
        _wait(
            "TCP_TX throughput completed",
            watcher, outcomes,
            lambda s: s.socket_connected and s.throughput_complete and s.total_bytes > 0,
            float(timeouts.get("throughput_s", 180)),
            relay_passkeys,
        )

        baseline = watcher.state.disconnect_count
        stability_s = max(60.0, float((config.get("ble") or {}).get("stability_s", 60)))
        print(f"[test] Holding both encrypted BLE links for {stability_s:.0f}s after TCP completion", flush=True)
        deadline = time.monotonic() + stability_s
        while time.monotonic() < deadline:
            watcher.check()
            _check_peers(outcomes)
            relay_passkeys()
            if watcher.state.disconnect_count != baseline:
                raise RuntimeError("BLE disconnected during the 60-second stability gate")
            time.sleep(0.25)
        print("[pass] two-role BLE remained intact for 60 seconds after TCP_TX", flush=True)

        return {
            "ok": True,
            "app_id": APP_ID,
            "wlan_workload": "TCP_TX",
            "build_job_id": None if build is None else build.get("id"),
            "server": server,
            "serial": _state_dict(watcher.state),
            "peers": {key: value.get("result") for key, value in outcomes.items()},
        }
    finally:
        for section, mode in (("pi", "peripheral"), ("central_pi", "central")):
            try:
                stop_peer(config, section=section, mode=mode)
            except Exception as exc:  # noqa: BLE001
                print(f"[cleanup] {mode}: {exc}", flush=True)
        for thread in threads:
            thread.join(timeout=15)
        if watcher is not None:
            watcher.stop()
        try:
            stop_tcp_sink(config, server)
        except Exception as exc:  # noqa: BLE001
            print(f"[cleanup] TCP sink: {exc}", flush=True)


def parser_self_test() -> None:
    state = AeState()
    lines = (
        "Wi-Fi initialization is successful",
        "8 Scan results:",
        "WLAN connected state",
        "192.168.1.162",
        "set ae params of set 1 successful and selected TX Power is 8 dbm",
        "set 1 ae adv enable success",
        "set ae params of set 2 successful and selected TX Power is 8 dbm",
        "set 2 ae adv enable success",
        "set ae scan enable success",
        "Local device address = B0:C7:DE:B5:5E:9B",
        "Number of central devices connected:1 -conn0",
        "Number of peripheral devices connected:1 -conn2",
        "in smp encrypt event -conn0",
        "In passkey event, remote addr: 45:70:F0:7D:D6:41, passkey: 833753 -conn0",
        "in smp security keys event -conn0",
        "in smp encrypt event -conn2",
        "in smp security keys event -conn2",
        "remote device profiles discovery completed -conn0",
        "remote device profiles discovery completed -conn2",
        "receiving notifications from remote device -conn0",
        "remote device enabled the notification -conn2",
        "Socket connected to TCP server",
        "TCP_TX Throughput test start",
        "Total bytes sent : 3051409",
        "Throughput achieved @ 0.06 Mbps in 40.000 sec successfully",
    )
    for line in lines:
        parse_serial_line(state, line)
    assert state.wifi_init and state.wifi_connected and state.ip_address
    assert state.ae_set1 and state.ae_set2 and state.ae_scan
    assert state.local_ble_address == "B0:C7:DE:B5:5E:9B"
    assert state.remote_central_links == 1 and state.remote_peripheral_links == 1
    assert state.encrypted_connections == {0, 2}
    assert state.security_connections == {0, 2}
    assert state.passkeys == ["833753"]
    assert state.profile_connections == {0, 2}
    assert state.receive_connections == {0} and state.transmit_connections == {2}
    assert state.socket_connected and state.throughput_complete
    assert state.total_bytes == 3051409 and state.throughput_mbps == 0.06
    print("Parser self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.local.json"))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        parser_self_test()
        return 0
    try:
        result = run(load_config(args.config), skip_build=args.skip_build)
        path = Path(__file__).with_name("last_result.json")
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nPASS: WLAN BLE Unified AE complete validation ({path})")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
