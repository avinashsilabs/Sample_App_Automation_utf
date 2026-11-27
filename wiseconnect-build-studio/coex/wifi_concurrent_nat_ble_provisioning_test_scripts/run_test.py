#!/usr/bin/env python3
"""Build, flash, BLE-provision, and validate Concurrent NAT for 60 seconds."""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Shared Studio config helpers (coex/_common); keep app-specific validation here.
_COEX_ROOT = Path(__file__).resolve().parents[1]
if str(_COEX_ROOT) not in sys.path:
    sys.path.insert(0, str(_COEX_ROOT))
from _common.studio_config import load_json_config, missing_nested_keys  # noqa: E402


@dataclass
class NatState:
    wifi_init: bool = False
    ble_advertising: bool = False
    ble_connected: bool = False
    credentials_received: bool = False
    sta_connected: bool = False
    sta_ip: Optional[str] = None
    ble_disconnected: bool = False
    ap_gateway: Optional[str] = None
    ap_started: bool = False
    nat_enabled: bool = False
    ap_client_connected: bool = False
    wlan_retry: Optional[str] = None
    failure: Optional[str] = None


IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def parse_serial_line(state: NatState, line: str) -> None:
    raw = line.strip()
    low = raw.lower()
    if not low:
        return
    if "wi-fi initialization success" in low:
        state.wifi_init = True
    if "[ble]: advertising started" in low or "[ble]: started advertising" in low:
        state.ble_advertising = True
    if "[ble]: ble connected" in low:
        state.ble_connected = True
    if "[ble]: pwd from ble app" in low:
        state.credentials_received = True
    if "[wi-fi sta]: wlan connection success" in low:
        state.sta_connected = True
    match = IP_RE.search(raw)
    if "[wi-fi sta]: sta ipv4" in low and match:
        state.sta_ip = match.group(0)
    elif state.sta_connected and not state.sta_ip and match and "gateway" not in low:
        # print_sl_ip_address() can arrive as a separate UART fragment.
        state.sta_ip = match.group(0)
    if "[ble]: ble disconnected" in low:
        state.ble_disconnected = True
    if "[wi-fi ap]: ap's default gateway" in low:
        match = IP_RE.search(raw)
        if match:
            state.ap_gateway = match.group(0)
    if "[wi-fi ap]: ap started" in low:
        state.ap_started = True
    if "enabled nat" in low:
        state.nat_enabled = True
    if "remote client connected" in low:
        state.ap_client_connected = True

    # Join is retried by writing the credentials again, and DHCP is retried by
    # patch_ip_retry(). Either UART line is fatal only when the wait times out.
    if "wlan connect failed" in low or "ip config failed" in low:
        state.wlan_retry = raw
        return
    failures = (
        "wi-fi initialization failed",
        "failed to bring wi-fi ap interface up",
        "enabling the nat failed",
    )
    if any(marker in low for marker in failures):
        state.failure = raw


class StudioApi:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(
        self, method: str, path: str, payload: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
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
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError("%s %s failed (%s): %s" % (method, path, exc.code, detail)) from exc
        except URLError as exc:
            raise RuntimeError("Cannot reach Build Studio at %s: %s" % (self.base_url, exc)) from exc

    def build_flash(self, config: dict[str, Any]) -> dict[str, Any]:
        studio = config["studio"]
        wifi = config["wifi"]
        nat = config["nat"]
        payload = {
            "app_id": "wifi_concurrent_nat_ble_provisioning",
            "target": "soc",
            "board": studio.get("board", "brd4338a"),
            "toolchain": studio.get("toolchain", "gcc"),
            "sdk_root": studio["sdk_root"],
            "ble_root": studio["examples_root"],
            "wifi_ssid": wifi["ssid"],
            "wifi_psk": wifi.get("password", ""),
            "nat_ap_ssid": nat["softap_ssid"],
            "nat_ap_psk": nat["softap_password"],
        }
        if studio.get("adapter_serial"):
            payload["adapter_serial"] = studio["adapter_serial"]
        started = self.request("POST", "/api/build-flash", payload)
        job_id = str(started["job_id"])
        seen = 0
        while True:
            job = self.request("GET", "/api/build/%s" % job_id)
            logs = list(job.get("logs") or [])
            for line in logs[seen:]:
                print("[build] " + str(line), flush=True)
            seen = len(logs)
            if job.get("status") in ("success", "failed"):
                if job["status"] != "success":
                    raise RuntimeError(job.get("error") or "Build/flash failed")
                return job
            time.sleep(1)


def serial_cursor(api: StudioApi) -> int:
    data = api.request("GET", "/api/serial/lines?since=999999999")
    return int(data.get("total", 0))


class SerialWatcher:
    def __init__(self, api: StudioApi, since: int):
        self.api = api
        self.since = max(0, since)
        self.state = NatState()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[Exception] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        since = self.since
        try:
            while not self._stop.is_set():
                data = self.api.request("GET", "/api/serial/lines?since=%d" % since)
                lines = list(data.get("lines") or [])
                since = int(data.get("total", since + len(lines)))
                for line in lines:
                    print("[dut] " + str(line), flush=True)
                    parse_serial_line(self.state, str(line))
                time.sleep(0.25)
        except Exception as exc:  # noqa: BLE001
            self._error = exc

    def wait_for(self, name: str, predicate, timeout: float) -> NatState:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._error:
                raise RuntimeError("Serial polling failed: %s" % self._error)
            if self.state.failure:
                raise RuntimeError("DUT reported failure: %s" % self.state.failure)
            if predicate(self.state):
                print("[pass] " + name, flush=True)
                return self.state
            time.sleep(0.25)
        raise TimeoutError("Timed out waiting for %s: %s" % (name, asdict(self.state)))

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


def load_config(path: Path) -> dict[str, Any]:
    config = load_json_config(path)
    required = (
        ("studio", "sdk_root"), ("studio", "examples_root"),
        ("wifi", "ssid"), ("pi", "host"),
        ("ble", "write_uuid"), ("ble", "read_uuid"), ("ble", "notify_uuid"),
        ("nat", "softap_ssid"), ("nat", "softap_password"),
    )
    missing = missing_nested_keys(config, required)
    if missing:
        raise ValueError("Missing config values: " + ", ".join(missing))
    if bool((config.get("nat") or {}).get("throughput_enabled", True)):
        throughput_missing = [
            "nuc." + key for key in ("host", "username")
            if not str((config.get("nuc") or {}).get(key, "")).strip()
        ]
        if throughput_missing:
            raise ValueError(
                "Missing throughput server values: " + ", ".join(throughput_missing)
            )
    return config


def run(config: dict[str, Any], skip_build: bool = False) -> dict[str, Any]:
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")
    if not skip_build:
        patch_ip_retry(config)
    before = serial_cursor(api)
    build = None if skip_build else api.build_flash(config)
    after = serial_cursor(api)
    cursor = 0 if skip_build or after < before else before
    watcher = SerialWatcher(api, cursor)
    watcher.start()
    results: dict[str, Any] = {
        "app_id": "wifi_concurrent_nat_ble_provisioning",
        "build_job_id": None if build is None else build.get("id"),
    }
    timeouts = config.get("timeouts") or {}
    try:
        settle = float(config.get("ble", {}).get("post_flash_settle_s", 15))
        print("[test] Waiting %.0fs for BLE_CONFIGURATOR..." % settle, flush=True)
        time.sleep(settle)
        watcher.wait_for(
            "BLE advertising", lambda s: s.ble_advertising,
            float(timeouts.get("ble_s", 60)),
        )
        try:
            from .pi_ble import provision_via_pi
        except ImportError:
            from pi_ble import provision_via_pi  # type: ignore
        results["provision"] = provision_via_pi(config)

        watcher.wait_for(
            "STA WLAN connection", lambda s: s.sta_connected,
            float(timeouts.get("wlan_s", 90)),
        )
        watcher.wait_for(
            "STA IPv4 address", lambda s: bool(s.sta_ip),
            float(timeouts.get("ip_s", 60)),
        )
        watcher.wait_for(
            "expected BLE disconnect after provisioning", lambda s: s.ble_disconnected,
            float(timeouts.get("ble_s", 60)),
        )
        watcher.wait_for(
            "DUT SoftAP started", lambda s: s.ap_started,
            float(timeouts.get("ap_s", 60)),
        )
        watcher.wait_for(
            "NAT enabled", lambda s: s.nat_enabled,
            float(timeouts.get("nat_s", 60)),
        )

        try:
            from .pi_nat import verify_nat_via_pi
        except ImportError:
            from pi_nat import verify_nat_via_pi  # type: ignore
        results["nat"] = verify_nat_via_pi(config)
        watcher.wait_for(
            "DUT SoftAP client connected", lambda s: s.ap_client_connected,
            float(timeouts.get("client_s", 30)),
        )
        results["serial"] = asdict(watcher.state)
        results["ok"] = True
        return results
    finally:
        watcher.stop()


def patch_ip_retry(config: dict[str, Any]) -> None:
    """Re-enter DHCP until the demo's own retry counter gives up.

    wifi_app.c increments `a` and disconnects at 3, but clears the connected
    event first, so a single DHCP miss never comes back.
    """
    path = (
        Path(config["studio"]["examples_root"])
        / "wifi_concurrent_nat_ble_provisioning"
        / "wifi_app.c"
    )
    text = path.read_text(encoding="utf-8")
    needle = (
        'SL_DEBUG_LOG_V2(ERROR, "[Wi-Fi STA]: IP Config Failed, Error Code : 0x%lX\\r\\n", status);\n'
        "          break;"
    )
    insert = (
        'SL_DEBUG_LOG_V2(ERROR, "[Wi-Fi STA]: IP Config Failed, Error Code : 0x%lX\\r\\n", status);\n'
        "          if (a < 3) {\n"
        "            wifi_app_set_event(WIFI_APP_CONNECTED_STATE);\n"
        "          }\n"
        "          break;"
    )
    tail = text.split("IP Config Failed", 1)[-1][:400]
    if "if (a < 3)" in text and "WIFI_APP_CONNECTED_STATE" in tail:
        print("[build] %s already retries IP config" % path.name, flush=True)
        return
    if needle not in text:
        raise RuntimeError("IP retry site not found in %s" % path)
    path.write_text(text.replace(needle, insert, 1), encoding="utf-8")
    print("[build] Patched %s to retry IP config" % path.name, flush=True)


def parser_self_test() -> None:
    state = NatState()
    lines = (
        " Wi-Fi Initialization Success",
        "[BLE]: Advertising Started...",
        "[BLE]: BLE Connected - remote_dev_addr : D8:3A:DD:13:53:66",
        "[BLE]: PWD from ble app",
        "[Wi-Fi STA]: WLAN Connection Success",
        "[Wi-Fi STA]: STA IPv4 : 192.168.50.22",
        "[BLE]: BLE Disconnected - remote_dev_addr : D8:3A:DD:13:53:66",
        "[Wi-Fi AP]: AP's default gateway: 192.168.10.10",
        "[Wi-Fi AP]: AP started",
        "Enabled NAT",
        "Remote Client connected: D8:3A:DD:13:53:66",
    )
    for line in lines:
        parse_serial_line(state, line)
    assert state.wifi_init and state.ble_advertising and state.ble_connected
    assert state.credentials_received and state.sta_connected
    assert state.sta_ip == "192.168.50.22" and state.ble_disconnected
    assert state.ap_gateway == "192.168.10.10" and state.ap_started
    assert state.nat_enabled and state.ap_client_connected and not state.failure
    retry = NatState()
    parse_serial_line(retry, "[Wi-Fi STA]: WLAN Connect Failed, Error Code : 0x10003")
    parse_serial_line(retry, "[Wi-Fi STA]: IP Config Failed, Error Code : 0x1FF9C")
    assert retry.wlan_retry and not retry.failure
    print("Parser self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path,
        default=Path(__file__).with_name("config.local.json"),
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
        print("\nPASS: Wi-Fi Concurrent NAT with BLE Provisioning (%s)" % result_path)
        return 0
    except Exception as exc:  # noqa: BLE001
        print("\nFAIL: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
