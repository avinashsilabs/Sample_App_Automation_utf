#!/usr/bin/env python3
"""Build, flash, and validate Wi-Fi BLE Power Save.

SDK readme steps 2–11: compile-time lab AP, TLS :5001 on the Pi, UART
power-save + TCP, then BLE simple-chat Hello from WLAN / Hello from BLE.
Energy Profiler (readme step 12) is out of scope.
"""

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

APP_ID = "wifi_ble_power_save"
HELLO_WLAN = "Hello from WLAN\r\n"
HELLO_BLE = "Hello from BLE\r\n"

PRIVATE_IP_RE = re.compile(
    r"(?<!\d)(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)"
)


@dataclass
class AppState:
    wifi_init: bool = False
    ssl_ca: bool = False
    ssid_seen: bool = False
    wlan_join: bool = False
    configured_ip: bool = False
    ip_address: Optional[str] = None
    power_save: bool = False
    tcp_socket: bool = False
    module_connected: bool = False
    wifi_to_ble: bool = False
    ble_to_wifi: bool = False
    wlan_retry: Optional[str] = None
    failure: Optional[str] = None


def parse_serial_line(state: AppState, line: str) -> None:
    raw = line.rstrip("\r\n")
    low = raw.strip().lower()
    if not low:
        return
    if "wi-fi initialization is successful" in low:
        state.wifi_init = True
    if "load ssl ca certificate at index" in low and "success" in low:
        state.ssl_ca = True
    if "loading tls ca certificate" in low and "failed" in low:
        state.failure = raw.strip()
    if re.search(r"ssid\s+\S+", raw, re.I):
        state.ssid_seen = True
    if "wlan connection is successful" in low or "wlan connection success" in low:
        state.wlan_join = True
    if "configured ip" in low:
        state.configured_ip = True
    ip_match = PRIVATE_IP_RE.search(raw)
    if ip_match and (
        "ip" in low or state.wlan_join or state.configured_ip or state.wifi_init
    ):
        state.ip_address = ip_match.group(1)
    if "module is in power save" in low:
        state.power_save = True
    if "tcp socket connect success" in low:
        state.tcp_socket = True
    if "module connected" in low and "disconnected" not in low:
        state.module_connected = True
    if "data from wi-fi to ble" in low and "hello from wlan" in low:
        state.wifi_to_ble = True
    if "data from ble to wi-fi" in low and "hello from ble" in low:
        state.ble_to_wifi = True
    # wifi_app.c loops back to UNCONNECTED and rejoins, so a join error is
    # only fatal if wlan_s expires without a successful connection.
    if "wlan connect failed" in low or "wlan connection failed" in low:
        state.wlan_retry = raw.strip()
        return
    # connect() is retried from WIFI_APP_IPCONFIG_DONE_STATE, so one
    # handshake failure is not fatal unless TCP never succeeds.
    if "socket connect failed" in low:
        state.wlan_retry = raw.strip()
        return
    failures = (
        "ip config failed",
        "socket creation failed",
        "failed to initiate power save",
        "wi-fi initialization failed",
    )
    if any(marker in low for marker in failures):
        state.failure = raw.strip()


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
            raise RuntimeError(f"{method} {path} failed ({exc.code}): {detail}") from exc
        except URLError as exc:
            raise RuntimeError(
                f"Cannot reach WiseConnect Build Studio at {self.base_url}: {exc}"
            ) from exc

    def build_flash(
        self, cfg: dict[str, Any], *, ssl_server_ip: str
    ) -> dict[str, Any]:
        studio = cfg["studio"]
        wifi = cfg.get("wifi") or {}
        ssl_cfg = cfg.get("ssl") or {}
        payload = {
            "app_id": APP_ID,
            "target": "soc",
            "board": studio.get("board", "brd4338a"),
            "toolchain": studio.get("toolchain", "gcc"),
            "sdk_root": studio["sdk_root"],
            "ble_root": studio["examples_root"],
            "ssl_server_ip": ssl_server_ip,
            "ssl_server_port": int(ssl_cfg.get("port") or 5001),
            "wifi_ssid": wifi.get("ssid") or "",
            "wifi_psk": wifi.get("password") or "",
        }
        if studio.get("adapter_serial"):
            payload["adapter_serial"] = studio["adapter_serial"]
        started = self.request("POST", "/api/build-flash", payload)
        job_id = str(started["job_id"])
        seen = 0
        while True:
            job = self.request("GET", f"/api/build/{job_id}")
            logs = list(job.get("logs") or [])
            for line in logs[seen:]:
                print(f"[build] {line}", flush=True)
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
    def __init__(self, api: StudioApi, *, since: int = 0):
        self.api = api
        self.since = max(0, int(since))
        self.state = AppState()
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
                data = self.api.request("GET", f"/api/serial/lines?since={since}")
                lines = list(data.get("lines") or [])
                since = int(data.get("total", since + len(lines)))
                for line in lines:
                    print(f"[dut] {line}", flush=True)
                    parse_serial_line(self.state, str(line))
                time.sleep(0.25)
        except Exception as exc:  # noqa: BLE001
            self._error = exc

    def wait_for(self, name: str, predicate, timeout: float) -> AppState:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._error:
                raise RuntimeError(f"Serial polling failed: {self._error}")
            if self.state.failure:
                raise RuntimeError(f"DUT reported failure: {self.state.failure}")
            if predicate(self.state):
                print(f"[pass] {name}", flush=True)
                return self.state
            time.sleep(0.25)
        raise TimeoutError(f"Timed out waiting for {name}: {asdict(self.state)}")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


def load_config(path: Path) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    required = (
        ("studio", "sdk_root"),
        ("studio", "examples_root"),
        ("wifi", "ssid"),
        ("pi", "host"),
        ("ble", "write_uuid"),
        ("ble", "notify_uuid"),
    )
    missing = [
        ".".join(keys)
        for keys in required
        if not str(config.get(keys[0], {}).get(keys[1], "")).strip()
    ]
    if missing:
        raise ValueError(f"Missing config values: {', '.join(missing)}")
    placeholder_values = {
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
    ):
        if str(config.get(section, {}).get(key, "")) in placeholder_values:
            unresolved.append(f"{section}.{key}")
    if (
        int(config.get("wifi", {}).get("security", 2)) != 0
        and str(config.get("wifi", {}).get("password", "")) in placeholder_values
    ):
        unresolved.append("wifi.password")
    if unresolved:
        raise ValueError(
            "Replace placeholder values in config.local.json: "
            + ", ".join(unresolved)
        )
    return config


SECURITY_MACROS = {
    0: "SL_WIFI_OPEN",
    1: "SL_WIFI_WPA",
    2: "SL_WIFI_WPA2",
    3: "SL_WIFI_WEP",
    6: "SL_WIFI_WPA_WPA2_MIXED",
    7: "SL_WIFI_WPA3",
    8: "SL_WIFI_WPA3_TRANSITION",
}
SCAN_TO_SECURITY = {"open": 0, "wpa": 1, "wpa2": 2, "wpa3": 7}


def resolve_security(configured: int, advertised: Optional[str]) -> int:
    """Prefer what the AP really advertises when it contradicts the config."""
    if advertised is None:
        return configured
    if advertised == "wpa2" and configured in (2, 6, 8):
        return configured
    if advertised == "wpa3" and configured in (7, 8):
        return configured
    wanted = SCAN_TO_SECURITY[advertised]
    if wanted != configured:
        print(
            f"[test] WARN: config wifi.security={configured} "
            f"({SECURITY_MACROS.get(configured, '?')}) but the AP advertises "
            f"{advertised.upper()}; building firmware for "
            f"{SECURITY_MACROS[wanted]}",
            flush=True,
        )
    return wanted


def patch_firmware_source(
    config: dict[str, Any], *, server_ip: str, server_port: int, security: int
) -> Path:
    """Apply readme steps 2–5 (SSID/PSK/security/TLS server) to wifi_app.c."""
    app_c = Path(config["studio"]["examples_root"]) / APP_ID / "wifi_app.c"
    if not app_c.is_file():
        raise FileNotFoundError(f"SDK example source not found: {app_c}")
    wifi = config.get("wifi") or {}

    def c_str(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    macros = {
        "SSID": c_str(str(wifi.get("ssid") or "")),
        "SECURITY_TYPE": SECURITY_MACROS.get(security, "SL_WIFI_WPA2"),
        "PSK": c_str(str(wifi.get("password") or "")),
        "SERVER_PORT": str(int(server_port)),
        "SERVER_IP_ADDRESS": c_str(server_ip),
    }
    text = app_c.read_text(encoding="utf-8")
    updated = text
    for macro, value in macros.items():
        pattern = rf"^([ \t]*#define[ \t]+{macro}[ \t]+).*$"
        if not re.search(pattern, updated, flags=re.MULTILINE):
            raise RuntimeError(f"#define {macro} not found in {app_c}")
        updated = re.sub(
            pattern, lambda m, v=value: m.group(1) + v, updated, count=1,
            flags=re.MULTILINE,
        )
    shown = {k: ("***" if k == "PSK" else v) for k, v in macros.items()}
    if updated != text:
        app_c.write_text(updated, encoding="utf-8")
        print(f"[build] Patched {app_c.name}: {shown}", flush=True)
    else:
        print(f"[build] {app_c.name} already matches: {shown}", flush=True)
    return app_c


def _notify_has(texts: list[str], needle: str) -> bool:
    want = needle.strip().lower()
    return any(want in str(item).lower() for item in texts)


def run(config: dict[str, Any], *, skip_build: bool = False) -> dict[str, Any]:
    try:
        from .pi_ssl import scan_ap_security, start_ssl_server
        from .pi_ble import start_ble_chat
    except ImportError:
        from pi_ssl import scan_ap_security, start_ssl_server  # type: ignore
        from pi_ble import start_ble_chat  # type: ignore

    print(f"=== {APP_ID} ===", flush=True)
    ssl = start_ssl_server(config)
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")
    if not skip_build:
        wifi = config.get("wifi") or {}
        security = resolve_security(
            int(wifi.get("security", 2)),
            scan_ap_security(config["pi"], str(wifi.get("ssid") or "")),
        )
        patch_firmware_source(
            config, server_ip=ssl.host, server_port=ssl.port, security=security
        )
    before = serial_cursor(api)
    build = None if skip_build else api.build_flash(config, ssl_server_ip=ssl.host)
    after = serial_cursor(api)
    if skip_build:
        cursor = 0
    elif after < before:
        print("[test] Serial buffer reset after flash — reading from start", flush=True)
        cursor = 0
    else:
        cursor = before

    watcher = SerialWatcher(api, since=cursor)
    watcher.start()
    ble = None
    results: dict[str, Any] = {
        "app_id": APP_ID,
        "build_job_id": None if build is None else build.get("id"),
        "ssl_host": ssl.host,
        "ssl_port": ssl.port,
    }
    timeouts = config.get("timeouts") or {}
    try:
        settle = float((config.get("ble") or {}).get("post_flash_settle_s", 12))
        print(f"[test] Waiting {settle:.0f}s for WLAN + TLS client...", flush=True)
        time.sleep(settle)

        watcher.wait_for(
            "Wi-Fi initialization is successful",
            lambda state: state.wifi_init,
            float(timeouts.get("wifi_init_s", 60)),
        )
        watcher.wait_for(
            "Load SSL CA certificate at index 0 Success",
            lambda state: state.ssl_ca,
            float(timeouts.get("ssl_ca_s", 60)),
        )
        watcher.wait_for(
            "WLAN connection is successful",
            lambda state: state.wlan_join,
            float(timeouts.get("wlan_s", 90)),
        )
        watcher.wait_for(
            "Configured IP",
            lambda state: state.configured_ip or bool(state.ip_address),
            float(timeouts.get("ip_s", 60)),
        )
        watcher.wait_for(
            "Module is in power save",
            lambda state: state.power_save,
            float(timeouts.get("power_save_s", 60)),
        )
        watcher.wait_for(
            "TCP Socket Connect Success",
            lambda state: state.tcp_socket,
            float(timeouts.get("socket_s", 90)),
        )
        # connect() blocks the Wi-Fi/BLE loop. GATT discovery only completes
        # after the TLS socket is up and the loop is polling BLE events again.
        print("[test] Connecting Pi BLE central to WLAN_BLE_SIMPLE_CHAT ...", flush=True)
        ble = start_ble_chat(config)
        ble.wait_connected(float(timeouts.get("ble_s", 90)))

        watcher.wait_for(
            "Module connected",
            lambda state: state.module_connected,
            float(timeouts.get("ble_s", 90)),
        )

        notify_before = list(ble.notifications())
        ssl.send(HELLO_WLAN.encode("utf-8"))
        print("[test] SSL → DUT: Hello from WLAN", flush=True)
        watcher.wait_for(
            "Data from Wi-Fi to BLE: Hello from WLAN",
            lambda state: state.wifi_to_ble,
            float(timeouts.get("wifi_to_ble_s", 20)),
        )
        deadline = time.time() + float(timeouts.get("wifi_to_ble_s", 20))
        while time.time() < deadline:
            notes = ble.notifications()
            if len(notes) > len(notify_before) and _notify_has(notes, "Hello from WLAN"):
                print("[pass] BLE 0x1BB1 notify: Hello from WLAN", flush=True)
                break
            time.sleep(0.5)
        else:
            raise TimeoutError(
                "0x1BB1 notify missing Hello from WLAN "
                f"(had {notify_before!r}, now {ble.notifications()!r})"
            )

        ssl_before = ssl.received_text()
        ble.write(HELLO_BLE)
        print("[test] BLE → DUT: Hello from BLE", flush=True)
        watcher.wait_for(
            "Data from BLE to Wi-Fi: Hello from BLE",
            lambda state: state.ble_to_wifi,
            float(timeouts.get("ble_to_wifi_s", 20)),
        )
        deadline = time.time() + float(timeouts.get("ble_to_wifi_s", 20))
        received = ssl_before
        while time.time() < deadline:
            received = ssl.received_text()
            if "Hello from BLE" in received:
                print("[pass] TLS server received Hello from BLE", flush=True)
                break
            time.sleep(0.5)
        else:
            raise TimeoutError(
                "TLS server did not receive Hello from BLE "
                f"(got {received!r})"
            )

        results["serial"] = asdict(watcher.state)
        results["ssl_rx"] = received
        results["ble_notifications"] = ble.notifications()
        results["ok"] = True
        return results
    finally:
        watcher.stop()
        if ble is not None:
            ble.stop()


def parser_self_test() -> None:
    state = AppState()
    lines = (
        "Wi-Fi initialization is successful",
        "Load SSL CA certificate at index 0 Success",
        "SSID  Radha",
        "WLAN connection is successful",
        "Configured IP : 192.168.50.22",
        "Module is in power save",
        "TCP Socket Connect Success",
        "Module connected",
        "Data from Wi-Fi to BLE: Hello from WLAN",
        "Data from BLE to Wi-Fi: Hello from BLE",
    )
    for line in lines:
        parse_serial_line(state, line)
    assert state.wifi_init and state.ssl_ca and state.ssid_seen
    assert state.wlan_join and state.configured_ip
    assert state.ip_address == "192.168.50.22"
    assert state.power_save and state.tcp_socket
    assert state.module_connected and state.wifi_to_ble and state.ble_to_wifi
    retry = AppState()
    parse_serial_line(retry, "WLAN Connect Failed, Error Code : 0x10003")
    assert retry.wlan_retry and not retry.failure
    assert resolve_security(2, "open") == 0
    assert resolve_security(2, "wpa2") == 2 and resolve_security(2, None) == 2
    failed = AppState()
    parse_serial_line(failed, "Socket connect failed with BSD error: 111")
    assert failed.wlan_retry and not failed.failure
    parse_serial_line(failed, "Socket creation failed with bsd error: 1")
    assert failed.failure
    ca_fail = AppState()
    parse_serial_line(
        ca_fail,
        "Loading TLS CA certificate in to FLASH Failed, Error Code : 0x1",
    )
    assert ca_fail.failure and not ca_fail.ssl_ca
    print("Parser self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
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
        print(f"\nPASS: Wi-Fi BLE Power Save ({result_path})")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"\nFAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
