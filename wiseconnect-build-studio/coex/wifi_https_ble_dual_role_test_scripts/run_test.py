#!/usr/bin/env python3
"""Build, flash, and validate Wi-Fi Client HTTPS BLE Dual Role.

HTTP and HTTPS file download from the lab NUC (same box used as
server/client for throughput). BLE advertise + scan are required after
the download starts. No MQTT / provisioning.
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

APP_ID = "wifi_https_ble_dual_role"

PRIVATE_IP_RE = re.compile(
    r"(?<!\d)(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)"
)


@dataclass
class AppState:
    wifi_init: bool = False
    wifi_connected: bool = False
    ip_address: Optional[str] = None
    tls_ca: bool = False
    socket_ok: bool = False
    tcp_ok: bool = False
    download_started: bool = False
    download_done: bool = False
    download_count: int = 0
    download_bytes: Optional[int] = None
    ble_init: bool = False
    ble_advertising: bool = False
    ble_scanning: bool = False
    ble_address: Optional[str] = None
    ble_connected: bool = False
    wlan_retry: Optional[str] = None
    failure: Optional[str] = None


def parse_serial_line(state: AppState, line: str, *, https: bool) -> None:
    raw = line.rstrip("\r\n")
    low = raw.strip().lower()
    if not low:
        return
    if "wi-fi initialization is successful" in low:
        state.wifi_init = True
    if "wlan connected state" in low or "wlan connection success" in low:
        state.wifi_connected = True
    ip_match = PRIVATE_IP_RE.search(raw)
    if ip_match and (
        "ip" in low or state.wifi_connected or state.wifi_init
    ):
        state.ip_address = ip_match.group(1)
    if "load tls ca certificate" in low and "success" in low:
        state.tls_ca = True
    if "socket create success" in low:
        state.socket_ok = True
    if "tcp socket connect success" in low:
        state.tcp_ok = True
    if https and ("https download started" in low or "https d" in low and "ownload" in low):
        state.download_started = True
    if (not https) and "https" not in low and (
        "http download started" in low
        or ("http" in low and "ownload" in low and "st" in low)
    ):
        state.download_started = True
    done = (
        "https download completed" in low
        if https
        else ("http download completed" in low and "https" not in low)
    )
    if done:
        state.download_started = True
        state.download_done = True
        state.download_count += 1
        count = re.search(r"total received bytes:\s*(\d+)", raw, re.I)
        if count:
            state.download_bytes = int(count.group(1))
    if "initiating ble" in low:
        state.ble_init = True
    if "advertising started" in low:
        state.ble_advertising = True
    if "scanning started" in low:
        state.ble_scanning = True
    addr_match = re.search(
        r"get local device address:\s*([0-9a-f:]{17})", low
    )
    if addr_match:
        state.ble_address = addr_match.group(1).upper()
    if "central devices connected" in low or "peripheral devices connected" in low:
        state.ble_connected = True
    # wifi_http_s.c stays in the current state after either of these and
    # tries again, so they are fatal only when the wait expires.
    if "wlan connect failed" in low or "ip config failed" in low:
        state.wlan_retry = raw.strip()
        return
    failures = (
        "socket connect failed",
        "socket creation failed",
        "recv failed",
        "send failed",
    )
    if any(marker in low for marker in failures):
        state.failure = raw.strip()
    if "tls ca certificate" in low and "failed" in low:
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
        self,
        cfg: dict[str, Any],
        *,
        https: bool,
        http_server_ip: str,
        http_server_port: int,
    ) -> dict[str, Any]:
        studio = cfg["studio"]
        wifi = cfg.get("wifi") or {}
        payload = {
            "app_id": APP_ID,
            "target": "soc",
            "board": studio.get("board", "brd4338a"),
            "toolchain": studio.get("toolchain", "gcc"),
            "sdk_root": studio["sdk_root"],
            "ble_root": studio["examples_root"],
            "https_download": 1 if https else 0,
            "continuous_http_download": int(
                (cfg.get("continuous_http_download", 1))
            ),
            "http_server_ip": http_server_ip,
            "http_server_port": int(http_server_port),
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
    """Current UART line count without pulling the backlog."""
    data = api.request("GET", "/api/serial/lines?since=999999999")
    return int(data.get("total", 0))


class SerialWatcher:
    def __init__(self, api: StudioApi, *, https: bool, since: int = 0):
        self.api = api
        self.https = https
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
                    parse_serial_line(self.state, str(line), https=self.https)
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
        ("nuc", "host"),
        ("nuc", "username"),
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
        "YOUR_NUC_PASSWORD",
    }
    unresolved = []
    for section, key in (
        ("studio", "sdk_root"),
        ("studio", "examples_root"),
        ("wifi", "ssid"),
        ("nuc", "host"),
    ):
        if str(config.get(section, {}).get(key, "")) in placeholder_values:
            unresolved.append(f"{section}.{key}")
    if str(config.get("wifi", {}).get("password", "")) in placeholder_values:
        unresolved.append("wifi.password")
    if str(config.get("nuc", {}).get("password", "")) in placeholder_values:
        unresolved.append("nuc.password")
    if unresolved:
        raise ValueError(
            "Replace placeholder values in config.local.json: "
            + ", ".join(unresolved)
        )
    return config


def patch_firmware(
    config: dict[str, Any], *, https: bool, server_ip: str
) -> None:
    """Point wifi_app_config.h at this lab's AP and the live download host."""
    header = Path(config["studio"]["examples_root"]) / APP_ID / "wifi_app_config.h"
    if not header.is_file():
        raise FileNotFoundError(f"SDK example header not found: {header}")
    wifi = config.get("wifi") or {}

    def c_str(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    text = header.read_text(encoding="utf-8")
    updated = text
    macros = {
        "SSID": c_str(str(wifi.get("ssid") or "")),
        "SECURITY_TYPE": "SL_WIFI_WPA2",
        "PSK": c_str(str(wifi.get("password") or "")),
        "SERVER_IP_ADDRESS": c_str(server_ip),
        "HTTPS_DOWNLOAD": "1" if https else "0",
    }
    for macro, value in macros.items():
        pattern = rf"^([ \t]*#define[ \t]+{macro}[ \t]+).*$"
        if not re.search(pattern, updated, flags=re.MULTILINE):
            raise RuntimeError(f"#define {macro} not found in {header}")
        updated = re.sub(
            pattern, lambda m, v=value: m.group(1) + v, updated, count=1,
            flags=re.MULTILINE,
        )
    if "#else\n#define SERVER_PORT 443" in updated or "#else\r\n#define SERVER_PORT 443" in updated:
        updated = re.sub(
            r"#else\s*\n#define SERVER_PORT\s+443",
            "#else\n#define SERVER_PORT      80",
            updated,
            count=1,
        )
    shown = {k: ("***" if k == "PSK" else v) for k, v in macros.items()}
    if updated != text:
        header.write_text(updated, encoding="utf-8")
        print(f"[build] Patched {header.name}: {shown}", flush=True)
    else:
        print(f"[build] {header.name} already matches: {shown}", flush=True)
    if not https and "SERVER_PORT      80" not in updated and "SERVER_PORT 80" not in updated:
        raise RuntimeError("HTTP mode still has no SERVER_PORT 80 in " + str(header))


def run_one_mode(
    config: dict[str, Any], *, https: bool, skip_build: bool
) -> dict[str, Any]:
    label = "HTTPS" if https else "HTTP"
    print(f"\n=== {label} download ({APP_ID}) ===", flush=True)
    try:
        from .nuc_http import start_download_server
    except ImportError:
        from nuc_http import start_download_server  # type: ignore

    server = start_download_server(config, https=https)
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")
    if not skip_build:
        patch_firmware(config, https=https, server_ip=str(server.get("host") or ""))
    before = serial_cursor(api)
    build = None if skip_build else api.build_flash(
        config,
        https=https,
        http_server_ip=str(server.get("host") or ""),
        http_server_port=int(server.get("port") or (443 if https else 80)),
    )
    after = serial_cursor(api)
    if skip_build:
        cursor = 0
    elif after < before:
        print("[test] Serial buffer reset after flash — reading from start", flush=True)
        cursor = 0
    else:
        cursor = before
    watcher = SerialWatcher(api, https=https, since=cursor)
    watcher.start()
    settle = float((config.get("timeouts") or {}).get("post_flash_settle_s", 8))
    print(f"[test] Waiting {settle:.0f}s for WLAN + {label} client...", flush=True)
    time.sleep(settle)
    timeouts = config.get("timeouts", {})
    try:
        watcher.wait_for(
            "WLAN connected state",
            lambda state: state.wifi_connected,
            float(timeouts.get("wlan_s", 90)),
        )
        watcher.wait_for(
            "DUT IPv4 address",
            lambda state: bool(state.ip_address),
            float(timeouts.get("ip_s", 60)),
        )
        if https:
            watcher.wait_for(
                "Load TLS CA certificate",
                lambda state: state.tls_ca,
                float(timeouts.get("tls_s", 30)),
            )
        try:
            watcher.wait_for(
                "TCP Socket Connect Success",
                lambda state: state.tcp_ok,
                float(timeouts.get("socket_s", 60)),
            )
        except TimeoutError:
            print(
                "[test] HTTPS/TCP connect never succeeded. BLE stays blocked "
                "until the first socket connect (WLAN_SYNC_REQ).",
                flush=True,
            )
            try:
                from .nuc_http import fetch_server_log
            except ImportError:
                from nuc_http import fetch_server_log  # type: ignore
            try:
                tail = fetch_server_log(config, https=https)
                if tail:
                    print(f"[nuc] download server log:\n{tail}", flush=True)
                else:
                    print(
                        "[nuc] download server log is empty "
                        "(DUT may never have reached the listener)",
                        flush=True,
                    )
            except Exception as exc:  # noqa: BLE001
                print(f"[nuc] could not fetch server log: {exc}", flush=True)
            raise
        watcher.wait_for(
            f"{label} download started or completed",
            lambda state: state.download_started or state.download_done,
            float(timeouts.get("download_s", 60)),
        )
        watcher.wait_for(
            f"{label} download completed",
            lambda state: state.download_done and (state.download_bytes or 0) > 0,
            float(timeouts.get("download_s", 90)),
        )
        watcher.wait_for(
            "BLE advertising + scanning",
            lambda state: state.ble_advertising and state.ble_scanning,
            float(timeouts.get("ble_s", 60)),
        )

        settle = float((config.get("ble") or {}).get("post_adv_settle_s", 5))
        print(
            f"[test] DUT advertising SI_COEX_MAX_DEMO — waiting {settle:.0f}s, "
            "then Pi BLE connect (scan stays on)",
            flush=True,
        )
        time.sleep(settle)
        try:
            from .pi_ble import connect_dut_advertiser
        except ImportError:
            from pi_ble import connect_dut_advertiser  # type: ignore

        results_ble = connect_dut_advertiser(config)
        watcher.wait_for(
            "BLE central connected (Pi → DUT)",
            lambda state: state.ble_connected,
            float(timeouts.get("ble_s", 60)),
        )

        continuous = int(config.get("continuous_http_download", 1))
        min_cycles = int(config.get("min_download_cycles", 2 if continuous else 1))
        if continuous and min_cycles > 1:
            watcher.wait_for(
                f"{label} continuous download x{min_cycles}",
                lambda state: state.download_count >= min_cycles,
                float(timeouts.get("download_s", 180)),
            )

        return {
            "mode": label.lower(),
            "ok": True,
            "server": server,
            "ble": results_ble,
            "build_job_id": None if build is None else build.get("id"),
            "serial": asdict(watcher.state),
        }
    finally:
        watcher.stop()


def run(
    config: dict[str, Any], *, skip_build: bool = False, mode: str = "both"
) -> dict[str, Any]:
    modes = []
    if mode in ("http", "both"):
        modes.append(False)
    if mode in ("https", "both"):
        modes.append(True)
    if not modes:
        raise ValueError("mode must be http, https, or both")

    results: dict[str, Any] = {"app_id": APP_ID, "runs": []}
    for https in modes:
        results["runs"].append(
            run_one_mode(config, https=https, skip_build=skip_build)
        )
    results["ok"] = all(run.get("ok") for run in results["runs"])
    return results


def parser_self_test() -> None:
    http = AppState()
    https = AppState()
    http_lines = (
        "Wi-Fi initialization is successful",
        "WLAN connected state",
        "192.168.50.22",
        "Socket create success : 0",
        "TCP Socket Connect Success",
        "HTTP download started",
        "HTTP download completed, total received bytes: 4096",
        "HTTP download started",
        "HTTP download completed, total received bytes: 4096",
        "Initiating BLE",
        "Advertising started, local device name : SI_COEX_MAX_DEMO",
        "Scanning started",
        "Number of central devices connected:1 - conn0",
    )
    https_lines = (
        "WLAN connected state",
        "192.168.50.22",
        "Load TLS CA certificate at index 0 Success",
        "TCP Socket Connect Success",
        "HTTPS download started",
        "HTTPS download completed, total received bytes: 12700",
        "HTTPS download started",
        "HTTPS download completed, total received bytes: 12700",
        "Advertising started, local device name : SI_COEX_MAX_DEMO",
        "Scanning started",
        "Number of central devices connected:1 - conn0",
    )
    for line in http_lines:
        parse_serial_line(http, line, https=False)
    for line in https_lines:
        parse_serial_line(https, line, https=True)
    assert http.wifi_connected and http.download_done and http.download_bytes == 4096
    assert http.download_count == 2
    assert http.ble_advertising and http.ble_scanning and http.ble_connected
    assert https.tls_ca and https.download_done and https.download_bytes == 12700
    assert https.download_count == 2 and https.ble_connected
    mixed_http = AppState()
    mixed_https = AppState()
    for line in https_lines:
        parse_serial_line(mixed_http, line, https=False)
    for line in http_lines:
        parse_serial_line(mixed_https, line, https=True)
    assert not mixed_http.download_started and not mixed_http.download_done
    assert not mixed_https.download_started and not mixed_https.download_done
    failed = AppState()
    parse_serial_line(failed, "Load TLS CA certificate at index 0 Success", https=True)
    assert failed.tls_ca and failed.failure is None
    parse_serial_line(
        failed, "Loading TLS CA certificate in to FLASH Failed, Error Code : 0x1", https=True
    )
    assert failed.failure
    retry = AppState()
    parse_serial_line(retry, "WLAN Connect Failed, Error Code : 0x10008", https=True)
    parse_serial_line(retry, "IP Config failed", https=True)
    assert retry.wlan_retry and retry.failure is None
    parse_serial_line(retry, "WLAN connected state", https=True)
    assert retry.wifi_connected
    print("Parser self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("config.local.json"),
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument(
        "--mode",
        choices=("http", "https", "both"),
        default="both",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        parser_self_test()
        return 0
    try:
        config = load_config(args.config)
        result = run(config, skip_build=args.skip_build, mode=args.mode)
        result_path = Path(__file__).with_name("last_result.json")
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        modes = "/".join(run["mode"].upper() for run in result["runs"])
        print(f"\nPASS: HTTPS BLE Dual Role {modes} ({result_path})")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
