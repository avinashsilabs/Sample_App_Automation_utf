#!/usr/bin/env python3
"""Build, flash, provision, and validate Wi-Fi Client BLE Provisioning.

Order: BLE advertise → BLE connect → Wi-Fi scan → Wi-Fi join → IPCONFIG
→ ping the obtained DUT IP from the NUC or Pi → BLE disconnect.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from .ble_protocol import (
        firmware_payload,
        password_payload,
        scan_payload,
        security_payload,
        ssid_payload,
        status_payload,
    )
except ImportError:
    from ble_protocol import (  # type: ignore
        firmware_payload,
        password_payload,
        scan_payload,
        security_payload,
        ssid_payload,
        status_payload,
    )


APP_ID = "wifi_station_ble_provisioning"

PRIVATE_IP_RE = re.compile(
    r"(?<!\d)(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)"
)
SCAN_COUNT_RE = re.compile(r"(\d+)\s+Scan results:", re.I)
SSID_SET_RE = re.compile(r"SSID(?: set to)?[:=]\s*(\S+)", re.I)


@dataclass
class AppState:
    wifi_connected: bool = False
    ip_address: Optional[str] = None
    ipconfig_done: bool = False
    scan_request: bool = False
    scanning: bool = False
    scan_table: bool = False
    scan_ssids: List[str] = field(default_factory=list)
    scan_displayed: bool = False
    ssid_set: Optional[str] = None
    ap_joined: bool = False
    ping_started: bool = False
    ping_responses: int = 0
    wlan_retry: Optional[str] = None
    failure: Optional[str] = None


def parse_serial_line(state: AppState, line: str) -> None:
    raw = line.rstrip("\r\n")
    low = raw.strip().lower()
    if not low:
        return
    if (
        "wlan connection success" in low
        or "wlan connection is successful" in low
        or "wifi app connected state" in low
        or "connected s" in low
        or ("joined" in low and "success" in low)
    ):
        state.wifi_connected = True
    if "ipconfig done" in low:
        state.ipconfig_done = True
    ip_match = PRIVATE_IP_RE.search(raw)
    if ip_match and (
        "ip" in low
        or "connected" in low
        or "onnected" in low
        or "ipconfig" in low
        or "joined" in low
        or state.wifi_connected
        or state.ipconfig_done
    ):
        state.ip_address = ip_match.group(1)
    if "received scan request" in low:
        state.scan_request = True
    if "scanning..." in low:
        state.scanning = True
    if SCAN_COUNT_RE.search(raw) or re.search(r"SSID\s+SECURITY", raw, re.I):
        state.scan_table = True
    if state.scan_table and not state.scan_displayed:
        token = raw.strip().split()
        if token and token[0].upper() != "SSID" and not SCAN_COUNT_RE.search(raw):
            if token[0] not in state.scan_ssids:
                state.scan_ssids.append(token[0])
    ssid_match = SSID_SET_RE.search(raw)
    if ssid_match:
        state.ssid_set = ssid_match.group(1).strip()
        if state.ssid_set not in state.scan_ssids:
            state.scan_ssids.append(state.ssid_set)
    if "displayed scan list in silabs app" in low:
        state.scan_displayed = True
        state.scan_table = True
    if "ap joined" in low or "cap joined" in low:
        state.ap_joined = True
        state.wifi_connected = True
    if "pinging www.silabs.com" in low:
        state.ping_started = True
    if "ping response from www.silabs.com" in low:
        state.ping_started = True
        state.ping_responses += 1
    # wifi_app.c returns to the join path when credentials are written again,
    # and its IP-config counter is only fatal after three tries. One UART
    # error is a retry until the wait timeout expires with no address.
    if (
        "wlan connect failed" in low
        or "wlan connection failed" in low
        or "ip config failed" in low
        or "ip configuration failed" in low
    ):
        state.wlan_retry = raw.strip()
        return
    failures = (
        "wlan scan wait failed",
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

    def build_flash(self, cfg: dict[str, Any]) -> dict[str, Any]:
        studio = cfg["studio"]
        payload = {
            "app_id": APP_ID,
            "target": "soc",
            "board": studio.get("board", "brd4338a"),
            "toolchain": studio.get("toolchain", "gcc"),
            "sdk_root": studio["sdk_root"],
            "ble_root": studio["examples_root"],
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


def ble_backend(cfg: dict[str, Any]) -> str:
    """Pick the BLE central: the lab Pi over SSH, or this host's own radio."""
    configured = str(cfg.get("ble", {}).get("backend", "auto")).lower()
    has_pi = bool(str(cfg.get("pi", {}).get("host") or "").strip())
    if configured in ("pi", "raspberry_pi"):
        if not has_pi:
            raise ValueError("ble.backend is 'pi' but pi.host is not set")
        return "pi"
    if configured == "host":
        return "host"
    return "pi" if has_pi else "host"


class HeldHostSession:
    """Host BLE central that stays connected until release() after DUT IP ping."""

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.result: dict[str, Any] = {}
        self._ready = threading.Event()
        self._release = threading.Event()
        self._error: Optional[BaseException] = None
        self._thread: Optional[threading.Thread] = None
        self._released = False

    def start(self) -> dict[str, Any]:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        ble = self.cfg["ble"]
        timeout = (
            float(ble.get("scan_timeout_s", 30))
            * int(ble.get("ssid_scan_retries", 3))
            + float(ble.get("connect_timeout_s", 75))
            + 60
        )
        if not self._ready.wait(timeout=timeout):
            raise TimeoutError("Host BLE provision did not become ready")
        if self._error:
            raise RuntimeError(str(self._error))
        return self.result

    def _run(self) -> None:
        try:
            asyncio.run(self._async())
        except Exception as exc:  # noqa: BLE001
            self._error = exc
            self._ready.set()

    async def _async(self) -> None:
        try:
            from bleak import BleakClient, BleakScanner
        except ImportError as exc:
            raise RuntimeError(
                "BLE provisioning needs bleak; run: pip install -r requirements.txt"
            ) from exc

        ble = self.cfg["ble"]
        wifi = self.cfg["wifi"]
        name = str(ble.get("device_name", "BLE_CONFIGURATOR"))
        timeout = float(ble.get("scan_timeout_s", 30))
        print(f"[ble] Scanning for {name!r}...", flush=True)
        device = await BleakScanner.find_device_by_filter(
            lambda dev, adv: dev.name == name or getattr(adv, "local_name", None) == name,
            timeout=timeout,
        )
        if device is None:
            raise RuntimeError(f"BLE advertiser {name!r} not found")

        aps: list[dict[str, Any]] = []
        notify_event = asyncio.Event()

        def on_notify(_sender, data: bytearray) -> None:
            if len(data) < 3:
                return
            ssid = bytes(data[2:]).decode("utf-8", errors="ignore").strip("\x00").strip()
            if ssid and ssid.isprintable():
                entry = {"security": int(data[0]), "ssid": ssid}
                if entry not in aps:
                    aps.append(entry)
                    print(f"[ble] AP: {ssid!r} security={data[0]}", flush=True)
            notify_event.set()

        client = BleakClient(device, timeout=float(ble.get("connect_timeout_s", 75)))
        await client.connect()
        try:
            await client.start_notify(ble["notify_uuid"], on_notify)
            await client.write_gatt_char(ble["write_uuid"], firmware_payload(), response=True)
            await asyncio.sleep(0.4)
            try:
                firmware = bytes(await client.read_gatt_char(ble["read_uuid"])).hex()
                print(f"[ble] Firmware/status bytes: {firmware}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[ble] Firmware read skipped: {exc}", flush=True)

            wanted = str(wifi["ssid"])
            found: Optional[dict[str, Any]] = None
            for attempt in range(1, int(ble.get("ssid_scan_retries", 3)) + 1):
                aps.clear()
                notify_event.clear()
                await client.write_gatt_char(ble["write_uuid"], scan_payload(), response=True)
                deadline = time.time() + timeout
                while time.time() < deadline:
                    found = next((ap for ap in aps if ap["ssid"] == wanted), None)
                    if found:
                        break
                    try:
                        await asyncio.wait_for(notify_event.wait(), timeout=1)
                        notify_event.clear()
                    except asyncio.TimeoutError:
                        pass
                if found:
                    break
                print(f"[ble] SSID {wanted!r} absent on scan {attempt}", flush=True)
            if not found:
                raise RuntimeError(f"Configured SSID {wanted!r} not found; seen={aps}")

            security = int(wifi.get("security", found["security"]))
            await client.write_gatt_char(
                ble["write_uuid"], ssid_payload(wanted), response=True
            )
            await asyncio.sleep(0.5)
            await client.write_gatt_char(
                ble["write_uuid"], security_payload(security), response=True
            )
            await asyncio.sleep(0.5)
            if security and wifi.get("password"):
                await client.write_gatt_char(
                    ble["write_uuid"],
                    password_payload(str(wifi["password"])),
                    response=True,
                )
            await asyncio.sleep(1)
            try:
                await client.write_gatt_char(
                    ble["write_uuid"], status_payload(), response=True
                )
            except Exception:
                pass
            self.result = {
                "ssid": wanted,
                "security": security,
                "advertiser": str(device.address),
                "backend": "host",
                "aps": aps,
                "ok": True,
                "held": True,
            }
            self._ready.set()
            hold_s = float(ble.get("hold_for_ping_s", 180))
            print("[ble] Holding connection until DUT IP ping finishes...", flush=True)
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._release.wait(timeout=hold_s)
            )
        finally:
            try:
                if client.is_connected:
                    await asyncio.wait_for(client.disconnect(), timeout=5)
                    print("[ble] BLE disconnected", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[ble] BLE disconnect note: {exc}", flush=True)

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._release.set()
        if self._thread:
            self._thread.join(timeout=20)


def start_provision(cfg: dict[str, Any]):
    backend = ble_backend(cfg)
    if backend == "host":
        print("[ble] Using this host's Bluetooth adapter", flush=True)
        session = HeldHostSession(cfg)
        session.start()
        return session

    pi = cfg["pi"]
    print(
        f"[ble] Using Raspberry Pi {pi.get('host')} as the BLE central (SSH)",
        flush=True,
    )
    try:
        from .pi_ble import start_held_provision
    except ImportError:
        from pi_ble import start_held_provision  # type: ignore

    return start_held_provision(cfg)


def load_config(path: Path) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    required = (
        ("studio", "sdk_root"),
        ("studio", "examples_root"),
        ("wifi", "ssid"),
        ("ble", "write_uuid"),
        ("ble", "read_uuid"),
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


def _ssid_seen(state: AppState, wanted: str, provision: dict[str, Any]) -> bool:
    wanted_l = wanted.lower()
    if any(ssid.lower() == wanted_l for ssid in state.scan_ssids):
        return True
    if state.ssid_set and state.ssid_set.lower() == wanted_l:
        return True
    for ap in provision.get("aps") or []:
        if str(ap.get("ssid") or "").lower() == wanted_l:
            return True
    return False


def run(config: dict[str, Any], *, skip_build: bool = False) -> dict[str, Any]:
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")
    if not skip_build:
        patch_ip_retry(config)
    before = serial_cursor(api)
    build = None if skip_build else api.build_flash(config)
    after = serial_cursor(api)
    # Flash often starts a new capture (COM remaps, buffer reset). A stale
    # pre-flash cursor then skips the boot/scan/join lines that already landed.
    if skip_build:
        cursor = 0
    elif after < before:
        print("[test] Serial buffer reset after flash — reading from start", flush=True)
        cursor = 0
    else:
        cursor = before

    watcher = SerialWatcher(api, since=cursor)
    watcher.start()
    session = None
    results: dict[str, Any] = {
        "app_id": APP_ID,
        "build_job_id": None if build is None else build.get("id"),
    }
    try:
        settle = float(config["ble"].get("post_flash_settle_s", 15))
        print(f"[test] Waiting {settle:.0f}s for BLE advertising...", flush=True)
        time.sleep(settle)
        session = start_provision(config)
        results["provision"] = session.result

        timeouts = config.get("timeouts", {})
        wanted = str(config["wifi"]["ssid"])
        ble_scan_ok = _ssid_seen(AppState(), wanted, results["provision"])
        if ble_scan_ok:
            print(f"[pass] Lab SSID {wanted!r} in BLE scan list", flush=True)
        else:
            watcher.wait_for(
                f"Lab SSID {wanted!r} in scan list",
                lambda state: _ssid_seen(state, wanted, results["provision"]),
                float(timeouts.get("scan_s", 60)),
            )

        watcher.wait_for(
            "WLAN connection",
            lambda state: state.wifi_connected,
            float(timeouts.get("wlan_s", 120)),
        )
        watcher.wait_for(
            "DUT IPv4 / IPCONFIG done",
            lambda state: bool(state.ip_address) and state.ipconfig_done,
            float(timeouts.get("ip_s", 60)),
        )
        watcher.wait_for(
            "AP joined successfully",
            lambda state: state.ap_joined or state.wifi_connected,
            float(timeouts.get("join_s", 60)),
        )

        dut_ip = watcher.state.ip_address or results["provision"].get("ip")
        if not dut_ip:
            raise RuntimeError("DUT IP was not obtained from UART or BLE status")
        print(f"[test] DUT IP {dut_ip} — pinging from NUC or Pi before BLE disconnect", flush=True)
        try:
            from .pi_ble import ping_dut_ip
        except ImportError:
            from pi_ble import ping_dut_ip  # type: ignore

        results["ping"] = ping_dut_ip(config, str(dut_ip))
        min_ping = int(config.get("min_ping_responses", 1))
        if int(results["ping"].get("received") or 0) < min_ping:
            raise RuntimeError(
                f"DUT {dut_ip} ping: need {min_ping} replies, "
                f"got {results['ping'].get('received')}"
            )
        print(
            f"[pass] DUT {dut_ip} ping "
            f"({results['ping']['received']} reply/replies from "
            f"{results['ping'].get('source', 'lab')})",
            flush=True,
        )

        print("[test] Ping done — disconnecting BLE", flush=True)
        session.release()
        session = None

        results["serial"] = asdict(watcher.state)
        results["ok"] = True
        return results
    finally:
        if session is not None:
            try:
                session.release()
            except Exception:  # noqa: BLE001
                pass
        watcher.stop()


def patch_ip_retry(config: dict[str, Any]) -> None:
    """Re-enter DHCP until the demo's own retry counter gives up.

    wifi_app.c increments `a` and disconnects at 3, but clears the connected
    event first, so a single DHCP miss never comes back.
    """
    path = (
        Path(config["studio"]["examples_root"])
        / APP_ID
        / "wifi_app.c"
    )
    text = path.read_text(encoding="utf-8")
    needle = (
        'SL_DEBUG_LOG_V2(ERROR, "IP Config Failed, Error Code : 0x%lX\\r\\n", status);\n'
        "          break;"
    )
    insert = (
        'SL_DEBUG_LOG_V2(ERROR, "IP Config Failed, Error Code : 0x%lX\\r\\n", status);\n'
        "          if (a < 3) {\n"
        "            wifi_app_set_event(WIFI_APP_CONNECTED_STATE);\n"
        "          }\n"
        "          break;"
    )
    if "if (a < 3)" in text and "WIFI_APP_CONNECTED_STATE" in text.split("IP Config Failed", 1)[-1][:400]:
        print(f"[build] {path.name} already retries IP config", flush=True)
        return
    if needle not in text:
        raise RuntimeError(f"IP retry site not found in {path}")
    path.write_text(text.replace(needle, insert, 1), encoding="utf-8")
    print(f"[build] Patched {path.name} to retry IP config", flush=True)


def parser_self_test() -> None:
    state = AppState()
    lines = (
        "Received scan request",
        "Scanning...",
        "11 Scan results:",
        "SSID    SECURITY NETWORK       BSSID      CHANNEL RSSI",
        "Radha                       2,     1,   10:7c:61:34:72:08,    4,  -25",
        "Displayed scan list in Silabs app",
        "SSID set to: Radha",
        "WLAN status request received",
        "WLAN connection is successful",
        "192.168.50.34WIFI App CAP joined onnected Ssuccessfultate",
        "WIFI App IPCONFIG Done State",
        "Disconnected - remote_dev_addr : D8:3A:DD:13:53:66Started Advertising",
    )
    for line in lines:
        parse_serial_line(state, line)
    assert state.scan_request and state.scanning and state.scan_table
    assert state.scan_displayed and "Radha" in state.scan_ssids
    assert state.wifi_connected and state.ip_address == "192.168.50.34"
    assert state.ipconfig_done and state.ap_joined
    retry = AppState()
    parse_serial_line(retry, "WLAN Connect Failed, Error Code : 0x10003")
    parse_serial_line(retry, "IP Config Failed, Error Code : 0x1FF9C")
    assert retry.wlan_retry and retry.failure is None
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
        print(f"\nPASS: Wi-Fi Client BLE Provisioning ({result_path})")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
