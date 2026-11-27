#!/usr/bin/env python3
"""Build, flash and validate Wi-Fi UDP_TX while BLE notifications are active.

Topology:
    Raspberry Pi : BLE Central + UDP iPerf server
    SiWG917 DUT  : BLE Peripheral + Wi-Fi STA / UDP_TX

The DUT BLE address is volatile. If ble.dut_address is empty, the Pi scans
for ble.dut_device_name.
"""
from __future__ import annotations

import json
import re
import shlex
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from common.harness import SerialWatcher, StudioApi  # noqa: E402
from common.pi_ble import _connect, _run, _stream  # noqa: E402

APP_ID = "wifi_station_ble_throughput_app"
DEFAULT_DUT_NAME = "SI_COEX_MAX_DEMO"
DEFAULT_NOTIFY_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"
DEFAULT_REMOTE_DIR = "/var/tmp/wcbs_throughput"


@dataclass
class State:
    wlan_connected: bool = False
    ble_connected: bool = False
    udp_started: bool = False
    udp_result: bool = False
    failure: str | None = None
    last_line: str = ""


def parse(state: State, line: str) -> None:
    state.last_line = line.strip()
    low = line.lower()

    if any(x in low for x in (
        "wlan connection success",
        "wlan connected state",
        "ip config is done",
        "got ip address",
        "ipv4 address",
    )):
        state.wlan_connected = True

    if any(x in low for x in (
        "number of central devices connected",
        "number of peripheral devices connected",
        "ble connected",
        "ble connection success",
    )):
        state.ble_connected = True

    if "udp_tx throughput test start" in low:
        state.udp_started = True

    if "throughput" in low and ("mbps" in low or "kbps" in low):
        state.udp_result = True

    if any(x in low for x in (
        "wlan connect failed",
        "ip config failed",
        "socket create failed",
        "socket connect failed",
        "udp transmit failed",
    )):
        state.failure = line.strip()


def replace_define(text: str, name: str, value: str) -> str:
    pattern = rf"^(\s*#define\s+{re.escape(name)}\s+).*$"
    result, count = re.subn(pattern, rf"\g<1>{value}", text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"Expected exactly one {name} definition; found {count}")
    return result


def replace_define_if_present(text: str, name: str, value: str) -> str:
    pattern = rf"^(\s*#define\s+{re.escape(name)}\s+).*$"
    return re.sub(pattern, rf"\g<1>{value}", text, flags=re.MULTILINE)


def _find_named_file(root: Path, filename: str) -> Path:
    """Find one documented source file below the application root."""
    matches = sorted(
        p for p in root.rglob(filename)
        if p.is_file()
        and not any(part.lower() in {".git", "build", "generated", "debug", "release", "output"} for part in p.parts)
    )
    if not matches:
        raise FileNotFoundError(f"Required source file not found: {filename} below {root}")
    if len(matches) > 1:
        locations = "\n  ".join(str(p) for p in matches)
        raise ValueError(f"Multiple {filename} files found; refusing to guess:\n  {locations}")
    return matches[0]


def _update_define_in_named_file(path: Path, name: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)

    matches = []

    define_re = re.compile(
        rf"^\s*#define\s+{re.escape(name)}(?:\s|$)"
    )

    for index, line in enumerate(lines):
        if define_re.match(line):
            matches.append(index)

    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one #define {name} in {path}, "
            f"found {len(matches)}"
        )

    index = matches[0]
    original = lines[index]

    newline = ""
    if original.endswith("\r\n"):
        newline = "\r\n"
        body = original[:-2]
    elif original.endswith("\n"):
        newline = "\n"
        body = original[:-1]
    else:
        body = original

    match = re.match(
        rf"^(\s*#define\s+{re.escape(name)}\s+)(.*)$",
        body
    )

    if not match:
        raise ValueError(
            f"Unable to parse #define {name} in {path}"
        )

    prefix = match.group(1)
    old_value = match.group(2)

    # Preserve an existing trailing comment.
    comment = ""
    comment_positions = []

    for marker in ("//", "/*"):
        position = old_value.find(marker)
        if position >= 0:
            comment_positions.append(position)

    if comment_positions:
        comment = old_value[min(comment_positions):].strip()

    replacement = prefix + value

    if comment:
        replacement += " " + comment

    lines[index] = replacement + newline

    path.write_text("".join(lines), encoding="utf-8")

    print(
        f"[macro] {path.name}: "
        f"{name} = {value}"
    )


def _update_required_macros(path: Path, macros: dict[str, str]) -> None:
    for name, value in macros.items():
        _update_define_in_named_file(path, name, value)


def configure_source(cfg: dict[str, Any]) -> None:
    root = Path(cfg["studio"]["examples_root"]) / APP_ID
    if not root.is_dir():
        raise FileNotFoundError(f"Application directory not found: {root}")

    wifi = cfg["wifi"]
    udp = cfg["udp"]
    ble = cfg["ble"]

    ssid = str(wifi.get("ssid") or "").strip()
    password = str(wifi.get("password") or "")
    server_ip = str(udp.get("server_ip") or udp.get("server_host") or "").strip()
    server_port = int(udp.get("server_port", 5001))
    device_port = int(udp.get("device_port", server_port))
    avg_ms = int(udp.get("average_time_ms", 60000))
    async_feature = int(udp.get("socket_async_feature", 1))

    if not ssid:
        raise ValueError("Set wifi.ssid before building")
    if not server_ip:
        raise ValueError("Set udp.server_ip or udp.server_host")

    security_map = {0: "SL_WIFI_OPEN", 1: "SL_WIFI_WPA", 2: "SL_WIFI_WPA2"}
    security_value = str(wifi.get("security_type") or security_map.get(int(wifi.get("security", 2)), "SL_WIFI_WPA2"))
    dut_name = str(ble.get("dut_device_name", DEFAULT_DUT_NAME)).strip() or DEFAULT_DUT_NAME

    # The documentation explicitly identifies wifi_config.h for the WLAN
    # throughput configuration. Do not search alternate Wi-Fi config filenames.
    wifi_config = _find_named_file(root, "wifi_config.h")
    ble_app = _find_named_file(root, "ble_app.c")

    # SSID/IP/socket settings are also documented as parameters in
    # wifi_config.h for this application.
    wifi_macros = {
        "SSID": f'"{ssid}"',
        "PSK": f'"{password}"',
        "SECURITY_TYPE": security_value,
        "DEVICE_PORT": str(device_port),
        "SERVER_PORT": str(server_port),
        "SERVER_IP_ADDRESS": f'"{server_ip}"',
        "SOCKET_ASYNC_FEATURE": str(async_feature),
        "THROUGHPUT_TYPE": "UDP_TX",
    }
    _update_required_macros(wifi_config, wifi_macros)

    if bool(udp.get("load_certificate", False)):
        _update_required_macros(wifi_config, {"LOAD_CERTIFICATE": "0x01"})

    ble_macros = {

        "RSI_BLE_DEVICE_NAME": f'"{dut_name}"',
    }
    _update_required_macros(ble_app, ble_macros)

    # THROUGHPUT_AVG_TIME belongs to wifi_throughput.c per the application
    # flow; locate that exact source file, not an arbitrary file containing the macro.
    # throughput_c = _find_named_file(root, "wifi_throughput.c")
    # _update_required_macros(throughput_c, {"THROUGHPUT_AVG_TIME": f"({avg_ms})"})

    print(f"[config] Application : {APP_ID}", flush=True)
    print(f"[config] App root    : {root}", flush=True)
    print(f"[config] Wi-Fi config: {wifi_config}", flush=True)
    print(f"[config] BLE source  : {ble_app}", flush=True)
    # print(f"[config] Throughput  : {throughput_c}", flush=True)
    print(f"[config] DUT role    : BLE Peripheral", flush=True)
    print(f"[config] Pi role     : BLE Central", flush=True)
    print(f"[config] DUT BLE name: {dut_name}", flush=True)
    print(f"[config] Wi-Fi       : {ssid} / security={security_value}", flush=True)
    print(f"[config] UDP_TX      : {server_ip}:{server_port}", flush=True)
    print(f"[config] Avg time    : {avg_ms} ms", flush=True)
    # print(f"[config] BLE dynamic : {wifi_macros['SL_BLE_DYNAMIC_DISABLE_THROUGHPUT_DEMO']}", flush=True)
    # print(f"[config] Continuous  : {wifi_macros['CONTINUOUS_THROUGHPUT']}", flush=True)


def start_udp_server(cfg: dict[str, Any]):
    pi = cfg["pi"]
    udp = cfg["udp"]
    server_host = str(udp.get("server_host") or udp.get("server_ip") or "").strip()
    if not pi.get("host") or not server_host:
        raise ValueError("Set pi.host and udp.server_ip/server_host")

    server_pi = dict(pi)
    server_pi["host"] = server_host
    client = _connect(server_pi)
    port = int(udp.get("server_port", 5001))
    command = str(udp.get("iperf_command", "iperf -s -u -p {port} -i 1")).format(port=port)
    parts = shlex.split(command)
    if not parts:
        client.close()
        raise RuntimeError("iperf_command is empty")
    program = parts[0]

    code, out, err = _run(client, f"command -v {shlex.quote(program)}", 20)
    if code and bool(udp.get("install_iperf_if_missing", True)) and program == "iperf":
        # Correct test: non-zero means /tmp is not writable.
        writable_test, _, _ = _run(client, "touch /tmp/.wcbs_write_test && rm -f /tmp/.wcbs_write_test", 20)
        if writable_test != 0:
            client.close()
            raise RuntimeError("iperf is missing and /tmp is not writable; repair/remount the Pi filesystem")
        code, out, err = _run(client, "sudo -n apt-get install -y --no-install-recommends iperf", 300)
        if code == 0:
            code, out, err = _run(client, "command -v iperf", 20)
    if code:
        client.close()
        raise RuntimeError(f"UDP server program unavailable on Pi: {err or out or program}")

    remote_dir = str(udp.get("remote_workdir") or pi.get("remote_workdir") or DEFAULT_REMOTE_DIR)
    pid_file = f"{remote_dir}/wcbs_iperf_udp.pid"
    log_file = f"{remote_dir}/wcbs_iperf_udp.log"
    _run(client, f"mkdir -p {shlex.quote(remote_dir)}", 20)
    _run(client, f"if [ -f {shlex.quote(pid_file)} ]; then P=$(cat {shlex.quote(pid_file)} 2>/dev/null || true); [ -z \"$P\" ] || kill $P 2>/dev/null || true; rm -f {shlex.quote(pid_file)}; fi; rm -f {shlex.quote(log_file)}", 20)

    _, existing, _ = _run(client, f"ss -lunp 2>&1 | grep -E ':{port}\\b' || true", 20)
    if existing.strip():
        print(f"[iperf] Existing UDP socket: {existing.strip()}", flush=True)

    start = f"nohup {command} >{shlex.quote(log_file)} 2>&1 & echo $! >{shlex.quote(pid_file)}"
    print(f"[iperf] Starting server: {command}", flush=True)
    code, out, err = _run(client, start, 20)
    if code:
        client.close()
        raise RuntimeError(f"Failed to launch iPerf server. stdout: {out}\nstderr: {err}")

    code, pid_out, pid_err = _run(client, f"cat {shlex.quote(pid_file)}", 20)
    pid = pid_out.strip()
    if code or not pid:
        _, log, _ = _run(client, f"cat {shlex.quote(log_file)} 2>/dev/null || true", 20)
        client.close()
        raise RuntimeError(f"iPerf started but no PID was created.\nPID stdout: {pid_out}\nPID stderr: {pid_err}\nLog:\n{log}")

    for attempt in range(1, 11):
        time.sleep(1)
        process_code, _, _ = _run(client, f"kill -0 {shlex.quote(pid)} 2>/dev/null", 20)
        _, log, _ = _run(client, f"cat {shlex.quote(log_file)} 2>/dev/null || true", 20)
        _, socket, _ = _run(client, f"ss -lunp 2>&1 | grep -E ':{port}\\b' || true", 20)
        print(f"[iperf] startup check {attempt}/10 alive={'yes' if process_code == 0 else 'no'} socket={'yes' if socket.strip() else 'no'}", flush=True)
        if process_code == 0 and socket.strip():
            print(f"[iperf] UDP server ready on {server_host}:{port}", flush=True)
            return client
        if process_code != 0:
            client.close()
            raise RuntimeError(f"iPerf exited before binding UDP port {port}.\nLog:\n{log}\nSocket:\n{socket}")

    _, proc, _ = _run(client, f"ps -fp {shlex.quote(pid)} 2>&1 || true", 20)
    _, socket, _ = _run(client, f"ss -lunp 2>&1 | grep -E ':{port}\\b' || true", 20)
    _, log, _ = _run(client, f"cat {shlex.quote(log_file)} 2>/dev/null || true", 20)
    client.close()
    raise RuntimeError(f"Pi UDP server did not bind port {port}.\nProcess:\n{proc}\nSocket:\n{socket}\niPerf log:\n{log}")


def stop_udp_server(client, cfg: dict[str, Any]) -> None:
    if client is None:
        return
    udp = cfg["udp"]
    pi = cfg["pi"]
    remote_dir = str(udp.get("remote_workdir") or pi.get("remote_workdir") or DEFAULT_REMOTE_DIR)
    pid_file = f"{remote_dir}/wcbs_iperf_udp.pid"
    try:
        _run(client, f"if [ -f {shlex.quote(pid_file)} ]; then P=$(cat {shlex.quote(pid_file)} 2>/dev/null || true); [ -z \"$P\" ] || kill $P 2>/dev/null || true; rm -f {shlex.quote(pid_file)}; fi", 20)
        print("[iperf] UDP server stopped", flush=True)
    except Exception as exc:
        print(f"[iperf] cleanup warning: {exc}", flush=True)


def ble_notifications(pi_client, cfg: dict[str, Any]) -> None:
    ble = cfg["ble"]
    workdir = str(cfg["pi"].get("remote_workdir", DEFAULT_REMOTE_DIR))
    dut_address = str(ble.get("dut_address") or "").strip()
    dut_name = str(ble.get("dut_device_name", DEFAULT_DUT_NAME)).strip() or DEFAULT_DUT_NAME
    notify_uuid = str(ble.get("notify_uuid", DEFAULT_NOTIFY_UUID)).strip()
    connect_timeout = float(ble.get("connect_timeout_s", 90))
    notification_wait = float(ble.get("notification_wait_s", 15))

    script = f'''import asyncio
from bleak import BleakClient, BleakScanner

NAME = {dut_name!r}
ADDRESS = {dut_address!r}
UUID = {notify_uuid!r}
TIMEOUT = {connect_timeout!r}
WAIT = {notification_wait!r}

async def main():
    print("BLE_SCAN_TARGET", ADDRESS if ADDRESS else NAME, flush=True)
    print("BLE_ROLE_PI Central", flush=True)
    print("BLE_ROLE_DUT Peripheral", flush=True)
    target = NAME.strip().lower()
    address = ADDRESS.strip().upper()

    def match(device, advertisement):
        if address:
            return (device.address or "").strip().upper() == address
        dev_name = (device.name or "").strip().lower()
        local_name = (getattr(advertisement, "local_name", None) or "").strip().lower()
        return dev_name == target or local_name == target

    d = await BleakScanner.find_device_by_filter(match, timeout=TIMEOUT)
    if not d:
        print("BLE_SCAN_NOT_FOUND", NAME, flush=True)
        for item in await BleakScanner.discover(timeout=5):
            print("BLE_SCAN_DEVICE", getattr(item, "name", None), getattr(item, "address", None), flush=True)
        raise RuntimeError("BLE advertiser not found: " + (ADDRESS or NAME))

    print("BLE_DEVICE_FOUND", getattr(d, "name", None), d.address, flush=True)
    count = [0]

    def notification_handler(_handle, data):
        count[0] += 1
        if count[0] <= 5:
            print("BLE_NOTIFICATION", count[0], len(data), flush=True)

    async with BleakClient(d, timeout=TIMEOUT) as c:
        if not c.is_connected:
            raise RuntimeError("BLE link is not connected")
        print("BLE_CONNECTED", d.address, flush=True)
        await c.start_notify(UUID, notification_handler)
        print("BLE_NOTIFY_STARTED", UUID, flush=True)
        await asyncio.sleep(WAIT)
        try:
            await c.stop_notify(UUID)
        except Exception as exc:
            print("BLE_STOP_NOTIFY_WARNING", str(exc), flush=True)
        print("BLE_NOTIFY_COMPLETE", count[0], flush=True)

    if count[0] <= 0:
        raise RuntimeError("No BLE notifications received from " + NAME)
    print("BLE_NOTIFICATIONS", count[0], flush=True)

asyncio.run(main())
'''
    command = f"mkdir -p {shlex.quote(workdir)} && python3 -c {shlex.quote(script)}"
    print(f"[ble] Pi Central -> DUT Peripheral {dut_name}", flush=True)
    code = _stream(pi_client, command, max(120, int(connect_timeout + notification_wait + 30)), "pi-ble")
    if code:
        raise RuntimeError("BLE connection/notification gate failed")


def run(cfg: dict[str, Any]) -> dict[str, Any]:
    configure_source(cfg)
    pi_client = None
    watcher = None
    try:
        pi_client = start_udp_server(cfg)
        api = StudioApi(cfg["studio"].get("url", "http://127.0.0.1:5050"))
        api.request("GET", "/api/health")
        print(f"[build] Build + flash {APP_ID}", flush=True)
        build = api.build_flash(APP_ID, cfg)
        watcher = SerialWatcher(api, State(), parse)
        watcher.start()

        timeouts = cfg.get("timeouts", {})
        wlan_timeout = float(timeouts.get("wlan_s", 90))
        udp_timeout = float(timeouts.get("udp_s", 90))

        watcher.wait_for("WLAN association and IP configuration", lambda s: s.wlan_connected, wlan_timeout)
        ble_notifications(pi_client, cfg)
        watcher.wait_for("DUT BLE connection", lambda s: s.ble_connected, udp_timeout)
        watcher.wait_for("DUT UDP_TX start", lambda s: s.udp_started, udp_timeout)
        watcher.wait_for("DUT UDP throughput result", lambda s: s.udp_result, udp_timeout)

        result = {"ok": True, "app_id": APP_ID, "build_job_id": build.get("id"), "serial": asdict(watcher.state)}
        HERE.joinpath("last_result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("PASS: BLE notification stream and DUT UDP_TX throughput validated", flush=True)
        return result
    finally:
        if watcher is not None:
            try:
                watcher.stop()
            except Exception as exc:
                print(f"[serial] cleanup warning: {exc}", flush=True)
        stop_udp_server(pi_client, cfg)
        if pi_client is not None:
            try:
                pi_client.close()
            except Exception as exc:
                print(f"[pi] cleanup warning: {exc}", flush=True)


def load_throughput_config(path: Path) -> dict[str, Any]:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    for section in ("studio", "wifi", "pi", "udp", "ble"):
        if section not in cfg:
            raise ValueError(f"Missing config section: {section}")
    cfg["ble"].setdefault("dut_device_name", DEFAULT_DUT_NAME)
    cfg["ble"].setdefault("dut_address", "")
    cfg["ble"].setdefault("notify_uuid", DEFAULT_NOTIFY_UUID)
    cfg["ble"].setdefault("connect_timeout_s", 90)
    cfg["ble"].setdefault("notification_wait_s", 15)
    return cfg


if __name__ == "__main__":
    try:
        result = run(load_throughput_config(HERE / "config.local.json"))
        print(result, flush=True)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
