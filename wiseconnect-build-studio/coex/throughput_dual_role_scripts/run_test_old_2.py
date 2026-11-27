#!/usr/bin/env python3
"""Build, flash and validate Wi-Fi UDP_TX while BLE notifications are active."""
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

APP_ID = "wifi_throughput_ble_dual_role"


@dataclass
class State:
    wlan_connected: bool = False
    ble_connected: bool = False
    udp_started: bool = False
    udp_result: bool = False
    failure: str | None = None


def parse(state: State, line: str) -> None:
    low = line.lower()
    if "wlan connection success" in low or "wlan connected state" in low or "ip config is done" in low:
        state.wlan_connected = True
    if "number of central devices connected" in low or "number of peripheral devices connected" in low:
        state.ble_connected = True
    if "udp_tx throughput test start" in low:
        state.udp_started = True
    if "throughput" in low and ("mbps" in low or "kbps" in low):
        state.udp_result = True
    if any(x in low for x in ("wlan connect failed", "ip config failed", "socket create failed", "socket connect failed")):
        state.failure = line.strip()


def replace_define(text: str, name: str, value: str) -> str:
    pattern = rf"^(\s*#define\s+{re.escape(name)}\s+).*$"
    result, count = re.subn(pattern, rf"\g<1>{value}", text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"Expected exactly one {name} definition; found {count}")
    return result


def configure_source(cfg: dict[str, Any]) -> Path:
    root = Path(cfg["studio"]["examples_root"]) / APP_ID
    header = root / "wifi_app_config.h"
    if not header.is_file():
        raise FileNotFoundError(f"Example header not found: {header}")
    udp = cfg["udp"]
    server_ip = str(udp.get("server_ip") or "").strip()
    if not server_ip:
        raise ValueError("Set udp.server_ip to the remote iPerf UDP-server address")
    text = header.read_text(encoding="utf-8")
    wifi = cfg["wifi"]
    ssid = str(wifi.get("ssid") or "").strip()
    password = str(wifi.get("password") or "")
    if not ssid or ssid == "YOUR_SSID":
        raise ValueError("Set wifi.ssid before building")
    text = replace_define(text, "SSID", f'"{ssid}"')
    text = replace_define(text, "PSK", f'"{password}"')
    text = replace_define(text, "SERVER_IP_ADDRESS", f'"{server_ip}"')
    text = replace_define(text, "SERVER_PORT", str(int(udp.get("server_port", 5001))))
    text = replace_define(text, "THROUGHPUT_TYPE", "UDP_TX")
    throughput_source = root / "wifi_throughput.c"
    source_text = throughput_source.read_text(encoding="utf-8")
    source_text = replace_define(
        source_text, "THROUGHPUT_AVG_TIME", f"({int(udp.get('average_time_ms', 60000))})"
    )
    header.write_text(text, encoding="utf-8")
    throughput_source.write_text(source_text, encoding="utf-8")
    print(f"[config] UDP_TX -> {server_ip}:{udp.get('server_port', 5001)}")
    return header


def start_udp_server(cfg: dict[str, Any]):
    pi = cfg["pi"]
    udp = cfg["udp"]
    server_host = str(udp.get("server_host") or udp.get("server_ip") or "").strip()
    if not pi.get("host") or not server_host:
        raise ValueError("Set pi.host for BLE and udp.server_ip for the UDP endpoint")
    # The server may be a different lab Pi than the BLE central. Reuse the
    # supplied SSH account unless a dedicated udp.server_host is supplied.
    server_pi = dict(pi)
    server_pi["host"] = server_host
    client = _connect(server_pi)
    port = int(udp.get("server_port", 5001))
    command = str(cfg["udp"].get("iperf_command", "iperf -s -u -p {port} -i 1")).format(port=port)
    # Verify the server binary first; no background process is launched until this passes.
    program = command.split()[0]
    code, _out, err = _run(client, f"command -v {shlex.quote(program)}", 20)
    if code and bool(udp.get("install_iperf_if_missing", True)) and program == "iperf":
        writable, _out, _err = _run(
            client, "touch /tmp/.wcbs_write_test && rm -f /tmp/.wcbs_write_test", 20
        )
        if writable:
            client.close()
            raise RuntimeError(
                "iperf is missing and the Pi filesystem is read-only; remount or repair "
                "the Pi root filesystem before the runner can install it"
            )
        print("[udp] Installing the README-required iperf 2 server...", flush=True)
        code, _out, err = _run(
            client,
            "sudo -n apt-get install -y --no-install-recommends iperf",
            300,
        )
        if code == 0:
            code, _out, err = _run(client, "command -v iperf", 20)
    if code:
        client.close()
        raise RuntimeError(f"UDP server program unavailable on Pi: {err or program}")
    channel = client.get_transport().open_session()
    channel.exec_command(f"nohup {command} >/tmp/wcbs_iperf_udp.log 2>&1 &")
    channel.recv_exit_status()
    time.sleep(1)
    code, out, err = _run(client, f"ss -lun | grep -E ':{port}\\b'", 20)
    if code:
        client.close()
        raise RuntimeError(f"Pi UDP server did not bind port {port}: {out}{err}")
    print(f"[udp] server ready on {server_host}:{port}")
    return client


def ble_notifications(pi_client, cfg: dict[str, Any]) -> None:
    ble = cfg["ble"]
    workdir = str(cfg["pi"].get("remote_workdir", "/var/tmp/wcbs_throughput"))
    script = f'''import asyncio
from bleak import BleakClient, BleakScanner
name={ble.get("device_name", "SI_COEX_MAX_DEMO")!r}; address={ble.get("address", "")!r}; uuid={ble["notify_uuid"]!r}
async def main():
 d=await BleakScanner.find_device_by_filter(lambda x,a: (address and x.address.upper()==address.upper()) or x.name==name, timeout={float(ble.get("connect_timeout_s",30))})
 if not d: raise RuntimeError("BLE advertiser not found")
 n=[0]
 async with BleakClient(d, timeout={float(ble.get("connect_timeout_s",30))}) as c:
  await c.start_notify(uuid, lambda _h,_d: n.__setitem__(0,n[0]+1))
  await asyncio.sleep({float(ble.get("notification_window_s",8))})
  await c.stop_notify(uuid)
 if not n[0]: raise RuntimeError("No BLE notifications received")
 print("BLE_NOTIFICATIONS",n[0])
asyncio.run(main())'''
    encoded = shlex.quote(script)
    code = _stream(pi_client, f"mkdir -p {shlex.quote(workdir)} && python3 -c {encoded}", 60, "pi-ble")
    if code:
        raise RuntimeError("BLE connection/notification gate failed")


def run(cfg: dict[str, Any]) -> dict[str, Any]:
    configure_source(cfg)
    pi_client = start_udp_server(cfg)
    api = StudioApi(cfg["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")
    build = api.build_flash(APP_ID, cfg)
    watcher = SerialWatcher(api, State(), parse)
    watcher.start()
    try:
        # The firmware's WLAN task blocks here until the BLE activity has
        # completed (WLAN_SYNC_REQ=1), matching the README sequence.
        watcher.wait_for(
            "WLAN association and IP configuration",
            lambda s: s.wlan_connected,
            float(cfg.get("timeouts", {}).get("wlan_s", 90)),
        )
        ble_notifications(pi_client, cfg)
        watcher.wait_for(
            "DUT BLE central connection",
            lambda s: s.ble_connected,
            float(cfg.get("timeouts", {}).get("udp_s", 90)),
        )
        watcher.wait_for("DUT UDP_TX start", lambda s: s.udp_started, float(cfg.get("timeouts", {}).get("udp_s", 90)))
        watcher.wait_for("DUT UDP throughput result", lambda s: s.udp_result, float(cfg.get("timeouts", {}).get("udp_s", 90)))
        result = {"ok": True, "build_job_id": build.get("id"), "serial": asdict(watcher.state)}
        HERE.joinpath("last_result.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
        return result
    finally:
        watcher.stop(); pi_client.close()


def load_throughput_config(path: Path) -> dict[str, Any]:
    """Load this suite's deliberately smaller config (no BLE provisioning UUIDs)."""
    cfg = json.loads(path.read_text(encoding="utf-8"))
    for section in ("studio", "wifi", "pi", "udp", "ble"):
        if section not in cfg:
            raise ValueError(f"Missing config section: {section}")
    return cfg


if __name__ == "__main__":
    try:
        result = run(load_throughput_config(HERE / "config.local.json"))
        print("PASS: BLE notification stream and DUT UDP_TX throughput validated", result)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
