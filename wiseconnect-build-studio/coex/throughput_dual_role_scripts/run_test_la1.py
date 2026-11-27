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

    if (
        "wlan connection success" in low
        or "wlan connected state" in low
        or "ip config is done" in low
    ):
        state.wlan_connected = True

    if (
        "number of central devices connected" in low
        or "number of peripheral devices connected" in low
    ):
        state.ble_connected = True

    if "udp_tx throughput test start" in low:
        state.udp_started = True

    if "throughput" in low and ("mbps" in low or "kbps" in low):
        state.udp_result = True

    if any(
        x in low
        for x in (
            "wlan connect failed",
            "ip config failed",
            "socket create failed",
            "socket connect failed",
        )
    ):
        state.failure = line.strip()


def replace_define(text: str, name: str, value: str) -> str:
    pattern = rf"^(\s*#define\s+{re.escape(name)}\s+).*$"

    result, count = re.subn(
        pattern,
        rf"\g<1>{value}",
        text,
        flags=re.MULTILINE,
    )

    if count != 1:
        raise ValueError(
            f"Expected exactly one {name} definition; found {count}"
        )

    return result


def configure_source(cfg: dict[str, Any]) -> Path:
    root = Path(cfg["studio"]["examples_root"]) / APP_ID

    header = root / "wifi_app_config.h"

    if not header.is_file():
        raise FileNotFoundError(
            f"Example header not found: {header}"
        )

    udp = cfg["udp"]

    server_ip = str(
        udp.get("server_ip") or ""
    ).strip()

    if not server_ip:
        raise ValueError(
            "Set udp.server_ip to the remote iPerf UDP-server address"
        )

    text = header.read_text(encoding="utf-8")

    wifi = cfg["wifi"]

    ssid = str(
        wifi.get("ssid") or ""
    ).strip()

    password = str(
        wifi.get("password") or ""
    )

    if not ssid or ssid == "YOUR_SSID":
        raise ValueError(
            "Set wifi.ssid before building"
        )

    text = replace_define(
        text,
        "SSID",
        f'"{ssid}"',
    )

    text = replace_define(
        text,
        "PSK",
        f'"{password}"',
    )

    text = replace_define(
        text,
        "SERVER_IP_ADDRESS",
        f'"{server_ip}"',
    )

    text = replace_define(
        text,
        "SERVER_PORT",
        str(int(udp.get("server_port", 5001))),
    )

    text = replace_define(
        text,
        "THROUGHPUT_TYPE",
        "UDP_TX",
    )

    throughput_source = root / "wifi_throughput.c"

    source_text = throughput_source.read_text(
        encoding="utf-8"
    )

    source_text = replace_define(
        source_text,
        "THROUGHPUT_AVG_TIME",
        f"({int(udp.get('average_time_ms', 60000))})",
    )

    header.write_text(
        text,
        encoding="utf-8",
    )

    throughput_source.write_text(
        source_text,
        encoding="utf-8",
    )

    print(
        f"[config] UDP_TX -> "
        f"{server_ip}:{udp.get('server_port', 5001)}",
        flush=True,
    )

    return header


def start_udp_server(cfg: dict[str, Any]):
    """
    Start the UDP iPerf server on the configured server Pi.

    The server is:
      1. checked for availability
      2. cleaned up if a stale instance exists
      3. started in the background
      4. assigned a PID file
      5. monitored for up to 10 seconds
      6. checked using ss
      7. diagnosed using the iPerf log if startup fails
    """

    pi = cfg["pi"]
    udp = cfg["udp"]

    server_host = str(
        udp.get("server_host")
        or udp.get("server_ip")
        or ""
    ).strip()

    if not pi.get("host") or not server_host:
        raise ValueError(
            "Set pi.host for BLE and udp.server_ip "
            "for the UDP endpoint"
        )

    # The UDP server may be a different Pi than the BLE Pi.
    server_pi = dict(pi)
    server_pi["host"] = server_host

    print(
        f"[iperf] Connecting to UDP server host "
        f"{server_host}...",
        flush=True,
    )

    client = _connect(server_pi)

    port = int(
        udp.get("server_port", 5001)
    )

    command = str(
        udp.get(
            "iperf_command",
            "iperf -s -u -p {port} -i 1",
        )
    ).format(port=port)

    # ------------------------------------------------------------
    # 1. Verify iPerf executable
    # ------------------------------------------------------------

    command_parts = shlex.split(command)

    if not command_parts:
        client.close()
        raise RuntimeError(
            "iperf_command is empty"
        )

    program = command_parts[0]

    code, out, err = _run(
        client,
        f"command -v {shlex.quote(program)}",
        20,
    )

    # ------------------------------------------------------------
    # 2. Install iPerf if configured and missing
    # ------------------------------------------------------------

    if (
        code
        and bool(
            udp.get(
                "install_iperf_if_missing",
                True,
            )
        )
        and program == "iperf"
    ):
        print(
            "[iperf] iPerf is not installed. "
            "Checking Pi filesystem...",
            flush=True,
        )

        # Test filesystem writability correctly.
        writable, _, _ = _run(
            client,
            """
            touch /tmp/.wcbs_write_test &&
            rm -f /tmp/.wcbs_write_test
            """,
            20,
        )

        if writable:
            client.close()

            raise RuntimeError(
                "iperf is missing and the Pi filesystem "
                "is not writable; remount or repair the "
                "Pi root filesystem before the runner "
                "can install it"
            )

        print(
            "[iperf] Installing the README-required "
            "iperf 2 server...",
            flush=True,
        )

        code, out, err = _run(
            client,
            "sudo -n apt-get install "
            "-y --no-install-recommends iperf",
            300,
        )

        if code == 0:
            code, out, err = _run(
                client,
                "command -v iperf",
                20,
            )

    if code:
        client.close()

        raise RuntimeError(
            f"UDP server program unavailable on Pi: "
            f"{err or out or program}"
        )

    print(
        f"[iperf] Found {program}: "
        f"{out.strip()}",
        flush=True,
    )

    # ------------------------------------------------------------
    # 3. Stop stale iPerf instance
    # ------------------------------------------------------------

    print(
        "[iperf] Cleaning up stale server...",
        flush=True,
    )

    _run(
        client,
        """
        if [ -f /tmp/wcbs_iperf_udp.pid ]; then
            OLD_PID=$(cat /tmp/wcbs_iperf_udp.pid 2>/dev/null || true)

            if [ -n "$OLD_PID" ]; then
                kill "$OLD_PID" 2>/dev/null || true
            fi

            rm -f /tmp/wcbs_iperf_udp.pid
        fi
        """,
        20,
    )

    _run(
        client,
        "rm -f /tmp/wcbs_iperf_udp.log",
        20,
    )

    # ------------------------------------------------------------
    # 4. Check whether UDP port is already occupied
    # ------------------------------------------------------------

    _, existing_socket, _ = _run(
        client,
        f"ss -lunp 2>&1 | "
        f"grep -E ':{port}\\b' || true",
        20,
    )

    if existing_socket.strip():
        print(
            "[iperf] Existing UDP socket before startup:",
            flush=True,
        )
        print(
            existing_socket.strip(),
            flush=True,
        )

    # ------------------------------------------------------------
    # 5. Start iPerf
    # ------------------------------------------------------------

    start_command = (
        f"nohup {command} "
        f">/tmp/wcbs_iperf_udp.log 2>&1 "
        f"& echo $! >/tmp/wcbs_iperf_udp.pid"
    )

    print(
        f"[iperf] Starting server: {command}",
        flush=True,
    )

    code, out, err = _run(
        client,
        start_command,
        20,
    )

    if code:
        client.close()

        raise RuntimeError(
            "Failed to launch iPerf server.\n"
            f"stdout: {out}\n"
            f"stderr: {err}"
        )

    # ------------------------------------------------------------
    # 6. Obtain PID
    # ------------------------------------------------------------

    code, pid_out, pid_err = _run(
        client,
        "cat /tmp/wcbs_iperf_udp.pid",
        20,
    )

    pid = pid_out.strip()

    if code or not pid:
        _, log_out, _ = _run(
            client,
            "cat /tmp/wcbs_iperf_udp.log "
            "2>/dev/null || true",
            20,
        )

        client.close()

        raise RuntimeError(
            "iPerf started but no PID was created.\n"
            f"PID stdout: {pid_out}\n"
            f"PID stderr: {pid_err}\n"
            f"iPerf log:\n{log_out}"
        )

    print(
        f"[iperf] Server PID={pid}",
        flush=True,
    )

    # ------------------------------------------------------------
    # 7. Wait for server to bind
    # ------------------------------------------------------------

    last_socket = ""
    last_log = ""

    for attempt in range(1, 11):

        time.sleep(1)

        # Check process.
        process_code, process_out, process_err = _run(
            client,
            f"kill -0 {shlex.quote(pid)} 2>/dev/null",
            20,
        )

        # Read iPerf log.
        _, log_out, _ = _run(
            client,
            "cat /tmp/wcbs_iperf_udp.log "
            "2>/dev/null || true",
            20,
        )

        last_log = log_out

        # Check UDP socket.
        _, socket_out, socket_err = _run(
            client,
            f"ss -lunp 2>&1 | "
            f"grep -E ':{port}\\b' || true",
            20,
        )

        last_socket = socket_out

        print(
            f"[iperf] startup check "
            f"{attempt}/10 "
            f"alive="
            f"{'yes' if process_code == 0 else 'no'} "
            f"socket="
            f"{'yes' if socket_out.strip() else 'no'}",
            flush=True,
        )

        # Server is alive and port is bound.
        if (
            process_code == 0
            and socket_out.strip()
        ):
            print(
                f"[iperf] UDP server ready on "
                f"{server_host}:{port}",
                flush=True,
            )

            return client

        # Process already died.
        if process_code != 0:

            client.close()

            raise RuntimeError(
                f"iPerf exited before binding "
                f"UDP port {port}.\n"
                f"PID: {pid}\n"
                f"iPerf log:\n{last_log}\n"
                f"Socket output:\n{last_socket}"
            )

    # ------------------------------------------------------------
    # 8. Final diagnostics
    # ------------------------------------------------------------

    _, process_out, process_err = _run(
        client,
        f"ps -fp {shlex.quote(pid)} 2>&1 || true",
        20,
    )

    _, socket_out, socket_err = _run(
        client,
        f"ss -lunp 2>&1 | "
        f"grep -E ':{port}\\b' || true",
        20,
    )

    _, log_out, log_err = _run(
        client,
        "cat /tmp/wcbs_iperf_udp.log "
        "2>/dev/null || true",
        20,
    )

    client.close()

    raise RuntimeError(
        f"Pi UDP server did not bind port {port}.\n"
        f"Command: {command}\n"
        f"PID: {pid}\n"
        f"Process:\n{process_out}\n"
        f"Socket:\n{socket_out}\n"
        f"iPerf log:\n{log_out}\n"
    )


def stop_udp_server(client) -> None:
    """Stop the iPerf server started by this test run."""

    if client is None:
        return

    try:
        _run(
            client,
            """
            if [ -f /tmp/wcbs_iperf_udp.pid ]; then
                PID=$(cat /tmp/wcbs_iperf_udp.pid 2>/dev/null || true)

                if [ -n "$PID" ]; then
                    kill "$PID" 2>/dev/null || true
                fi

                rm -f /tmp/wcbs_iperf_udp.pid
            fi
            """,
            20,
        )

        print(
            "[iperf] UDP server stopped",
            flush=True,
        )

    except Exception as exc:
        print(
            f"[iperf] cleanup warning: {exc}",
            flush=True,
        )


def ble_notifications(
    pi_client,
    cfg: dict[str, Any],
) -> None:
    """
    Connect to the BLE DUT using the address from config.

    IMPORTANT:
    The BLE address remains volatile.
    No MAC address is hard-coded here.
    """

    ble = cfg["ble"]

    workdir = str(
        cfg["pi"].get(
            "remote_workdir",
            "/var/tmp/wcbs_throughput",
        )
    )

    # Address is deliberately taken from config.
    # Do NOT hard-code the current DUT MAC.
    ble_address = str(
        ble.get("address") or ""
    ).strip()

    device_name = str(
        ble.get(
            "device_name",
            "SI_COEX_MAX_DEMO",
        )
    )

    notify_uuid = str(
        ble["notify_uuid"]
    )

    connect_timeout = float(
        ble.get(
            "connect_timeout_s",
            30,
        )
    )

    notification_window = float(
        ble.get(
            "notification_window_s",
            8,
        )
    )

    script = f'''import asyncio
from bleak import BleakClient, BleakScanner

name = {device_name!r}
address = {ble_address!r}
uuid = {notify_uuid!r}


async def main():

    def match(device, advertisement):
        if address:
            return (
                device.address.upper()
                == address.upper()
            )

        return device.name == name

    print(
        "BLE_SCAN_TARGET",
        address if address else name,
        flush=True,
    )

    d = await BleakScanner.find_device_by_filter(
        match,
        timeout={connect_timeout},
    )

    if not d:
        raise RuntimeError(
            "BLE advertiser not found"
        )

    print(
        "BLE_DEVICE_FOUND",
        d.name,
        d.address,
        flush=True,
    )

    n = [0]

    async with BleakClient(
        d,
        timeout={connect_timeout},
    ) as c:

        print(
            "BLE_CONNECTED",
            d.address,
            flush=True,
        )

        await c.start_notify(
            uuid,
            lambda _h, _d:
                n.__setitem__(
                    0,
                    n[0] + 1,
                ),
        )

        await asyncio.sleep(
            {notification_window}
        )

        await c.stop_notify(uuid)

    if not n[0]:
        raise RuntimeError(
            "No BLE notifications received"
        )

    print(
        "BLE_NOTIFICATIONS",
        n[0],
        flush=True,
    )


asyncio.run(main())
'''

    encoded = shlex.quote(script)

    command = (
        f"mkdir -p {shlex.quote(workdir)} "
        f"&& python3 -c {encoded}"
    )

    code = _stream(
        pi_client,
        command,
        60,
        "pi-ble",
    )

    if code:
        raise RuntimeError(
            "BLE connection/notification gate failed"
        )


def run(cfg: dict[str, Any]) -> dict[str, Any]:

    configure_source(cfg)

    pi_client = None
    watcher = None

    try:

        # --------------------------------------------------------
        # Start iPerf BEFORE build/flash.
        # --------------------------------------------------------

        pi_client = start_udp_server(cfg)

        # --------------------------------------------------------
        # Start Studio API
        # --------------------------------------------------------

        api = StudioApi(
            cfg["studio"].get(
                "url",
                "http://127.0.0.1:5050",
            )
        )

        api.request(
            "GET",
            "/api/health",
        )

        # --------------------------------------------------------
        # Build + flash DUT
        # --------------------------------------------------------

        build = api.build_flash(
            APP_ID,
            cfg,
        )

        # --------------------------------------------------------
        # Serial watcher
        # --------------------------------------------------------

        watcher = SerialWatcher(
            api,
            State(),
            parse,
        )

        watcher.start()

        # --------------------------------------------------------
        # WLAN
        # --------------------------------------------------------

        watcher.wait_for(
            "WLAN association and IP configuration",
            lambda s: s.wlan_connected,
            float(
                cfg.get(
                    "timeouts",
                    {},
                ).get(
                    "wlan_s",
                    90,
                )
            ),
        )

        # --------------------------------------------------------
        # BLE notification gate
        # --------------------------------------------------------

        ble_notifications(
            pi_client,
            cfg,
        )

        # --------------------------------------------------------
        # DUT BLE connection
        # --------------------------------------------------------

        watcher.wait_for(
            "DUT BLE central connection",
            lambda s: s.ble_connected,
            float(
                cfg.get(
                    "timeouts",
                    {},
                ).get(
                    "udp_s",
                    90,
                )
            ),
        )

        # --------------------------------------------------------
        # DUT UDP_TX start
        # --------------------------------------------------------

        watcher.wait_for(
            "DUT UDP_TX start",
            lambda s: s.udp_started,
            float(
                cfg.get(
                    "timeouts",
                    {},
                ).get(
                    "udp_s",
                    90,
                )
            ),
        )

        # --------------------------------------------------------
        # DUT UDP throughput result
        # --------------------------------------------------------

        watcher.wait_for(
            "DUT UDP throughput result",
            lambda s: s.udp_result,
            float(
                cfg.get(
                    "timeouts",
                    {},
                ).get(
                    "udp_s",
                    90,
                )
            ),
        )

        result = {
            "ok": True,
            "build_job_id": build.get("id"),
            "serial": asdict(
                watcher.state
            ),
        }

        HERE.joinpath(
            "last_result.json"
        ).write_text(
            json.dumps(
                result,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        return result

    finally:

        if watcher is not None:
            watcher.stop()

        # Always stop the iPerf server started
        # by this test.
        stop_udp_server(
            pi_client
        )

        if pi_client is not None:
            pi_client.close()


def load_throughput_config(
    path: Path,
) -> dict[str, Any]:
    """
    Load this suite's deliberately smaller config
    (no BLE provisioning UUIDs).
    """

    cfg = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    for section in (
        "studio",
        "wifi",
        "pi",
        "udp",
        "ble",
    ):
        if section not in cfg:
            raise ValueError(
                f"Missing config section: {section}"
            )

    return cfg


if __name__ == "__main__":

    try:

        result = run(
            load_throughput_config(
                HERE / "config.local.json"
            )
        )

        print(
            "PASS: BLE notification stream "
            "and DUT UDP_TX throughput validated",
            result,
        )

    except Exception as exc:

        print(
            f"FAIL: {exc}",
            file=sys.stderr,
        )

        raise SystemExit(1)