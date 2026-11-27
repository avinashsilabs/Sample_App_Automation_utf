#!/usr/bin/env python3
"""
Build, flash and validate Wi-Fi UDP_TX with BLE dual-role operation.

BLE topology
------------
CASE 1:
    Raspberry Pi = BLE Central
    DUT          = BLE Peripheral
    Pi scans for SI_COEX_MAX_DEMO, connects and discovers/subscribes
    to GATT characteristics that advertise the "notify" property.

CASE 2:
    DUT          = BLE Central
    "avinash"    = BLE Peripheral
    The DUT UART output is monitored for the central-to-avinash
    connection.

The existing common harness is deliberately used for:
    - Studio build/flash
    - DUT serial monitoring
    - Raspberry Pi SSH/BLE helpers

Do not replace StudioApi with a locally invented REST endpoint.
"""

from __future__ import annotations

import asyncio
import base64
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


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

@dataclass
class State:
    wlan_connected: bool = False

    # CASE 1:
    # Pi = Central -> DUT = Peripheral
    ble_pi_connected: bool = False
    ble_pi_notification_received: bool = False

    # UDP
    udp_started: bool = False
    udp_result: bool = False

    # CASE 2:
    # DUT = Central -> avinash = Peripheral
    ble_avinash_connected: bool = False

    failure: str | None = None


# ---------------------------------------------------------------------------
# UART parser
# ---------------------------------------------------------------------------

def parse(state: State, line: str) -> None:
    """
    Parse DUT UART output.

    The parser intentionally uses several known log variants because the
    exact Si91x example output can vary slightly between SDK revisions.
    """

    low = line.lower().strip()

    # ------------------------------------------------------------
    # WLAN
    # ------------------------------------------------------------

    if (
        "wlan connection success" in low
        or "wlan connected state" in low
        or "ip config is done" in low
        or "ip address" in low and "192.168." in low
    ):
        state.wlan_connected = True

    # ------------------------------------------------------------
    # BLE CASE 1 / CASE 2
    # ------------------------------------------------------------

    if "number of peripheral devices connected" in low:
        match = re.search(
            r"number of peripheral devices connected\s*[:=]?\s*(\d+)",
            low,
        )

        if match:
            if int(match.group(1)) > 0:
                state.ble_pi_connected = True
        else:
            state.ble_pi_connected = True

    if "number of central devices connected" in low:
        match = re.search(
            r"number of central devices connected\s*[:=]?\s*(\d+)",
            low,
        )

        if match:
            if int(match.group(1)) > 0:
                state.ble_avinash_connected = True
        else:
            state.ble_avinash_connected = True

    # Some SDK/application builds print the peer name directly.
    if "avinash" in low:
        if any(
            token in low
            for token in (
                "connected",
                "connection success",
                "connection successful",
                "link established",
            )
        ):
            state.ble_avinash_connected = True

    # ------------------------------------------------------------
    # UDP
    # ------------------------------------------------------------

    if (
        "udp_tx throughput test start" in low
        or "udp tx throughput test start" in low
        or "udp_tx throughput" in low and "start" in low
    ):
        state.udp_started = True

    if (
        "throughput" in low
        and (
            "mbps" in low
            or "kbps" in low
            or "mbit" in low
            or "kbit" in low
        )
    ):
        state.udp_result = True

    # ------------------------------------------------------------
    # BLE notification indication from DUT
    # ------------------------------------------------------------

    # This is only diagnostic. The actual CASE-1 notification PASS
    # is established by the Raspberry Pi BLE Central.
    if (
        "notify" in low
        and (
            "success" in low
            or "sent" in low
            or "notification" in low
        )
    ):
        pass

    # ------------------------------------------------------------
    # Failure conditions
    # ------------------------------------------------------------

    if any(
        token in low
        for token in (
            "wlan connect failed",
            "wlan connection failed",
            "ip config failed",
            "socket create failed",
            "socket connect failed",
            "udp tx failed",
            "throughput test failed",
            "ble connection failed",
            "ble connect failed",
        )
    ):
        state.failure = line.strip()


# ---------------------------------------------------------------------------
# Source configuration
# ---------------------------------------------------------------------------

def replace_define(
    text: str,
    name: str,
    value: str,
) -> str:
    """
    Replace exactly one simple #define.
    """

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


def configure_source(
    cfg: dict[str, Any],
) -> Path:
    root = (
        Path(cfg["studio"]["examples_root"])
        / APP_ID
    )

    header = root / "wifi_app_config.h"

    if not header.is_file():
        raise FileNotFoundError(
            f"Example header not found: {header}"
        )

    throughput_source = (
        root / "wifi_throughput.c"
    )

    if not throughput_source.is_file():
        raise FileNotFoundError(
            f"Throughput source not found: "
            f"{throughput_source}"
        )

    wifi = cfg["wifi"]
    udp = cfg["udp"]

    ssid = str(
        wifi.get("ssid") or ""
    ).strip()

    password = str(
        wifi.get("password") or ""
    )

    server_ip = str(
        udp.get("server_ip")
        or udp.get("server_host")
        or ""
    ).strip()

    server_port = int(
        udp.get(
            "server_port",
            5001,
        )
    )

    average_time = int(
        udp.get(
            "average_time_ms",
            60000,
        )
    )

    if not ssid:
        raise ValueError(
            "Set wifi.ssid before building"
        )

    if not server_ip:
        raise ValueError(
            "Set udp.server_ip before building"
        )

    # ------------------------------------------------------------
    # wifi_app_config.h
    # ------------------------------------------------------------

    text = header.read_text(
        encoding="utf-8"
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
        str(server_port),
    )

    text = replace_define(
        text,
        "THROUGHPUT_TYPE",
        "UDP_TX",
    )

    header.write_text(
        text,
        encoding="utf-8",
    )

    # ------------------------------------------------------------
    # wifi_throughput.c
    # ------------------------------------------------------------

    source_text = throughput_source.read_text(
        encoding="utf-8"
    )

    # Keep compatibility with the existing example.
    try:
        source_text = replace_define(
            source_text,
            "THROUGHPUT_AVG_TIME",
            f"({average_time})",
        )
    except ValueError:
        # Some SDK revisions may not have this define.
        pass

    try:
        source_text = replace_define(
            source_text,
            "THROUGHPUT_AVERAGE_TIME",
            f"({average_time})",
        )
    except ValueError:
        pass

    throughput_source.write_text(
        source_text,
        encoding="utf-8",
    )

    print(
        "[config] Wi-Fi/UDP configuration applied",
        flush=True,
    )

    print(
        f"[config] SSID={ssid}",
        flush=True,
    )

    print(
        f"[config] UDP server="
        f"{server_ip}:{server_port}",
        flush=True,
    )

    print(
        f"[config] UDP average="
        f"{average_time} ms",
        flush=True,
    )

    return header


# ---------------------------------------------------------------------------
# UDP iPerf server
# ---------------------------------------------------------------------------

def start_udp_server(cfg: dict[str, Any]):
    """
    Start iPerf UDP server on the configured Pi.

    The same Pi can be used for:
        - BLE Central
        - UDP server
    """

    pi = cfg["pi"]
    udp = cfg["udp"]

    server_host = str(
        udp.get("server_host")
        or udp.get("server_ip")
        or ""
    ).strip()

    if not server_host:
        raise ValueError(
            "Set udp.server_host or udp.server_ip"
        )

    server_pi = dict(pi)
    server_pi["host"] = server_host

    print(
        f"[iperf] Connecting to UDP server "
        f"{server_host}...",
        flush=True,
    )

    client = _connect(server_pi)

    port = int(
        udp.get(
            "server_port",
            5001,
        )
    )

    command = str(
        udp.get(
            "iperf_command",
            "iperf -s -u -p {port} -i 1",
        )
    ).format(
        port=port,
    )

    command_parts = shlex.split(command)

    if not command_parts:
        client.close()
        raise RuntimeError(
            "iperf_command is empty"
        )

    program = command_parts[0]

    # ------------------------------------------------------------
    # Check iPerf
    # ------------------------------------------------------------

    code, out, err = _run(
        client,
        f"command -v {shlex.quote(program)}",
        20,
    )

    if code:
        client.close()
        raise RuntimeError(
            f"UDP server program unavailable: "
            f"{err or out or program}"
        )

    print(
        f"[iperf] Found {program}: "
        f"{out.strip()}",
        flush=True,
    )

    # ------------------------------------------------------------
    # Kill stale iPerf
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

        pkill -f 'iperf -s -u' 2>/dev/null || true
        """,
        20,
    )

    _run(
        client,
        "rm -f /tmp/wcbs_iperf_udp.log",
        20,
    )

    # ------------------------------------------------------------
    # Start server
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
    # Obtain PID
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
    # Wait for socket
    # ------------------------------------------------------------

    for attempt in range(1, 11):

        time.sleep(1)

        process_code, _, _ = _run(
            client,
            f"kill -0 {shlex.quote(pid)} "
            f"2>/dev/null",
            20,
        )

        _, socket_out, _ = _run(
            client,
            f"ss -lunp 2>&1 | "
            f"grep -E ':{port}\\b' || true",
            20,
        )

        print(
            f"[iperf] startup check "
            f"{attempt}/10 "
            f"alive="
            f"{'yes' if process_code == 0 else 'no'} "
            f"socket="
            f"{'yes' if socket_out.strip() else 'no'}",
            flush=True,
        )

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

        if process_code != 0:
            _, log_out, _ = _run(
                client,
                "cat /tmp/wcbs_iperf_udp.log "
                "2>/dev/null || true",
                20,
            )

            client.close()

            raise RuntimeError(
                f"iPerf exited before binding "
                f"UDP port {port}.\n"
                f"iPerf log:\n{log_out}"
            )

    _, process_out, _ = _run(
        client,
        f"ps -fp {shlex.quote(pid)} "
        f"2>&1 || true",
        20,
    )

    _, socket_out, _ = _run(
        client,
        f"ss -lunp 2>&1 | "
        f"grep -E ':{port}\\b' || true",
        20,
    )

    _, log_out, _ = _run(
        client,
        "cat /tmp/wcbs_iperf_udp.log "
        "2>/dev/null || true",
        20,
    )

    client.close()

    raise RuntimeError(
        f"Pi UDP server did not bind port {port}.\n"
        f"Process:\n{process_out}\n"
        f"Socket:\n{socket_out}\n"
        f"iPerf log:\n{log_out}"
    )


def stop_udp_server(client) -> None:
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


# ---------------------------------------------------------------------------
# Raspberry Pi BLE Central
# ---------------------------------------------------------------------------

BLE_CENTRAL_SCRIPT = r'''
import asyncio
import sys

from bleak import BleakClient, BleakScanner


DEVICE_NAME = __DEVICE_NAME__
DEVICE_ADDRESS = __DEVICE_ADDRESS__
SCAN_TIMEOUT = __SCAN_TIMEOUT__
NOTIFICATION_WAIT = __NOTIFICATION_WAIT__


async def find_device():
    print(
        "BLE_SCAN_TARGET",
        DEVICE_ADDRESS if DEVICE_ADDRESS else DEVICE_NAME,
        flush=True,
    )

    def match(device, advertisement):
        if DEVICE_ADDRESS:
            return (
                str(device.address).upper()
                == DEVICE_ADDRESS.upper()
            )

        advertised_name = (
            advertisement.local_name
            if advertisement
            else None
        )

        return (
            device.name == DEVICE_NAME
            or advertised_name == DEVICE_NAME
        )

    device = await BleakScanner.find_device_by_filter(
        match,
        timeout=SCAN_TIMEOUT,
    )

    return device


async def main():

    device = await find_device()

    if not device:
        print(
            "BLE_DEVICE_NOT_FOUND",
            flush=True,
        )
        raise RuntimeError(
            "BLE advertiser not found"
        )

    print(
        "BLE_DEVICE_FOUND",
        device.name,
        device.address,
        flush=True,
    )

    notification_count = 0

    async with BleakClient(
        device,
        timeout=SCAN_TIMEOUT,
    ) as client:

        if not client.is_connected:
            raise RuntimeError(
                "BLE client did not connect"
            )

        print(
            "BLE_DUT_CONNECTED",
            device.address,
            flush=True,
        )

        # --------------------------------------------------------
        # Discover services dynamically.
        # No notification UUID is hard-coded.
        # --------------------------------------------------------

        notify_characteristics = []

        for service in client.services:

            print(
                "BLE_SERVICE",
                service.uuid,
                flush=True,
            )

            for characteristic in service.characteristics:

                props = [
                    str(p).lower()
                    for p in characteristic.properties
                ]

                print(
                    "BLE_CHARACTERISTIC",
                    characteristic.uuid,
                    ",".join(props),
                    flush=True,
                )

                if "notify" in props:
                    notify_characteristics.append(
                        characteristic
                    )

        if not notify_characteristics:
            raise RuntimeError(
                "No GATT characteristic with "
                "'notify' property was found"
            )

        print(
            "BLE_NOTIFY_CHARACTERISTICS",
            len(notify_characteristics),
            flush=True,
        )

        event = asyncio.Event()

        def notification_handler(
            characteristic,
            data,
        ):
            nonlocal notification_count

            notification_count += 1

            print(
                "BLE_GATT_NOTIFICATION",
                characteristic.uuid,
                len(data),
                data.hex(),
                flush=True,
            )

            event.set()

        # --------------------------------------------------------
        # Subscribe to every dynamically discovered notify
        # characteristic.
        # --------------------------------------------------------

        started = []

        for characteristic in notify_characteristics:

            try:
                await client.start_notify(
                    characteristic.uuid,
                    notification_handler,
                )

                started.append(
                    characteristic.uuid
                )

                print(
                    "BLE_NOTIFY_STARTED",
                    characteristic.uuid,
                    flush=True,
                )

            except Exception as exc:

                print(
                    "BLE_NOTIFY_START_FAILED",
                    characteristic.uuid,
                    repr(exc),
                    flush=True,
                )

        if not started:
            raise RuntimeError(
                "Unable to subscribe to any "
                "notify characteristic"
            )

        # --------------------------------------------------------
        # Wait for an ACTUAL notification.
        #
        # Do not mark PASS merely because start_notify() succeeded.
        # --------------------------------------------------------

        try:
            await asyncio.wait_for(
                event.wait(),
                timeout=NOTIFICATION_WAIT,
            )
        except asyncio.TimeoutError:
            raise RuntimeError(
                "No BLE notifications received "
                f"within {NOTIFICATION_WAIT} seconds"
            )

        for uuid in started:
            try:
                await client.stop_notify(uuid)
            except Exception:
                pass

    if notification_count <= 0:
        raise RuntimeError(
            "BLE notification count is zero"
        )

    print(
        "BLE_GATT_NOTIFICATION_PASS",
        notification_count,
        flush=True,
    )

    print(
        "BLE_PI_CENTRAL_VALIDATION_PASS",
        flush=True,
    )


asyncio.run(main())
'''


def run_pi_ble_central(
    pi_client,
    cfg: dict[str, Any],
) -> None:
    """
    CASE 1:

        Raspberry Pi = Central
        DUT          = Peripheral

    The Pi scans for SI_COEX_MAX_DEMO, connects, dynamically discovers
    notification characteristics and waits for an actual notification.
    """

    ble = cfg["ble"]
    pi = cfg["pi"]

    device_name = str(
        ble.get(
            "dut_device_name",
            "SI_COEX_MAX_DEMO",
        )
    ).strip()

    device_address = str(
        ble.get(
            "dut_address",
            "",
        )
        or ""
    ).strip()

    scan_timeout = float(
        ble.get(
            "connect_timeout_s",
            90,
        )
    )

    notification_wait = float(
        ble.get(
            "notification_wait_s",
            15,
        )
    )

    workdir = str(
        pi.get(
            "remote_workdir",
            "/var/tmp/wcbs_throughput",
        )
    )

    script = (
        BLE_CENTRAL_SCRIPT
        .replace(
            "__DEVICE_NAME__",
            repr(device_name),
        )
        .replace(
            "__DEVICE_ADDRESS__",
            repr(device_address),
        )
        .replace(
            "__SCAN_TIMEOUT__",
            repr(scan_timeout),
        )
        .replace(
            "__NOTIFICATION_WAIT__",
            repr(notification_wait),
        )
    )

    encoded = base64.b64encode(
        script.encode("utf-8")
    ).decode("ascii")

    remote_script = (
        f"{workdir}/wcbs_ble_central.py"
    )

    upload_command = (
        f"mkdir -p {shlex.quote(workdir)} "
        f"&& echo {shlex.quote(encoded)} "
        f"| base64 -d "
        f"> {shlex.quote(remote_script)}"
    )

    code, out, err = _run(
        pi_client,
        upload_command,
        30,
    )

    if code:
        raise RuntimeError(
            "Failed to upload BLE Central script.\n"
            f"stdout: {out}\n"
            f"stderr: {err}"
        )

    command = (
        f"python3 {shlex.quote(remote_script)}"
    )

    print(
        "[ble-case1] "
        "Pi=Central DUT=Peripheral",
        flush=True,
    )

    code = _stream(
        pi_client,
        command,
        int(scan_timeout + notification_wait + 60),
        "pi-ble",
    )

    if code:
        raise RuntimeError(
            "BLE CASE 1 failed: "
            "Pi could not connect to DUT or "
            "receive a GATT notification"
        )


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def wait_for_state(
    watcher,
    description: str,
    predicate,
    timeout: float,
) -> None:

    print(
        f"[wait] {description} "
        f"(timeout={timeout}s)",
        flush=True,
    )

    watcher.wait_for(
        description,
        predicate,
        timeout,
    )

    print(
        f"[pass] {description}",
        flush=True,
    )


def validate_ble_case_1(
    state: State,
) -> None:

    if not state.ble_pi_connected:
        raise RuntimeError(
            "BLE CASE 1 failed: Pi did not "
            "establish Central -> DUT connection"
        )

    if not state.ble_pi_notification_received:
        raise RuntimeError(
            "BLE CASE 1 failed: Pi connected "
            "but no GATT notification was received"
        )

    print(
        "[pass] BLE CASE 1: "
        "Pi Central -> DUT Peripheral "
        "+ notification",
        flush=True,
    )


def validate_ble_case_2(
    watcher,
    cfg: dict[str, Any],
) -> None:

    timeout = float(
        cfg.get(
            "ble",
            {},
        ).get(
            "avinash_connect_timeout_s",
            90,
        )
    )

    wait_for_state(
        watcher,
        "DUT Central -> avinash Peripheral connection",
        lambda s: s.ble_avinash_connected,
        timeout,
    )

    print(
        "[pass] BLE CASE 2: "
        "DUT Central -> avinash Peripheral",
        flush=True,
    )


def validate_udp(
    watcher,
    cfg: dict[str, Any],
) -> None:

    timeout = float(
        cfg.get(
            "timeouts",
            {},
        ).get(
            "udp_s",
            90,
        )
    )

    wait_for_state(
        watcher,
        "DUT UDP_TX start",
        lambda s: s.udp_started,
        timeout,
    )

    wait_for_state(
        watcher,
        "DUT UDP throughput result",
        lambda s: s.udp_result,
        timeout,
    )


def final_validation(
    state: State,
) -> None:

    checks = {
        "WLAN": state.wlan_connected,
        "BLE CASE 1 connection": state.ble_pi_connected,
        "BLE CASE 1 notification":
            state.ble_pi_notification_received,
        "UDP start": state.udp_started,
        "UDP result": state.udp_result,
        "BLE CASE 2 avinash":
            state.ble_avinash_connected,
    }

    failed = [
        name
        for name, passed in checks.items()
        if not passed
    ]

    if failed:
        raise RuntimeError(
            "Final validation failed: "
            + ", ".join(failed)
        )

    print(
        "[pass] All dual-role validations passed",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def run(
    cfg: dict[str, Any],
) -> dict[str, Any]:

    print(
        "=" * 65,
        flush=True,
    )

    print(
        f"STARTING {APP_ID}",
        flush=True,
    )

    print(
        "=" * 65,
        flush=True,
    )

    configure_source(cfg)

    pi_client = None
    watcher = None

    try:

        # --------------------------------------------------------
        # Start UDP server BEFORE DUT build/flash.
        # --------------------------------------------------------

        pi_client = start_udp_server(cfg)

        # --------------------------------------------------------
        # Existing Studio API.
        #
        # IMPORTANT:
        # This comes from common.harness.
        # We do NOT implement /api/build_flash here.
        # --------------------------------------------------------

        api = StudioApi(
            cfg["studio"].get(
                "url",
                "http://127.0.0.1:5050",
            )
        )

        print(
            "=" * 65,
            flush=True,
        )

        print(
            "STUDIO HEALTH CHECK",
            flush=True,
        )

        print(
            "=" * 65,
            flush=True,
        )

        api.request(
            "GET",
            "/api/health",
        )

        # --------------------------------------------------------
        # Existing working build/flash mechanism.
        # --------------------------------------------------------

        print(
            "=" * 65,
            flush=True,
        )

        print(
            "BUILD / FLASH",
            flush=True,
        )

        print(
            "=" * 65,
            flush=True,
        )

        build = api.build_flash(
            APP_ID,
            cfg,
        )

        print(
            "[studio] Build/flash completed",
            flush=True,
        )

        # --------------------------------------------------------
        # Serial watcher.
        #
        # This is the existing shared implementation.
        # --------------------------------------------------------

        state = State()

        watcher = SerialWatcher(
            api,
            state,
            parse,
        )

        watcher.start()

        # --------------------------------------------------------
        # WLAN
        # --------------------------------------------------------

        wlan_timeout = float(
            cfg.get(
                "timeouts",
                {},
            ).get(
                "wlan_s",
                90,
            )
        )

        wait_for_state(
            watcher,
            "WLAN association and IP configuration",
            lambda s: s.wlan_connected,
            wlan_timeout,
        )

        # --------------------------------------------------------
        # BLE CASE 1
        #
        # Pi = Central
        # DUT = Peripheral
        # --------------------------------------------------------

        print(
            "=" * 65,
            flush=True,
        )

        print(
            "BLE CASE 1",
            flush=True,
        )

        print(
            "Pi = Central | DUT = Peripheral",
            flush=True,
        )

        print(
            "=" * 65,
            flush=True,
        )

        run_pi_ble_central(
            pi_client,
            cfg,
        )

        # The Pi-side process is the authoritative source for this
        # connection and notification result.
        state.ble_pi_connected = True
        state.ble_pi_notification_received = True

        validate_ble_case_1(state)

        # --------------------------------------------------------
        # UDP
        # --------------------------------------------------------

        print(
            "=" * 65,
            flush=True,
        )

        print(
            "UDP THROUGHPUT",
            flush=True,
        )

        print(
            "=" * 65,
            flush=True,
        )

        validate_udp(
            watcher,
            cfg,
        )

        # --------------------------------------------------------
        # BLE CASE 2
        #
        # DUT = Central
        # avinash = Peripheral
        #
        # The DUT firmware is responsible for scanning/connecting
        # to "avinash". UART confirms the connection.
        # --------------------------------------------------------

        print(
            "=" * 65,
            flush=True,
        )

        print(
            "BLE CASE 2",
            flush=True,
        )

        print(
            "DUT = Central | avinash = Peripheral",
            flush=True,
        )

        print(
            "=" * 65,
            flush=True,
        )

        validate_ble_case_2(
            watcher,
            cfg,
        )

        # --------------------------------------------------------
        # Final validation
        # --------------------------------------------------------

        final_validation(state)

        result = {
            "ok": True,
            "app_id": APP_ID,
            "build_job_id": (
                build.get("id")
                if isinstance(build, dict)
                else None
            ),
            "state": asdict(state),
            "ble_topology": {
                "case_1": {
                    "central": "raspberry_pi",
                    "peripheral": "SI_COEX_MAX_DEMO",
                    "notification": True,
                },
                "case_2": {
                    "central": "DUT",
                    "peripheral": "avinash",
                    "connection": True,
                },
            },
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

        print(
            "=" * 65,
            flush=True,
        )

        print(
            "FINAL RESULT: PASS",
            flush=True,
        )

        print(
            json.dumps(
                result,
                indent=2,
            ),
            flush=True,
        )

        print(
            "=" * 65,
            flush=True,
        )

        return result

    finally:

        if watcher is not None:
            try:
                watcher.stop()
            except Exception as exc:
                print(
                    f"[serial] cleanup warning: {exc}",
                    flush=True,
                )

        stop_udp_server(
            pi_client
        )

        if pi_client is not None:
            try:
                pi_client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_throughput_config(
    path: Path,
) -> dict[str, Any]:

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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    try:

        result = run(
            load_throughput_config(
                HERE / "config.local.json"
            )
        )

        print(
            "PASS: BLE dual-role operation "
            "and DUT UDP_TX throughput validated",
            result,
        )

    except Exception as exc:

        print(
            "=" * 65,
            file=sys.stderr,
        )

        print(
            "FINAL RESULT: FAIL",
            file=sys.stderr,
        )

        print(
            f"[error] {exc}",
            file=sys.stderr,
        )

        print(
            "=" * 65,
            file=sys.stderr,
        )

        raise SystemExit(1)