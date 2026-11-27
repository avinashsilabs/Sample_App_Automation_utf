#!/usr/bin/env python3
"""
WiSeConnect Wi-Fi + BLE throughput coexistence automation.

Flow:
    1. Use ONLY wifi_station_ble_throughput_app.
    2. Prepare/configure the application source.
    3. Build + flash through the existing common.harness StudioApi.
    4. Start UDP iPerf server on Raspberry Pi.
    5. Raspberry Pi acts as BLE Central.
    6. SiWG917 DUT acts as BLE Peripheral.
    7. Wait for BLE connection.
    8. Wait for WLAN connection.
    9. Wait for UDP throughput result.
   10. Stop iPerf and clean up.

The Pi is accessed only through SSH.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


from pathlib import Path
import sys

# ------------------------------------------------------------
# Use the shared coex/common package.
#
# Directory:
#   coex/
#       common/
#       wifi_sta_throughput_scripts/
# ------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
COEX_DIR = SCRIPT_DIR.parent

if str(COEX_DIR) not in sys.path:
    sys.path.insert(0, str(COEX_DIR))

from common.harness import SerialWatcher, StudioApi
from common.pi_ble import _connect, _run, _stream


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

APP_ID = "wifi_station_ble_throughput_app"

SOURCE_APP = (
    Path(r"C:\Avinash\wiseconnect_809")
    / "examples"
    / "snippets"
    / "wlan_ble"
    / APP_ID
)

SCRIPT_DIR = Path(__file__).resolve().parent

# The generated/staged project is kept under the automation directory.
PROJECTS_DIR = SCRIPT_DIR / "projects"
STAGED_APP = PROJECTS_DIR / APP_ID


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

@dataclass
class DutState:
    ble_connected: bool = False
    wlan_connected: bool = False
    throughput_started: bool = False
    throughput_complete: bool = False
    throughput_result: Optional[str] = None
    wlan_ip: Optional[str] = None
    failure: Optional[str] = None
    last_line: str = ""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config() -> dict[str, Any]:
    config_path = SCRIPT_DIR / "config.local.json"

    if not config_path.is_file():
        raise FileNotFoundError(
            f"Missing configuration file:\n{config_path}"
        )

    with config_path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


# ---------------------------------------------------------------------------
# Source preparation
# ---------------------------------------------------------------------------

def replace_define(
    text: str,
    name: str,
    value: str,
) -> str:
    """
    Replace an existing #define.

    If the define does not exist, append it to the end of the file.
    """

    pattern = re.compile(
        rf"^[ \t]*#define[ \t]+{re.escape(name)}[ \t]+.*$",
        re.MULTILINE,
    )

    replacement = f"#define {name} {value}"

    new_text, count = pattern.subn(replacement, text)

    if count:
        return new_text

    if not new_text.endswith("\n"):
        new_text += "\n"

    return new_text + replacement + "\n"


def security_macro(security: int) -> str:
    """
    Preserve the numeric security value expected by the application.

    Your supplied config uses:
        security = 2
    """

    return str(int(security))


def configure_wifi_source(
    app_root: Path,
    cfg: dict[str, Any],
) -> None:

    wifi_cfg = app_root / "wifi_config.h"

    if not wifi_cfg.is_file():
        raise FileNotFoundError(
            f"wifi_config.h not found:\n{wifi_cfg}"
        )

    wifi = cfg["wifi"]
    udp = cfg["udp"]

    server_ip = (
        str(udp.get("server_ip") or "").strip()
        or str(cfg["pi"]["host"])
    )

    server_port = int(udp["server_port"])

    text = wifi_cfg.read_text(encoding="utf-8")

    defines = {
        "SSID": f'"{wifi["ssid"]}"',
        "PSK": f'"{wifi["password"]}"',
        "SECURITY_TYPE": security_macro(
            int(wifi.get("security", 2))
        ),

        # Keep the application configured for UDP TX.
        "DEVICE_PORT": str(server_port),
        "SERVER_PORT": str(server_port),
        "SERVER_IP_ADDRESS": f'"{server_ip}"',

        # Async socket feature.
        "SOCKET_ASYNC_FEATURE": "1",

        # UDP TX according to the throughput application.
        "THROUGHPUT_TYPE": "UDP_TX",

        # One BLE-connected throughput run.
        "SL_BLE_DYNAMIC_DISABLE_THROUGHPUT_DEMO": "0",
    }

    for name, value in defines.items():
        text = replace_define(text, name, value)

    wifi_cfg.write_text(text, encoding="utf-8")

    print(f"[source] Configured {wifi_cfg}", flush=True)


def configure_ble_source(
    app_root: Path,
    cfg: dict[str, Any],
) -> None:

    ble_cfg = app_root / "ble_app.c"

    if not ble_cfg.is_file():
        raise FileNotFoundError(
            f"ble_app.c not found:\n{ble_cfg}"
        )

    ble = cfg["ble"]

    text = ble_cfg.read_text(encoding="utf-8")

    defines = {
        "RSI_BLE_CHAR_SERV_UUID": "0x2803",
        "RSI_BLE_CLIENT_CHAR_UUID": "0x2902",
        "RSI_BLE_NEW_SERVICE_UUID": "0xAABB",
        "RSI_BLE_ATTRIBUTE_1_UUID": "0x1AA1",
        "RSI_BLE_ATTRIBUTE_2_UUID": "0x1BB1",
        "RSI_BLE_MAX_DATA_LEN": "20",
        "RSI_BLE_DEVICE_NAME": f'"{ble["device_name"]}"',
    }

    for name, value in defines.items():
        text = replace_define(text, name, value)

    ble_cfg.write_text(text, encoding="utf-8")

    print(f"[source] Configured {ble_cfg}", flush=True)


def prepare_project(
    cfg: dict[str, Any],
) -> Path:
    """
    Copy the requested example into the automation project directory and
    apply the runtime configuration.

    ONLY wifi_station_ble_throughput_app is used.
    """

    source = Path(
        cfg["studio"].get(
            "throughput_source",
            str(SOURCE_APP),
        )
    )

    if not source.is_dir():
        raise FileNotFoundError(
            "Required application source directory was not found:\n"
            f"{source}\n\n"
            "Expected application:\n"
            f"{APP_ID}"
        )

    if source.name != APP_ID:
        raise RuntimeError(
            f"Refusing to use unexpected application directory: {source}"
        )

    PROJECTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if STAGED_APP.exists():
        print(
            f"[source] Removing previous staged project: {STAGED_APP}",
            flush=True,
        )
        shutil.rmtree(STAGED_APP)

    print(
        f"[source] Fetching application source:\n"
        f"         {source}",
        flush=True,
    )

    shutil.copytree(
        source,
        STAGED_APP,
    )

    print(
        f"[source] Staged application:\n"
        f"         {STAGED_APP}",
        flush=True,
    )

    configure_wifi_source(
        STAGED_APP,
        cfg,
    )

    configure_ble_source(
        STAGED_APP,
        cfg,
    )

    return STAGED_APP


# ---------------------------------------------------------------------------
# DUT serial parser
# ---------------------------------------------------------------------------

def parse_dut_line(
    state: DutState,
    line: str,
) -> None:

    state.last_line = line

    lower = line.lower()

    # ---------------------------------------------------------------
    # Failure detection
    # ---------------------------------------------------------------

    failure_patterns = (
        "assert",
        "fatal",
        "failed",
        "failure",
        "error:",
        "error code",
        "socket create failed",
        "socket connect failed",
        "wlan connection failed",
        "ble connection failed",
    )

    # Do not treat ordinary "failed" BLE notify messages as fatal.
    # The application may print notify failures during normal cleanup.
    if any(pattern in lower for pattern in failure_patterns):
        if (
            "notify" not in lower
            and "advertising failed to stop" not in lower
        ):
            state.failure = line

    # ---------------------------------------------------------------
    # BLE
    # ---------------------------------------------------------------

    if (
        "ble connected" in lower
        or "connection established" in lower
        or "ble connection established" in lower
    ):
        state.ble_connected = True

    # ---------------------------------------------------------------
    # WLAN
    # ---------------------------------------------------------------

    if (
        "wlan connected" in lower
        or "wifi connected" in lower
        or "network connected" in lower
        or "station connected" in lower
    ):
        state.wlan_connected = True

    # Capture an IPv4 address if printed by the DUT.
    ip_match = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        line,
    )

    if ip_match:
        ip = ip_match.group(0)

        # Do not accidentally treat unrelated addresses as the DUT IP.
        if not ip.startswith("127."):
            state.wlan_ip = ip

    # ---------------------------------------------------------------
    # Throughput
    # ---------------------------------------------------------------

    if (
        "throughput start" in lower
        or "starting throughput" in lower
        or "start wlan throughput" in lower
    ):
        state.throughput_started = True

    if (
        "throughput result" in lower
        or "throughput completed" in lower
        or "throughput complete" in lower
        or "throughput test complete" in lower
        or "udp throughput result" in lower
        or "average throughput" in lower
    ):
        state.throughput_complete = True
        state.throughput_result = line

    # Common SiWx91x output can contain a numeric throughput result
    # without the exact phrase above.
    if (
        "mbps" in lower
        and (
            "throughput" in lower
            or "udp" in lower
        )
    ):
        state.throughput_complete = True
        state.throughput_result = line


# ---------------------------------------------------------------------------
# Pi iPerf
# ---------------------------------------------------------------------------

def start_udp_server(
    cfg: dict[str, Any],
):
    """
    Start iPerf UDP server on the Raspberry Pi.

    Uses the actual common.pi_ble._connect(pi) API.
    """

    pi = cfg["pi"]
    udp = cfg["udp"]

    port = int(udp["server_port"])

    print(
        f"[pi] Connecting to Raspberry Pi "
        f"{pi['host']}:{pi.get('port', 22)}",
        flush=True,
    )

    client = _connect(pi)

    try:
        # Check whether iPerf exists.
        code, out, err = _run(
            client,
            "command -v iperf || command -v iperf3 || true",
            timeout=30,
        )

        iperf_path = out.strip().splitlines()[0] if out.strip() else ""

        if not iperf_path:
            if not udp.get("install_iperf_if_missing", True):
                raise RuntimeError(
                    "iperf is not installed on the Raspberry Pi"
                )

            print(
                "[pi] iPerf not found; attempting installation",
                flush=True,
            )

            install_cmd = (
                "sudo -S apt-get update -y && "
                "sudo -S apt-get install -y iperf"
            )

            password = str(pi.get("password") or "")

            if password:
                install_cmd = (
                    f"printf '%s\\n' {shlex.quote(password)} | "
                    f"{install_cmd}"
                )

            code, out, err = _run(
                client,
                install_cmd,
                timeout=600,
            )

            if code != 0:
                raise RuntimeError(
                    "Could not install iperf on Raspberry Pi:\n"
                    f"{out}\n{err}"
                )

            code, out, err = _run(
                client,
                "command -v iperf",
                timeout=30,
            )

            if code != 0 or not out.strip():
                raise RuntimeError(
                    "iperf installation completed but executable "
                    "could not be found"
                )

            iperf_path = out.strip().splitlines()[0]

        print(
            f"[pi] Using iPerf: {iperf_path}",
            flush=True,
        )

        remote_workdir = str(
            pi.get(
                "remote_workdir",
                "/var/tmp/wcbs_throughput",
            )
        )

        mkdir_cmd = (
            f"mkdir -p {shlex.quote(remote_workdir)}"
        )

        code, out, err = _run(
            client,
            mkdir_cmd,
            timeout=30,
        )

        if code != 0:
            raise RuntimeError(
                f"Unable to create Pi work directory:\n"
                f"{out}\n{err}"
            )

        pid_file = (
            f"{remote_workdir}/iperf_udp.pid"
        )

        log_file = (
            f"{remote_workdir}/iperf_udp.log"
        )

        # Kill only the iPerf process previously launched by this test.
        cleanup_old = (
            f"if [ -f {shlex.quote(pid_file)} ]; then "
            f"kill $(cat {shlex.quote(pid_file)}) "
            f"2>/dev/null || true; "
            f"rm -f {shlex.quote(pid_file)}; "
            f"fi"
        )

        _run(
            client,
            cleanup_old,
            timeout=30,
        )

        iperf_cmd = (
            f"{shlex.quote(iperf_path)} "
            f"-s -u "
            f"-p {port} "
            f"-i 1"
        )

        launch_cmd = (
            f"nohup {iperf_cmd} "
            f"> {shlex.quote(log_file)} 2>&1 "
            f"< /dev/null & "
            f"echo $! > {shlex.quote(pid_file)}"
        )

        code, out, err = _run(
            client,
            launch_cmd,
            timeout=30,
        )

        if code != 0:
            raise RuntimeError(
                "Failed to start Pi iPerf server:\n"
                f"{out}\n{err}"
            )

        # Give iPerf a moment to bind.
        time.sleep(1)

        code, out, err = _run(
            client,
            f"cat {shlex.quote(pid_file)} "
            f"&& grep -E 'Server listening|UDP port' "
            f"{shlex.quote(log_file)} || true",
            timeout=30,
        )

        print(
            "[pi] iPerf status:",
            out.strip(),
            flush=True,
        )

        if "Server listening" not in out and "UDP port" not in out:
            # Print log to make a bind problem immediately visible.
            _, log_out, log_err = _run(
                client,
                f"cat {shlex.quote(log_file)} 2>/dev/null || true",
                timeout=30,
            )

            raise RuntimeError(
                "Pi UDP server did not bind port "
                f"{port}.\n{log_out}\n{log_err}"
            )

        print(
            f"[pi] UDP iPerf server listening on port {port}",
            flush=True,
        )

        return client, pid_file, log_file

    except Exception:
        client.close()
        raise


def stop_udp_server(
    client,
    pid_file: str,
    log_file: str,
) -> None:

    try:
        command = (
            f"if [ -f {shlex.quote(pid_file)} ]; then "
            f"kill $(cat {shlex.quote(pid_file)}) "
            f"2>/dev/null || true; "
            f"rm -f {shlex.quote(pid_file)}; "
            f"fi"
        )

        _run(
            client,
            command,
            timeout=30,
        )

        code, out, err = _run(
            client,
            f"cat {shlex.quote(log_file)} "
            f"2>/dev/null || true",
            timeout=30,
        )

        print(
            "[pi] Final iPerf log:",
            flush=True,
        )

        if out.strip():
            print(out.rstrip(), flush=True)

        if err.strip():
            print(err.rstrip(), flush=True)

        print(
            "[pi] iPerf UDP server stopped",
            flush=True,
        )

    finally:
        client.close()


# ---------------------------------------------------------------------------
# BLE Central on Pi
# ---------------------------------------------------------------------------

def connect_ble_central(
    cfg: dict[str, Any],
):
    """
    Connect the Raspberry Pi BLE Central to the DUT BLE Peripheral.

    This uses the existing Pi environment but intentionally does NOT use
    the Wi-Fi provisioning flow in common.pi_ble.
    """

    pi = cfg["pi"]
    ble = cfg["ble"]

    target_name = str(
        ble.get(
            "device_name","SI_COEX_MAX_DEMO",
        )
    )

    notify_uuid = str(
        ble.get(
            "notify_uuid",
            "00001aa1-0000-1000-8000-00805f9b34fb",
        )
    )

    timeout_s = int(
        float(
            ble.get(
                "connect_timeout_s",
                30,
            )
        )
    )

    print(
        "[ble] DUT role    : BLE Peripheral",
        flush=True,
    )

    print(
        "[ble] Pi role     : BLE Central",
        flush=True,
    )

    print(
        f"[ble] Target name : {target_name}",
        flush=True,
    )

    print(
        f"[ble] Notify UUID : {notify_uuid}",
        flush=True,
    )

    client = _connect(pi)

    workdir = str(
        pi.get(
            "remote_workdir",
            "/var/tmp/wcbs_throughput",
        )
    )

    # The Pi already has Bleak provisioning support from common.pi_ble.
    # Reuse its virtual environment if present.
    python_candidates = (
        f"{workdir}/.venv/bin/python",
        "python3",
    )

    python = "python3"

    for candidate in python_candidates:
        code, out, _err = _run(
            client,
            f"{shlex.quote(candidate)} -c "
            f"{shlex.quote('import bleak; print(\"BLEAK_OK\")')}",
            timeout=30,
        )

        if code == 0 and "BLEAK_OK" in out:
            python = candidate
            break

    script = r'''
import asyncio
import sys
from bleak import BleakClient, BleakScanner

TARGET = sys.argv[1]
NOTIFY_UUID = sys.argv[2]
TIMEOUT = float(sys.argv[3])

async def main():
    print(f"[pi-ble] Scanning for {TARGET} ({TIMEOUT:.0f}s)...", flush=True)

    device = await BleakScanner.find_device_by_filter(
        lambda dev, adv:
            dev.name == TARGET
            or getattr(adv, "local_name", None) == TARGET,
        timeout=TIMEOUT,
    )

    if device is None:
        print(
            f"[pi-ble] ERROR: DUT {TARGET!r} not found",
            flush=True,
        )
        return 2

    print(
        f"[pi-ble] Found DUT {device.name} "
        f"address={device.address}",
        flush=True,
    )

    try:
        async with BleakClient(
            device,
            timeout=TIMEOUT,
        ) as ble:

            print(
                f"[pi-ble] Connected to {TARGET}",
                flush=True,
            )

            try:
                await ble.start_notify(
                    NOTIFY_UUID,
                    lambda sender, data:
                        print(
                            f"[pi-ble] notify "
                            f"{bytes(data).hex()}",
                            flush=True,
                        ),
                )

                print(
                    "[pi-ble] Notifications enabled",
                    flush=True,
                )

            except Exception as exc:
                print(
                    f"[pi-ble] Notification setup skipped: {exc}",
                    flush=True,
                )

            # Keep the BLE connection alive for the WLAN throughput run.
            # The DUT performs its actual throughput operation.
            while ble.is_connected:
                await asyncio.sleep(1)

            print(
                "[pi-ble] DUT disconnected",
                flush=True,
            )

    except Exception as exc:
        print(
            f"[pi-ble] BLE connection error: {exc}",
            flush=True,
        )
        return 3

    return 0

raise SystemExit(asyncio.run(main()))
'''

    remote_script = f"{workdir}/throughput_ble_central.py"

    # Upload script.
    sftp = client.open_sftp()

    try:
        with sftp.file(remote_script, "w") as fp:
            fp.write(script)
    finally:
        sftp.close()

    command = (
        f"cd {shlex.quote(workdir)} && "
        f"{shlex.quote(python)} "
        f"{shlex.quote(remote_script)} "
        f"{shlex.quote(target_name)} "
        f"{shlex.quote(notify_uuid)} "
        f"{timeout_s}"
    )

    print(
        "[ble] Starting Pi BLE Central...",
        flush=True,
    )

    return client, command


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def main() -> int:

    cfg = load_config()

    # Validate the selected application.
    if APP_ID != "wifi_station_ble_throughput_app":
        raise RuntimeError(
            "Only wifi_station_ble_throughput_app is allowed"
        )

    print("=" * 72)
    print("WiSeConnect Wi-Fi + BLE Throughput Coexistence Test")
    print("=" * 72)

    print(
        f"[config] Application : {APP_ID}",
        flush=True,
    )

    print(
        f"[config] Source      : {SOURCE_APP}",
        flush=True,
    )

    print(
        "[config] DUT role    : BLE Peripheral",
        flush=True,
    )

    print(
        "[config] Pi role     : BLE Central",
        flush=True,
    )

    pi = cfg["pi"]
    udp = cfg["udp"]
    ble = cfg["ble"]

    pi_iperf_client = None
    pid_file = None
    log_file = None

    ble_client = None
    ble_command = None
    ble_process_active = False

    api = None
    watcher = None
    state = DutState()

    try:

        # ---------------------------------------------------------------
        # 1. Prepare source
        # ---------------------------------------------------------------

        staged_app = prepare_project(cfg)

        print(
            f"[source] Project ready: {staged_app}",
            flush=True,
        )

        # ---------------------------------------------------------------
        # 2. Build + flash
        # ---------------------------------------------------------------

        studio_url = cfg["studio"].get(
            "url",
            "http://127.0.0.1:5050",
        )

        api = StudioApi(studio_url)

        print(
            f"[studio] Checking Build Studio: {studio_url}",
            flush=True,
        )

        api.request(
            "GET",
            "/api/health",
        )

        print(
            "[studio] Build Studio is healthy",
            flush=True,
        )

        print(
            f"[build] Building/flashing {APP_ID}",
            flush=True,
        )

        # Use the existing common.harness implementation.
        build = api.build_flash(
            APP_ID,
            cfg,
        )

        print(
            "[pass] Build + flash completed",
            flush=True,
        )

        # ---------------------------------------------------------------
        # 3. Start serial watcher
        # ---------------------------------------------------------------

        watcher = SerialWatcher(
            api,
            state,
            parse_dut_line,
        )

        watcher.start()

        # ---------------------------------------------------------------
        # 4. Start UDP iPerf server on Pi
        # ---------------------------------------------------------------

        pi_iperf_client, pid_file, log_file = start_udp_server(
            cfg,
        )

        # ---------------------------------------------------------------
        # 5. Start BLE Central on Pi
        # ---------------------------------------------------------------

        ble_client, ble_command = connect_ble_central(
            cfg,
        )

        # Run BLE Central in streaming mode.

        # This process remains alive while the DUT performs throughput.
        # It is intentionally not the old BLE provisioning flow.
        import threading

        ble_result = {
            "code": None,
            "error": None,
        }

        def run_ble():
            try:
                ble_result["code"] = _stream(
                    ble_client,
                    ble_command,
                    timeout=int(
                        float(
                            ble.get(
                                "notification_window_s",
                                8,
                            )
                        )
                        + float(
                            ble.get(
                                "connect_timeout_s",
                                30,
                            )
                        )
                        + float(
                            cfg["timeouts"].get(
                                "udp_s",
                                90,
                            )
                        )
                        + 60
                    ),
                    prefix="pi-ble",
                )
            except Exception as exc:
                ble_result["error"] = exc

        ble_thread = threading.Thread(
            target=run_ble,
            daemon=True,
        )

        ble_thread.start()
        ble_process_active = True

        # ---------------------------------------------------------------
        # 6. Wait for BLE connection
        # ---------------------------------------------------------------

        watcher.wait_for(
            "BLE connection",
            lambda s: s.ble_connected,
            timeout=float(
                ble.get(
                    "connect_timeout_s",
                    30,
                )
            ),
        )

        # ---------------------------------------------------------------
        # 7. Wait for WLAN
        # ---------------------------------------------------------------

        watcher.wait_for(
            "WLAN connection",
            lambda s: s.wlan_connected,
            timeout=float(
                cfg["timeouts"].get(
                    "wlan_s",
                    90,
                )
            ),
        )

        if state.wlan_ip:
            print(
                f"[pass] DUT WLAN IP: {state.wlan_ip}",
                flush=True,
            )

        # ---------------------------------------------------------------
        # 8. Wait for throughput completion
        # ---------------------------------------------------------------

        watcher.wait_for(
            "UDP throughput completion",
            lambda s: s.throughput_complete,
            timeout=float(
                cfg["timeouts"].get(
                    "udp_s",
                    90,
                )
            )
            + float(
                udp.get(
                    "average_time_ms",
                    60000,
                )
            )
            / 1000.0
            + 30,
        )

        if state.throughput_result:
            print(
                f"[pass] {state.throughput_result}",
                flush=True,
            )

        # ---------------------------------------------------------------
        # 9. Test passed
        # ---------------------------------------------------------------

        print("=" * 72)
        print("FINAL RESULT: PASS")
        print("=" * 72)

        return 0

    except Exception as exc:

        print(
            "=" * 72,
            flush=True,
        )

        print(
            "FINAL RESULT: FAIL",
            flush=True,
        )

        print(
            f"Reason: {exc}",
            flush=True,
        )

        if state.last_line:
            print(
                f"Last DUT line: {state.last_line}",
                flush=True,
            )

        return 1

    finally:

        # ---------------------------------------------------------------
        # Stop serial watcher
        # ---------------------------------------------------------------

        if watcher is not None:
            try:
                watcher.stop()
            except Exception as exc:
                print(
                    f"[cleanup] Serial watcher stop failed: {exc}",
                    flush=True,
                )

        # ---------------------------------------------------------------
        # Stop BLE Pi connection
        # ---------------------------------------------------------------

        if ble_client is not None:
            try:
                if ble_process_active:
                    # Terminate the remote BLE process.
                    _run(
                        ble_client,
                        "pkill -f throughput_ble_central.py "
                        "2>/dev/null || true",
                        timeout=30,
                    )
            except Exception as exc:
                print(
                    f"[cleanup] BLE cleanup failed: {exc}",
                    flush=True,
                )

            try:
                ble_client.close()
            except Exception:
                pass

        # ---------------------------------------------------------------
        # Stop iPerf
        # ---------------------------------------------------------------

        if (
            pi_iperf_client is not None
            and pid_file is not None
            and log_file is not None
        ):
            try:
                stop_udp_server(
                    pi_iperf_client,
                    pid_file,
                    log_file,
                )
            except Exception as exc:
                print(
                    f"[cleanup] iPerf cleanup failed: {exc}",
                    flush=True,
                )


if __name__ == "__main__":
    sys.exit(main())