"""SLC generate + CMake build orchestration."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from app_catalog import resolve_slcp
from config import WORKSPACE
from sdk_manager import sdk_info, validate_local_sdk
from serial_monitor import DEFAULT_BAUD, guess_vcom_port, start_serial
from tool_finder import build_env, discover_tools, env_summary, find_commander


LogFn = Callable[[str], None]


def _wiseconnect_root_from_examples(examples_root: Optional[str]) -> Optional[Path]:
    """Find the extension owning an explicitly selected examples directory."""
    if not examples_root:
        return None
    root = Path(examples_root).expanduser().resolve()
    for candidate in (root, *root.parents):
        if (candidate / "wiseconnect.slce").is_file():
            return candidate
    return None


def _is_coex_examples_root(examples_root: Optional[str]) -> bool:
    if not examples_root:
        return False
    return Path(examples_root).expanduser().resolve().name.lower() == "wlan_ble"


def _stage_coex_project(
    source_dir: Path,
    app_id: str,
    target: str,
    toolchain: str,
    job: "BuildJob",
) -> Path:
    """Copy a WLAN+BLE example into the Build Studio workspace before generation."""
    projects_root = WORKSPACE / "projects" / "coex" / app_id
    staged_dir = projects_root / f"{target}_{toolchain}"
    projects_root.mkdir(parents=True, exist_ok=True)
    if staged_dir.exists():
        shutil.rmtree(staged_dir)
    shutil.copytree(
        source_dir,
        staged_dir,
        ignore=shutil.ignore_patterns(
            "output_*",
            ".git",
            "__pycache__",
            "*.pyc",
        ),
    )
    job.config["source_project_dir"] = str(source_dir)
    job.config["staged_project_dir"] = str(staged_dir)
    job.append(f"Source example (read-only): {source_dir}")
    job.append(f"Created staged coexistence project: {staged_dir}")
    return staged_dir


LOG_LEVEL_SETTING = "SL_LOG_CONFIG_LEVEL_COMPILE_TIME"


def _enable_info_logging(slcp: Path, job: "BuildJob") -> None:
    """Compile the staged project's INFO logs in.

    WLAN, IP, ping and MQTT progress use SL_DEBUG_LOG_V2(INFO, ...), but the
    shipped projects compile at ERROR level, so the DUT UART stays silent and
    the test has nothing to validate against.
    """
    text = slcp.read_text(encoding="utf-8")
    if LOG_LEVEL_SETTING in text:
        return
    if "\nconfiguration:\n" not in text:
        job.append(f"WARNING: no configuration block in {slcp.name}; INFO logs not enabled")
        return
    text = text.replace(
        "\nconfiguration:\n",
        f"\nconfiguration:\n- name: {LOG_LEVEL_SETTING}\n  value: SL_LOG_CONFIG_LEVEL_INFO\n",
        1,
    )
    slcp.write_text(text, encoding="utf-8")
    job.append(f"Staged project logs at INFO level ({LOG_LEVEL_SETTING})")


def _configure_aws_iot(
    project_dir: Path,
    port: Optional[int],
    endpoint: Optional[str],
    job: "BuildJob",
) -> None:
    """Point the generated AWS config at the endpoint and port we can reach.

    SLC copies the SDK's default aws_iot_config.h into the generated project,
    so this runs after generate. Port 443 matters on the bench: outbound 8883
    is blocked, and the SDK's AWS port adds the x-amzn-mqtt-ca ALPN extension
    whenever the destination port is 443, which is how AWS expects MQTT to
    arrive there.
    """
    if not port and not endpoint:
        return
    matches = sorted(project_dir.rglob("config/aws_iot_config.h"))
    if not matches:
        job.append("WARNING: aws_iot_config.h not found; AWS settings unchanged")
        return

    for header in matches:
        text = header.read_text(encoding="utf-8")
        original = text
        if port:
            text = re.sub(
                r"(#define\s+AWS_IOT_MQTT_PORT\s+)\d+",
                lambda m: f"{m.group(1)}{port}",
                text,
                count=1,
            )
        if endpoint:
            text = re.sub(
                r'(#define\s+AWS_IOT_MQTT_HOST\s*\\?\s*\n?\s*)"[^"]*"',
                lambda m: f'{m.group(1)}"{endpoint}"',
                text,
                count=1,
            )
        if text == original:
            continue
        header.write_text(text, encoding="utf-8")
        detail = ", ".join(
            part
            for part in (
                f"host {endpoint}" if endpoint else "",
                f"port {port}" if port else "",
            )
            if part
        )
        job.append(f"AWS IoT config set to {detail} ({header.name})")


def _ipv4_le_value(address: str) -> int:
    """Pack a dotted-quad the way the SiWx917 stores sl_ipv4_address_t."""
    octets = [int(part) for part in address.split(".")]
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        raise ValueError(f"Invalid IPv4 address: {address}")
    return octets[0] | (octets[1] << 8) | (octets[2] << 16) | (octets[3] << 24)


def _point_mqtt_at_broker(example_dir: Path, broker_ip: str, job: "BuildJob") -> None:
    """Send the demo's MQTT traffic to a broker on the lab network.

    The bench router blocks outbound port 1883, so the demo's default
    test.mosquitto.org connection always fails. The DNS lookup is left in
    place (it succeeds and feeds the log line) but the resolved address is
    replaced with the local broker.
    """
    source = example_dir / "wifi_app.c"
    if not source.is_file():
        job.append(f"WARNING: {source.name} not found; MQTT broker not redirected")
        return
    text = source.read_text(encoding="utf-8")
    if "WCBS_MQTT_BROKER_IPV4" in text:
        return

    value = _ipv4_le_value(broker_ip)
    anchor = "#define MQTT_BROKER_PORT  1883"
    if anchor not in text:
        job.append("WARNING: MQTT_BROKER_PORT not found; MQTT broker not redirected")
        return
    text = text.replace(
        anchor,
        f"{anchor}\n// Build Studio: bench router blocks outbound 1883, use the lab broker\n"
        f"#define WCBS_MQTT_BROKER_IPV4 0x{value:08X} // {broker_ip}",
        1,
    )

    replacements = (
        ("server_address = dns_query_rsp.ip.v4.value;", "server_address = WCBS_MQTT_BROKER_IPV4;"),
        (
            "mqtt_broker_configuration.ip.ip.v4.value = dns_query_rsp.ip.v4.value;",
            "mqtt_broker_configuration.ip.ip.v4.value = WCBS_MQTT_BROKER_IPV4;",
        ),
    )
    applied = 0
    for old, new in replacements:
        if old in text:
            text = text.replace(old, new, 1)
            applied += 1
    if applied != len(replacements):
        job.append(
            f"WARNING: MQTT broker redirect matched {applied}/{len(replacements)} sites"
        )
    source.write_text(text, encoding="utf-8")
    job.append(f"Staged project MQTT broker set to {broker_ip}:1883")


@dataclass
class BuildJob:
    id: str
    status: str = "queued"
    phase: str = "build"
    logs: List[str] = field(default_factory=list)
    artifacts: List[dict] = field(default_factory=list)
    error: Optional[str] = None
    flash_output: Optional[str] = None
    serial_port: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    config: dict = field(default_factory=dict)

    def append(self, line: str) -> None:
        self.logs.append(line)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "phase": self.phase,
            "logs": self.logs,
            "artifacts": self.artifacts,
            "error": self.error,
            "flash_output": self.flash_output,
            "serial_port": self.serial_port,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "config": self.config,
        }


_jobs: Dict[str, BuildJob] = {}
_lock = threading.Lock()


def get_job(job_id: str) -> Optional[BuildJob]:
    return _jobs.get(job_id)


def list_jobs() -> list:
    return [j.to_dict() for j in sorted(_jobs.values(), key=lambda x: x.started_at, reverse=True)]


def _run_logged(cmd: list, cwd: Path, env: dict, job: BuildJob) -> None:
    job.append(f"$ {' '.join(str(c) for c in cmd)}")
    job.append(f"  (cwd: {cwd})")
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        shell=False,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        job.append(line.rstrip())
    code = proc.wait()
    if code != 0:
        raise RuntimeError(f"Command failed with exit code {code}")


WIN_MAX_PATH = 260

# Longest header/source file name we expect to be appended to an include directory.
_FILENAME_ALLOWANCE = 45

_INCLUDE_BLOCK_RE = re.compile(
    r"(?P<head>(?:target_)?include_directories\s*\([^)]*?\))",
    re.IGNORECASE | re.DOTALL,
)
_QUOTED_RELATIVE_RE = re.compile(r'"(\.\.[^"]*)"')


def _collapse_include_paths(cmake_dir: Path, job: BuildJob) -> None:
    """Rewrite generated include directories as normalized absolute paths.

    SLC emits WiSeConnect include dirs relative to the CMake project directory,
    e.g. ``"../../../../../../components/.../inc"``. CMake makes those absolute by
    prepending the project directory but never collapses the ``..`` segments, so
    every include path carries ``<app>/output_<target>_<toolchain>/<cmake_sub>/``
    as dead weight. arm-none-eabi-gcc is built against the ANSI Win32 API and
    cannot open a file whose path exceeds MAX_PATH, so headers that land past 260
    characters fail as "No such file or directory". clang is long-path aware,
    which is why the same project builds with llvm_lto but not gcc.
    """
    longest = 0
    for cmake_file in sorted(cmake_dir.glob("*.cmake")):
        original = cmake_file.read_text(encoding="utf-8")

        def collapse_block(match: re.Match) -> str:
            def collapse_entry(entry: re.Match) -> str:
                nonlocal longest
                resolved = Path(cmake_dir / entry.group(1)).resolve()
                longest = max(longest, len(str(resolved)))
                return '"' + resolved.as_posix() + '"'

            return _QUOTED_RELATIVE_RE.sub(collapse_entry, match.group("head"))

        updated = _INCLUDE_BLOCK_RE.sub(collapse_block, original)
        if updated != original:
            cmake_file.write_text(updated, encoding="utf-8")
            job.append(f"Collapsed relative include paths in {cmake_file.name}")

    if longest:
        job.append(f"Longest include directory after collapsing: {longest} characters")
        budget = WIN_MAX_PATH - _FILENAME_ALLOWANCE
        if longest > budget:
            job.append(
                f"WARNING: include paths are within {WIN_MAX_PATH - longest} characters "
                "of the Windows MAX_PATH limit. arm-none-eabi-gcc cannot open files "
                "past 260 characters — move the SDK to a shorter root (e.g. C:\\sdk) "
                "if the build reports missing headers."
            )


def _cmake_output_dir(cmake_dir: Path) -> Path:
    presets_file = cmake_dir / "CMakePresets.json"
    if presets_file.is_file():
        data = json.loads(presets_file.read_text(encoding="utf-8"))
        for preset in data.get("buildPresets", []):
            if preset.get("name") == "default_config" and preset.get("configuration"):
                return cmake_dir / "build" / preset["configuration"]
    for name in ("default_config", "base"):
        candidate = cmake_dir / "build" / name
        if candidate.is_dir():
            return candidate
    return cmake_dir / "build" / "default_config"


_OOB_BLE_SELF_SNIPPET = """
  // Build Studio: print DUT BLE name + public MAC so the Pi can filter scan.
  {
    uint8_t wcbs_ble_self_addr[6] = { 0 };
    char wcbs_ble_self_mac[18]    = { 0 };
    if (rsi_bt_get_local_device_address(wcbs_ble_self_addr) == RSI_SUCCESS) {
      sprintf(wcbs_ble_self_mac,
              "%02X:%02X:%02X:%02X:%02X:%02X",
              wcbs_ble_self_addr[5],
              wcbs_ble_self_addr[4],
              wcbs_ble_self_addr[3],
              wcbs_ble_self_addr[2],
              wcbs_ble_self_addr[1],
              wcbs_ble_self_addr[0]);
      SL_DEBUG_LOG_V2(INFO,
                      "[BLE self] name=%s address=%s\\r\\n",
                      (uintptr_t)RSI_BLE_APP_DEVICE_NAME,
                      (uintptr_t)wcbs_ble_self_mac);
    } else {
      SL_DEBUG_LOG_V2(INFO,
                      "[BLE self] name=%s address=unknown\\r\\n",
                      (uintptr_t)RSI_BLE_APP_DEVICE_NAME);
    }
  }
"""

_OOB_ADV_STARTED = 'SL_DEBUG_LOG_V2(INFO, "BLE Advertising Started ...\\r\\n");'


def _patch_oob_ble_self_identity(example_dir: Path, job: "BuildJob") -> None:
    """Make the staged Out of Box demo print its own BLE MAC on UART.

    The Raspberry Pi then scans for that MAC instead of a hard-coded
    ``ble.address`` in config.local.json.
    """
    ble_app = example_dir / "ble_app.c"
    if not ble_app.is_file():
        job.append("WARNING: ble_app.c not found; BLE self MAC print not added")
        return
    text = ble_app.read_text(encoding="utf-8")
    if "[BLE self] name=%s address=%s" in text:
        job.append("Out of Box BLE self identity print already present")
        return
    if _OOB_ADV_STARTED not in text:
        job.append(
            "WARNING: BLE Advertising Started log not found; BLE self MAC print not added"
        )
        return
    text = text.replace(_OOB_ADV_STARTED, _OOB_ADV_STARTED + _OOB_BLE_SELF_SNIPPET, 1)
    ble_app.write_text(text, encoding="utf-8")
    job.append(
        "Staged Out of Box firmware prints [BLE self] name=... address=... after advertising"
    )


def _patch_ble_ae_peripheral_sources(example_dir: Path, job: BuildJob) -> None:
    """Lab patches for SDK ble_ae_peripheral so Pi scan+connect automation works.

    SDK sample issues addressed:
    - ENABLE_NWP_POWER_SAVE=1 stops advertising right after enable
    - On-air AE payload is raw AE_PERIPHERAL_DATA_1, not LocalName AD (adv[] unused)
    - RSI_BLE_SET_RAND_ADDR default is not the UTF static-random test value
    """
    app_c = example_dir / "app.c"
    ble_cfg = example_dir / "ble_config.h"
    if not app_c.is_file():
        return

    changed: List[str] = []

    if ble_cfg.is_file():
        text = ble_cfg.read_text(encoding="utf-8")
        new_text, n = re.subn(
            r'(#define\s+RSI_BLE_SET_RAND_ADDR\s+)"[^"]*"',
            r'\1"C1:44:33:AA:BB:CC"',
            text,
            count=1,
        )
        text = new_text
        new_text, n2 = re.subn(
            r"#define\s+BLE_SCANNABLE_ADV\s+\(\s*0\s*<<\s*1\s*\)",
            "#define BLE_SCANNABLE_ADV          (1 << 1)",
            text,
            count=1,
        )
        text = new_text
        new_text, n3 = re.subn(
            r"#define\s+BLE_LEGACY_ADV\s+\(\s*0\s*<<\s*4\s*\)",
            "#define BLE_LEGACY_ADV             (1 << 4)",
            text,
            count=1,
        )
        if n or n2 or n3:
            ble_cfg.write_text(new_text, encoding="utf-8")
            if n:
                changed.append("ble_config.h: RSI_BLE_SET_RAND_ADDR → C1:44:33:AA:BB:CC")
            if n2 or n3:
                changed.append(
                    "ble_config.h: AE adv scannable+legacy (BlueZ discovery)"
                )

    text = app_c.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r"#define\s+ENABLE_NWP_POWER_SAVE\s+1\b",
        "#define ENABLE_NWP_POWER_SAVE 0",
        text,
        count=1,
    )
    if n:
        text = new_text
        changed.append("app.c: ENABLE_NWP_POWER_SAVE → 0")

    old_block = (
        "  ble_ae_data.data_len = BLE_AE_ADV_DATA_LEN;\n"
        "  memcpy(ble_ae_data.data, data, ble_ae_data.data_len);"
    )
    new_block = (
        "  ble_ae_data.data_len = (uint8_t)(5 + strlen(RSI_BLE_LOCAL_NAME));\n"
        "  memcpy(ble_ae_data.data, adv, ble_ae_data.data_len);"
    )
    if old_block in text:
        count = text.count(old_block)
        text = text.replace(old_block, new_block)
        changed.append(
            f"app.c: AE adv/scan-rsp use LocalName AD ({count} site(s))"
        )
    elif "memcpy(ble_ae_data.data, adv, ble_ae_data.data_len)" not in text:
        alt_count = text.count("memcpy(ble_ae_data.data, data, ble_ae_data.data_len)")
        if alt_count:
            text = text.replace(
                "ble_ae_data.data_len = BLE_AE_ADV_DATA_LEN;",
                "ble_ae_data.data_len = (uint8_t)(5 + strlen(RSI_BLE_LOCAL_NAME));",
            )
            text = text.replace(
                "memcpy(ble_ae_data.data, data, ble_ae_data.data_len);",
                "memcpy(ble_ae_data.data, adv, ble_ae_data.data_len);",
            )
            changed.append(
                f"app.c: AE adv/scan-rsp use LocalName AD ({alt_count} site(s))"
            )

    # SET2 blocks often use spaced assignment — catch any remaining data[] payloads.
    spaced_len = text.count("ble_ae_data.data_len   = BLE_AE_ADV_DATA_LEN")
    if spaced_len:
        text = text.replace(
            "ble_ae_data.data_len   = BLE_AE_ADV_DATA_LEN",
            "ble_ae_data.data_len   = (uint8_t)(5 + strlen(RSI_BLE_LOCAL_NAME))",
        )
        changed.append(
            f"app.c: SET2 AE data_len uses LocalName ({spaced_len} site(s))"
        )
    remain_data = text.count("memcpy(ble_ae_data.data, data, ble_ae_data.data_len)")
    if remain_data:
        text = text.replace(
            "memcpy(ble_ae_data.data, data, ble_ae_data.data_len);",
            "memcpy(ble_ae_data.data, adv, ble_ae_data.data_len);",
        )
        changed.append(
            f"app.c: remaining AE payloads use adv[] ({remain_data} site(s))"
        )

    new_text, n_set2 = re.subn(
        r"ble_ae_params\.adv_event_prop\s*=\s*0x01\s*;\s*//Connectable;",
        "ble_ae_params.adv_event_prop            = BLE_AE_ADV_EVNT_PROP;",
        text,
        count=1,
    )
    if n_set2:
        text = new_text
        changed.append("app.c: SET2 uses BLE_AE_ADV_EVNT_PROP (not connectable-only)")

    if changed:
        app_c.write_text(text, encoding="utf-8")
        job.append("=== UTF patches (ble_ae_peripheral) ===")
        for line in changed:
            job.append(f"  {line}")


def _collect_artifacts(out_dir: Path) -> List[dict]:
    if not out_dir.is_dir():
        return []
    artifacts = []
    for ext in (".rps", ".hex", ".s37", ".bin", ".out", ".map"):
        for f in sorted(out_dir.glob(f"*{ext}")):
            artifacts.append({
                "name": f.name,
                "path": str(f),
                "size": f.stat().st_size,
                "ext": ext,
            })
    return artifacts


FLASHABLE_EXTENSIONS = (".rps", ".hex", ".s37", ".bin")


def _suggest_serial_port() -> Optional[str]:
    """Best-effort VCOM hint; pyserial may be absent or no port attached."""
    try:
        return guess_vcom_port()
    except Exception:
        return None


def _commander_env(toolchain: str = "gcc") -> dict:
    return build_env(toolchain, refresh=True)


def _commander_cmd(
    *args: str,
    adapter_serial: Optional[str] = None,
    toolchain: str = "gcc",
) -> tuple:
    commander = find_commander()
    if not commander:
        raise RuntimeError("Simplicity Commander not found")
    cmd = [str(commander), *args]
    if adapter_serial:
        cmd.extend(["--serialno", adapter_serial])
    return cmd, _commander_env(toolchain)


def _run_commander(
    *args: str,
    adapter_serial: Optional[str] = None,
    toolchain: str = "gcc",
) -> dict:
    cmd, env = _commander_cmd(*args, adapter_serial=adapter_serial, toolchain=toolchain)
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    output = (result.stdout or "") + (result.stderr or "")
    return {
        "command": " ".join(cmd),
        "output": output,
        "returncode": result.returncode,
        "success": result.returncode == 0,
    }


def _is_connection_error(output: str) -> bool:
    text = output.lower()
    return any(
        phrase in text
        for phrase in (
            "could not connect",
            "could not connect to target",
            "could not connect debugger",
            "no emulator found",
        )
    )


def device_info(adapter_serial: Optional[str] = None, toolchain: str = "gcc") -> dict:
    result = _run_commander(
        "device", "info",
        adapter_serial=adapter_serial,
        toolchain=toolchain,
    )
    if not result["success"]:
        raise RuntimeError(f"device info failed:\n{result['output']}")
    return result


def device_recover(adapter_serial: Optional[str] = None, toolchain: str = "gcc") -> dict:
    result = _run_commander(
        "device", "recover",
        adapter_serial=adapter_serial,
        toolchain=toolchain,
    )
    if not result["success"]:
        raise RuntimeError(f"device recover failed:\n{result['output']}")
    return result


def check_device(adapter_serial: Optional[str] = None, toolchain: str = "gcc") -> dict:
    """Non-throwing device availability check."""
    result = _run_commander(
        "device", "info",
        adapter_serial=adapter_serial,
        toolchain=toolchain,
    )
    return {
        "available": result["success"],
        "output": result["output"],
        "error": None if result["success"] else result["output"],
    }


def ensure_device_ready(
    adapter_serial: Optional[str] = None,
    toolchain: str = "gcc",
    job: Optional[BuildJob] = None,
) -> dict:
    """Check device; run recover once if unavailable, then re-check."""
    def log(msg: str) -> None:
        if job:
            job.append(msg)

    log("=== Checking device before flash ===")
    info = check_device(adapter_serial=adapter_serial, toolchain=toolchain)
    if info["available"]:
        log("Device is available")
        return info

    log("Device not available — running commander device recover (once)…")
    log(info.get("error") or info.get("output") or "")
    recover = _run_commander(
        "device", "recover",
        adapter_serial=adapter_serial,
        toolchain=toolchain,
    )
    log(recover["output"])
    if not recover["success"]:
        raise RuntimeError(f"Device recover failed:\n{recover['output']}")

    info = check_device(adapter_serial=adapter_serial, toolchain=toolchain)
    if not info["available"]:
        raise RuntimeError(
            "Device still not available after recover:\n"
            + (info.get("error") or info.get("output") or "")
        )
    log("Device recovered and is now available")
    return info


def _flash_file(
    artifacts: List[dict],
    target: str,
    artifact_path: Optional[str] = None,
) -> Optional[str]:
    if artifact_path:
        path = Path(artifact_path)
        if path.is_file():
            return str(path)
        raise FileNotFoundError(f"Selected artifact not found: {artifact_path}")

    flashable = [a for a in artifacts if a["ext"] in FLASHABLE_EXTENSIONS]
    if not flashable:
        return None

    # Prefer .rps for SoC, .hex for NCP, then any flashable
    preferred = [".rps", ".hex"] if target == "soc" else [".hex", ".s37"]
    for ext in preferred:
        for a in flashable:
            if a["ext"] == ext:
                return a["path"]
    return flashable[0]["path"]


def run_build(
    app_id: str,
    target: str,
    board: str,
    toolchain: str,
    sdk_root: str,
    ble_root: Optional[str] = None,
    flash_after: bool = False,
    adapter_serial: Optional[str] = None,
    artifact_path: Optional[str] = None,
    mqtt_broker_ip: Optional[str] = None,
    aws_mqtt_port: Optional[int] = None,
    aws_endpoint: Optional[str] = None,
) -> str:
    job_id = str(uuid.uuid4())[:8]
    job = BuildJob(
        id=job_id,
        config={
            "app_id": app_id,
            "target": target,
            "board": board,
            "toolchain": toolchain,
            "sdk_root": sdk_root,
            "flash_after": flash_after,
            "adapter_serial": adapter_serial,
            "artifact_path": artifact_path,
            "mqtt_broker_ip": mqtt_broker_ip,
            "aws_mqtt_port": aws_mqtt_port,
            "aws_endpoint": aws_endpoint,
        },
    )
    with _lock:
        _jobs[job_id] = job

    thread = threading.Thread(
        target=_build_worker,
        args=(job, app_id, target, board, toolchain, sdk_root, ble_root),
        kwargs={
            "flash_after": flash_after,
            "adapter_serial": adapter_serial,
            "artifact_path": artifact_path,
            "mqtt_broker_ip": mqtt_broker_ip,
            "aws_mqtt_port": aws_mqtt_port,
            "aws_endpoint": aws_endpoint,
        },
        daemon=True,
    )
    thread.start()
    return job_id


def _build_worker(
    job: BuildJob,
    app_id: str,
    target: str,
    board: str,
    toolchain: str,
    sdk_root: str,
    ble_root: Optional[str],
    flash_after: bool = False,
    adapter_serial: Optional[str] = None,
    artifact_path: Optional[str] = None,
    mqtt_broker_ip: Optional[str] = None,
    aws_mqtt_port: Optional[int] = None,
    aws_endpoint: Optional[str] = None,
) -> None:
    try:
        job.status = "running"
        job.phase = "build"
        sdk = validate_local_sdk(Path(sdk_root))
        selected_wiseconnect = _wiseconnect_root_from_examples(ble_root)
        if selected_wiseconnect:
            sdk = sdk_info(Path(sdk["sdk_root"]), selected_wiseconnect)
            job.append(
                "Using WiSeConnect extension from selected examples root: "
                f"{selected_wiseconnect}"
            )
        source_slcp = resolve_slcp(
            app_id, target, Path(ble_root) if ble_root else None
        )
        example_dir = source_slcp.parent
        slcp = source_slcp
        if _is_coex_examples_root(ble_root):
            example_dir = _stage_coex_project(
                example_dir, app_id, target, toolchain, job
            )
            slcp = example_dir / source_slcp.name
            _enable_info_logging(slcp, job)
            if app_id == "out_of_box_demo":
                _patch_oob_ble_self_identity(example_dir, job)
            if mqtt_broker_ip:
                _point_mqtt_at_broker(example_dir, mqtt_broker_ip, job)

        tools = discover_tools(refresh=True)
        for line in env_summary(toolchain):
            job.append(line)

        missing = tools.missing(toolchain)
        if missing:
            raise RuntimeError(
                f"Missing build tools: {', '.join(missing)}. "
                "Install them with 'slt install pkg.slt' (see README) or put them on PATH."
            )
        slc, cmake = tools.slc, tools.cmake

        if app_id == "ble_ae_peripheral":
            job.append("=== Apply UTF source patches (ble_ae_peripheral) ===")
            _patch_ble_ae_peripheral_sources(example_dir, job)

        is_llvm = toolchain == "llvm_lto"
        is_gcc_lto = toolchain == "gcc_lto"
        output_dir = f"output_{target}_{toolchain}"
        cmake_sub = "cmake_llvm" if is_llvm else "cmake_gcc"

        with_parts = [board]
        if is_llvm:
            with_parts += ["toolchain_llvm", "toolchain_llvm_lto"]

        slc_cmd = [
            str(slc), "generate",
            f"--sdk-package-path={sdk['sdk_package_path']}",
            "--with", ",".join(with_parts),
        ]
        if is_llvm:
            slc_cmd.append("-tlcn=llvm")
        slc_cmd += [str(slcp.name), "-d", output_dir]

        env = build_env(toolchain, refresh=True)
        if is_gcc_lto:
            job.append("GCC LTO enabled via -flto compile/link flags")
        job.append("=== Trust SDK (signature) ===")
        _run_logged([
            str(slc), "signature", "trust",
            f"--sdk-package-path={sdk['sdk_package_path']}",
        ], example_dir, env, job)

        job.append("=== SLC Generate ===")
        _run_logged(slc_cmd, example_dir, env, job)

        if aws_mqtt_port or aws_endpoint:
            _configure_aws_iot(
                example_dir / output_dir, aws_mqtt_port, aws_endpoint, job
            )

        cmake_dir = example_dir / output_dir / cmake_sub
        if not cmake_dir.is_dir():
            raise FileNotFoundError(f"CMake project not found: {cmake_dir}")

        job.append("=== Normalize include paths ===")
        _collapse_include_paths(cmake_dir, job)

        job.append("=== CMake Build ===")
        _run_logged([str(cmake), "--workflow", "--preset", "project"], cmake_dir, env, job)

        out_dir = _cmake_output_dir(cmake_dir)
        job.artifacts = _collect_artifacts(out_dir)
        job.append(f"=== Build complete ({len(job.artifacts)} artifacts) ===")

        if flash_after:
            job.phase = "flash"
            job.append("=== Starting flash phase ===")
            flash_result = _flash_with_device_check(
                job,
                target=target,
                toolchain=toolchain,
                adapter_serial=adapter_serial,
                artifact_path=artifact_path,
            )
            job.flash_output = flash_result.get("output")
            job.serial_port = flash_result.get("serial_port")
            job.phase = "serial"
            job.append("=== Flash complete — open serial console for DUT logs ===")

        job.status = "success"
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.append(f"ERROR: {exc}")
    finally:
        job.finished_at = time.time()


def _flash_with_device_check(
    job: BuildJob,
    target: str,
    toolchain: str,
    adapter_serial: Optional[str] = None,
    artifact_path: Optional[str] = None,
) -> dict:
    ensure_device_ready(adapter_serial=adapter_serial, toolchain=toolchain, job=job)

    flash_path = _flash_file(job.artifacts, target, artifact_path)
    if not flash_path:
        raise FileNotFoundError("No flashable image in build artifacts")

    cmd, env = _commander_cmd("flash", flash_path, adapter_serial=adapter_serial, toolchain=toolchain)
    job.append(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    output = (result.stdout or "") + (result.stderr or "")

    if result.returncode != 0:
        raise RuntimeError(f"Flash failed:\n{output}")

    job.append(output)
    serial_port = _suggest_serial_port()
    if serial_port:
        job.append(f"Suggested serial port: {serial_port}")
        try:
            started = start_serial(
                serial_port, DEFAULT_BAUD, label=job.config.get("app_id")
            )
            job.append(f"=== DUT serial listening on {serial_port} @ {DEFAULT_BAUD} ===")
            if started.get("log_path"):
                job.append(f"=== DUT serial log file: {started['log_path']} ===")
        except Exception as exc:
            job.append(f"WARNING: Could not open serial {serial_port}: {exc}")

    return {"flashed": flash_path, "output": output, "serial_port": serial_port}


def flash_build(
    job_id: str,
    adapter_serial: Optional[str] = None,
    artifact_path: Optional[str] = None,
    auto_recover: bool = False,
) -> dict:
    job = get_job(job_id)
    if not job:
        raise FileNotFoundError("Build job not found")
    if job.status != "success":
        raise RuntimeError("Build did not succeed")

    target = job.config.get("target", "soc")
    toolchain = job.config.get("toolchain", "gcc")

    if auto_recover:
        return _flash_with_device_check(
            job,
            target=target,
            toolchain=toolchain,
            adapter_serial=adapter_serial,
            artifact_path=artifact_path,
        )

    flash_path = _flash_file(job.artifacts, target, artifact_path)
    if not flash_path:
        raise FileNotFoundError("No flashable image in build artifacts")

    cmd, env = _commander_cmd("flash", flash_path, adapter_serial=adapter_serial, toolchain=toolchain)
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    output = (result.stdout or "") + (result.stderr or "")

    if result.returncode != 0:
        hint = ""
        if _is_connection_error(output):
            hint = (
                "\n\nTip: Connect the debug adapter, then run "
                "'commander device recover' and 'commander device info', "
                "or use Build & Flash with auto-recover."
            )
        raise RuntimeError(f"Flash failed:\n{output}{hint}")
    return {
        "flashed": flash_path,
        "output": output,
        "serial_port": _suggest_serial_port(),
    }


def list_adapters() -> dict:
    result = _run_commander("adapter", "list")
    text = result["output"]
    adapters = []

    # Format A: "0: J-Link ..."
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"(\d+):\s*(.+)", line)
        if m:
            info = m.group(2).strip()
            serial_match = re.search(r"serial[:\s]+(\S+)", info, re.I)
            adapters.append({
                "index": int(m.group(1)),
                "info": info,
                "serial": serial_match.group(1) if serial_match else None,
            })

    # Format B: structured device(...) block
    if not adapters:
        serial = re.search(r"serialNumber=(\d+)", text)
        nickname = re.search(r"adapterNickname=(\S*)", text)
        name = re.search(r"adapterName=([^\n]+)", text)
        board = re.search(r"boardName\[1\]=([^\n]+)", text) or re.search(r"boardName\[0\]=([^\n]+)", text)
        if serial:
            adapters.append({
                "index": 0,
                "info": " | ".join(filter(None, [
                    name.group(1).strip() if name else None,
                    board.group(1).strip() if board else None,
                    nickname.group(1).strip() if nickname and nickname.group(1) else None,
                ])),
                "serial": serial.group(1),
            })

    count_match = re.search(r"deviceCount=(\d+)", text)
    return {
        "adapters": adapters,
        "device_count": int(count_match.group(1)) if count_match else len(adapters),
        "raw": text,
    }
