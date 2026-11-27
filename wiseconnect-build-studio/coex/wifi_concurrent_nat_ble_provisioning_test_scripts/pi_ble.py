#!/usr/bin/env python3
"""Run BLE Wi-Fi commissioning on a Raspberry Pi over SSH.

The Windows test host usually has no usable Bluetooth radio, so the BLE
central role is delegated to the lab Pi: this module prepares the Pi
(workdir, bleak, BlueZ access), uploads the provisioner, runs it, and
returns the parsed result.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Dict, Optional

HERE = Path(__file__).resolve().parent
DEPLOY_FILES = ("ble_protocol.py", "pi_ble_provisioner.py")
# Buster ships Python 3.7; bleak 0.19 is the last line whose dependencies are
# pure Python, so it installs without a compiler or modern manylinux wheels.
BLEAK_SPEC = "bleak>=0.19,<0.20"
HCI_LOCK = "/tmp/wcbs_hci0.lock"
HCI_LOCK_BUSY = 75
WORKDIR_CANDIDATES = (
    "/var/tmp/wcbs_coex_ble",
    "/tmp/wcbs_coex_ble",
    "~/wcbs_coex_ble",
)


def log(message: str) -> None:
    print(f"[pi] {message}", flush=True)


def _connect(pi: Dict[str, Any]):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError(
            "Pi BLE provisioning needs paramiko; run: pip install -r requirements.txt"
        ) from exc

    host = str(pi.get("host") or "").strip()
    if not host:
        raise ValueError("pi.host is required for BLE provisioning over SSH")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username = str(pi.get("username") or "pi")
    port = int(pi.get("port", 22))
    log(f"Connecting {username}@{host}:{port} ...")
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=str(pi.get("password") or ""),
        timeout=float(pi.get("connect_timeout_s", 30)),
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def _run(client, command: str, timeout: int = 120) -> tuple:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _sudo_prefix(pi: Dict[str, Any]) -> str:
    password = str(pi.get("password") or "")
    if password:
        return f"echo {shlex.quote(password)} | sudo -S -p '' -E "
    return "sudo -n -E "


def _stream(client, command: str, timeout: int, prefix: str = "pi") -> int:
    """Run a command and echo its output as it arrives."""
    _stdin, stdout, stderr = client.exec_command(
        command, timeout=timeout, get_pty=True
    )
    for raw in iter(stdout.readline, ""):
        line = raw.rstrip("\r\n")
        if line:
            print(f"[{prefix}] {line}" if not line.startswith("[pi-ble]") else line, flush=True)
    code = stdout.channel.recv_exit_status()
    tail = stderr.read().decode("utf-8", errors="replace").strip()
    if tail:
        print(f"[{prefix}] {tail}", flush=True)
    return code


def _resolve_workdir(client, preferred: Optional[str]) -> str:
    candidates = [preferred] if preferred else []
    candidates += [path for path in WORKDIR_CANDIDATES if path != preferred]
    for path in candidates:
        probe = shlex.quote(path)
        code, out, _err = _run(
            client,
            f"mkdir -p {probe} 2>/dev/null && test -w {probe} && "
            f"touch {probe}/.wcbs_write_test && rm -f {probe}/.wcbs_write_test && "
            f"cd {probe} && pwd",
            timeout=30,
        )
        if code == 0 and out.strip():
            resolved = out.strip().splitlines()[-1].strip()
            log(f"Using workdir {resolved}")
            return resolved
    raise RuntimeError(
        "No writable directory on the Pi. Set pi.remote_workdir to a writable "
        "path, or run: sudo mount -o remount,rw / && sudo chmod 1777 /tmp"
    )


def _ensure_bleak(client, workdir: str) -> str:
    """Return the Python on the Pi that can import bleak, installing if needed."""
    # bleak 0.19 exposes no __version__, so probe the import itself.
    probe = "import bleak; print(getattr(bleak, '__version__', 'installed'))"
    venv_python = f"{workdir}/.venv/bin/python"
    for candidate in (venv_python, "python3"):
        code, out, _err = _run(
            client,
            f"{shlex.quote(candidate)} -c {shlex.quote(probe)} 2>/dev/null",
            timeout=60,
        )
        if code == 0:
            log(f"bleak {out.strip()} available via {candidate}")
            return candidate

    log(f"Installing {BLEAK_SPEC} into {workdir}/.venv (first run only, few minutes)...")
    venv = shlex.quote(f"{workdir}/.venv")
    python = shlex.quote(venv_python)
    code = _stream(
        client,
        f"rm -rf {venv} && python3 -m venv {venv} && "
        # pip 18 on Buster cannot read modern wheel tags; refresh it first.
        f"{python} -m pip install --upgrade 'pip<24.1' setuptools wheel && "
        f"{python} -m pip install {shlex.quote(BLEAK_SPEC)}",
        timeout=1800,
        prefix="pi-pip",
    )
    if code != 0:
        raise RuntimeError(f"Failed to install bleak on the Pi (exit {code})")
    code, out, err = _run(client, f"{python} -c {shlex.quote(probe)}", timeout=60)
    if code != 0:
        raise RuntimeError(f"bleak installed but import failed: {err or out}")
    log(f"bleak {out.strip()} installed")
    return venv_python


def _ensure_bluetooth(client, pi: Dict[str, Any]) -> bool:
    """Restart BlueZ and reset hci0 before the Bleak process is launched."""
    sudo = _sudo_prefix(pi)
    setup_body = (
            "rfkill unblock bluetooth >/dev/null 2>&1 || true; "
            "systemctl unmask bluetooth >/dev/null 2>&1 || true; "
            "systemctl restart bluetooth || true; "
            # Lab Pis mount / read-only, so a masked unit cannot be unmasked;
            # start bluetoothd directly so org.bluez is owned on the system bus.
            "if ! pgrep -x bluetoothd >/dev/null; then "
            "  setsid nohup /usr/lib/bluetooth/bluetoothd -E -P battery "
            "  >/var/tmp/wcbs_bluetoothd.log 2>&1 </dev/null & "
            "fi; "
            "sleep 3; "
            "bluetoothctl scan off >/dev/null 2>&1 || true; "
            "hciconfig hci0 down >/dev/null 2>&1 || true; "
            "sleep 1; "
            "hciconfig hci0 up || true; "
            "bluetoothctl power on >/dev/null 2>&1 || true"
    )
    locked_setup = (
        f"flock -E {HCI_LOCK_BUSY} -n {shlex.quote(HCI_LOCK)} "
        f"bash -lc {shlex.quote(setup_body)}"
    )
    setup = (
        f"{sudo}bash -lc "
        + shlex.quote(locked_setup)
    )
    code, _out, _err = _run(client, setup, timeout=60)
    if code == HCI_LOCK_BUSY:
        raise RuntimeError(
            "Pi hci0 is already in use by another BLE test; "
            "controller reset was not performed"
        )
    code, out, _err = _run(client, "hciconfig hci0 2>/dev/null | head -n 3", timeout=30)
    if code != 0 or "UP" not in out:
        raise RuntimeError(
            "Bluetooth adapter hci0 is not up on the Pi. Check: "
            "sudo systemctl start bluetooth && sudo hciconfig hci0 up\n"
            f"{out.strip()}"
        )
    power_probe = (
        "for i in 1 2 3 4 5; do "
        "bluetoothctl show 2>/dev/null | grep -qi 'Powered: yes' && exit 0; "
        "bluetoothctl power on >/dev/null 2>&1 || true; sleep 1; "
        "done; exit 1"
    )
    code, _out, _err = _run(
        client,
        f"{sudo}bash -lc {shlex.quote(power_probe)}",
        timeout=30,
    )
    if code == 0:
        log("BlueZ restarted; hci0 is UP and Powered: yes")
    else:
        log("hci0 is UP; bluetoothctl power state unavailable, continuing to Bleak")

    if bool(pi.get("ble_use_sudo", False)):
        return True
    code, out, err = _run(
        client,
        "dbus-send --system --dest=org.bluez --print-reply / "
        "org.freedesktop.DBus.ObjectManager.GetManagedObjects 2>&1 | head -n 3",
        timeout=30,
    )
    text = (out or "") + (err or "")
    if "AccessDenied" in text or "Rejected send message" in text:
        log("BlueZ D-Bus denies this user — running the provisioner with sudo")
        return True
    log("BlueZ D-Bus access OK for this user")
    return False


def _deploy(client, workdir: str, payload: Dict[str, Any]) -> None:
    sftp = client.open_sftp()
    try:
        for name in DEPLOY_FILES:
            local = HERE / name
            if not local.is_file():
                raise FileNotFoundError(f"Missing script to deploy: {local}")
            sftp.put(str(local), f"{workdir}/{name}")
            log(f"Deployed {name}")
        with sftp.file(f"{workdir}/provision_config.json", "w") as handle:
            handle.write(json.dumps(payload, indent=2))
    finally:
        sftp.close()


def _read_result(client, path: str) -> Dict[str, Any]:
    sftp = client.open_sftp()
    try:
        with sftp.file(path, "r") as handle:
            return json.loads(handle.read().decode("utf-8"))
    finally:
        sftp.close()


def probe_tcp_from_pi(pi: Dict[str, Any], host: str, port: int) -> bool:
    """Check from the lab network whether host:port accepts connections."""
    client = _connect(pi)
    try:
        script = (
            "import socket,sys\n"
            "s=socket.socket(); s.settimeout(6)\n"
            "try:\n"
            f"    s.connect(('{host}', {port})); print('OPEN')\n"
            "except Exception as exc:\n"
            "    print('CLOSED', exc)\n"
        )
        code, out, _err = _run(
            client, f"python3 -c {shlex.quote(script)}", timeout=60
        )
        return code == 0 and "OPEN" in out
    finally:
        client.close()


def provision_via_pi(config: Dict[str, Any]) -> Dict[str, Any]:
    """Provision the DUT over BLE using the Pi as the BLE central."""
    pi = config.get("pi") or {}
    ble = config["ble"]
    payload = {"ble": ble, "wifi": config["wifi"]}

    client = _connect(pi)
    try:
        workdir = _resolve_workdir(client, pi.get("remote_workdir"))
        python = _ensure_bleak(client, workdir)
        use_sudo = _ensure_bluetooth(client, pi)
        _deploy(client, workdir, payload)

        result_path = f"{workdir}/provision_result.json"
        inner = (
            f"cd {shlex.quote(workdir)} && {shlex.quote(python)} pi_ble_provisioner.py "
            f"--config provision_config.json --result provision_result.json"
        )
        locked_inner = (
            f"flock -E {HCI_LOCK_BUSY} -n {shlex.quote(HCI_LOCK)} "
            f"bash -lc {shlex.quote(inner)}"
        )
        def remote_command() -> str:
            if use_sudo:
                password = str(pi.get("password") or "")
                return (
                    f"echo {shlex.quote(password)} | sudo -S -E bash -lc "
                    f"{shlex.quote(locked_inner)}"
                    if password
                    else f"sudo -n -E bash -lc {shlex.quote(locked_inner)}"
                )
            return f"bash -lc {shlex.quote(locked_inner)}"

        timeout = int(
            float(ble.get("scan_timeout_s", 30)) * int(ble.get("ssid_scan_retries", 5))
            + float(ble.get("connect_timeout_s", 75))
            + float(ble.get("ble_join_poll_s", 20))
            + 180
        )
        code = 1
        result: Dict[str, Any] = {}
        for cycle in range(1, 3):
            _run(client, f"rm -f {shlex.quote(result_path)}", timeout=30)
            log(f"Starting BLE provisioning on the Pi (controller cycle {cycle}/2)...")
            code = _stream(client, remote_command(), timeout=timeout)
            if code == HCI_LOCK_BUSY:
                raise RuntimeError(
                    "Pi hci0 is already in use by another BLE test; "
                    "wait for that test to finish"
                )
            try:
                result = _read_result(client, result_path)
            except Exception:  # noqa: BLE001
                result = {"ok": False, "error": "Provisioner left no result file"}
            if code == 0 and result.get("ok"):
                break
            error = str(result.get("error") or "").lower()
            recoverable = any(
                marker in error
                for marker in (
                    "software caused connection abort",
                    "ble connect failed",
                    "failed to discover services",
                    "device disconnected",
                )
            )
            if cycle == 1 and recoverable:
                log("BLE link setup failed; performing one full BlueZ/hci0 recovery")
                use_sudo = _ensure_bluetooth(client, pi)
                continue
            break

        if not result:
            raise RuntimeError(
                f"Pi provisioner exited with {code} and left no result file"
            )
        result["exit_code"] = code
        result["backend"] = "pi"
        result["pi_host"] = pi.get("host")
        if not result.get("ok"):
            raise RuntimeError(
                result.get("error") or f"Pi BLE provisioning failed (exit {code})"
            )
        return result
    finally:
        client.close()
