#!/usr/bin/env python3
"""Connect the lab Pi to the DUT SI_COEX_MAX_DEMO advertiser over SSH."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Dict, Optional

HERE = Path(__file__).resolve().parent
PROVISION_WORKDIR = "/var/tmp/wcbs_coex_ble"
BLEAK_SPEC = "bleak>=0.19,<0.20"


def log(message: str) -> None:
    print(f"[pi] {message}", flush=True)


def _connect(pi: Dict[str, Any]):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError(
            "Pi BLE needs paramiko; run: pip install -r requirements.txt"
        ) from exc

    host = str(pi.get("host") or "").strip()
    if not host:
        raise ValueError("pi.host is required for BLE connect")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=int(pi.get("port", 22)),
        username=str(pi.get("username") or "pi"),
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


def _stream(client, command: str, timeout: int) -> int:
    _stdin, stdout, stderr = client.exec_command(
        command, timeout=timeout, get_pty=True
    )
    for raw in iter(stdout.readline, ""):
        line = raw.rstrip("\r\n")
        if line:
            print(line if line.startswith("[pi-ble]") else f"[pi] {line}", flush=True)
    return stdout.channel.recv_exit_status()


def _sudo_prefix(pi: Dict[str, Any]) -> str:
    password = str(pi.get("password") or "")
    if password:
        return f"echo {shlex.quote(password)} | sudo -S -E "
    return "sudo -n -E "


def _ensure_bluetooth(client, pi: Dict[str, Any]) -> bool:
    sudo = _sudo_prefix(pi)
    username = str(pi.get("username") or "pi")
    setup = (
        f"{sudo}bash -lc "
        + shlex.quote(
            "systemctl unmask bluetooth >/dev/null 2>&1 || true; "
            "unit=''; "
            "for p in /lib/systemd/system/bluetooth.service "
            "/usr/lib/systemd/system/bluetooth.service; do "
            "  [ -f \"$p\" ] && unit=\"$p\" && break; "
            "done; "
            "if [ -n \"$unit\" ]; then "
            "  ln -sfn \"$unit\" /etc/systemd/system/dbus-org.bluez.service; "
            "  systemctl daemon-reload; "
            "fi; "
            "systemctl start bluetooth || true; "
            "systemctl start dbus-org.bluez.service || true; "
            # Lab Pis mount / read-only, so a masked unit cannot be unmasked;
            # start bluetoothd directly so org.bluez is owned on the system bus.
            "if ! pgrep -x bluetoothd >/dev/null; then "
            "  setsid nohup /usr/lib/bluetooth/bluetoothd -E -P battery "
            "  >/var/tmp/wcbs_bluetoothd.log 2>&1 </dev/null & sleep 2; "
            "fi; "
            f"usermod -aG bluetooth,netdev {shlex.quote(username)} || true; "
            "hciconfig hci0 up || true"
        )
    )
    _run(client, setup, timeout=60)
    code, out, _err = _run(client, "hciconfig hci0 2>/dev/null | head -n 3", timeout=30)
    if code != 0 or "UP" not in out:
        raise RuntimeError(f"Bluetooth adapter hci0 is not up on the Pi\n{out.strip()}")
    log("hci0 is up")
    return True


LE_DEBUGFS = "/sys/kernel/debug/bluetooth/hci0"


def _write_le_link(client, pi: Dict[str, Any], values: Optional[tuple]) -> Optional[tuple]:
    """Write (min_interval, max_interval, supervision) when given; return what is set."""
    base = LE_DEBUGFS
    script = ""
    if values:
        low, high, supervision = values
        # min, max, min again so the kernel's min <= max check passes whether
        # the window grows or shrinks.
        script = (
            f"echo {low} > {base}/conn_min_interval; "
            f"echo {high} > {base}/conn_max_interval; "
            f"echo {low} > {base}/conn_min_interval; "
            f"echo {supervision} > {base}/supervision_timeout; "
        )
    script += (
        f"cat {base}/conn_min_interval {base}/conn_max_interval {base}/supervision_timeout"
    )
    _code, out, _err = _run(
        client, f"{_sudo_prefix(pi)}bash -c {shlex.quote(script)}", timeout=30
    )
    numbers = [int(line.strip()) for line in out.splitlines() if line.strip().isdigit()]
    return tuple(numbers[-3:]) if len(numbers) >= 3 else None


def _tune_le_link(client, pi: Dict[str, Any], ble: Dict[str, Any]) -> Optional[tuple]:
    """Widen the Pi LE link window; return the original values for restore.

    BlueZ defaults (30-50 ms interval, 420 ms supervision) leave the DUT too
    few radio slots to answer while Wi-Fi downloads share its radio, so the
    link aborts or times out.
    """
    original = _write_le_link(client, pi, None)
    wanted = (
        int(ble.get("conn_min_interval_1_25ms", 80)),
        int(ble.get("conn_max_interval_1_25ms", 120)),
        int(ble.get("supervision_timeout_10ms", 400)),
    )
    applied = _write_le_link(client, pi, wanted)
    if applied == wanted:
        log(
            f"LE link: interval {wanted[0] * 1.25:.0f}-{wanted[1] * 1.25:.0f} ms, "
            f"supervision {wanted[2] * 10} ms"
        )
    else:
        log(f"LE link parameters not applied (now {applied})")
    return original


def _python_with_bleak(client, pi: Dict[str, Any], workdir: str) -> str:
    probe = "import bleak; print(getattr(bleak, '__version__', 'installed'))"
    candidates = (
        f"{PROVISION_WORKDIR}/.venv/bin/python",
        f"{workdir}/.venv/bin/python",
        "python3",
    )
    for candidate in candidates:
        code, out, _err = _run(
            client, f"{shlex.quote(candidate)} -c {shlex.quote(probe)} 2>/dev/null", 60
        )
        if code == 0:
            log(f"bleak {out.strip()} via {candidate}")
            return candidate
    venv_python = f"{workdir}/.venv/bin/python"
    log(f"Installing {BLEAK_SPEC} into {workdir}/.venv ...")
    code = _stream(
        client,
        f"python3 -m venv {shlex.quote(workdir + '/.venv')} && "
        f"{shlex.quote(venv_python)} -m pip install --upgrade 'pip<24.1' setuptools wheel && "
        f"{shlex.quote(venv_python)} -m pip install {shlex.quote(BLEAK_SPEC)}",
        timeout=1800,
    )
    if code != 0:
        raise RuntimeError("Failed to install bleak on the Pi")
    return venv_python


def connect_dut_advertiser(config: Dict[str, Any]) -> Dict[str, Any]:
    """Scan for SI_COEX_MAX_DEMO and connect from the Pi (DUT peripheral)."""
    pi = config.get("pi") or {}
    ble = config.get("ble") or {}
    name = str(ble.get("device_name") or "SI_COEX_MAX_DEMO")
    address = str(ble.get("address") or "").strip()
    scan_s = float(ble.get("scan_timeout_s", 30))
    connect_s = float(ble.get("connect_timeout_s", 75))
    hold_s = float(ble.get("hold_s", 8))
    retries = int(ble.get("connect_retries", 5))
    retry_delay = float(ble.get("retry_delay_s", 4))
    settle = float(ble.get("pre_connect_delay_s", 3))
    workdir = str(pi.get("remote_workdir") or PROVISION_WORKDIR)

    client = _connect(pi)
    original_link: Optional[tuple] = None
    try:
        _run(client, f"mkdir -p {shlex.quote(workdir)}", timeout=15)
        _ensure_bluetooth(client, pi)
        original_link = _tune_le_link(client, pi, ble)
        python = _python_with_bleak(client, pi, workdir)
        sftp = client.open_sftp()
        try:
            sftp.put(str(HERE / "pi_ble_connect.py"), f"{workdir}/pi_ble_connect.py")
        finally:
            sftp.close()
        extra_addr = f" --address {shlex.quote(address)}" if address else ""
        inner = (
            f"cd {shlex.quote(workdir)} && {shlex.quote(python)} pi_ble_connect.py "
            f"--name {shlex.quote(name)}{extra_addr} "
            f"--scan-timeout {scan_s} --connect-timeout {connect_s} "
            f"--hold {hold_s} --retries {retries} "
            f"--retry-delay {retry_delay} --settle {settle}"
        )
        password = str(pi.get("password") or "")
        command = (
            f"echo {shlex.quote(password)} | sudo -S -E bash -lc {shlex.quote(inner)}"
            if password
            else f"sudo -n -E bash -lc {shlex.quote(inner)}"
        )
        log(f"Connecting Pi BLE central to {name!r} (scan stays on, {retries} retries)...")
        code = _stream(
            client,
            command,
            timeout=int(
                retries * (scan_s + connect_s + retry_delay) + hold_s + 90
            ),
        )
        if code != 0:
            raise RuntimeError(f"Pi BLE connect to {name!r} failed (exit {code})")
        return {"ok": True, "device_name": name}
    finally:
        if original_link:
            try:
                _write_le_link(client, pi, original_link)
            except Exception as exc:  # noqa: BLE001
                log(f"LE link restore note: {exc}")
        client.close()
