#!/usr/bin/env python3
"""Deploy and run a unified-coex BLE peer on a Raspberry Pi over SSH."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).resolve().parent
HCI_LOCK = "/tmp/wcbs_hci0.lock"
HCI_LOCK_BUSY = 75


def log(label: str, message: str) -> None:
    print(f"[{label}] {message}", flush=True)


def _connect(peer: Dict[str, Any]):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("Pi BLE needs paramiko; install requirements.txt") from exc
    host = str(peer.get("host") or "").strip()
    if not host:
        raise ValueError("BLE peer host is required")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=int(peer.get("port", 22)),
        username=str(peer.get("username") or "pi"),
        password=str(peer.get("password") or ""),
        timeout=30,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def _run(client, command: str, timeout: int = 60):
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), out, err


def _stream(client, command: str, label: str, timeout: int) -> int:
    _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout, get_pty=True)
    for raw in iter(stdout.readline, ""):
        line = raw.rstrip("\r\n")
        if line:
            print(line if line.startswith("[pi-ble]") else f"[{label}] {line}", flush=True)
    return stdout.channel.recv_exit_status()


def _sudo(peer: Dict[str, Any]) -> str:
    password = str(peer.get("password") or "")
    return (
        f"echo {shlex.quote(password)} | sudo -S -E "
        if password
        else "sudo -n -E "
    )


def _reset_controller(client, peer: Dict[str, Any], label: str) -> None:
    body = (
        "rfkill unblock bluetooth >/dev/null 2>&1 || true; "
        "systemctl restart bluetooth; sleep 3; "
        "bluetoothctl scan off >/dev/null 2>&1 || true; "
        "hciconfig hci0 down >/dev/null 2>&1 || true; sleep 1; "
        "hciconfig hci0 up; bluetoothctl power on >/dev/null 2>&1 || true; "
        "bluetoothctl agent NoInputNoOutput >/dev/null 2>&1 || true; "
        "bluetoothctl default-agent >/dev/null 2>&1 || true"
    )
    locked = f"flock -E {HCI_LOCK_BUSY} -n {HCI_LOCK} bash -lc {shlex.quote(body)}"
    code, out, err = _run(client, _sudo(peer) + "bash -lc " + shlex.quote(locked), 60)
    if code == HCI_LOCK_BUSY:
        raise RuntimeError(f"{label}: hci0 is in use by another test")
    if code != 0:
        raise RuntimeError(f"{label}: Bluetooth reset failed: {(err or out).strip()}")
    log(label, "BlueZ restarted; hci0 is ready")


def run_peer(
    config: Dict[str, Any], *, section: str, mode: str, name: str, label: str
) -> Dict[str, Any]:
    peer = config.get(section) or {}
    ble = config.get("ble") or {}
    hold = max(60.0, float(ble.get("hold_s", 180)))
    connect_timeout = float(ble.get("connection_timeout_s", 120))
    max_reconnects = max(0, int(ble.get("max_establishment_retries", 2)))
    reconnect_timeout = max(1.0, float(ble.get("reconnect_timeout_s", 30)))
    workdir = str(peer.get("remote_workdir") or "/var/tmp/wcbs_unified_coex")
    stop_file = f"{workdir}/stop_{mode}"
    client = _connect(peer)
    try:
        _run(
            client,
            f"mkdir -p {shlex.quote(workdir)} && rm -f {shlex.quote(stop_file)}",
            15,
        )
        _reset_controller(client, peer, label)
        sftp = client.open_sftp()
        try:
            sftp.put(str(HERE / "pi_ble_peer.py"), f"{workdir}/pi_ble_peer.py")
        finally:
            sftp.close()
        inner = (
            f"cd {shlex.quote(workdir)} && python3 pi_ble_peer.py {mode} "
            f"--name {shlex.quote(name)} --hold {hold} "
            f"--connect-timeout {connect_timeout} --stop-file {shlex.quote(stop_file)}"
            f" --max-reconnects {max_reconnects} --reconnect-timeout {reconnect_timeout}"
        )
        locked = (
            f"flock -E {HCI_LOCK_BUSY} -n {shlex.quote(HCI_LOCK)} "
            f"bash -lc {shlex.quote(inner)}"
        )
        command = _sudo(peer) + "bash -lc " + shlex.quote(locked)
        log(label, f"Starting {mode} peer {name!r} on {peer.get('host')}")
        code = _stream(client, command, label, int(hold + connect_timeout + 90))
        if code == HCI_LOCK_BUSY:
            raise RuntimeError(f"{label}: hci0 is in use by another test")
        if code != 0:
            raise RuntimeError(f"{label}: BLE {mode} peer exited {code}")
        return {"ok": True, "mode": mode, "host": peer.get("host"), "name": name}
    finally:
        client.close()


def stop_peer(config: Dict[str, Any], *, section: str, mode: str) -> None:
    peer = config.get(section) or {}
    if not str(peer.get("host") or "").strip():
        return
    workdir = str(peer.get("remote_workdir") or "/var/tmp/wcbs_unified_coex")
    client = _connect(peer)
    try:
        _run(client, f"touch {shlex.quote(workdir + '/stop_' + mode)}", 15)
    finally:
        client.close()
