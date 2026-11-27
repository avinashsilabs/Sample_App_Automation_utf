#!/usr/bin/env python3
"""Deploy and run one of the two independent BLE peers over SSH."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).resolve().parent
HCI_LOCK = "/tmp/wcbs_unified_ae_hci0.lock"
HCI_LOCK_BUSY = 75
BLEAK_SPEC = "bleak>=0.19,<0.20"


def log(label: str, message: str) -> None:
    print(f"[{label}] {message}", flush=True)


def _connect(peer: Dict[str, Any]):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("BLE SSH needs paramiko; install requirements.txt") from exc
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
        timeout=float(peer.get("connect_timeout_s", 30)),
        allow_agent=not bool(peer.get("password")),
        look_for_keys=not bool(peer.get("password")),
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
            if line.startswith("[pi-ble] "):
                line = line[len("[pi-ble] "):]
            print(f"[{label}] {line}", flush=True)
    return stdout.channel.recv_exit_status()


def _sudo(peer: Dict[str, Any]) -> str:
    password = str(peer.get("password") or "")
    return (
        f"echo {shlex.quote(password)} | sudo -S -p '' -E "
        if password else "sudo -n -E "
    )


def _reset_controller(client, peer: Dict[str, Any], label: str, adapter: str) -> None:
    body = (
        "rfkill unblock bluetooth >/dev/null 2>&1 || true; "
        "systemctl restart bluetooth; sleep 3; "
        "bluetoothctl scan off >/dev/null 2>&1 || true; "
        "bluetoothctl devices 2>/dev/null | awk '{print $2}' | "
        "while read d; do bluetoothctl remove \"$d\" >/dev/null 2>&1 || true; done; "
        f"hciconfig {shlex.quote(adapter)} down >/dev/null 2>&1 || true; sleep 1; "
        f"hciconfig {shlex.quote(adapter)} up; "
        "bluetoothctl power on >/dev/null 2>&1 || true; "
        f"hciconfig {shlex.quote(adapter)} | grep -q 'UP RUNNING'"
    )
    locked = f"flock -E {HCI_LOCK_BUSY} -n {HCI_LOCK} bash -lc {shlex.quote(body)}"
    code, out, err = _run(client, _sudo(peer) + "bash -lc " + shlex.quote(locked), 60)
    if code == HCI_LOCK_BUSY:
        raise RuntimeError(f"{label}: {adapter} is in use by another test")
    if code != 0:
        raise RuntimeError(f"{label}: Bluetooth reset failed: {(err or out).strip()}")
    log(label, f"BlueZ restarted; {adapter} is UP/RUNNING")


def _bleak_python(client, workdir: str, label: str) -> str:
    candidates = (f"{workdir}/.venv/bin/python", "python3")
    probe = "import bleak; print(getattr(bleak, '__version__', 'installed'))"
    for candidate in candidates:
        code, out, _err = _run(
            client, f"{shlex.quote(candidate)} -c {shlex.quote(probe)} 2>/dev/null", 30
        )
        if code == 0:
            log(label, f"bleak {out.strip()} via {candidate}")
            return candidate
    python = f"{workdir}/.venv/bin/python"
    command = (
        f"python3 -m venv --system-site-packages {shlex.quote(workdir + '/.venv')} && "
        f"{shlex.quote(python)} -m pip install {shlex.quote(BLEAK_SPEC)}"
    )
    code, out, err = _run(client, command, 1200)
    if code != 0:
        raise RuntimeError(f"{label}: bleak install failed: {(err or out)[-1200:]}")
    return python


def run_peer(config: Dict[str, Any], *, section: str, mode: str, label: str) -> Dict[str, Any]:
    if mode not in ("peripheral", "central"):
        raise ValueError("mode must be peripheral or central")
    peer = dict(config.get(section) or {})
    ble = config.get("ble") or {}
    adapter = str(peer.get("adapter") or "hci0")
    # The peripheral is started before build/flash so it is already visible
    # when the DUT boots and begins its one-shot scan.  Leave ample time for a
    # clean build plus the 60-second coexistence gate.
    hold = max(180.0, float(ble.get("peer_hold_s", 900)))
    workdir = str(peer.get("remote_workdir") or "/var/tmp/wcbs_unified_ae")
    stop_file = f"{workdir}/stop_{mode}"
    passkey_file = f"{workdir}/pairing_passkey"
    script = "pi_ble_peripheral.py" if mode == "peripheral" else "pi_ble_central.py"
    client = _connect(peer)
    try:
        _run(
            client,
            f"mkdir -p {shlex.quote(workdir)} && "
            f"rm -f {shlex.quote(stop_file)} {shlex.quote(passkey_file)}",
            20,
        )
        _reset_controller(client, peer, label, adapter)
        code, _out, _err = _run(
            client, "python3 -c 'import dbus; from gi.repository import GLib'", 20
        )
        if code != 0:
            raise RuntimeError(
                f"{label}: install Linux packages python3-dbus and python3-gi"
            )
        if mode == "peripheral":
            python = "python3"
        else:
            python = _bleak_python(client, workdir, label)
        sftp = client.open_sftp()
        try:
            sftp.put(str(HERE / script), f"{workdir}/{script}")
            if mode == "central":
                sftp.put(
                    str(HERE / "pi_ble_agent.py"),
                    f"{workdir}/pi_ble_agent.py",
                )
        finally:
            sftp.close()

        if mode == "peripheral":
            inner = (
                f"cd {shlex.quote(workdir)} && {python} {script} "
                f"--name {shlex.quote(str(ble.get('pi_advertising_name') or 'SILABS_DEV'))} "
                f"--adapter {shlex.quote(adapter)} --hold {hold} "
                f"--stop-file {shlex.quote(stop_file)} "
                f"--passkey-file {shlex.quote(passkey_file)}"
            )
        else:
            address = str(ble.get("dut_address") or ble.get("address") or "").strip()
            address_arg = f" --address {shlex.quote(address)}" if address else ""
            central_command = (
                f"{shlex.quote(python)} {script} "
                f"--name {shlex.quote(str(ble.get('device_name') or 'BLE_AE_DEMO'))}"
                f"{address_arg} --scan-timeout {float(ble.get('scan_timeout_s', 60))} "
                f"--connect-timeout {float(ble.get('connect_timeout_s', 60))} "
                f"--hold {hold} --stop-file {shlex.quote(stop_file)} "
                f"--min-notifications {int(ble.get('min_notifications', 10))}"
            )
            inner = (
                f"cd {shlex.quote(workdir)} || exit 1; "
                f"python3 pi_ble_agent.py --stop-file {shlex.quote(stop_file)} "
                f"--passkey-file {shlex.quote(passkey_file)} & "
                "agent_pid=$!; sleep 2; "
                f"{central_command}; rc=$?; "
                f"touch {shlex.quote(stop_file)}; wait $agent_pid || true; exit $rc"
            )
        locked = (
            f"flock -E {HCI_LOCK_BUSY} -n {shlex.quote(HCI_LOCK)} "
            f"bash -lc {shlex.quote(inner)}"
        )
        command = _sudo(peer) + "bash -lc " + shlex.quote(locked)
        log(label, f"Starting {mode} data peer on {peer.get('host')} ({adapter})")
        code = _stream(client, command, label, int(hold + 240))
        if code == HCI_LOCK_BUSY:
            raise RuntimeError(f"{label}: {adapter} is in use by another test")
        if code != 0:
            raise RuntimeError(f"{label}: BLE {mode} peer exited {code}")
        return {"ok": True, "mode": mode, "host": peer.get("host"), "adapter": adapter}
    finally:
        client.close()


def stop_peer(config: Dict[str, Any], *, section: str, mode: str) -> None:
    peer = config.get(section) or {}
    if not str(peer.get("host") or "").strip():
        return
    workdir = str(peer.get("remote_workdir") or "/var/tmp/wcbs_unified_ae")
    client = _connect(peer)
    try:
        _run(client, f"touch {shlex.quote(workdir + '/stop_' + mode)}", 15)
    finally:
        client.close()


def supply_passkey(config: Dict[str, Any], passkey: str) -> None:
    """Deliver one UART-generated passkey to whichever peer is pairing."""
    if not (str(passkey).isdigit() and len(str(passkey)) == 6):
        raise ValueError(f"invalid six-digit passkey: {passkey!r}")
    errors = []
    delivered = 0
    for section in ("pi", "central_pi"):
        peer = config.get(section) or {}
        if not str(peer.get("host") or "").strip():
            continue
        workdir = str(peer.get("remote_workdir") or "/var/tmp/wcbs_unified_ae")
        client = None
        try:
            client = _connect(peer)
            sftp = client.open_sftp()
            try:
                with sftp.file(f"{workdir}/pairing_passkey", "w") as stream:
                    stream.write(str(passkey) + "\n")
            finally:
                sftp.close()
            delivered += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{section}: {exc}")
        finally:
            if client is not None:
                client.close()
    if not delivered:
        raise RuntimeError("passkey delivery failed: " + " | ".join(errors))
    log("pi-ble", f"Delivered DUT UART passkey to {delivered} BLE peer(s)")
