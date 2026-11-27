#!/usr/bin/env python3
"""Run BLE simple-chat on a Raspberry Pi over SSH."""

from __future__ import annotations

import json
import shlex
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
DEPLOY_FILES = ("pi_ble_chat.py",)
BLEAK_SPEC = "bleak>=0.19,<0.20"
WORKDIR_CANDIDATES = (
    "/var/tmp/wcbs_power_save",
    "/tmp/wcbs_power_save",
    "~/wcbs_power_save",
)


def log(message: str) -> None:
    print(f"[pi] {message}", flush=True)


def _connect(pi: Dict[str, Any]):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError(
            "Pi BLE chat needs paramiko; run: pip install -r requirements.txt"
        ) from exc

    host = str(pi.get("host") or "").strip()
    if not host:
        raise ValueError("pi.host is required for BLE chat over SSH")
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


def _stream(client, command: str, timeout: int, prefix: str = "pi") -> int:
    _stdin, stdout, stderr = client.exec_command(
        command, timeout=timeout, get_pty=True
    )
    for raw in iter(stdout.readline, ""):
        line = raw.rstrip("\r\n")
        if line:
            print(
                f"[{prefix}] {line}" if not line.startswith("[pi-ble]") else line,
                flush=True,
            )
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
        "No writable directory on the Pi. Set pi.remote_workdir to a writable path."
    )


def _sudo_prefix(pi: Optional[Dict[str, Any]] = None) -> str:
    password = str((pi or {}).get("password") or "")
    if password:
        return f"echo {shlex.quote(password)} | sudo -S -E "
    return "sudo -n -E "


def _ensure_python_venv_package(client, pi: Optional[Dict[str, Any]] = None) -> None:
    code, _out, _err = _run(
        client, 'python3 -c "import ensurepip" 2>/dev/null', timeout=30
    )
    if code == 0:
        return
    log("python3-venv / ensurepip missing — installing via apt (needs sudo)...")
    sudo = _sudo_prefix(pi)
    code = _stream(
        client,
        f"{sudo}apt-get update -qq && "
        f"{sudo}DEBIAN_FRONTEND=noninteractive apt-get install -y "
        f"python3-venv python3-pip",
        timeout=900,
        prefix="pi-apt",
    )
    if code != 0:
        raise RuntimeError(
            "Failed to install python3-venv on the Pi. Run once over SSH:\n"
            "  sudo apt-get update && sudo apt-get install -y python3-venv python3-pip"
        )


def _ensure_bleak(
    client,
    workdir: str,
    pi: Optional[Dict[str, Any]] = None,
) -> str:
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

    _ensure_python_venv_package(client, pi)
    log(f"Installing {BLEAK_SPEC} into {workdir}/.venv (first run only)...")
    venv = shlex.quote(f"{workdir}/.venv")
    python = shlex.quote(venv_python)
    code = _stream(
        client,
        f"rm -rf {venv} && python3 -m venv {venv} && "
        f"{python} -m pip install --upgrade 'pip<24.1' setuptools wheel && "
        f"{python} -m pip install {shlex.quote(BLEAK_SPEC)}",
        timeout=1800,
        prefix="pi-pip",
    )
    if code != 0:
        log("venv install failed — falling back to python3 -m pip --user ...")
        code = _stream(
            client,
            "python3 -m pip install --user --upgrade 'pip<24.1' setuptools wheel && "
            f"python3 -m pip install --user {shlex.quote(BLEAK_SPEC)}",
            timeout=1800,
            prefix="pi-pip",
        )
        if code != 0:
            raise RuntimeError(f"Failed to install bleak on the Pi (exit {code})")
        return "python3"
    return venv_python


def _dbus_probe(client) -> str:
    code, out, err = _run(
        client,
        "dbus-send --system --dest=org.bluez --print-reply / "
        "org.freedesktop.DBus.ObjectManager.GetManagedObjects 2>&1 | head -n 8",
        timeout=30,
    )
    return f"{code}\n{(out or '')}{(err or '')}"


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

    BlueZ defaults (30-50 ms interval, 420 ms supervision) are shorter than
    the gaps between power-save wakeups, so GATT discovery loses the link.
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
    code, out, err = _run(client, setup, timeout=60)
    if code != 0:
        log(f"BlueZ systemd setup note: {(err or out or '').strip()[:300]}")
    else:
        log("bluetooth.service unmasked/started; dbus-org.bluez.service alias ready")

    _run(
        client,
        f"{sudo}hciconfig hci0 up 2>/dev/null || hciconfig hci0 up 2>/dev/null || true",
        timeout=30,
    )
    code, out, _err = _run(client, "hciconfig hci0 2>/dev/null | head -n 3", timeout=30)
    if code != 0 or "UP" not in out:
        raise RuntimeError(
            "Bluetooth adapter hci0 is not up on the Pi. Check: "
            "sudo systemctl start bluetooth && sudo hciconfig hci0 up\n"
            f"{out.strip()}"
        )
    log("hci0 is up")

    ready = False
    for _ in range(8):
        text = _dbus_probe(client)
        if "AccessDenied" in text or "Rejected send message" in text:
            break
        if "object" in text.lower() or "/org/bluez" in text:
            ready = True
            break
        time.sleep(0.5)
    if ready:
        log("BlueZ D-Bus access OK for this user")
        return bool(pi.get("ble_use_sudo", False))
    log("BlueZ D-Bus denies this user — running the chat central with sudo")
    return True


def _read_json(client, path: str) -> Dict[str, Any]:
    sftp = client.open_sftp()
    try:
        with sftp.file(path, "r") as handle:
            return json.loads(handle.read().decode("utf-8"))
    except Exception:
        return {}
    finally:
        sftp.close()


def _write_json(client, path: str, payload: Dict[str, Any]) -> None:
    sftp = client.open_sftp()
    try:
        with sftp.file(path, "w") as handle:
            handle.write(json.dumps(payload))
    finally:
        sftp.close()


class PiBleChat:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.pi = config.get("pi") or {}
        self.ble = config.get("ble") or {}
        self.workdir = ""
        self.cmd_id = 0
        self._client = None
        self._original_link: Optional[tuple] = None

    def start(self) -> None:
        pi = self.pi
        ble = self.ble
        client = _connect(pi)
        self._client = client
        try:
            workdir = _resolve_workdir(client, pi.get("remote_workdir"))
            self.workdir = workdir
            python = _ensure_bleak(client, workdir, pi)
            use_sudo = _ensure_bluetooth(client, pi)
            self._original_link = _tune_le_link(client, pi, ble)
            sftp = client.open_sftp()
            try:
                for name in DEPLOY_FILES:
                    sftp.put(str(HERE / name), f"{workdir}/{name}")
                    log(f"Deployed {name}")
            finally:
                sftp.close()
            _run(
                client,
                f"rm -f {shlex.quote(workdir)}/chat_status.json "
                f"{shlex.quote(workdir)}/chat_cmd.json; "
                f"pkill -f pi_ble_chat.py || true",
                timeout=15,
            )
            inner = (
                f"cd {shlex.quote(workdir)} && umask 000 && "
                f"{shlex.quote(python)} pi_ble_chat.py "
                f"--name {shlex.quote(str(ble.get('device_name') or 'WLAN_BLE_SIMPLE_CHAT'))} "
                f"--write-uuid {shlex.quote(str(ble['write_uuid']))} "
                f"--notify-uuid {shlex.quote(str(ble['notify_uuid']))} "
                f"--status chat_status.json --cmd chat_cmd.json "
                f"--scan-timeout {float(ble.get('scan_timeout_s', 45))} "
                f"--connect-timeout {float(ble.get('connect_timeout_s', 75))} "
                f"--hold-s {float(ble.get('hold_s', 600))} > chat.log 2>&1"
            )
            # setsid detaches the chat process. A plain background job under
            # sudo keeps the SSH channel open until the hold timer ends.
            background = (
                f"setsid nohup bash -lc {shlex.quote(inner)} "
                f"</dev/null >/dev/null 2>&1 & echo $!"
            )
            password = str(pi.get("password") or "")
            if use_sudo:
                command = (
                    f"echo {shlex.quote(password)} | sudo -S -E bash -lc {shlex.quote(background)}"
                    if password
                    else f"sudo -n -E bash -lc {shlex.quote(background)}"
                )
            else:
                command = f"bash -lc {shlex.quote(background)}"
            code, out, err = _run(client, command, timeout=20)
            if code != 0:
                raise RuntimeError(f"Failed to start pi_ble_chat.py: {err or out}")
            pid = next(
                (ln.strip() for ln in reversed((out or "").splitlines())
                 if ln.strip().isdigit()),
                "?",
            )
            log(f"Started BLE chat central pid={pid}")
        except Exception:
            self._restore_link()
            client.close()
            self._client = None
            raise

    def _restore_link(self) -> None:
        if not (self._client and self._original_link):
            return
        try:
            _write_le_link(self._client, self.pi, self._original_link)
        except Exception as exc:  # noqa: BLE001
            log(f"LE link restore note: {exc}")
        self._original_link = None

    def wait_connected(self, timeout: float) -> Dict[str, Any]:
        deadline = time.time() + timeout
        last: Dict[str, Any] = {}
        while time.time() < deadline:
            last = _read_json(self._client, f"{self.workdir}/chat_status.json")
            if last.get("connected"):
                log("BLE connected to WLAN_BLE_SIMPLE_CHAT")
                return last
            if last.get("error"):
                raise RuntimeError(f"Pi BLE chat failed: {last['error']}")
            time.sleep(1.0)
        tail = ""
        try:
            _code, out, _err = _run(
                self._client,
                f"tail -n 40 {shlex.quote(self.workdir)}/chat.log 2>/dev/null",
                timeout=15,
            )
            tail = (out or "").strip()
        except Exception:
            pass
        extra = f"\n{tail}" if tail else ""
        raise TimeoutError(
            "Timed out waiting for BLE connect to WLAN_BLE_SIMPLE_CHAT: "
            f"{last}{extra}"
        )

    def notifications(self) -> List[str]:
        status = _read_json(self._client, f"{self.workdir}/chat_status.json")
        raw = status.get("notifications") or []
        return [str(item) for item in raw]

    def write(self, text: str) -> None:
        self.cmd_id += 1
        _write_json(
            self._client,
            f"{self.workdir}/chat_cmd.json",
            {"id": self.cmd_id, "op": "write", "text": text},
        )
        log(f"BLE write queued: {text!r}")

    def stop(self) -> None:
        if not self._client:
            return
        try:
            self.cmd_id += 1
            _write_json(
                self._client,
                f"{self.workdir}/chat_cmd.json",
                {"id": self.cmd_id, "op": "stop"},
            )
        except Exception:
            pass
        self._restore_link()
        try:
            self._client.close()
        except Exception:
            pass
        self._client = None


def start_ble_chat(config: Dict[str, Any]) -> PiBleChat:
    session = PiBleChat(config)
    session.start()
    return session
