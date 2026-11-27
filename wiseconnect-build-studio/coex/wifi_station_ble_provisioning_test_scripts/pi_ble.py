#!/usr/bin/env python3
"""Run BLE Wi-Fi commissioning on a Raspberry Pi over SSH.

The Windows test host usually has no usable Bluetooth radio, so the BLE
central role is delegated to the lab Pi: this module prepares the Pi
(workdir, bleak, BlueZ access), uploads the provisioner, runs it, and
returns the parsed result.
"""

from __future__ import annotations

import json
import re
import shlex
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

HERE = Path(__file__).resolve().parent
DEPLOY_FILES = ("ble_protocol.py", "pi_ble_provisioner.py")
# Buster ships Python 3.7; bleak 0.19 is the last line whose dependencies are
# pure Python, so it installs without a compiler or modern manylinux wheels.
BLEAK_SPEC = "bleak>=0.19,<0.20"
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


def _sudo_prefix(pi: Optional[Dict[str, Any]] = None) -> str:
    """Build an `echo pass | sudo -S` prefix when a Pi password is configured."""
    password = str((pi or {}).get("password") or "")
    if password:
        return f"echo {shlex.quote(password)} | sudo -S -E "
    return "sudo -n -E "


def _ensure_python_venv_package(client, pi: Optional[Dict[str, Any]] = None) -> None:
    """Install python3-venv on Debian/Ubuntu when ensurepip is missing."""
    code, _out, _err = _run(
        client,
        "python3 -c \"import ensurepip\" 2>/dev/null",
        timeout=30,
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

    _ensure_python_venv_package(client, pi)

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
        code, out, err = _run(client, f"python3 -c {shlex.quote(probe)}", timeout=60)
        if code != 0:
            raise RuntimeError(f"bleak installed but import failed: {err or out}")
        log(f"bleak {out.strip()} installed via python3 --user")
        return "python3"

    code, out, err = _run(client, f"{python} -c {shlex.quote(probe)}", timeout=60)
    if code != 0:
        raise RuntimeError(f"bleak installed but import failed: {err or out}")
    log(f"bleak {out.strip()} installed")
    return venv_python


def _dbus_probe(client) -> str:
    code, out, err = _run(
        client,
        "dbus-send --system --dest=org.bluez --print-reply / "
        "org.freedesktop.DBus.ObjectManager.GetManagedObjects 2>&1 | head -n 8",
        timeout=30,
    )
    return f"{code}\n{(out or '')}{(err or '')}"


def _ensure_bluetooth(client, pi: Dict[str, Any]) -> bool:
    """Start bluetoothd and the alias bleak 0.19 expects.

    hci0 UP is not enough. bleak talks to org.bluez on the system bus, and
    on scan it StartUnit('dbus-org.bluez.service'). Many Pi images only
    ship bluetooth.service, so sudo+bleak fails with NoSuchUnit.
    """
    sudo = _sudo_prefix(pi)
    username = str(pi.get("username") or "pi")
    # This corporate Pi ships bluetooth.service masked. bleak 0.19 then
    # StartUnit('dbus-org.bluez.service') and fails with NoSuchUnit.
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

    if bool(pi.get("ble_use_sudo", False)):
        return True
    log("BlueZ D-Bus denies this user — running the provisioner with sudo")
    return True


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


def _parse_ping_output(text: str, code: int, host: str, label: str) -> Dict[str, Any]:
    received = 0
    match = re.search(r"(\d+)\s+received", text, re.I)
    if match:
        received = int(match.group(1))
    elif re.search(r"bytes from|Reply from", text, re.I):
        received = len(re.findall(r"bytes from|Reply from", text, re.I))
    if received < 1:
        raise RuntimeError(
            f"{label} ping to {host} failed (exit {code}, received={received}).\n{text}"
        )
    log(f"{label} ping {host}: {received} reply/replies")
    return {
        "ok": True,
        "host": host,
        "source": label,
        "received": received,
        "output": text,
    }


def ping_from_box(
    box: Dict[str, Any],
    host: str,
    count: int = 4,
    timeout_s: float = 90,
    label: str = "pi",
) -> Dict[str, Any]:
    """ICMP ping from a lab box (Pi or NUC) to the DUT STA IP."""
    client = _connect(box)
    try:
        command = f"ping -c {int(count)} -W 2 {shlex.quote(host)} 2>&1"
        log(f"Pinging DUT {host} ({count} ICMP) from {label} {box.get('host')} ...")
        code, out, err = _run(client, command, timeout=int(timeout_s))
        text = ((out or "") + (err or "")).strip()
        for line in text.splitlines():
            if line.strip():
                print(f"[{label}-ping] {line}", flush=True)
        return _parse_ping_output(text, code, host, label)
    finally:
        client.close()


def ping_from_pi(
    pi: Dict[str, Any],
    host: str,
    count: int = 4,
    timeout_s: float = 90,
) -> Dict[str, Any]:
    return ping_from_box(pi, host, count=count, timeout_s=timeout_s, label="pi")


def ping_dut_ip(config: Dict[str, Any], dut_ip: str) -> Dict[str, Any]:
    """Ping the provisioned DUT IP from the NUC if reachable, else the Pi."""
    ping_cfg = config.get("ping") or {}
    count = int(ping_cfg.get("count") or 4)
    timeout_s = float((config.get("timeouts") or {}).get("ping_s", 90))
    prefer = str(ping_cfg.get("source") or "auto").lower()
    nuc = config.get("nuc") or {}
    pi = config.get("pi") or {}
    nuc_ready = bool(
        str(nuc.get("host") or "").strip() and str(nuc.get("password") or "").strip()
    )
    pi_ready = bool(str(pi.get("host") or "").strip())

    order = []
    if prefer in ("nuc", "n") and nuc_ready:
        order = [("nuc", nuc)]
        if pi_ready:
            order.append(("pi", pi))
    elif prefer in ("pi", "raspi", "raspberry_pi") and pi_ready:
        order = [("pi", pi)]
    else:
        if nuc_ready:
            order.append(("nuc", nuc))
        if pi_ready:
            order.append(("pi", pi))

    if not order:
        raise RuntimeError(
            f"No NUC or Pi SSH to ping DUT IP {dut_ip}. Set nuc.password or pi.host."
        )

    last_error: Optional[Exception] = None
    for label, box in order:
        try:
            return ping_from_box(
                box, dut_ip, count=count, timeout_s=timeout_s, label=label
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            log(f"{label} ping of {dut_ip} failed: {exc}")
    raise RuntimeError(f"DUT IP ping failed: {last_error}")


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


class HeldPiSession:
    """BLE provision on the Pi; stay connected until release() after DUT IP ping."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.result: Dict[str, Any] = {}
        self._client = None
        self._workdir = ""
        self._thread: Optional[threading.Thread] = None
        self._code: Optional[int] = None
        self._released = False

    def start(self) -> Dict[str, Any]:
        pi = self.config.get("pi") or {}
        ble = self.config["ble"]
        payload = {"ble": ble, "wifi": self.config["wifi"]}
        hold_s = float(ble.get("hold_for_ping_s", 180))
        payload["ble"] = dict(ble)
        payload["ble"]["hold_for_ping_s"] = hold_s

        self._client = _connect(pi)
        self._workdir = _resolve_workdir(self._client, pi.get("remote_workdir"))
        python = _ensure_bleak(self._client, self._workdir, pi)
        use_sudo = _ensure_bluetooth(self._client, pi)
        _run(
            self._client,
            f"rm -f {shlex.quote(self._workdir + '/release_ble.flag')} "
            f"{shlex.quote(self._workdir + '/provision_ready.json')} "
            f"{shlex.quote(self._workdir + '/provision_result.json')}",
            timeout=15,
        )
        _deploy(self._client, self._workdir, payload)

        inner = (
            f"cd {shlex.quote(self._workdir)} && {shlex.quote(python)} "
            f"pi_ble_provisioner.py --config provision_config.json "
            f"--result provision_result.json "
            f"--ready-file provision_ready.json "
            f"--release-file release_ble.flag"
        )
        if use_sudo:
            password = str(pi.get("password") or "")
            command = (
                f"echo {shlex.quote(password)} | sudo -S -E bash -lc {shlex.quote(inner)}"
                if password
                else f"sudo -n -E bash -lc {shlex.quote(inner)}"
            )
        else:
            command = f"bash -lc {shlex.quote(inner)}"

        timeout = int(
            float(ble.get("scan_timeout_s", 30)) * int(ble.get("ssid_scan_retries", 5))
            + float(ble.get("connect_timeout_s", 75))
            + float(ble.get("ble_join_poll_s", 20))
            + hold_s
            + 60
        )
        log("Starting BLE provisioning on the Pi (hold until DUT IP ping)...")
        self._thread = threading.Thread(
            target=self._stream, args=(command, timeout), daemon=True
        )
        self._thread.start()

        ready_path = f"{self._workdir}/provision_ready.json"
        result_path = f"{self._workdir}/provision_result.json"
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._thread and not self._thread.is_alive() and self._code is not None:
                try:
                    self.result = _read_result(self._client, result_path)
                except Exception as exc:  # noqa: BLE001
                    raise RuntimeError(
                        f"Pi provisioner exited with {self._code} "
                        f"and left no result file: {exc}"
                    ) from exc
                if not self.result.get("ok"):
                    raise RuntimeError(
                        self.result.get("error")
                        or f"Pi BLE provisioning failed (exit {self._code})"
                    )
                return self._finish_result()
            for path in (ready_path, result_path):
                try:
                    data = _read_result(self._client, path)
                except Exception:  # noqa: BLE001
                    continue
                if data.get("credentials_sent") or data.get("ok"):
                    if not data.get("ok") and data.get("error"):
                        raise RuntimeError(data["error"])
                    self.result = data
                    return self._finish_result()
            time.sleep(0.5)
        raise TimeoutError("Timed out waiting for BLE credentials to be sent")

    def _stream(self, command: str, timeout: int) -> None:
        try:
            self._code = _stream(self._client, command, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            log(f"Provisioner stream ended: {exc}")
            self._code = -1

    def _finish_result(self) -> Dict[str, Any]:
        self.result["backend"] = "pi"
        self.result["pi_host"] = (self.config.get("pi") or {}).get("host")
        self.result["held"] = True
        return self.result

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            if self._client and self._workdir:
                _run(
                    self._client,
                    f"touch {shlex.quote(self._workdir + '/release_ble.flag')}",
                    timeout=15,
                )
                log("Released BLE hold — Pi will disconnect")
        except Exception as exc:  # noqa: BLE001
            log(f"Release note: {exc}")
        if self._thread:
            self._thread.join(timeout=20)
        try:
            if self._client:
                self._client.close()
        except Exception:  # noqa: BLE001
            pass
        self._client = None


def start_held_provision(config: Dict[str, Any]) -> HeldPiSession:
    session = HeldPiSession(config)
    session.start()
    return session


def provision_via_pi(config: Dict[str, Any]) -> Dict[str, Any]:
    """Back-compat: start held provision and return the ready result."""
    return start_held_provision(config).result
