#!/usr/bin/env python3
"""Start the wifi_ble_power_save TLS listener on the lab Pi over SSH."""

from __future__ import annotations

import shlex
import time
from pathlib import Path
from typing import Any, Dict, Optional

HERE = Path(__file__).resolve().parent
WORKDIR_CANDIDATES = (
    "/var/tmp/wcbs_power_save",
    "/tmp/wcbs_power_save",
    "~/wcbs_power_save",
)


def log(message: str) -> None:
    print(f"[pi-ssl] {message}", flush=True)


def _connect(pi: Dict[str, Any]):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError(
            "Pi SSL needs paramiko; run: pip install -r requirements.txt"
        ) from exc

    host = str(pi.get("host") or "").strip()
    if not host:
        raise ValueError("pi.host is required")
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
        allow_agent=not bool(pi.get("password")),
        look_for_keys=not bool(pi.get("password")),
    )
    return client


def _run(client, command: str, timeout: int = 60) -> tuple:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _resolve_workdir(client, preferred: Optional[str]) -> str:
    candidates = [preferred] if preferred else []
    candidates += [path for path in WORKDIR_CANDIDATES if path != preferred]
    for path in candidates:
        probe = shlex.quote(path)
        code, out, _err = _run(
            client,
            f"mkdir -p {probe} 2>/dev/null && test -w {probe} && "
            f"cd {probe} && pwd",
            timeout=30,
        )
        if code == 0 and out.strip():
            resolved = out.strip().splitlines()[-1].strip()
            log(f"Using workdir {resolved}")
            return resolved
    raise RuntimeError("No writable directory on the Pi. Set pi.remote_workdir.")


def _wiseconnect_certs(examples_root: str) -> tuple[Path, Path]:
    root = Path(examples_root).resolve()
    for parent in [root, *root.parents]:
        cert = parent / "resources" / "certificates" / "server-cert.pem"
        key = parent / "resources" / "certificates" / "server-key.pem"
        if cert.is_file() and key.is_file():
            return cert, key
    raise FileNotFoundError(
        "Could not find resources/certificates/server-cert.pem above "
        f"{examples_root}. Set studio.examples_root to the SDK "
        "examples/snippets/wlan_ble folder."
    )


def dut_facing_ip(client, preferred: str = "") -> str:
    """Pick the Pi IPv4 the DUT STA can reach (lab AP subnet first)."""
    _code, out, _err = _run(client, "hostname -I 2>/dev/null", timeout=15)
    ips = [token.strip() for token in (out or "").split() if token.strip()]
    if preferred and preferred in ips:
        return preferred
    for prefix in ("192.168.50.", "192.168.43.", "192.168.1.", "192.168.0."):
        for ip in ips:
            if ip.startswith(prefix):
                return ip
    for ip in ips:
        if ip.startswith("192.168."):
            return ip
    if preferred:
        return preferred
    return ips[0] if ips else ""


def _cell_security(cell: str) -> Optional[str]:
    """Classify one ``iwlist scan`` cell as open / wpa / wpa2 / wpa3."""
    if "Encryption key:off" in cell:
        return "open"
    rsn = ""
    wpa1 = "WPA Version 1" in cell
    for raw in cell.splitlines():
        line = raw.strip()
        if "IEEE 802.11i/WPA2" in line:
            rsn = rsn or "text"
        if line.startswith("IE: Unknown:"):
            blob = line.split(":", 2)[-1].strip().upper()
            if blob.startswith("30"):
                rsn = blob
            elif blob.startswith("DD") and "0050F201" in blob[:20]:
                wpa1 = True
    if rsn:
        if "000FAC08" in rsn and "000FAC02" not in rsn:
            return "wpa3"
        return "wpa2"
    if "Authentication Suites (1) : SAE" in cell:
        return "wpa3"
    if wpa1:
        return "wpa"
    return "wpa2" if "Encryption key:on" in cell else None


def scan_ap_security(pi: Dict[str, Any], ssid: str) -> Optional[str]:
    """Return what the lab AP really advertises (open/wpa/wpa2/wpa3), or None."""
    if not ssid:
        return None
    client = _connect(pi)
    try:
        iface = str(pi.get("scan_iface") or "wlan0")
        code, out, _err = _run(
            client,
            f"sudo -n iwlist {shlex.quote(iface)} scan 2>/dev/null || "
            f"iwlist {shlex.quote(iface)} scan 2>/dev/null",
            timeout=45,
        )
    finally:
        client.close()
    if not out:
        log(f"AP scan on Pi unavailable (exit {code}); keeping configured security")
        return None
    found: Optional[str] = None
    for cell in out.split("Cell ")[1:]:
        if f'ESSID:"{ssid}"' not in cell:
            continue
        kind = _cell_security(cell)
        if kind:
            found = kind
            if kind != "open":
                break
    if found:
        log(f"AP '{ssid}' advertises {found.upper()}")
    else:
        log(f"AP '{ssid}' not seen in Pi scan")
    return found


def _listen_ok(client, port: int) -> bool:
    script = (
        "import socket\n"
        "s=socket.socket(); s.settimeout(3)\n"
        "try:\n"
        f"    s.connect(('127.0.0.1', {int(port)})); print('OPEN')\n"
        "except Exception as exc:\n"
        "    print('CLOSED', exc)\n"
    )
    code, out, _err = _run(client, f"python3 -c {shlex.quote(script)}", timeout=30)
    return code == 0 and "OPEN" in out


def _tail_log(client, path: str) -> str:
    _code, out, _err = _run(client, f"tail -n 40 {shlex.quote(path)} 2>/dev/null", 15)
    return (out or "").strip()


def _read_text(client, path: str) -> str:
    _code, out, _err = _run(client, f"cat {shlex.quote(path)} 2>/dev/null", 15)
    return out or ""


class PiSslSession:
    def __init__(self, pi: Dict[str, Any], workdir: str, host: str, port: int) -> None:
        self.pi = pi
        self.workdir = workdir
        self.host = host
        self.port = port

    def send(self, data: bytes) -> None:
        client = _connect(self.pi)
        try:
            path = f"{self.workdir}/ssl_tx.pending"
            sftp = client.open_sftp()
            try:
                with sftp.file(path, "wb") as handle:
                    handle.write(data)
            finally:
                sftp.close()
            log(f"Queued {len(data)} bytes to DUT via {self.host}:{self.port}")
        finally:
            client.close()

    def received_text(self) -> str:
        client = _connect(self.pi)
        try:
            return _read_text(client, f"{self.workdir}/ssl_rx.txt")
        finally:
            client.close()

    def accepted(self) -> bool:
        client = _connect(self.pi)
        try:
            raw = _read_text(client, f"{self.workdir}/ssl_status.json")
        finally:
            client.close()
        try:
            import json

            return bool((json.loads(raw) or {}).get("accepted"))
        except Exception:
            return False


def start_ssl_server(config: Dict[str, Any]) -> PiSslSession:
    """Start TLS :5001 on the Pi and return the DUT-facing IPv4."""
    pi = config.get("pi") or {}
    ssl_cfg = config.get("ssl") or {}
    port = int(ssl_cfg.get("port") or 5001)
    preferred = str(ssl_cfg.get("server_ip") or "").strip()
    cert, key = _wiseconnect_certs(config["studio"]["examples_root"])

    client = _connect(pi)
    try:
        code, out, err = _run(client, "python3 -V", timeout=30)
        text = (out or "") + (err or "")
        if code != 0 or "Python" not in text:
            raise RuntimeError("Pi needs python3 on PATH (ssl_chat_server.py).\n" + text)
        log(text.strip())

        workdir = _resolve_workdir(client, pi.get("remote_workdir"))
        host = dut_facing_ip(client, preferred)
        if not host:
            raise RuntimeError(
                "Pi has no DUT-facing IPv4. Set ssl.server_ip to the Pi "
                "address on the lab AP (usually 192.168.50.x)."
            )

        sftp = client.open_sftp()
        try:
            sftp.put(str(HERE / "ssl_chat_server.py"), f"{workdir}/ssl_chat_server.py")
            sftp.put(str(cert), f"{workdir}/server-cert.pem")
            sftp.put(str(key), f"{workdir}/server-key.pem")
        finally:
            sftp.close()
        log("Deployed ssl_chat_server.py and SDK TLS certs")

        # /tmp/ssl_chat.log is often root-owned on the lab Pi (PermissionError 13).
        # The resolved workdir is already writable by the SSH user.
        log_path = f"{workdir}/ssl_chat.log"
        _run(
            client,
            f"pkill -f 'ssl_chat_server.py --port {port}' || true; "
            f"pkill -f 'openssl s_server -accept {port}' || true; "
            f"rm -f {shlex.quote(workdir)}/ssl_tx.pending "
            f"{shlex.quote(workdir)}/ssl_rx.txt "
            f"{shlex.quote(workdir)}/ssl_status.json "
            f"{shlex.quote(log_path)} 2>/dev/null || true",
            timeout=15,
        )
        starter = (
            "import os, subprocess\n"
            f"os.chdir({workdir!r})\n"
            f"log = open({log_path!r}, 'ab', buffering=0)\n"
            "args = ['python3', 'ssl_chat_server.py', '--port', "
            f"'{int(port)}', '--cert', 'server-cert.pem', '--key', "
            f"'server-key.pem', '--workdir', {workdir!r}]\n"
            "proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, "
            "stdin=subprocess.DEVNULL, start_new_session=True)\n"
            "print(proc.pid)\n"
        )
        code, out, err = _run(
            client, f"python3 -c {shlex.quote(starter)}", timeout=20
        )
        pid_line = ""
        for line in reversed((out or "").splitlines()):
            if line.strip().isdigit():
                pid_line = line.strip()
                break
        if not pid_line:
            raise RuntimeError(
                f"Failed to start ssl_chat_server.py: {err or out or code}"
            )
        log(f"Started ssl_chat_server.py pid={pid_line} on {host}:{port}")

        deadline = time.time() + 12
        while time.time() < deadline:
            if _listen_ok(client, port):
                break
            time.sleep(0.5)
        else:
            tail = _tail_log(client, log_path)
            raise RuntimeError(
                f"ssl_chat_server.py is not listening on {host}:{port}.\n{tail}"
            )
        log(f"Pi loopback :{port} is open; DUT SERVER_IP_ADDRESS={host}")
    finally:
        client.close()

    return PiSslSession(pi, workdir, host, port)
