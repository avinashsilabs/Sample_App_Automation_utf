#!/usr/bin/env python3
"""Start a DUT-facing raw TCP sink on the NUC, with Pi fallback."""

from __future__ import annotations

import shlex
import socket
import time
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).resolve().parent


def log(message: str) -> None:
    print(f"[tcp-server] {message}", flush=True)


def _connect(box: Dict[str, Any], label: str, *, timeout: float = 10, sock=None):
    import paramiko
    host = str(box.get("host") or "").strip()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    password = str(box.get("password") or "")
    client.connect(
        hostname=host or "127.0.0.1",
        port=int(box.get("port", 22)),
        username=str(box.get("username") or ("pi" if label == "pi" else "silabs")),
        password=password,
        timeout=timeout,
        allow_agent=not bool(password),
        look_for_keys=not bool(password),
        sock=sock,
    )
    return client


def _run(client, command: str, timeout: int = 30):
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), out, err


def _via_pi(nuc, pi):
    jump = _connect(pi, "pi")
    dest = (str(nuc["host"]), int(nuc.get("port", 22)))
    channel = jump.get_transport().open_channel("direct-tcpip", dest, ("127.0.0.1", 0))
    client = _connect(nuc, "nuc", sock=channel, timeout=15)
    client._wcbs_jump = jump
    return client


def _facing_ip(client, preferred: str = "") -> str:
    _code, out, _err = _run(client, "hostname -I 2>/dev/null", 15)
    ips = [token for token in out.split() if token.count(".") == 3]
    if preferred and preferred in ips:
        return preferred
    for prefix in ("192.168.50.", "192.168.43.", "192.168.1.", "192.168.0."):
        match = next((ip for ip in ips if ip.startswith(prefix)), None)
        if match:
            return match
    return preferred or (ips[0] if ips else "")


def _open_host(config):
    nuc = dict(config.get("nuc") or {})
    pi = dict(config.get("pi") or {})
    backend = str(nuc.get("backend") or "auto").lower()
    if backend in ("auto", "nuc") and str(nuc.get("host") or "").strip():
        errors = []
        try:
            return _connect(nuc, "nuc", timeout=7), nuc, "nuc"
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
        if str(pi.get("host") or "").strip():
            try:
                return _via_pi(nuc, pi), nuc, "nuc-jump"
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))
        if backend == "nuc":
            raise RuntimeError("NUC SSH failed: " + " | ".join(errors))
    return _connect(pi, "pi"), pi, "pi"


def start_tcp_sink(config: Dict[str, Any]) -> Dict[str, Any]:
    throughput = config.get("throughput") or {}
    port = int(throughput.get("port") or 5001)
    client, box, backend = _open_host(config)
    workdir = str(box.get("remote_workdir") or "/var/tmp/wcbs_ae_coex")
    try:
        code, _out, err = _run(client, f"mkdir -p {shlex.quote(workdir)}", 20)
        if code != 0:
            raise RuntimeError(f"Cannot create TCP sink workdir: {err}")
        sftp = client.open_sftp()
        try:
            sftp.put(str(HERE / "tcp_sink_server.py"), f"{workdir}/tcp_sink_server.py")
        finally:
            sftp.close()
        host = _facing_ip(client, str(throughput.get("host") or ""))
        if not host:
            raise RuntimeError("TCP sink host has no DUT-facing IPv4 address")
        log_path = f"/tmp/wcbs_ae_tcp_{port}.log"
        starter = (
            "import os,subprocess; "
            f"os.chdir({workdir!r}); "
            f"log=open({log_path!r},'ab',buffering=0); "
            f"p=subprocess.Popen(['python3','tcp_sink_server.py','--port','{port}'],"
            "stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True); "
            "print(p.pid)"
        )
        _run(client, f"pkill -f 'tcp_sink_server.py --port {port}' >/dev/null 2>&1 || true", 15)
        code, out, err = _run(client, f"python3 -c {shlex.quote(starter)}", 20)
        pid = next((line.strip() for line in reversed(out.splitlines()) if line.strip().isdigit()), "")
        if code != 0 or not pid:
            raise RuntimeError(f"TCP sink start failed: {err or out}")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            probe = socket.socket()
            probe.settimeout(1)
            try:
                # Local Windows may not route to lab subnet; verify remotely instead.
                pcode, pout, _ = _run(
                    client,
                    "python3 -c " + shlex.quote(
                        f"import socket;s=socket.create_connection(('127.0.0.1',{port}),2);s.close();print('OK')"
                    ),
                    10,
                )
                if pcode == 0 and "OK" in pout:
                    break
            finally:
                probe.close()
            time.sleep(0.5)
        else:
            raise RuntimeError("TCP sink did not listen on the configured port")
        log(f"Started raw TCP sink on {host}:{port} ({backend}, pid {pid})")
        return {"host": host, "port": port, "pid": int(pid), "backend": backend, "log": log_path}
    finally:
        jump = getattr(client, "_wcbs_jump", None)
        client.close()
        if jump is not None:
            jump.close()


def stop_tcp_sink(config: Dict[str, Any], server: Dict[str, Any]) -> None:
    """Stop only the TCP sink instance created for this validation."""
    client, _box, _backend = _open_host(config)
    try:
        pid = int(server.get("pid") or 0)
        if pid > 1:
            _run(client, f"kill {pid} >/dev/null 2>&1 || true", 15)
            log(f"Stopped raw TCP sink pid {pid}")
    finally:
        jump = getattr(client, "_wcbs_jump", None)
        client.close()
        if jump is not None:
            jump.close()
