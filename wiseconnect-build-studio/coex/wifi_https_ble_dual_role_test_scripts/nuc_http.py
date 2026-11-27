#!/usr/bin/env python3
"""Run the SDK HTTP or HTTPS download server on the lab NUC or Pi.

Windows cannot open 192.168.50.36. SSH tries the NUC directly, then
jumps through the Pi. If NUC login is missing, the same download_server.py
is started on the Pi's lab-AP IPv4 (usually 192.168.50.57) so the DUT
can still fetch index.html.
"""

from __future__ import annotations

import shlex
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

HERE = Path(__file__).resolve().parent
WORKDIR_CANDIDATES = (
    "/var/tmp/wcbs_https_ble",
    "/tmp/wcbs_https_ble",
    "~/wcbs_https_ble",
)


def log(message: str) -> None:
    print(f"[nuc] {message}", flush=True)


def _ssh_client():
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError(
            "NUC HTTP/HTTPS needs paramiko; run: pip install -r requirements.txt"
        ) from exc
    return paramiko


def _connect(
    box: Dict[str, Any],
    label: str = "nuc",
    *,
    sock=None,
    timeout: Optional[float] = None,
):
    paramiko = _ssh_client()
    host = str(box.get("host") or "").strip()
    if not host and sock is None:
        raise ValueError(f"{label}.host is required")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username = str(box.get("username") or ("pi" if label == "pi" else "silabs"))
    port = int(box.get("port", 22))
    password = str(box.get("password") or "")
    log(f"Connecting {username}@{host or 'jump'}:{port} ...")
    # The lab Pi sshd sometimes resets back-to-back sessions (WinError 10054).
    attempts = 1 if sock is not None else 3
    for attempt in range(1, attempts + 1):
        try:
            client.connect(
                hostname=host or "127.0.0.1",
                port=port,
                username=username,
                password=password,
                timeout=float(
                    timeout if timeout is not None else box.get("connect_timeout_s", 20)
                ),
                allow_agent=not bool(password),
                look_for_keys=not bool(password),
                sock=sock,
            )
            return client
        except Exception as exc:  # noqa: BLE001
            if attempt == attempts or isinstance(exc, paramiko.AuthenticationException):
                raise
            log(f"SSH {host} attempt {attempt} failed ({exc}); retrying")
            time.sleep(3.0 * attempt)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return client


def _connect_nuc_via_pi(nuc: Dict[str, Any], pi: Dict[str, Any]):
    """Windows → Pi (10.207) → NUC (192.168.50.36)."""
    jump = _connect(pi, "pi")
    dest = (str(nuc.get("host") or "").strip(), int(nuc.get("port", 22)))
    chan = jump.get_transport().open_channel(
        "direct-tcpip", dest, ("127.0.0.1", 0)
    )
    client = _connect(nuc, "nuc", sock=chan, timeout=20)
    client._wcbs_jump = jump  # keep the jump channel alive
    log(f"NUC SSH via Pi jump {pi.get('host')} → {dest[0]}:{dest[1]}")
    return client


def _run(client, command: str, timeout: int = 60) -> tuple:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _sudo_wrap(box: Dict[str, Any], inner: str, *, need_root: bool) -> str:
    if not need_root:
        return f"bash -lc {shlex.quote(inner)}"
    password = str(box.get("password") or "")
    if password:
        return (
            f"echo {shlex.quote(password)} | sudo -S -p '' -E bash -lc {shlex.quote(inner)}"
        )
    return f"sudo -n -E bash -lc {shlex.quote(inner)}"


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
    raise RuntimeError("No writable directory. Set nuc.remote_workdir.")


def _wiseconnect_resources(examples_root: str) -> Path:
    root = Path(examples_root).resolve()
    for parent in [root, *root.parents]:
        scripts = parent / "resources" / "scripts" / "simple_http_server.py"
        if scripts.is_file():
            return parent / "resources"
    raise FileNotFoundError(
        "Could not find resources/scripts/simple_http_server.py above "
        f"{examples_root}. Set studio.examples_root to the SDK "
        "examples/snippets/wlan_ble folder."
    )


def _deploy(client, workdir: str, resources: Path) -> None:
    sftp = client.open_sftp()
    try:
        pairs = (
            (HERE / "download_server.py", "download_server.py"),
            (HERE / "index.html", "index.html"),
            (resources / "scripts" / "simple_http_server.py", "simple_http_server.py"),
            (resources / "certificates" / "server-cert.pem", "server-cert.pem"),
            (resources / "certificates" / "server-key.pem", "server-key.pem"),
        )
        for local, name in pairs:
            if not local.is_file():
                raise FileNotFoundError(f"Missing file to deploy: {local}")
            sftp.put(str(local), f"{workdir}/{name}")
            log(f"Deployed {name}")
    finally:
        sftp.close()


def _preflight(client) -> None:
    code, out, err = _run(client, "python3 -V", timeout=30)
    text = (out or "") + (err or "")
    if code != 0 or "Python" not in text:
        raise RuntimeError("python3 is required on the download host.\n" + text)
    log(text.strip())


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


def _stop_old_server(client, box: Dict[str, Any], port: int, workdir: str, log_name: str) -> None:
    """Stop a previous download_server.py so the port can be bound again."""
    script = (
        f"pkill -f 'download_server.py --port {int(port)}' || true; "
        f"rm -f {shlex.quote(workdir + '/' + log_name)} "
        f"{shlex.quote('/tmp/' + log_name)}"
    )
    _run(client, _sudo_wrap(box, script, need_root=port < 1024), timeout=20)


def _tail_log(client, path: str) -> str:
    _code, out, _err = _run(client, f"tail -n 40 {shlex.quote(path)} 2>/dev/null", 15)
    return (out or "").strip()


def dut_facing_ip(client, preferred: str = "") -> str:
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
    return preferred or (ips[0] if ips else "")


def probe_tcp_from_pi(pi: Dict[str, Any], host: str, port: int) -> bool:
    """Check from the lab STA subnet whether host:port accepts connections."""
    if not str(pi.get("host") or "").strip():
        return False
    client = _connect(pi, "pi")
    try:
        script = (
            "import socket\n"
            "s=socket.socket(); s.settimeout(6)\n"
            "try:\n"
            f"    s.connect(('{host}', {int(port)})); print('OPEN')\n"
            "except Exception as exc:\n"
            "    print('CLOSED', exc)\n"
        )
        code, out, _err = _run(
            client, f"python3 -c {shlex.quote(script)}", timeout=60
        )
        return code == 0 and "OPEN" in out
    finally:
        client.close()


def _open_nuc_or_pi(
    config: Dict[str, Any],
) -> Tuple[Any, Dict[str, Any], str, str]:
    """Return (client, sudo_box, dut_ip, backend)."""
    nuc = dict(config.get("nuc") or {})
    pi = dict(config.get("pi") or {})
    backend = str(nuc.get("backend") or "auto").strip().lower()
    nuc_host = str(nuc.get("host") or "").strip()

    have_nuc_login = bool(str(nuc.get("password") or "").strip())
    if backend == "auto" and nuc_host and not have_nuc_login:
        log(
            "nuc.password unset — skipping NUC SSH "
            f"({nuc_host} is not reachable from Windows)"
        )
    elif backend in ("nuc", "auto") and nuc_host:
        last_err: Optional[Exception] = None
        try:
            return _connect(nuc, "nuc", timeout=6), nuc, nuc_host, "nuc"
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            log(f"Direct NUC SSH failed ({exc})")
        if str(pi.get("host") or "").strip():
            try:
                return _connect_nuc_via_pi(nuc, pi), nuc, nuc_host, "nuc-jump"
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                log(f"NUC SSH via Pi jump failed ({exc})")
        if backend == "nuc":
            raise RuntimeError(
                f"Cannot SSH to NUC {nuc_host}. Set nuc.password or an SSH key. "
                f"Last error: {last_err}"
            )

    if not str(pi.get("host") or "").strip():
        raise RuntimeError("pi.host is required to serve HTTP/HTTPS when NUC SSH fails")
    client = _connect(pi, "pi")
    dut_ip = dut_facing_ip(client, str(nuc.get("serve_ip") or "").strip())
    if not dut_ip:
        client.close()
        raise RuntimeError(
            "Pi has no DUT-facing IPv4. Set nuc.serve_ip to the Pi address "
            "on the lab AP (usually 192.168.50.57)."
        )
    log(
        f"Serving download on the lab Pi {dut_ip} "
        "(Windows cannot reach the NUC; set nuc.password to use 192.168.50.36)"
    )
    return client, pi, dut_ip, "pi"


def start_download_server(config: Dict[str, Any], *, https: bool) -> Dict[str, Any]:
    """Start HTTP :80 or HTTPS :443 and prove the port is open on the STA LAN."""
    nuc = config.get("nuc") or {}
    pi = config.get("pi") or {}
    resources = _wiseconnect_resources(config["studio"]["examples_root"])
    label = "HTTPS download_server.py" if https else "HTTP download_server.py"
    log_name = "https_server.log" if https else "http_server.log"

    client, box, host, backend = _open_nuc_or_pi(config)
    if backend == "pi":
        port = int(nuc.get("pi_https_port" if https else "pi_http_port", 8443 if https else 8080))
    else:
        port = int(nuc.get("https_port" if https else "http_port", 443 if https else 80))
    try:
        _preflight(client)
        workdir = _resolve_workdir(
            client,
            nuc.get("remote_workdir") or box.get("remote_workdir"),
        )
        _deploy(client, workdir, resources)

        _stop_old_server(client, box, port, workdir, log_name)
        log_path = f"{workdir}/{log_name}"
        starter = (
            "import os, subprocess\n"
            f"os.chdir({workdir!r})\n"
            f"log = open({log_path!r}, 'ab', buffering=0)\n"
            "args = ['python3', 'download_server.py', '--port', "
            f"'{int(port)}', '--file', 'index.html']\n"
        )
        if https:
            starter += (
                "args += ['--cert', 'server-cert.pem', '--key', 'server-key.pem']\n"
            )
        starter += (
            "proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, "
            "stdin=subprocess.DEVNULL, start_new_session=True)\n"
            "print(proc.pid)\n"
        )
        command = f"python3 -c {shlex.quote(starter)}"
        if port < 1024:
            command = _sudo_wrap(box, command, need_root=True)
        code, out, err = _run(client, command, timeout=20)
        pid_line = ""
        for line in reversed((out or "").splitlines()):
            if line.strip().isdigit():
                pid_line = line.strip()
                break
        if not pid_line:
            raise RuntimeError(f"Failed to start {label}: {err or out or code}")
        log(f"Started {label} pid={pid_line} on {host}:{port} ({backend})")

        deadline = time.time() + 18
        while time.time() < deadline:
            if _listen_ok(client, port):
                break
            time.sleep(0.5)
        else:
            tail = _tail_log(client, log_path)
            raise RuntimeError(
                f"{label} is not listening on {host}:{port}.\n{tail}"
            )
        log(f"Loopback :{port} is open; DUT SERVER_IP_ADDRESS={host}")
    finally:
        jump = getattr(client, "_wcbs_jump", None)
        try:
            client.close()
        except Exception:
            pass
        if jump is not None:
            try:
                jump.close()
            except Exception:
                pass

    if backend != "pi" and str(pi.get("host") or "").strip():
        if not probe_tcp_from_pi(pi, host, port):
            raise RuntimeError(
                f"Lab Pi {pi.get('host')} cannot open {host}:{port}. "
                "DUT and the download host must share the STA subnet (Radha)."
            )
        log(f"Lab Pi can reach {host}:{port}")
    elif backend == "pi":
        log(f"Pi loopback already proved :{port}; DUT target {host}:{port}")

    return {
        "ok": True,
        "host": host,
        "port": port,
        "https": https,
        "label": label,
        "backend": backend,
    }
