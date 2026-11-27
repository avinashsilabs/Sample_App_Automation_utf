#!/usr/bin/env python3
"""Run the downstream NAT validation on the lab Raspberry Pi over SSH."""

from __future__ import annotations

import json
import shlex
import time
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from .pi_ble import _connect, _read_result, _resolve_workdir, _stream
except ImportError:
    from pi_ble import _connect, _read_result, _resolve_workdir, _stream  # type: ignore

HERE = Path(__file__).resolve().parent


def _ssh_connect(host_config: Dict[str, Any], jump_config: Optional[Dict[str, Any]] = None):
    """SSH to the NUC directly, or through the lab Pi when Windows has no route."""
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("NUC throughput server needs paramiko") from exc
    host = str(host_config.get("host") or "")
    port = int(host_config.get("port") or 22)

    def login(sock=None, timeout=30.0):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=str(host_config.get("username") or ""),
            password=str(host_config.get("password") or ""),
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            sock=sock,
        )
        return client

    try:
        return login(timeout=6.0 if jump_config else 30.0)
    except Exception as exc:  # noqa: BLE001
        if not jump_config or not str(jump_config.get("host") or "").strip():
            raise
        print("[nuc-iperf] Direct NUC SSH failed (%s); using Pi jump" % exc, flush=True)
    jump = paramiko.SSHClient()
    jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jump.connect(
        hostname=str(jump_config["host"]),
        port=int(jump_config.get("port") or 22),
        username=str(jump_config.get("username") or "pi"),
        password=str(jump_config.get("password") or ""),
        timeout=30,
        allow_agent=False,
        look_for_keys=False,
    )
    chan = jump.get_transport().open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0))
    try:
        client = login(sock=chan)
    except Exception:
        jump.close()
        raise
    close_nuc = client.close

    def close_both() -> None:
        try:
            close_nuc()
        finally:
            jump.close()

    client.close = close_both  # type: ignore[method-assign]
    return client


def _start_iperf_server(config: Dict[str, Any]):
    nat = config.get("nat") or {}
    if not bool(nat.get("throughput_enabled", True)):
        return None
    nuc = config.get("nuc") or {}
    if not str(nuc.get("host") or "").strip() or not str(nuc.get("username") or "").strip():
        raise ValueError("nuc.host and nuc.username are required for NAT throughput")
    port = int(nat.get("iperf_port") or 5201)
    client = _ssh_connect(nuc, config.get("pi"))
    # iperf 3.7 and newer open the reverse-test connection from the client,
    # which is what works through NAT. The system iperf3 on this NUC is 3.9.
    # Drop a 3.6 server if one is still listening from an older run.
    code, out, _err = _run(client, "command -v iperf3", timeout=30)
    binary = next(
        (ln.strip() for ln in reversed((out or "").splitlines()) if ln.strip().startswith("/")),
        "",
    )
    if code != 0 or not binary.startswith("/"):
        client.close()
        raise RuntimeError("iperf3 is not installed on the NUC")
    _run(
        client,
        "pkill -f '[i]perf-3.6-install' >/dev/null 2>&1 || true; "
        "if ss -ltn 2>/dev/null | grep -Eq '[:.]%d[[:space:]]'; then "
        "pkill -f '[i]perf3 -s' || true; sleep 1; fi" % port,
        timeout=20,
    )
    log_path = "/tmp/wcbs_iperf3_%d.log" % port
    # One client per server process. A reverse test can leave iperf 3.9
    # holding the port, and the next client then hangs.
    command = (
        "setsid nohup bash -c 'while true; do %s -s -p %d -1; sleep 0.3; done' "
        ">%s 2>&1 < /dev/null & echo $!"
        % (shlex.quote(binary), port, shlex.quote(log_path))
    )
    code, out, err = _run(client, command, timeout=30)
    pid = out.strip().splitlines()[-1] if out.strip() else ""
    if code != 0 or not pid.isdigit():
        client.close()
        raise RuntimeError("Could not start NUC iperf3 server: %s" % (err or out))
    time.sleep(1)
    code, _out, _err = _run(client, "kill -0 %s" % pid, timeout=15)
    if code != 0:
        _code, server_log, _err = _run(client, "tail -n 20 %s" % shlex.quote(log_path))
        client.close()
        raise RuntimeError("NUC iperf3 server exited: %s" % server_log)
    print("[nuc-iperf] Started iperf3 server on port %d (pid %s)" % (port, pid), flush=True)
    return (client, pid)


def _stop_iperf_server(server) -> None:
    if not server:
        return
    client, pid = server
    try:
        if pid:
            _run(
                client,
                "kill %s >/dev/null 2>&1 || true; "
                "pkill -f '[i]perf3 -s' >/dev/null 2>&1 || true" % pid,
                timeout=15,
            )
            print("[nuc-iperf] Stopped test iperf3 server", flush=True)
    finally:
        client.close()


def _run(client, command: str, timeout: int = 60) -> tuple:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _management_interface(client, management_ip: str) -> str:
    code, out, _err = _run(client, "ip -o -4 addr show", timeout=30)
    if code != 0:
        return ""
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "inet":
            if fields[3].split("/", 1)[0] == management_ip:
                return fields[1]
    return ""


def verify_nat_via_pi(config: Dict[str, Any]) -> Dict[str, Any]:
    pi = config.get("pi") or {}
    nat = dict(config.get("nat") or {})
    management_ip = str(pi.get("host") or "").strip()
    wifi_interface = str(nat.get("wifi_interface") or "wlan0")
    nuc = config.get("nuc") or {}
    nat.setdefault("iperf_host", str(nuc.get("host") or nat.get("probe_host") or ""))
    # Pi OS iperf is 3.6, which asks the server to connect back. That hangs
    # through NAT. A 3.9 client next to the NUC's 3.9 server opens both ways.
    nat["iperf3_bin"] = "/var/tmp/wcbs-iperf39/bin/iperf3"
    if not management_ip:
        raise ValueError("pi.host is required")

    server = _start_iperf_server(config)
    client = None
    try:
        client = _connect(pi)
        management_interface = _management_interface(client, management_ip)
        if management_interface == wifi_interface:
            raise RuntimeError(
                "Refusing to switch %s: it carries the SSH management address %s"
                % (wifi_interface, management_ip)
            )
        if management_interface:
            print(
                "[pi-nat] SSH safety check: %s is on %s; switching %s is safe"
                % (management_ip, management_interface, wifi_interface),
                flush=True,
            )

        workdir = _resolve_workdir(client, pi.get("remote_workdir"))
        remote_script = workdir + "/pi_nat_client.py"
        remote_config = workdir + "/nat_config.json"
        remote_result = workdir + "/nat_result.json"
        sftp = client.open_sftp()
        try:
            sftp.put(str(HERE / "pi_nat_client.py"), remote_script)
            with sftp.file(remote_config, "w") as handle:
                handle.write(json.dumps(nat, indent=2))
        finally:
            sftp.close()

        inner = (
            "python3 %s --config %s --result %s"
            % (shlex.quote(remote_script), shlex.quote(remote_config), shlex.quote(remote_result))
        )
        password = str(pi.get("password") or "")
        command = (
            "echo %s | sudo -S -p '' -E bash -lc %s"
            % (shlex.quote(password), shlex.quote(inner))
            if password
            else "sudo -n -E bash -lc %s" % shlex.quote(inner)
        )
        throughput_time = (
            2 * int(nat.get("throughput_duration_s") or 60)
            if bool(nat.get("throughput_enabled", True)) else 0
        )
        timeout = int(float(nat.get("duration_s") or 60) + throughput_time + 420)
        code = _stream(client, command, timeout=timeout, prefix="pi-nat")
        result = _read_result(client, remote_result)
        result["exit_code"] = code
        result["management_interface"] = management_interface
        if code != 0 or not result.get("ok"):
            raise RuntimeError(result.get("error") or "Pi NAT validation failed")
        return result
    finally:
        if client is not None:
            client.close()
        _stop_iperf_server(server)
