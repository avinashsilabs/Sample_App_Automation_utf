#!/usr/bin/env python3
"""Serve DOWNLOAD_FILENAME and close the HTTP/TLS session cleanly.

wifi_http_s.c treats recv() ENOTCONN as end-of-file. The SDK
simple_http_server.py waits up to 30s for the DUT FIN first; openssl
s_server -WWW may keep the TLS session open. This helper sends the full file,
briefly lets the offload stack drain it, then closes HTTP with FIN or HTTPS
with TLS close_notify so the DUT completes promptly without truncation.

TLS matches the SDK README:
  openssl s_server -accept 443 -cert server-cert.pem -key server-key.pem -tls1_2 -WWW

Each client is handled on its own thread so leftover DUT downloads from a
previous flash cannot stall the host readiness probe or crash the listener.

  python3 download_server.py --port 80
  python3 download_server.py --port 443 --cert server-cert.pem --key server-key.pem
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import threading
import time

# OpenSSL names for SL_SI91X_TLS_DEFAULT_CIPHERS (RSA/DHE/ECDHE CBC).
_SI91X_CIPHERS = (
    "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:"
    "AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:"
    "DEFAULT:@SECLEVEL=0"
)


def log(message: str) -> None:
    print(f"[download-server] {message}", flush=True)


def tls_server_context(cert: str, key: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "OP_NO_TLSv1_3"):
        context.options |= ssl.OP_NO_TLSv1_3
    try:
        context.set_ciphers(_SI91X_CIPHERS)
    except ssl.SSLError:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context


def handle(conn: socket.socket, filename: str, close_delay: float) -> None:
    raw_after_tls = None
    try:
        conn.settimeout(15)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        if not os.path.isfile(filename):
            body = b"File Not Found\n"
            status = "404 Not Found"
            ctype = "text/plain"
        else:
            with open(filename, "rb") as handle:
                body = handle.read()
            status = "200 OK"
            ctype = "text/html"
        header = (
            f"HTTP/1.0 {status}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        conn.sendall(header + body)
        log(f"sent {len(body)} bytes ({status})")
        if close_delay > 0:
            time.sleep(close_delay)
        if isinstance(conn, ssl.SSLSocket):
            conn.settimeout(2)
            try:
                raw_after_tls = conn.unwrap()
            except (OSError, ssl.SSLError):
                pass
        else:
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
    except Exception as exc:  # noqa: BLE001
        log(f"client error: {exc}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        if raw_after_tls is not None:
            try:
                raw_after_tls.close()
            except OSError:
                pass


def _serve_client(
    conn: socket.socket,
    addr: tuple,
    context: ssl.SSLContext | None,
    filename: str,
    close_delay: float,
) -> None:
    peer = f"{addr[0]}:{addr[1]}"
    try:
        if context is not None:
            try:
                conn = context.wrap_socket(conn, server_side=True)
                cipher = conn.cipher()
                log(f"TLS handshake {peer} cipher={cipher[0] if cipher else '?'}")
            except (ssl.SSLError, OSError) as exc:
                log(f"TLS handshake failed {peer}: {exc}")
                try:
                    conn.close()
                except OSError:
                    pass
                return
        handle(conn, filename, close_delay)
    except Exception as exc:  # noqa: BLE001
        log(f"client {peer}: {exc}")
        try:
            conn.close()
        except OSError:
            pass


def serve(port: int, filename: str, cert: str, key: str, close_delay: float) -> None:
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("0.0.0.0", port))
    raw.listen(32)
    context = None
    if cert and key:
        context = tls_server_context(cert, key)
        log(f"HTTPS TLS1.2 0.0.0.0:{port} cert={cert} file={filename}")
    else:
        log(f"HTTP 0.0.0.0:{port} file={filename}")
    while True:
        conn, addr = raw.accept()
        log(f"accept {addr[0]}:{addr[1]}")
        threading.Thread(
            target=_serve_client,
            args=(conn, addr, context, filename, close_delay),
            daemon=True,
            name=f"dl-{addr[1]}",
        ).start()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--file", default="index.html")
    parser.add_argument("--cert", default="")
    parser.add_argument("--key", default="")
    parser.add_argument(
        "--close-delay",
        type=float,
        default=0.75,
        help="seconds to wait after sendall before orderly close",
    )
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        print("Provide both --cert and --key for HTTPS", file=sys.stderr)
        return 2
    if args.close_delay < 0:
        parser.error("--close-delay must be non-negative")
    serve(args.port, args.file, args.cert, args.key, args.close_delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
