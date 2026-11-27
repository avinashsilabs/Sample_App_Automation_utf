#!/usr/bin/env python3
"""TLS chat server for wifi_ble_power_save (SDK openssl s_server role).

Listens on 0.0.0.0:5001 with the SDK server-cert.pem / server-key.pem.
Control is file-based so the Windows host can send and read over SSH:

  ssl_status.json   accepted / error / received
  ssl_rx.txt        bytes the DUT sent
  ssl_tx.pending    if present, send contents to the DUT then delete
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import threading
import time


def log(message):
    print("[ssl-chat] {}".format(message), flush=True)


def write_json(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(payload, handle)
    os.replace(tmp, path)


def write_text(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        handle.write(text)
    os.replace(tmp, path)


class ChatState(object):
    def __init__(self, workdir):
        self.workdir = workdir
        self.lock = threading.Lock()
        self.accepted = False
        self.error = None
        self.received = b""
        self.status_path = os.path.join(workdir, "ssl_status.json")
        self.rx_path = os.path.join(workdir, "ssl_rx.txt")
        self.tx_path = os.path.join(workdir, "ssl_tx.pending")
        write_text(self.rx_path, "")
        self.flush()

    def flush(self):
        with self.lock:
            received = self.received.decode("utf-8", "replace")
            accepted = self.accepted
            error = self.error
        write_json(
            self.status_path,
            {"accepted": accepted, "error": error, "received": received},
        )
        write_text(self.rx_path, received)

    def append(self, chunk):
        with self.lock:
            self.received += chunk
        self.flush()

    def pop_tx(self):
        try:
            with open(self.tx_path, "rb") as handle:
                data = handle.read()
        except OSError:
            return b""
        try:
            os.remove(self.tx_path)
        except OSError:
            pass
        return data


def handle_client(conn, state):
    log("DUT connected")
    with state.lock:
        state.accepted = True
        state.error = None
    state.flush()
    try:
        conn.settimeout(0.5)
        while True:
            outgoing = state.pop_tx()
            if outgoing:
                conn.sendall(outgoing)
                log("sent {} bytes".format(len(outgoing)))
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            except ssl.SSLError:
                continue
            if not chunk:
                log("DUT closed TLS")
                break
            state.append(chunk)
            log("recv {} bytes".format(len(chunk)))
    except Exception as exc:
        with state.lock:
            state.error = str(exc)
        state.flush()
        log("client error: {}".format(exc))
    finally:
        try:
            conn.close()
        except OSError:
            pass


# OpenSSL names for the Si91x TLS client (RSA/DHE/ECDHE CBC, TLS 1.2 only).
_SI91X_CIPHERS = (
    "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:"
    "AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:"
    "DEFAULT:@SECLEVEL=0"
)


def tls_context(cert, key):
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


def serve(port, cert, key, workdir):
    state = ChatState(workdir)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("0.0.0.0", port))
    raw.listen(5)
    context = tls_context(cert, key)
    log("listening TLS1.2 0.0.0.0:{}".format(port))
    while True:
        conn, addr = raw.accept()
        try:
            tls = context.wrap_socket(conn, server_side=True)
        except Exception as exc:
            log("handshake failed {}: {}".format(addr, exc))
            try:
                conn.close()
            except OSError:
                pass
            continue
        cipher = tls.cipher()
        log("accept {} cipher={}".format(addr, cipher[0] if cipher else "?"))
        thread = threading.Thread(target=handle_client, args=(tls, state))
        thread.daemon = True
        thread.start()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--workdir", default=".")
    args = parser.parse_args()
    try:
        serve(args.port, args.cert, args.key, args.workdir)
    except Exception as exc:
        print("ssl-chat fatal: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
