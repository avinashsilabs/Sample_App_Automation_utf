#!/usr/bin/env python3
"""Raw TCP sink for the SiWx91x TCP_TX throughput example."""

from __future__ import annotations

import argparse
import socket
import threading
import time


def handle(conn: socket.socket, addr) -> None:
    started = time.monotonic()
    total = 0
    try:
        conn.settimeout(45)
        while True:
            data = conn.recv(65536)
            if not data:
                break
            total += len(data)
    except (OSError, socket.timeout) as exc:
        print(f"[tcp-sink] {addr[0]}:{addr[1]} ended: {exc}", flush=True)
    finally:
        duration = max(0.001, time.monotonic() - started)
        mbps = total * 8.0 / duration / 1_000_000.0
        print(
            f"[tcp-sink] complete peer={addr[0]}:{addr[1]} bytes={total} "
            f"seconds={duration:.3f} mbps={mbps:.3f}",
            flush=True,
        )
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", args.port))
    server.listen(4)
    print(f"[tcp-sink] listening on 0.0.0.0:{args.port}", flush=True)
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    raise SystemExit(main())
