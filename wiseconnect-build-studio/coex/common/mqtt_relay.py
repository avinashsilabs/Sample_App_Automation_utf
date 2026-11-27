#!/usr/bin/env python3
"""TCP relay that lets the DUT reach an internet MQTT broker.

The bench network blocks outbound MQTT ports (1883/1884/8883 all time out
from the lab LAN), but this test host also has a corporate interface that
reaches test.mosquitto.org. The relay listens on the host's lab address and
forwards each connection to the real broker, so the DUT still talks to
test.mosquitto.org rather than a substitute broker.
"""

from __future__ import annotations

import socket
import threading
from typing import Optional


def log(message: str) -> None:
    print(f"[relay] {message}", flush=True)


def host_address_towards(peer: str) -> str:
    """Return this host's IP on the route towards peer (no traffic sent)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((peer, 9))
        return probe.getsockname()[0]
    finally:
        probe.close()


def _pump(source: socket.socket, sink: socket.socket) -> None:
    try:
        while True:
            chunk = source.recv(4096)
            if not chunk:
                break
            sink.sendall(chunk)
    except OSError:
        pass
    finally:
        for sock in (source, sink):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class MqttRelay:
    def __init__(
        self,
        target_host: str,
        target_port: int = 1883,
        listen_port: int = 1883,
        listen_host: str = "0.0.0.0",
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.listen_port = listen_port
        self.listen_host = listen_host
        self.connections = 0
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.listen_host, self.listen_port))
        except OSError as exc:
            server.close()
            raise RuntimeError(
                f"Cannot listen on {self.listen_host}:{self.listen_port} for the "
                f"MQTT relay: {exc}"
            ) from exc
        server.listen(8)
        server.settimeout(0.5)
        self._server = server
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        log(
            f"Forwarding {self.listen_host}:{self.listen_port} -> "
            f"{self.target_host}:{self.target_port}"
        )

    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                client, peer = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._serve, args=(client, peer), daemon=True
            ).start()

    def _serve(self, client: socket.socket, peer) -> None:
        self.connections += 1
        log(f"{peer[0]}:{peer[1]} connected -> {self.target_host}")
        try:
            upstream = socket.create_connection(
                (self.target_host, self.target_port), timeout=15
            )
        except OSError as exc:
            log(f"Upstream connect failed: {exc}")
            client.close()
            return
        client.settimeout(None)
        upstream.settimeout(None)
        threading.Thread(target=_pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=_pump, args=(upstream, client), daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        log(f"Stopped after {self.connections} connection(s)")
