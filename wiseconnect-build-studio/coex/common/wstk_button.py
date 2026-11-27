#!/usr/bin/env python3
"""Press the DUT's buttons through the WSTK/WPK admin console (telnet 4902).

The mainboard exposes a `target button` command set on its admin port, so the
Out of Box Demo's BTN0 step runs unattended instead of asking someone to reach
over and press the board.

Python 3.13 dropped telnetlib, so this speaks just enough of the protocol:
refuse every option the console offers and strip the negotiation bytes.
"""

from __future__ import annotations

import re
import socket
import time
from typing import Optional

IAC = 255
DONT, DO, WONT, WILL = 254, 253, 252, 251
SB, SE = 250, 240

PROMPT = re.compile(r"W(?:ST|P)K>")


def log(message: str) -> None:
    print(f"[button] {message}", flush=True)


class WstkConsole:
    """A line-oriented session with the mainboard admin console."""

    def __init__(self, host: str, port: int = 4902, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._buffer = ""

    def __enter__(self) -> "WstkConsole":
        self.open()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def open(self) -> None:
        try:
            self.sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
        except OSError as exc:
            raise RuntimeError(
                f"Cannot reach the WSTK admin console at {self.host}:{self.port}: "
                f"{exc}. Only one telnet session is allowed at a time."
            ) from exc
        self.sock.settimeout(0.5)

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.send("quit")
            time.sleep(0.2)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _negotiate(self, data: bytes) -> str:
        """Strip telnet control sequences, refusing every offered option."""
        assert self.sock is not None
        out = bytearray()
        replies = bytearray()
        index = 0
        while index < len(data):
            byte = data[index]
            if byte != IAC:
                out.append(byte)
                index += 1
                continue
            if index + 1 >= len(data):
                break
            command = data[index + 1]
            if command in (DO, DONT, WILL, WONT):
                if index + 2 >= len(data):
                    break
                option = data[index + 2]
                if command == DO:
                    replies += bytes((IAC, WONT, option))
                elif command == WILL:
                    replies += bytes((IAC, DONT, option))
                index += 3
                continue
            if command == SB:
                end = data.find(bytes((IAC, SE)), index)
                index = len(data) if end == -1 else end + 2
                continue
            index += 2
        if replies:
            self.sock.sendall(bytes(replies))
        return out.decode("utf-8", errors="replace")

    def expect(self, pattern: re.Pattern[str], timeout: Optional[float] = None) -> str:
        """Read until pattern matches; return and consume the text up to it."""
        assert self.sock is not None
        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while True:
            match = pattern.search(self._buffer)
            if match:
                text = self._buffer[: match.end()]
                self._buffer = self._buffer[match.end() :]
                return text
            if time.time() > deadline:
                tail = self._buffer[-200:].replace("\r", "")
                raise TimeoutError(
                    f"Timed out waiting for {pattern.pattern!r} from "
                    f"{self.host}:{self.port}. Last output: {tail!r}"
                )
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise RuntimeError("WSTK console closed the connection")
            self._buffer += self._negotiate(chunk)

    def send(self, line: str) -> None:
        assert self.sock is not None
        self.sock.sendall((line + "\r\n").encode("ascii"))

    def command(self, line: str, timeout: Optional[float] = None) -> str:
        self.send(line)
        return self.expect(PROMPT, timeout)

    def wake(self) -> None:
        """Get a prompt, whether or not the console greets us first."""
        self.send("")
        self.expect(PROMPT)


def press_button(
    host: str,
    port: int = 4902,
    index: int = 0,
    hold_s: float = 1.5,
    timeout: float = 15.0,
) -> None:
    """Press and release BTN<index> on the mainboard's target."""
    with WstkConsole(host, port, timeout) as console:
        console.wake()
        log(f"Console ready at {host}:{port}")
        # Toggling the pin off and on clears any latched state from an
        # earlier run before the press registers.
        console.command(f"target button disable {index}")
        console.command(f"target button enable {index}")
        console.command(f"target button press {index}")
        log(f"BTN{index} pressed; holding {hold_s:.1f}s")
        time.sleep(hold_s)
        console.command(f"target button release {index}")
        log(f"BTN{index} released")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Press a WSTK target button")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=4902)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--hold", type=float, default=1.5)
    args = parser.parse_args()
    press_button(args.host, args.port, args.index, args.hold)
