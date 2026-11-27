"""Simplicity Connect BLE Wi-Fi commissioning command payloads."""

from __future__ import annotations

from typing import Optional

CMD_SSID = 2
CMD_SCAN = 3
CMD_DISCONNECT = 4
CMD_SECURITY = 5
CMD_PASSWORD = 6
CMD_CHECK_STATUS = 7
CMD_FW_VERSION = 8


def command_payload(command: int, value: Optional[str] = None) -> bytes:
    if value is None:
        return str(command).encode("utf-8")
    return f"{command}{len(value):02d}{value}".encode("utf-8")


def scan_payload() -> bytes:
    return command_payload(CMD_SCAN)


def ssid_payload(ssid: str) -> bytes:
    return command_payload(CMD_SSID, ssid)


def security_payload(mode: int) -> bytes:
    return command_payload(CMD_SECURITY, str(mode))


def password_payload(password: str) -> bytes:
    return command_payload(CMD_PASSWORD, password)


def status_payload() -> bytes:
    return command_payload(CMD_CHECK_STATUS)


def firmware_payload() -> bytes:
    return command_payload(CMD_FW_VERSION)


def disconnect_payload() -> bytes:
    return command_payload(CMD_DISCONNECT)
