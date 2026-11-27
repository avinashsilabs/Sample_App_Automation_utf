#!/usr/bin/env python3
"""BLE Wi-Fi commissioning executed on the Raspberry Pi (BlueZ + bleak).

Deployed over SSH by pi_ble.py and invoked with a JSON config. Kept
Python 3.7 compatible because lab Pis still run Raspberry Pi OS Buster.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from ble_protocol import (
        firmware_payload,
        password_payload,
        scan_payload,
        security_payload,
        ssid_payload,
        status_payload,
    )
except ImportError as exc:  # pragma: no cover - deployment error
    print(f"ERROR: ble_protocol.py missing next to this script: {exc}", file=sys.stderr)
    raise SystemExit(2)

try:
    from bleak import BleakClient, BleakScanner
except ImportError:  # pragma: no cover - preflight installs bleak
    print("ERROR: bleak is not installed on this Pi", file=sys.stderr)
    raise SystemExit(2)


def log(message: str) -> None:
    print(f"[pi-ble] {message}", flush=True)


def _rssi(device) -> int:
    value = getattr(device, "rssi", None)
    return -999 if value is None else int(value)


def _pick(devices: List[Any], name: str, address: Optional[str]):
    """Choose the DUT among the devices seen so far.

    Several boards on the bench advertise the same name, so prefer a pinned
    address and otherwise take the strongest signal (the DUT sits next to
    the Pi, distant boards report much weaker RSSI).
    """
    if address:
        wanted = address.upper()
        matches = [dev for dev in devices if dev.address.upper() == wanted]
    else:
        matches = [dev for dev in devices if dev.name == name]
    if not matches:
        return None, []
    matches.sort(key=_rssi, reverse=True)
    return matches[0], matches


def forget_device(address: str) -> None:
    """Drop BlueZ's cached entry for the DUT.

    A stale cache (wrong address type or leftover GATT database from an
    earlier firmware) makes bluetoothd reject the connection with
    'Input/output error' until the device is removed.
    """
    try:
        subprocess.run(
            ["bluetoothctl", "remove", address],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
        log(f"Cleared BlueZ cache for {address}")
    except Exception as exc:  # noqa: BLE001
        log(f"BlueZ cache clear skipped: {exc}")


async def scan_and_connect(
    ble: Dict[str, Any], name: str, address: Optional[str] = None
) -> BleakClient:
    """Find the DUT and connect while discovery stays active.

    BlueZ on the lab Pi rejects a connect with 'Input/output error' when
    discovery has already been stopped, the same way `bluetoothctl connect`
    only works after `scan on`. So keep the scanner running until the link
    is up, and retry with a fresh advertisement each time.
    """
    scan_window = float(ble.get("scan_timeout_s", 30))
    timeout = float(ble.get("connect_timeout_s", 75))
    retries = int(ble.get("connect_retries", 5))
    retry_delay = float(ble.get("retry_delay_s", 4))
    settle = float(ble.get("pre_connect_delay_s", 3))
    last_error: Optional[Exception] = None

    if address:
        log(f"Scanning for address {address.upper()} ({scan_window:.0f}s)...")
    else:
        log(f"Scanning for {name!r} ({scan_window:.0f}s)...")

    for attempt in range(1, retries + 1):
        # Each attempt rediscovers the DUT. A device object from an earlier
        # scan goes stale once BlueZ drops it -- especially after we clear its
        # cache -- and connecting to it fails with "was not found".
        scanner = BleakScanner()
        await scanner.start()
        stop_scanner = True
        try:
            device = None
            deadline = time.time() + scan_window
            while time.time() < deadline:
                await asyncio.sleep(0.5)
                device, matches = _pick(list(scanner.discovered_devices), name, address)
                if device:
                    if len(matches) > 1:
                        listing = ", ".join(
                            f"{dev.address} rssi={_rssi(dev)}" for dev in matches
                        )
                        log(f"{len(matches)} boards advertise {name!r}: {listing}")
                        log("Using the closest one; set ble.address to pin a board")
                    break
            if device is None:
                seen = len(list(scanner.discovered_devices))
                last_error = RuntimeError(
                    f"BLE advertiser {address or name!r} not found; "
                    f"saw {seen} device(s)"
                )
                log(str(last_error))
                continue
            log(f"Found {device.name} address={device.address} rssi={_rssi(device)}")

            if attempt == 1 and settle > 0:
                log(f"Waiting {settle:.1f}s for the DUT GATT database to settle...")
                await asyncio.sleep(settle)

            # Pass the scanned device, not a bare address, so BlueZ keeps the
            # advertised address type instead of guessing it.
            client = BleakClient(device, timeout=timeout)
            try:
                log(f"Connect attempt {attempt}/{retries} to {device.address}...")
                await client.connect()
                services = list(client.services) if client.services else []
                if not services:
                    raise RuntimeError("Connected but no GATT services discovered")
                log(f"Connected; {len(services)} GATT service(s)")
                return client
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                log(f"Connect failed: {exc}")
                try:
                    if client.is_connected:
                        await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
                if attempt < retries:
                    if bool(ble.get("clear_bluez_cache", True)):
                        await scanner.stop()
                        stop_scanner = False
                        forget_device(device.address)
                    await asyncio.sleep(retry_delay)
        finally:
            if stop_scanner:
                try:
                    await scanner.stop()
                except Exception as exc:  # noqa: BLE001
                    log(f"Scanner stop note: {exc}")

    raise RuntimeError(f"BLE connect failed after {retries} attempt(s): {last_error}")


async def disconnect_quietly(client: Optional[BleakClient], notify_uuid: str) -> None:
    if client is None:
        return
    try:
        if client.is_connected:
            try:
                await client.stop_notify(notify_uuid)
            except Exception:  # noqa: BLE001
                pass
            await asyncio.wait_for(client.disconnect(), timeout=5)
            log("BLE disconnected")
    except Exception as exc:  # noqa: BLE001
        log(f"BLE disconnect note: {exc}")


async def provision(config: Dict[str, Any]) -> Dict[str, Any]:
    ble = config["ble"]
    wifi = config["wifi"]
    name = str(ble.get("device_name", "BLE_CONFIGURATOR"))
    address = str(ble.get("address") or "").strip() or None
    write_uuid = ble["write_uuid"]
    read_uuid = ble["read_uuid"]
    notify_uuid = ble["notify_uuid"]

    wanted = str(wifi["ssid"])
    password = str(wifi.get("password") or "")
    security = int(wifi.get("security", 2))

    scan_window = float(ble.get("scan_timeout_s", 30))
    scan_retries = int(ble.get("ssid_scan_retries", 5))
    scan_retry_delay = float(ble.get("ssid_scan_retry_delay_s", 2))
    restart_after = int(ble.get("ssid_scan_fail_before_ble_restart", 3))
    restart_limit = int(ble.get("ble_restart_retries", 2))
    restart_settle = float(ble.get("ble_restart_settle_s", 5))

    result: Dict[str, Any] = {"ok": False, "aps": [], "ip": None, "mac": None}
    seen: List[Dict[str, Any]] = []
    aps: List[Dict[str, Any]] = []
    notify_event = asyncio.Event()

    def on_notify(_sender, data: bytearray) -> None:
        # Notification layout: [security_u8][','][SSID bytes]
        if len(data) < 3:
            return
        ssid = bytes(data[2:]).decode("utf-8", errors="ignore").strip("\x00").strip()
        ssid = "".join(ch for ch in ssid if ch.isprintable())
        if ssid:
            entry = {"security": int(data[0]), "ssid": ssid}
            if entry not in aps:
                aps.append(entry)
                log(f"AP: {ssid!r} security={data[0]}")
        notify_event.set()

    client: Optional[BleakClient] = None
    try:
        client = await scan_and_connect(ble, name, address)
        await client.start_notify(notify_uuid, on_notify)
        await asyncio.sleep(0.5)

        await client.write_gatt_char(write_uuid, firmware_payload(), response=True)
        await asyncio.sleep(0.5)
        try:
            firmware = bytes(await client.read_gatt_char(read_uuid))
            log(f"Firmware/status bytes: {firmware.hex()}")
        except Exception as exc:  # noqa: BLE001
            log(f"Firmware read skipped: {exc}")

        match: Optional[Dict[str, Any]] = None
        attempt = 0
        consecutive_failures = 0
        restarts = 0
        while attempt < scan_retries and match is None:
            attempt += 1
            aps.clear()
            notify_event.clear()
            await client.write_gatt_char(write_uuid, scan_payload(), response=True)
            log(f"Wi-Fi scan {attempt}/{scan_retries} for SSID={wanted!r}...")
            deadline = time.time() + scan_window
            while time.time() < deadline:
                try:
                    await asyncio.wait_for(notify_event.wait(), timeout=1)
                    notify_event.clear()
                except asyncio.TimeoutError:
                    pass
                match = next((ap for ap in aps if ap["ssid"] == wanted), None)
                if match:
                    break
            for entry in aps:
                if entry not in seen:
                    seen.append(entry)
            result["aps"] = list(seen)
            if match:
                log(f"Found {wanted!r} (security={match['security']})")
                break

            consecutive_failures += 1
            log(f"SSID {wanted!r} not seen on scan {attempt}")
            if (
                consecutive_failures >= restart_after
                and restarts < restart_limit
                and attempt < scan_retries
            ):
                restarts += 1
                log(f"Restarting BLE link ({restarts}/{restart_limit}) after repeated scan failures")
                await disconnect_quietly(client, notify_uuid)
                client = None
                await asyncio.sleep(restart_settle)
                client = await scan_and_connect(ble, name, address)
                await client.start_notify(notify_uuid, on_notify)
                await asyncio.sleep(0.5)
                consecutive_failures = 0
            elif attempt < scan_retries:
                await asyncio.sleep(scan_retry_delay)

        if not match:
            raise RuntimeError(
                f"Configured SSID {wanted!r} not found after {attempt} scan(s); "
                f"seen={[ap['ssid'] for ap in seen] or ['(none)']}"
            )

        result["ssid_found"] = True
        result["ssid"] = wanted
        if not wifi.get("security_override", False):
            security = int(match["security"])
        result["security"] = security

        # A 0x02/0x00 status is one join attempt. Writing the password again
        # sets WIFI_APP_JOIN_STATE, so retry before failing the run.
        join_retries = max(1, int(ble.get("join_retries", 3)))
        poll_s = float(ble.get("ble_join_poll_s", 20))
        explicit_failure = False
        for join_try in range(1, join_retries + 1):
            await client.write_gatt_char(write_uuid, ssid_payload(wanted), response=True)
            await asyncio.sleep(0.5)
            await client.write_gatt_char(
                write_uuid, security_payload(security), response=True
            )
            await asyncio.sleep(0.5)
            if security != 0 and password:
                await client.write_gatt_char(
                    write_uuid, password_payload(password), response=True
                )
                await asyncio.sleep(0.5)
            result["credentials_sent"] = True
            log(f"Credentials sent (attempt {join_try}/{join_retries})")
            log(f"Polling join status for up to {poll_s:.0f}s...")
            deadline = time.time() + poll_s
            while time.time() < deadline:
                try:
                    if not client.is_connected:
                        log("BLE link dropped (expected once the DUT joins Wi-Fi)")
                        result["ble_disconnected_after_provision"] = True
                        break
                    await client.write_gatt_char(
                        write_uuid, status_payload(), response=True
                    )
                    await asyncio.sleep(0.5)
                    data = await client.read_gatt_char(read_uuid)
                    log(f"Status bytes: {list(data)}")
                    if len(data) >= 2 and data[0] == 0x02:
                        if data[1] == 0x01:
                            result["ok"] = True
                            if len(data) >= 14:
                                result["mac"] = ":".join(f"{b:02X}" for b in data[3:9])
                                result["ip"] = ".".join(str(b) for b in data[10:14])
                            log(f"Join OK mac={result['mac']} ip={result['ip']}")
                        else:
                            log("DUT reported Wi-Fi join failure (0x02/0x00)")
                        break
                    if len(data) >= 2 and data[0] == 0x07 and data[1] == 0x01:
                        result["ok"] = True
                        log("DUT already connected (status 0x07)")
                        break
                except Exception as exc:  # noqa: BLE001
                    log(f"Join poll ended: {exc}")
                    result["ble_disconnected_after_provision"] = True
                    break
                await asyncio.sleep(1)
            if result["ok"] or result.get("ble_disconnected_after_provision"):
                break
            if join_try < join_retries and client.is_connected:
                log("Sending credentials again")
                await asyncio.sleep(2)
                continue
            explicit_failure = True
            result["error"] = "DUT reported Wi-Fi join failure (0x02/0x00)"
            break

        if not result["ok"] and result.get("credentials_sent") and not explicit_failure:
            result["ok"] = True
            result["join_pending_uart"] = True
            log("Credentials delivered; host will confirm WLAN/IP from DUT UART")
    finally:
        await disconnect_quietly(client, notify_uuid)

    if not result["ok"]:
        raise RuntimeError(result.get("error") or "BLE Wi-Fi provisioning failed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    try:
        result = asyncio.get_event_loop().run_until_complete(provision(config))
    except Exception as exc:  # noqa: BLE001
        log(f"FAILED: {exc}")
        Path(args.result).write_text(
            json.dumps({"ok": False, "error": str(exc)}, indent=2), encoding="utf-8"
        )
        return 1
    Path(args.result).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
