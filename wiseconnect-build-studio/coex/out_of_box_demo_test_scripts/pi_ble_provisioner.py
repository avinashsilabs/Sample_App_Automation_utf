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


def _normalize_mac(value: Optional[str]) -> Optional[str]:
    text = str(value or "").strip().upper().replace("-", ":")
    if not text:
        return None
    parts = [p for p in text.split(":") if p]
    if len(parts) == 6 and all(len(p) <= 2 for p in parts):
        return ":".join("{0:0>2}".format(p) for p in parts)
    return text


def _rssi(device) -> int:
    value = getattr(device, "rssi", None)
    return -999 if value is None else int(value)


def _advertised_name(device) -> str:
    return (getattr(device, "name", None) or "").strip()


def _pick(devices: List[Any], name: str, address: Optional[str]):
    """Choose the DUT only when the advert matches the UART self identity.

    A MAC match with a different name, or a shared name on another MAC, is
    left for a later advertisement. Several boards advertise BLE_CONFIGURATOR.
    """
    wanted_mac = _normalize_mac(address)
    wanted_name = (name or "").strip()
    matches = []
    for dev in devices:
        dev_mac = _normalize_mac(str(getattr(dev, "address", "")))
        dev_name = _advertised_name(dev)
        if wanted_mac and dev_mac != wanted_mac:
            continue
        if wanted_name and dev_name != wanted_name:
            continue
        if not wanted_mac and not wanted_name:
            continue
        matches.append(dev)
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


def recover_adapter(address: str) -> None:
    """Reset BlueZ's link state after a controller-level connect failure.

    Removing a device record only clears its GATT/address cache.  It does not
    clear a pending ACL link in bluetoothd or the controller, both of which
    commonly surface as ``org.bluez.Error.Failed: Input/output error`` on the
    next Connect call.  A short power cycle does, and is available to an
    unprivileged user when that user already has BlueZ D-Bus access.
    """
    commands = (
        ("disconnect", address),
        ("remove", address),
        ("power", "off"),
        ("power", "on"),
    )
    try:
        for command in commands:
            subprocess.run(
                ["bluetoothctl", *command],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
            )
        log("Recovered BlueZ adapter state after connect I/O error")
    except Exception as exc:  # noqa: BLE001
        # The ordinary retry remains useful on older BlueZ versions where
        # bluetoothctl power requires extra privileges.
        log(f"BlueZ adapter recovery skipped: {exc}")


def is_io_connect_error(exc: Exception) -> bool:
    """Return whether BlueZ rejected link establishment at the controller."""
    return "input/output error" in str(exc).lower()


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
    use_address = _normalize_mac(address)
    require_self = bool(ble.get("require_self_identity", False))

    if require_self and not use_address:
        raise RuntimeError(
            "ble.address (DUT self MAC) is required before Pi BLE connect; "
            "wait for UART '[BLE self] name=... address=...' first"
        )

    if use_address:
        log(
            "Scanning for self MAC {0} name={1!r} ({2:.0f}s)...".format(
                use_address, name, scan_window
            )
        )
    else:
        log(f"Scanning for {name!r} ({scan_window:.0f}s)...")

    if use_address and bool(ble.get("clear_bluez_cache", True)):
        log("Dropping stale BlueZ device record for {0} before connect".format(use_address))
        forget_device(use_address)

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
                device, matches = _pick(
                    list(scanner.discovered_devices), name, use_address
                )
                if device:
                    dev_mac = _normalize_mac(str(getattr(device, "address", "")))
                    dev_name = _advertised_name(device)
                    if use_address and dev_mac != use_address:
                        log("Reject {0}; self MAC is {1}".format(dev_mac, use_address))
                        device = None
                        continue
                    if name and dev_name != name:
                        log("Reject name {0!r}; self name is {1!r}".format(dev_name, name))
                        device = None
                        continue
                    log(
                        "Verified self DUT name={0!r} address={1} rssi={2}; connecting to this device".format(
                            dev_name, dev_mac, _rssi(device)
                        )
                    )
                    if not use_address and len(matches) > 1:
                        listing = ", ".join(
                            f"{dev.address} rssi={_rssi(dev)}" for dev in matches
                        )
                        log(f"{len(matches)} boards advertise {name!r}: {listing}")
                        log("Using the closest one; UART self MAC pins a board")
                    break
            if device is None:
                seen = len(list(scanner.discovered_devices))
                last_error = RuntimeError(
                    f"BLE advertiser {use_address or name!r} not found; "
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
                    if (
                        is_io_connect_error(exc)
                        and bool(ble.get("recover_adapter_on_connect_failure", True))
                    ):
                        recover_adapter(device.address)
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
        log("Credentials sent (SSID/SECURITY/PASSWORD)")

        # The demo disables BLE once WLAN comes up, so a dropped link here is
        # normal; the host confirms the join from the DUT UART log.
        poll_s = float(ble.get("ble_join_poll_s", 20))
        log(f"Polling join status for up to {poll_s:.0f}s...")
        deadline = time.time() + poll_s
        explicit_failure = False
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
                        explicit_failure = True
                        result["error"] = "DUT reported Wi-Fi join failure (0x02/0x00)"
                        log(result["error"])
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

    result_path = Path(args.result)
    if result_path.is_file():
        result_path.unlink()
        log("Removed stale result file {0}".format(result_path.name))

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
