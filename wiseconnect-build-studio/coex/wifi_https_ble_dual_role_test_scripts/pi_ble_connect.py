#!/usr/bin/env python3
"""Connect to SI_COEX_MAX_DEMO while BlueZ discovery stays on.

Same scan-then-connect path as the working provisioning provisioner.
Python 3.7 / bleak 0.19.
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
import time

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("ERROR: bleak is not installed on this Pi", file=sys.stderr)
    raise SystemExit(2)


def log(message):
    print("[pi-ble] %s" % message, flush=True)


def _rssi(device):
    value = getattr(device, "rssi", None)
    return -999 if value is None else int(value)


def _pick(devices, name, address):
    if address:
        wanted = address.upper()
        matches = [dev for dev in devices if dev.address.upper() == wanted]
    else:
        matches = [
            dev
            for dev in devices
            if dev.name == name
            or (dev.name and name.lower() in dev.name.lower())
        ]
    if not matches:
        return None, []
    matches.sort(key=_rssi, reverse=True)
    return matches[0], matches


def forget_device(address):
    try:
        subprocess.run(
            ["bluetoothctl", "remove", address],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
        log("Cleared BlueZ cache for %s" % address)
    except Exception as exc:  # noqa: BLE001
        log("BlueZ cache clear skipped: %s" % exc)


async def scan_and_connect(
    name,
    address,
    scan_s,
    connect_s,
    hold_s,
    retries,
    retry_delay,
    settle,
):
    last_error = None
    if address:
        log("Scanning for address %s (%.0fs)..." % (address.upper(), scan_s))
    else:
        log("Scanning for %r (%.0fs)..." % (name, scan_s))

    for attempt in range(1, retries + 1):
        scanner = BleakScanner()
        await scanner.start()
        stop_scanner = True
        try:
            device = None
            deadline = time.time() + scan_s
            while time.time() < deadline:
                await asyncio.sleep(0.5)
                device, matches = _pick(list(scanner.discovered_devices), name, address)
                if device:
                    if len(matches) > 1:
                        listing = ", ".join(
                            "%s rssi=%s" % (dev.address, _rssi(dev)) for dev in matches
                        )
                        log("%s boards advertise %r: %s" % (len(matches), name, listing))
                    break
            if device is None:
                seen = len(list(scanner.discovered_devices))
                last_error = RuntimeError(
                    "BLE advertiser %r not found; saw %s device(s)"
                    % (address or name, seen)
                )
                log(str(last_error))
                continue
            log(
                "Found %s address=%s rssi=%s"
                % (device.name, device.address, _rssi(device))
            )
            if attempt == 1 and settle > 0:
                log("Waiting %.1fs with scan still on before connect..." % settle)
                await asyncio.sleep(settle)

            # Keep the scanner running. BlueZ on this Pi aborts connect
            # (Software caused connection abort) if discovery has stopped.
            disconnected = asyncio.Event()

            def on_disconnect(_client):
                disconnected.set()

            client = BleakClient(
                device,
                timeout=connect_s,
                disconnected_callback=on_disconnect,
            )
            try:
                log("Connect attempt %s/%s to %s..." % (attempt, retries, device.address))
                await client.connect()
                services = list(client.services) if client.services else []
                if not services:
                    raise RuntimeError("Connected but no GATT services discovered")
                log("CONNECTED %s; %s GATT service(s)" % (device.address, len(services)))
                hold_started = time.monotonic()
                try:
                    # Keep discovery running during the observation period.
                    # This Pi's BlueZ stack can abort or destabilize a link
                    # when discovery is stopped around connection setup.
                    await asyncio.wait_for(disconnected.wait(), timeout=hold_s)
                except asyncio.TimeoutError:
                    log("Connection remained stable for %.1fs" % hold_s)
                    return client, device
                elapsed = time.monotonic() - hold_started
                raise RuntimeError(
                    "BLE dropped after %.1fs (requested hold %.1fs)"
                    % (elapsed, hold_s)
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                log("Connection attempt failed: %s" % exc)
                try:
                    if client.is_connected:
                        await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
                if attempt < retries:
                    await scanner.stop()
                    stop_scanner = False
                    forget_device(device.address)
                    await asyncio.sleep(retry_delay)
        finally:
            if stop_scanner:
                try:
                    await scanner.stop()
                except Exception as exc:  # noqa: BLE001
                    log("Scanner stop note: %s" % exc)

    raise RuntimeError(
        "BLE connect failed after %s attempt(s): %s" % (retries, last_error)
    )


async def run(args):
    hold_s = max(2.0, float(args.hold))
    client, device = await scan_and_connect(
        args.name,
        (args.address or "").strip() or None,
        args.scan_timeout,
        args.connect_timeout,
        hold_s,
        args.retries,
        args.retry_delay,
        args.settle,
    )
    try:
        return device.address
    finally:
        try:
            if client.is_connected:
                await asyncio.wait_for(client.disconnect(), timeout=5)
        except Exception as exc:  # noqa: BLE001
            log("Disconnect note: %s" % exc)
        log("DISCONNECTED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="SI_COEX_MAX_DEMO")
    parser.add_argument("--address", default="")
    parser.add_argument("--scan-timeout", type=float, default=30)
    parser.add_argument("--connect-timeout", type=float, default=75)
    parser.add_argument("--hold", type=float, default=8)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--retry-delay", type=float, default=4)
    parser.add_argument("--settle", type=float, default=3)
    args = parser.parse_args()
    try:
        address = asyncio.get_event_loop().run_until_complete(run(args))
    except Exception as exc:  # noqa: BLE001
        log("FAILED: %s" % exc)
        return 1
    print("OK %s" % address, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
