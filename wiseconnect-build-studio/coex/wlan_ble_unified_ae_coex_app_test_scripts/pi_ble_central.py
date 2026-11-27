#!/usr/bin/env python3
"""BLE central peer: pair with AE DUT and receive AABB/1AA1 notifications."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("[pi-ble] FAILED: bleak is not installed", file=sys.stderr, flush=True)
    raise SystemExit(2)


NOTIFY_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"


def log(message: str) -> None:
    print(f"[pi-ble] {message}", flush=True)


async def find_target(name: str, address: str, timeout: float):
    wanted = address.upper().strip()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        devices = await BleakScanner.discover(timeout=min(5.0, max(1.0, deadline - time.monotonic())))
        matches = [
            dev for dev in devices
            if (wanted and dev.address.upper() == wanted)
            or (not wanted and dev.name and name.lower() in dev.name.lower())
        ]
        if matches:
            matches.sort(key=lambda dev: getattr(dev, "rssi", -999) or -999, reverse=True)
            return matches[0]
    return None


async def run(args) -> int:
    device = await find_target(args.name, args.address, args.scan_timeout)
    if device is None:
        raise RuntimeError(f"DUT advertiser {args.address or args.name!r} not found")
    log(f"Found DUT {device.name} at {device.address}")

    notification_count = 0
    accepted = False

    def notification(_sender, data):
        nonlocal notification_count
        notification_count += 1
        if notification_count == 1 or notification_count % 100 == 0:
            log(f"DUT notifications received={notification_count} last_len={len(data)}")

    async with BleakClient(device, timeout=args.connect_timeout) as client:
        if not client.is_connected:
            raise RuntimeError("Bleak returned without a connected DUT")
        accepted = True
        log("CONNECTED: Pi central -> DUT peripheral")
        try:
            paired = await client.pair()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"authenticated SMP pairing failed: {exc}") from exc
        if paired is False:
            raise RuntimeError("authenticated SMP pairing was rejected")
        log("PAIRED: authenticated SMP completed")
        services = await client.get_services()
        characteristic = services.get_characteristic(NOTIFY_UUID)
        if characteristic is None:
            available = sorted(
                str(char.uuid) for service in services for char in service.characteristics
            )
            raise RuntimeError(
                f"DUT notification characteristic {NOTIFY_UUID} not found; "
                f"available={available}"
            )
        await client.start_notify(characteristic, notification)
        log(f"SUBSCRIBED: {NOTIFY_UUID}")
        started = time.monotonic()
        next_status = 10.0
        while time.monotonic() - started < args.hold:
            if args.stop_file and os.path.exists(args.stop_file):
                log("Stop requested by test runner")
                break
            if not client.is_connected:
                raise RuntimeError("established BLE link dropped; reconnect is disabled")
            elapsed = time.monotonic() - started
            if elapsed >= next_status:
                log(f"Central link stable at {elapsed:.1f}s; notifications={notification_count}")
                next_status += 10.0
            await asyncio.sleep(0.5)
        if notification_count < args.min_notifications:
            raise RuntimeError(
                f"only {notification_count} DUT notifications received; "
                f"need {args.min_notifications}"
            )
        await client.stop_notify(characteristic)
        log(f"PASS: central data path received {notification_count} notifications")
    if not accepted:
        raise RuntimeError("DUT connection was never accepted")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="BLE_AE_DEMO")
    parser.add_argument("--address", default="")
    parser.add_argument("--scan-timeout", type=float, default=60)
    parser.add_argument("--connect-timeout", type=float, default=60)
    parser.add_argument("--hold", type=float, default=240)
    parser.add_argument("--stop-file", default="")
    parser.add_argument("--min-notifications", type=int, default=10)
    args = parser.parse_args()
    try:
        return asyncio.get_event_loop().run_until_complete(run(args))
    except Exception as exc:  # noqa: BLE001
        log(f"FAILED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
