#!/usr/bin/env python3
"""Raspberry Pi BLE peer for wlan_ble_unified_coex_app.

advertise: Pi is a peripheral named SILABS_DEV; DUT connects as central.
connect:   Pi is a central; it connects to DUT BLE_8S2M_COEX_DEMO.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time


def log(message):
    print("[pi-ble] %s" % message, flush=True)


def run(command, timeout=15):
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def text(command, timeout=15):
    try:
        return run(command, timeout).stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def start_owner():
    owner = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1,
    )
    if owner.stdin is None:
        owner.terminate()
        raise RuntimeError("bluetoothctl stdin is unavailable")
    return owner


def send(owner, command, pause=0.25):
    if owner.poll() is not None:
        raise RuntimeError("persistent bluetoothctl owner exited")
    owner.stdin.write(command + "\n")
    owner.stdin.flush()
    time.sleep(pause)


def stop_owner(owner):
    if owner is None or owner.poll() is not None:
        return
    try:
        send(owner, "scan off", 0.1)
        send(owner, "advertise off", 0.1)
        send(owner, "quit", 0.1)
        owner.wait(timeout=5)
    except Exception:
        owner.terminate()
        try:
            owner.wait(timeout=3)
        except Exception:
            owner.kill()


def hci_connection_count():
    output = text(["hcitool", "-i", "hci0", "con"], 5)
    return sum(1 for line in output.splitlines() if " handle " in line.lower())


def device_connected(address):
    output = text(["bluetoothctl", "info", address], 8).lower()
    return "connected: yes" in output


def find_by_name(name):
    output = text(["bluetoothctl", "devices"], 8)
    for line in output.splitlines():
        match = re.match(r"Device\s+([0-9A-F:]{17})\s+(.+)$", line.strip(), re.I)
        if match and name.lower() in match.group(2).lower():
            return match.group(1).upper()
    return None


def configure_advertiser(owner, name):
    send(owner, "power on")
    # The agent must live in this persistent bluetoothctl process.  Registering
    # it from a one-shot bluetoothctl command unregisters it immediately when
    # that command exits, which leaves later SMP requests unanswered.
    send(owner, "agent NoInputNoOutput")
    send(owner, "default-agent")
    send(owner, "pairable on")
    send(owner, "discoverable on")
    send(owner, "system-alias %s" % name)
    # Register the SDK test service when supported by this BlueZ version.
    # Advertising/connection still proceeds if an older bluetoothctl ignores
    # the local-GATT commands; DUT UART profile evidence makes that visible.
    send(owner, "menu gatt")
    send(owner, "register-service 0000aabb-0000-1000-8000-00805f9b34fb")
    send(
        owner,
        "register-characteristic 00001aa1-0000-1000-8000-00805f9b34fb read,write,notify",
    )
    send(
        owner,
        "register-characteristic 00001bb1-0000-1000-8000-00805f9b34fb read,indicate",
    )
    send(owner, "register-application")
    send(owner, "back")
    send(owner, "menu advertise")
    send(owner, "name %s" % name)
    send(owner, "uuids 0000aabb-0000-1000-8000-00805f9b34fb")
    send(owner, "discoverable on")
    send(owner, "back")
    send(owner, "advertise on", 1.0)
    log("Advertising as %s with AABB/1AA1/1BB1 GATT registration" % name)


def advertise_mode(args):
    owner = start_owner()
    try:
        baseline = hci_connection_count()
        configure_advertiser(owner, args.name)
        deadline = time.monotonic() + args.connect_timeout
        while time.monotonic() < deadline:
            if owner.poll() is not None:
                raise RuntimeError("advertising owner exited")
            if hci_connection_count() > baseline:
                log("CONNECTED: DUT established its central-role link")
                break
            time.sleep(1)
        else:
            raise RuntimeError("DUT did not connect to Pi advertiser %r" % args.name)

        stop_at = time.monotonic() + args.hold
        reconnects = 0
        reconnect_deadline = None
        while time.monotonic() < stop_at:
            if args.stop_file and os.path.exists(args.stop_file):
                log("Stop requested by test-runner cleanup")
                return
            if hci_connection_count() <= baseline:
                if reconnect_deadline is None:
                    reconnects += 1
                    if reconnects > args.max_reconnects:
                        raise RuntimeError("DUT central-role BLE link repeatedly dropped")
                    reconnect_deadline = time.monotonic() + args.reconnect_timeout
                    log(
                        "Link establishment drop %d/%d; waiting for DUT retry"
                        % (reconnects, args.max_reconnects)
                    )
                elif time.monotonic() >= reconnect_deadline:
                    raise RuntimeError("DUT did not reconnect before retry timeout")
            elif reconnect_deadline is not None:
                reconnect_deadline = None
                log("RECONNECTED: DUT central-role link restored")
            time.sleep(1)
        log("Advertiser link stable for %.1fs" % args.hold)
    finally:
        stop_owner(owner)


def connect_mode(args):
    owner = start_owner()
    address = None
    try:
        send(owner, "power on")
        send(owner, "agent NoInputNoOutput")
        send(owner, "default-agent")
        send(owner, "pairable on")
        send(owner, "scan on", 1.0)
        deadline = time.monotonic() + args.connect_timeout
        while time.monotonic() < deadline and address is None:
            address = find_by_name(args.name)
            if address is None:
                time.sleep(1)
        if address is None:
            raise RuntimeError("DUT advertiser %r not found" % args.name)
        log("Found DUT %s at %s" % (args.name, address))
        send(owner, "connect %s" % address, 1.0)
        while time.monotonic() < deadline:
            if device_connected(address):
                log("CONNECTED: Pi established DUT peripheral-role link")
                break
            time.sleep(1)
        else:
            raise RuntimeError("Pi could not connect to DUT %s" % address)

        stop_at = time.monotonic() + args.hold
        while time.monotonic() < stop_at:
            if args.stop_file and os.path.exists(args.stop_file):
                log("Stop requested by test-runner cleanup")
                return
            if not device_connected(address):
                raise RuntimeError("DUT peripheral-role BLE link dropped")
            time.sleep(1)
        log("Central link stable for %.1fs" % args.hold)
    finally:
        if address:
            try:
                send(owner, "disconnect %s" % address, 0.2)
            except Exception:
                pass
        stop_owner(owner)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("advertise", "connect"))
    parser.add_argument("--name", required=True)
    parser.add_argument("--hold", type=float, default=180)
    parser.add_argument("--connect-timeout", type=float, default=120)
    parser.add_argument("--max-reconnects", type=int, default=2)
    parser.add_argument("--reconnect-timeout", type=float, default=30)
    parser.add_argument("--stop-file", default="")
    args = parser.parse_args()
    try:
        advertise_mode(args) if args.mode == "advertise" else connect_mode(args)
    except Exception as exc:
        log("FAILED: %s" % exc)
        return 1
    log("PASS: %s peer completed" % args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
