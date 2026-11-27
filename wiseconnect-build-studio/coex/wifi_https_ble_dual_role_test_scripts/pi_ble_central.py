#!/usr/bin/env python3
"""Connect Pi-2 to SI_COEX_MAX_DEMO and hold the ACL.

Pi-2 is a dedicated central. BlueZ must stay up after the connect so the
kernel has an owner for the LE link. Killing bluetoothd after hcitool lecc
makes Linux send LL_TERMINATE (DUT reason 0x4E13) within a few seconds.
"""

from __future__ import print_function

import argparse
import os
import subprocess
import sys
import time

try:
    import dbus
    from gi.repository import GLib
except ImportError as exc:
    print("[pi-central] FAILED: install python3-dbus and python3-gi: %s" % exc, flush=True)
    raise SystemExit(2)


BLUEZ = "org.bluez"
ADAPTER_IFACE = "org.bluez.Adapter1"
DEVICE_IFACE = "org.bluez.Device1"
OM_IFACE = "org.freedesktop.DBus.ObjectManager"
PROP_IFACE = "org.freedesktop.DBus.Properties"


def log(message):
    print("[pi-central] %s" % message, flush=True)


def _run(command, timeout=20):
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def managed_objects(bus):
    return dbus.Interface(bus.get_object(BLUEZ, "/"), OM_IFACE).GetManagedObjects()


def adapter_path(bus, adapter):
    wanted = "/org/bluez/%s" % adapter
    objects = managed_objects(bus)
    if wanted not in objects:
        raise RuntimeError("Bluetooth adapter %s not found" % adapter)
    return wanted


def device_name(dev):
    return str(dev.get("Name") or "") or str(dev.get("Alias") or "")


def match_device(dev, name, address):
    if address:
        return str(dev.get("Address") or "").upper() == address.upper()
    seen = device_name(dev)
    if not seen:
        return False
    return seen == name or name.lower() in seen.lower()


def list_devices(bus):
    found = []
    for path, ifaces in managed_objects(bus).items():
        dev = ifaces.get(DEVICE_IFACE)
        if not dev:
            continue
        found.append((path, dev))
    return found


def find_device(bus, name, address):
    matches = [
        (path, dev)
        for path, dev in list_devices(bus)
        if match_device(dev, name, address)
    ]
    if not matches:
        return None, None
    matches.sort(key=lambda item: int(item[1].get("RSSI") or -999), reverse=True)
    return matches[0]


def remove_stale(bus, adapter, name, address):
    adapter_iface = dbus.Interface(bus.get_object(BLUEZ, adapter), ADAPTER_IFACE)
    removed = 0
    for path, dev in list_devices(bus):
        if not match_device(dev, name, address):
            continue
        if bool(dev.get("Connected")):
            continue
        try:
            adapter_iface.RemoveDevice(dbus.ObjectPath(path))
            removed += 1
        except Exception as exc:
            log("stale-device note: %s" % exc)
    if removed:
        log("Removed %d cached BlueZ device(s) before scan" % removed)


def start_discovery(bus, adapter):
    iface = dbus.Interface(bus.get_object(BLUEZ, adapter), ADAPTER_IFACE)
    try:
        iface.SetDiscoveryFilter(
            dbus.Dictionary(
                {"Transport": "le", "DuplicateData": False},
                signature="sv",
            )
        )
    except Exception as exc:
        log("Discovery filter note: %s" % exc)
    try:
        iface.StartDiscovery()
        log("LE scan started on %s" % adapter)
    except dbus.exceptions.DBusException as exc:
        if "InProgress" in str(exc):
            log("LE scan already running")
        else:
            raise


def stop_discovery(bus, adapter):
    iface = dbus.Interface(bus.get_object(BLUEZ, adapter), ADAPTER_IFACE)
    try:
        iface.StopDiscovery()
    except Exception:
        pass


def props(bus, path):
    return dbus.Interface(bus.get_object(BLUEZ, path), PROP_IFACE)


def is_connected(bus, path):
    try:
        return bool(props(bus, path).Get(DEVICE_IFACE, "Connected"))
    except Exception:
        return False


class PreLinkFailure(RuntimeError):
    """Safe to retry; the DUT has not accepted a stable ACL yet."""


def hci_link_active(address):
    try:
        result = _run(["hcitool", "-i", "hci0", "con"], timeout=5)
        table = result.stdout.decode("utf-8", "replace").upper()
        return address.upper() in table
    except Exception:
        return False


def tune_le_defaults():
    debug_dir = "/sys/kernel/debug/bluetooth/hci0"
    settings = {
        "conn_min_interval": "80",
        "conn_max_interval": "160",
        "conn_latency": "0",
        "supervision_timeout": "2000",
    }
    if not os.path.isdir(debug_dir):
        return
    applied = []
    for name, value in settings.items():
        path = os.path.join(debug_dir, name)
        if not os.path.exists(path):
            continue
        try:
            result = _run(["sh", "-c", "echo %s > %s" % (value, path)], timeout=5)
            if result.returncode == 0:
                applied.append("%s=%s" % (name, value))
        except Exception:
            pass
    if applied:
        log("Applied LE connection defaults: %s" % ", ".join(applied))


def connection_handle(address):
    result = _run(["hcitool", "-i", "hci0", "con"], timeout=5)
    text = result.stdout.decode("utf-8", "replace")
    wanted = address.upper()
    for line in text.splitlines():
        if wanted not in line.upper():
            continue
        parts = line.replace("<", " ").replace(">", " ").split()
        if "handle" not in [p.lower() for p in parts]:
            continue
        for idx, part in enumerate(parts):
            if part.lower() == "handle" and idx + 1 < len(parts):
                try:
                    return int(parts[idx + 1], 0)
                except ValueError:
                    return None
    return None


def apply_lecup(address):
    """Same units as POST /ble/connect (interval 1.25ms, timeout 10ms)."""
    handle = connection_handle(address)
    if handle is None:
        time.sleep(0.4)
        handle = connection_handle(address)
    if handle is None:
        log("lecup skipped: no HCI handle yet")
        return
    result = _run(
        [
            "hcitool",
            "lecup",
            "--handle",
            str(handle),
            "--min",
            "80",
            "--max",
            "160",
            "--latency",
            "0",
            "--timeout",
            "2000",
        ],
        timeout=8,
    )
    if result.returncode == 0:
        log("Applied lecup handle=%s min=80 max=160 timeout=2000" % handle)
    else:
        log(
            "lecup note: %s"
            % result.stdout.decode("utf-8", "replace").strip()
        )


def link_held(bus, path, address):
    """D-Bus Connected, or HCI ACL if Device1 lags on the second simultaneous link."""
    return is_connected(bus, path) or hci_link_active(address)


def connect_bluez(bus, path, timeout):
    """Own the ACL through BlueZ the same way /ble/connect (bond=false) does."""
    iface = dbus.Interface(bus.get_object(BLUEZ, path), DEVICE_IFACE)
    address = str(props(bus, path).Get(DEVICE_IFACE, "Address"))
    log("BlueZ Connect (bluetoothd stays up; no SMP)")
    try:
        iface.Connect()
    except dbus.exceptions.DBusException as exc:
        text = str(exc)
        if "Already Connected" not in text and "InProgress" not in text:
            raise PreLinkFailure(text)
        log("Connect note: %s" % text)
    deadline = time.monotonic() + max(8.0, float(timeout))
    while time.monotonic() < deadline:
        pump(200)
        if not link_held(bus, path, address):
            continue
        apply_lecup(address)
        time.sleep(2)
        pump(200)
        if not link_held(bus, path, address):
            raise PreLinkFailure(
                "immediate disconnect after connect (same check as /ble/connect)"
            )
        try:
            resolved = bool(props(bus, path).Get(DEVICE_IFACE, "ServicesResolved"))
        except Exception:
            resolved = False
        log(
            "CONNECTED via BlueZ; services_resolved=%s dbus=%s hci=%s "
            "(link held, no extra GATT)"
            % (resolved, is_connected(bus, path), hci_link_active(address))
        )
        return
    raise PreLinkFailure("BlueZ Connect timed out")


def pump(ms=50):
    ctx = GLib.MainContext.default()
    deadline = time.monotonic() + (ms / 1000.0)
    while time.monotonic() < deadline:
        if not ctx.iteration(False):
            break


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="SI_COEX_MAX_DEMO")
    parser.add_argument("--address", default="")
    parser.add_argument("--adapter", default="hci0")
    parser.add_argument("--scan-timeout", type=float, default=60)
    parser.add_argument("--connect-timeout", type=float, default=40)
    parser.add_argument("--hold", type=float, default=240)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--retry-delay", type=float, default=4)
    parser.add_argument("--settle", type=float, default=1)
    args = parser.parse_args()

    from dbus.mainloop.glib import DBusGMainLoop

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter = adapter_path(bus, args.adapter)
    address = (args.address or "").strip()
    last_error = None

    for attempt in range(1, max(1, args.retries) + 1):
        path = None
        try:
            remove_stale(bus, adapter, args.name, address)
            start_discovery(bus, adapter)
            log(
                "Scanning for %s (%.0fs), attempt %s/%s..."
                % (address or repr(args.name), args.scan_timeout, attempt, args.retries)
            )
            deadline = time.monotonic() + args.scan_timeout
            while time.monotonic() < deadline:
                pump(200)
                path, dev = find_device(bus, args.name, address)
                if path:
                    rssi = dev.get("RSSI")
                    log(
                        "Found %s address=%s rssi=%s"
                        % (device_name(dev) or args.name, dev.get("Address"), rssi)
                    )
                    break
            if path is None:
                seen = []
                for _path, dev in list_devices(bus):
                    label = device_name(dev) or "?"
                    seen.append("%s/%s" % (label, dev.get("Address")))
                raise RuntimeError(
                    "advertiser %r not found; BlueZ saw %s"
                    % (address or args.name, seen[:12] or "no devices")
                )

            if args.settle > 0:
                time.sleep(args.settle)
            stop_discovery(bus, adapter)

            target = str(props(bus, path).Get(DEVICE_IFACE, "Address"))
            tune_le_defaults()
            connect_bluez(bus, path, min(args.connect_timeout, 25.0))

            started = time.monotonic()
            next_status = 10.0
            hold_s = max(2.0, float(args.hold))
            while True:
                elapsed = time.monotonic() - started
                remaining = hold_s - elapsed
                if remaining <= 0:
                    log("Connection remained stable for %.1fs" % hold_s)
                    return 0
                pump(200)
                if not link_held(bus, path, target):
                    raise RuntimeError(
                        "Established BLE session failed; reconnect is disabled "
                        "(dropped after %.1fs, requested hold %.1fs)"
                        % (elapsed, hold_s)
                    )
                if elapsed >= next_status:
                    log("BLE HCI link stable at %.1fs" % elapsed)
                    next_status += 10.0
                time.sleep(min(1.0, remaining))
        except PreLinkFailure as exc:
            last_error = exc
            log("Pre-link attempt failed: %s" % exc)
            stop_discovery(bus, adapter)
            if attempt < args.retries:
                time.sleep(args.retry_delay)
        except Exception as exc:
            last_error = exc
            log("FAILED after link-up: %s" % exc)
            stop_discovery(bus, adapter)
            break

    log("FAILED: BLE connect failed after %s attempt(s): %s" % (args.retries, last_error))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
