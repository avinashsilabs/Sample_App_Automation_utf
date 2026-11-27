#!/usr/bin/env python3
"""BLE simple-chat central for wifi_ble_power_save (runs on the Pi).

Connects to WLAN_BLE_SIMPLE_CHAT, enables 0x1BB1 notifications, and
accepts file-based write commands on 0x1AA1.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import time


def log(message):
    print("[pi-ble] {}".format(message), flush=True)


def forget_device(address):
    # Every Coex firmware advertises from the same board address, so BlueZ
    # can hold another app's GATT objects and bleak then fails with a
    # KeyError on 'org.bluez.GattService1'.
    try:
        subprocess.run(
            ["bluetoothctl", "remove", address],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
        log("Cleared BlueZ cache for {}".format(address))
    except Exception as exc:
        log("BlueZ cache clear skipped: {}".format(exc))


def write_json(path, payload):
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(payload, handle)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o666)
    except OSError:
        pass


def read_json(path):
    try:
        with open(path, "r") as handle:
            return json.load(handle)
    except Exception:
        return None


class ChatCentral(object):
    def __init__(self, args):
        self.args = args
        self.notifications = []
        self.connected = False
        self.error = None
        self.last_cmd_id = 0
        self.status_path = args.status
        self.cmd_path = args.cmd
        self.flush()

    def flush(self):
        write_json(
            self.status_path,
            {
                "ok": self.connected and not self.error,
                "connected": self.connected,
                "error": self.error,
                "notifications": list(self.notifications),
                "last_cmd_id": self.last_cmd_id,
            },
        )

    def on_notify(self, _sender, data):
        text = data.decode("utf-8", "replace")
        self.notifications.append(text)
        log("notify: {!r}".format(text))
        self.flush()

    def _matches(self, item, name):
        local = item.name or ""
        return local == name or name.lower() in local.lower()

    async def _connect(self, scanner):
        from bleak import BleakClient

        name = self.args.name
        last_error = RuntimeError("Advertiser {} not found".format(name))
        # Discovery has to stay on. This Pi's BlueZ drops the link, and bleak
        # then raises KeyError('org.bluez.GattService1'), if scanning stops
        # before the sleeping DUT has published its GATT table.
        for attempt in range(1, 5):
            device = None
            deadline = time.time() + 12.0
            while time.time() < deadline and device is None:
                await asyncio.sleep(0.5)
                for item in list(scanner.discovered_devices):
                    if self._matches(item, name):
                        device = item
                        break
            if device is None:
                last_error = RuntimeError("Advertiser {} not found".format(name))
                log("BLE attempt {}: {}".format(attempt, last_error))
                continue
            log(
                "Connect attempt {}/4 to {} {}".format(
                    attempt, device.address, device.name
                )
            )
            client = BleakClient(device, timeout=20.0)
            try:
                await client.connect()
                services = []
                for _ in range(10):
                    services = list(client.services) if client.services else []
                    if services:
                        break
                    await asyncio.sleep(0.4)
                if not services:
                    raise RuntimeError("Connected but no GATT services")
                log(
                    "Connected; {} service(s); enabling notify {}".format(
                        len(services), self.args.notify_uuid
                    )
                )
                await client.start_notify(self.args.notify_uuid, self.on_notify)
                self.connected = True
                self.flush()
                return client
            except Exception as exc:
                last_error = exc
                self.connected = False
                log("BLE attempt {} failed: {}".format(attempt, exc))
                try:
                    if client.is_connected:
                        await client.disconnect()
                except Exception:
                    pass
                forget_device(device.address)
                await asyncio.sleep(2.0)
        raise last_error

    async def run(self):
        from bleak import BleakScanner

        log("Scanning for {} ...".format(self.args.name))
        scanner = BleakScanner()
        await scanner.start()
        client = None
        try:
            client = await self._connect(scanner)
            stop_at = time.time() + float(self.args.hold_s)
            while time.time() < stop_at:
                cmd = read_json(self.cmd_path)
                if isinstance(cmd, dict):
                    cmd_id = int(cmd.get("id") or 0)
                    if cmd_id > self.last_cmd_id:
                        op = str(cmd.get("op") or "")
                        if op == "write":
                            payload = str(cmd.get("text") or "").encode("utf-8")
                            log(
                                "write {} bytes on {}".format(
                                    len(payload), self.args.write_uuid
                                )
                            )
                            await client.write_gatt_char(
                                self.args.write_uuid, payload, response=True
                            )
                        elif op == "stop":
                            log("stop requested")
                            self.last_cmd_id = cmd_id
                            self.flush()
                            return
                        self.last_cmd_id = cmd_id
                        self.flush()
                await asyncio.sleep(0.25)
            log("hold timeout")
        finally:
            try:
                if client is not None:
                    await client.disconnect()
            except Exception:
                pass
            try:
                await scanner.stop()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="WLAN_BLE_SIMPLE_CHAT")
    parser.add_argument("--write-uuid", required=True)
    parser.add_argument("--notify-uuid", required=True)
    parser.add_argument("--status", default="chat_status.json")
    parser.add_argument("--cmd", default="chat_cmd.json")
    parser.add_argument("--scan-timeout", type=float, default=45)
    parser.add_argument("--connect-timeout", type=float, default=75)
    parser.add_argument("--hold-s", type=float, default=600)
    args = parser.parse_args()
    central = ChatCentral(args)
    try:
        asyncio.get_event_loop().run_until_complete(central.run())
        return 0
    except Exception as exc:
        central.error = str(exc)
        central.flush()
        log("FAIL: {}".format(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
