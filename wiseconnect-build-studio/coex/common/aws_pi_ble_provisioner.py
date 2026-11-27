#!/usr/bin/env python3
"""AWS DevKit BLE Wi-Fi provisioner for the Pi (Si Connect AWS IoT demo flow).

This is NOT the generic pi_ble_provisioner used by other coexistence examples.

Si Connect Android source of truth (AWS IoT path):
  Demo -> AWS IoT -> scan BLE_CONFIGURATOR -> pick device
  -> BluetoothService.connectGatt:
       stopDiscovery(); connectGatt(autoConnect=false, TRANSPORT_LE)
  -> WifiCommissioningActivity (GattConnectType.AWS_DEMO)
       GATT aabb / write 1aa1 / read 1bb1 / notify 1cc1
       BoardCommand: FW(8) -> CHECK(7) -> SCAN(3)
                     -> SSID(2) -> SECURITY(5) -> PASSWORD(6)
                     -> CONNECTION(2); BLE drops after join
  -> AWSIOTDemoActivity phone MQTT with .p12 (NOT over BLE)

Pi: filter UART self MAC, keep BlueZ discovery active through connect
(lab Pi returns I/O error if discovery is stopped first). On I/O errors,
restart the bluetooth service — power cycle alone is not enough.
run_test.py replicates AWSIOTDemoActivity via host MQTT.
Python 3.7 compatible for lab Raspberry Pi OS Buster.
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
except ImportError as exc:  # pragma: no cover
    print("ERROR: ble_protocol.py missing next to this script: {0}".format(exc), file=sys.stderr)
    raise SystemExit(2)

try:
    from bleak import BleakClient, BleakScanner
except ImportError:  # pragma: no cover
    print("ERROR: bleak is not installed on this Pi", file=sys.stderr)
    raise SystemExit(2)


# Si Connect Wi-Fi commissioning GATT used by the AWS IoT demo.
DEVICE_NAME = "BLE_CONFIGURATOR"
SERVICE_UUID = "0000aabb-0000-1000-8000-00805f9b34fb"
WRITE_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"
READ_UUID = "00001bb1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "00001cc1-0000-1000-8000-00805f9b34fb"

# Android WifiCommissioningActivity uses 500 ms between writes.
WRITE_GAP_S = 0.5

_RSSI = {}  # type: Dict[str, int]
_ADV_NAME = {}  # type: Dict[str, str]


def log(message):
    # type: (str) -> None
    print("[aws-ble] {0}".format(message), flush=True)


def _normalize_mac(value):
    # type: (Optional[str]) -> Optional[str]
    text = str(value or "").strip().upper().replace("-", ":")
    if not text:
        return None
    parts = [p for p in text.split(":") if p]
    if len(parts) == 6 and all(len(p) <= 2 for p in parts):
        return ":".join("{0:0>2}".format(p) for p in parts)
    return text


def _on_detect(device, advertisement_data):
    address = getattr(device, "address", None)
    if not address:
        return
    key = str(address).upper()
    rssi = getattr(advertisement_data, "rssi", None)
    if rssi is not None:
        _RSSI[key] = int(rssi)
    adv_name = getattr(advertisement_data, "local_name", None)
    if adv_name:
        _ADV_NAME[key] = str(adv_name)


def _rssi(device):
    address = str(getattr(device, "address", "") or "").upper()
    if address in _RSSI:
        return _RSSI[address]
    return -999


def _name_of(device):
    address = str(getattr(device, "address", "") or "").upper()
    if address in _ADV_NAME and _ADV_NAME[address]:
        return _ADV_NAME[address]
    return str(getattr(device, "name", None) or "")


def _pick(devices, name, address):
    # type: (List[Any], str, Optional[str]) -> tuple
    """Filter scanned devices to the DUT self identity (MAC and/or name)."""
    wanted_mac = _normalize_mac(address)
    wanted_name = str(name or "").strip()
    by_name = [d for d in devices if wanted_name and _name_of(d) == wanted_name]
    if wanted_mac:
        matches = [
            d for d in devices if _normalize_mac(str(d.address)) == wanted_mac
        ]
        # Prefer the self MAC; if name is also known, require it when present.
        if matches and wanted_name:
            named = [d for d in matches if _name_of(d) in ("", wanted_name)]
            if named:
                matches = named
            else:
                # Seen the MAC under a different name — still the DUT BD addr.
                log(
                    "Self MAC {0} found but advertised name={1!r} "
                    "(expected {2!r}); using MAC filter".format(
                        wanted_mac,
                        _name_of(matches[0]),
                        wanted_name,
                    )
                )
    else:
        matches = by_name
    if not matches:
        return None, by_name
    matches.sort(key=_rssi, reverse=True)
    return matches[0], matches


def soft_disconnect(address):
    # type: (str) -> None
    """Drop an existing ACL if any — do NOT remove/cache-purge before connect.

    Removing the device before connect invalidates the Bleak scan object and
    commonly yields org.bluez.Error.Failed Input/output error on the Pi.
    """
    try:
        subprocess.run(
            ["bluetoothctl", "disconnect", address],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        log("BlueZ disconnect skipped: {0}".format(exc))


def forget_device(address):
    # type: (str) -> None
    """Remove BlueZ cache after a failed connect (then rescan for a fresh object)."""
    try:
        for args in (("disconnect", address), ("remove", address)):
            subprocess.run(
                ["bluetoothctl", args[0], args[1]],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
            )
        log("Cleared BlueZ cache for {0}".format(address))
    except Exception as exc:  # noqa: BLE001
        log("BlueZ cache clear skipped: {0}".format(exc))


def recover_adapter(address):
    # type: (str) -> None
    """Reset BlueZ after controller-level I/O connect failures.

    bluetoothctl power off/on is not enough when bluetoothd is wedged (scan
    works, every connect returns Input/output error). A service restart
    restores the real HCI controller and makes connects succeed again.
    """
    try:
        if address:
            for args in (("disconnect", address), ("remove", address)):
                subprocess.run(
                    ["bluetoothctl", args[0], args[1]],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=15,
                )
        for args in (("power", "off"), ("power", "on")):
            subprocess.run(
                ["bluetoothctl", args[0], args[1]],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
            )
        # Full stack reset — confirmed required on this lab Pi.
        restart = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", "bluetooth"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
        if restart.returncode != 0:
            log(
                "bluetooth service restart failed rc={0}: {1}".format(
                    restart.returncode,
                    (restart.stdout or b"").decode("utf-8", "replace").strip(),
                )
            )
        else:
            log("Restarted bluetooth service after connect I/O error")
        time.sleep(4)
        subprocess.run(
            ["bluetoothctl", "power", "on"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
        time.sleep(1)
    except Exception as exc:  # noqa: BLE001
        log("BlueZ adapter recovery skipped: {0}".format(exc))


def preflight_bluetooth(ble):
    # type: (Dict[str, Any]) -> None
    """Optional clean BlueZ start before the first scan/connect."""
    if not bool(ble.get("restart_bluetooth_before_connect", True)):
        return
    log("Preflight: restarting bluetooth service for a clean adapter")
    recover_adapter("")


def is_connect_io_error(exc):
    # type: (Exception) -> bool
    text = str(exc).lower()
    return "input/output error" in text or "org.bluez.error.failed" in text


async def scan_and_connect(ble, name, address):
    # type: (Dict[str, Any], str, Optional[str]) -> BleakClient
    """Filter self DUT, then connect while discovery stays active.

    Post-connect GATT/BoardCommand sequence matches Si Connect AWS_DEMO.
    Connect itself follows the lab Pi BlueZ rule from pi_ble_provisioner:
    stopping discovery before connect yields Input/output error on this Pi
    (same as ``bluetoothctl connect`` needing ``scan on``).
    """
    scan_window = float(ble.get("scan_timeout_s", 30))
    timeout = float(ble.get("connect_timeout_s", 75))
    retries = int(ble.get("connect_retries", 8))
    retry_delay = float(ble.get("retry_delay_s", 5))
    settle = float(ble.get("pre_connect_delay_s", 3))
    require_self = bool(ble.get("require_self_identity", True))
    drop_address_after = int(
        ble.get(
            "drop_pinned_address_after",
            0 if (address or require_self) else 3,
        )
    )
    recover = bool(ble.get("recover_adapter_on_connect_failure", True))
    last_error = None  # type: Optional[Exception]
    use_address = _normalize_mac(address)

    if require_self and not use_address:
        raise RuntimeError(
            "ble.address (DUT self MAC) is required before Pi BLE connect; "
            "wait for UART '[BLE self] name=... address=...' first"
        )

    if use_address:
        log(
            "AWS IoT BLE: scan+filter self MAC={0} name={1!r} "
            "(keep discovery on through connect)".format(use_address, name)
        )
    else:
        log(
            "AWS IoT BLE: scan name={0!r} (keep discovery on through connect)".format(
                name
            )
        )

    preflight_bluetooth(ble)

    for attempt in range(1, retries + 1):
        if use_address and attempt > drop_address_after > 0:
            log(
                "Pinned address keep failing; falling back to name={0!r}".format(name)
            )
            use_address = None

        # Fresh advertisement each attempt — cache-cleared device objects go stale.
        scanner = BleakScanner(detection_callback=_on_detect)
        await scanner.start()
        stop_scanner = True
        last_listing = ""
        try:
            device = None
            deadline = time.time() + scan_window
            while time.time() < deadline:
                await asyncio.sleep(0.5)
                discovered = list(scanner.discovered_devices)
                named = [d for d in discovered if _name_of(d) == name]
                if named:
                    listing = ", ".join(
                        "{0}({1}) rssi={2}".format(
                            d.address, _name_of(d) or "?", _rssi(d)
                        )
                        for d in named
                    )
                    if listing != last_listing:
                        log(
                            "Scan saw {0} {1!r} advertiser(s): {2}".format(
                                len(named), name, listing
                            )
                        )
                        last_listing = listing
                device, matches = _pick(discovered, name, use_address)
                if device:
                    if use_address:
                        log(
                            "Filtered to self DUT {0} name={1!r} rssi={2}".format(
                                device.address,
                                _name_of(device) or name,
                                _rssi(device),
                            )
                        )
                    elif len(matches) > 1:
                        listing = ", ".join(
                            "{0} rssi={1}".format(d.address, _rssi(d)) for d in matches
                        )
                        log(
                            "{0} boards advertise {1!r}: {2}".format(
                                len(matches), name, listing
                            )
                        )
                    break

            if device is None:
                last_error = RuntimeError(
                    "Self DUT not in scan filter (wanted mac={0!r} name={1!r}); "
                    "saw {2} device(s)".format(
                        use_address,
                        name,
                        len(list(scanner.discovered_devices)),
                    )
                )
                log(str(last_error))
                continue

            log(
                "Proceeding with filtered DUT {0} address={1} rssi={2}".format(
                    _name_of(device) or name, device.address, _rssi(device)
                )
            )
            if settle > 0 and attempt == 1:
                log("Waiting {0:.1f}s with discovery still on...".format(settle))
                await asyncio.sleep(settle)

            # Pass scanned device (keeps address type). Scanner stays running.
            client = BleakClient(device, timeout=timeout)
            try:
                log(
                    "Connect attempt {0}/{1} to {2} (discovery active)...".format(
                        attempt, retries, device.address
                    )
                )
                await client.connect()
                services = list(client.services) if client.services else []
                if not services:
                    raise RuntimeError("Connected but no GATT services discovered")
                uuids = [str(s.uuid).lower() for s in services]
                if SERVICE_UUID.lower() not in uuids:
                    log(
                        "Warning: Wi-Fi commissioning service {0} not listed yet "
                        "({1} service(s)); continuing".format(SERVICE_UUID, len(services))
                    )
                else:
                    log(
                        "AWS IoT Wi-Fi commissioning service present ({0})".format(
                            SERVICE_UUID
                        )
                    )
                log("Connected; {0} GATT service(s)".format(len(services)))
                return client
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                log("Connect failed: {0}".format(exc))
                try:
                    if client.is_connected:
                        await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
                if attempt < retries:
                    await scanner.stop()
                    stop_scanner = False
                    if bool(ble.get("clear_bluez_cache", True)):
                        forget_device(device.address)
                    if is_connect_io_error(exc) and recover:
                        log(
                            "BlueZ I/O error — recovering adapter then fresh scan"
                        )
                        recover_adapter(device.address)
                    await asyncio.sleep(retry_delay)
        finally:
            if stop_scanner:
                try:
                    await scanner.stop()
                except Exception as exc:  # noqa: BLE001
                    log("Scanner stop note: {0}".format(exc))

    raise RuntimeError(
        "AWS IoT BLE connect failed after {0} attempt(s): {1}".format(retries, last_error)
    )


async def disconnect_quietly(client, notify_uuid):
    # type: (Optional[BleakClient], str) -> None
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
        log("BLE disconnect note: {0}".format(exc))


async def provision(config):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    ble = config["ble"]
    wifi = config["wifi"]
    name = str(ble.get("device_name") or DEVICE_NAME)
    address = str(ble.get("address") or "").strip() or None
    write_uuid = str(ble.get("write_uuid") or WRITE_UUID)
    read_uuid = str(ble.get("read_uuid") or READ_UUID)
    notify_uuid = str(ble.get("notify_uuid") or NOTIFY_UUID)

    wanted = str(wifi["ssid"])
    password = str(wifi.get("password") or "")
    security = int(wifi.get("security", 2))
    scan_window = float(ble.get("scan_timeout_s", 30))
    scan_retries = int(ble.get("ssid_scan_retries", 5))

    result = {
        "ok": False,
        "flow": "aws_iot",
        "device_name": name,
        "aps": [],
        "ip": None,
        "mac": None,
    }  # type: Dict[str, Any]
    seen = []  # type: List[Dict[str, Any]]
    aps = []  # type: List[Dict[str, Any]]
    notify_event = asyncio.Event()

    def on_notify(_sender, data):
        # Si Connect AP notify: [security_u8][','][SSID...]
        if len(data) < 3:
            return
        ssid = bytes(data[2:]).decode("utf-8", errors="ignore").strip("\x00").strip()
        ssid = "".join(ch for ch in ssid if ch.isprintable())
        if ssid:
            entry = {"security": int(data[0]), "ssid": ssid}
            if entry not in aps:
                aps.append(entry)
                log("AP: {0!r} security={1}".format(ssid, data[0]))
        notify_event.set()

    client = None  # type: Optional[BleakClient]
    try:
        client = await scan_and_connect(ble, name, address)
        result["device_address"] = getattr(client, "address", None) or getattr(
            getattr(client, "_device", None), "address", None
        )

        # Android: enable CCCD notify on 1cc1, then GET_FIRMWARE_VERSION.
        await client.start_notify(notify_uuid, on_notify)
        await asyncio.sleep(WRITE_GAP_S)

        log("AWS IoT step: GET_FIRMWARE_VERSION (8)")
        await client.write_gatt_char(write_uuid, firmware_payload(), response=True)
        await asyncio.sleep(WRITE_GAP_S)
        try:
            firmware = bytes(await client.read_gatt_char(read_uuid))
            log("Firmware/status bytes: {0}".format(firmware.hex()))
        except Exception as exc:  # noqa: BLE001
            log("Firmware read skipped: {0}".format(exc))

        # Android onFirmwareVersionReceived -> CHECK_CONNECTION before SCAN.
        log("AWS IoT step: CHECK_CONNECTION (7)")
        already_joined = False
        try:
            await client.write_gatt_char(write_uuid, status_payload(), response=True)
            await asyncio.sleep(WRITE_GAP_S)
            check = bytes(await client.read_gatt_char(read_uuid))
            log("CHECK_CONNECTION bytes: {0}".format(list(check)))
            if len(check) >= 2 and check[0] == 0x07 and check[1] == 0x01:
                already_joined = True
                result["ok"] = True
                result["already_joined"] = True
                log("DUT already on Wi-Fi (0x07/0x01); skipping SCAN/join")
        except Exception as exc:  # noqa: BLE001
            log("CHECK_CONNECTION skipped: {0}".format(exc))

        match = None  # type: Optional[Dict[str, Any]]
        if not already_joined:
            for attempt in range(1, scan_retries + 1):
                aps[:] = []
                notify_event.clear()
                log(
                    "AWS IoT step: SCAN (3) attempt {0}/{1} for SSID={2!r}".format(
                        attempt, scan_retries, wanted
                    )
                )
                await client.write_gatt_char(write_uuid, scan_payload(), response=True)
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
                    log("Found {0!r} (security={1})".format(wanted, match["security"]))
                    break
                log("SSID {0!r} not seen on scan {1}".format(wanted, attempt))
                await asyncio.sleep(WRITE_GAP_S)

            if not match:
                raise RuntimeError(
                    "Configured SSID {0!r} not found; seen={1}".format(
                        wanted, [ap["ssid"] for ap in seen] or ["(none)"]
                    )
                )

            result["ssid_found"] = True
            result["ssid"] = wanted
            if not wifi.get("security_override", False):
                security = int(match["security"])
            result["security"] = security

            # Android chains writes on GATT write-success:
            # SSID -> SECURITY_TYPE -> PASSWORD (if non-empty) -> read CONNECTION.
            log("AWS IoT step: SSID (2) = {0!r}".format(wanted))
            await client.write_gatt_char(write_uuid, ssid_payload(wanted), response=True)
            await asyncio.sleep(WRITE_GAP_S)

            log("AWS IoT step: SECURITY_TYPE (5) = {0}".format(security))
            await client.write_gatt_char(write_uuid, security_payload(security), response=True)
            await asyncio.sleep(WRITE_GAP_S)

            if security != 0 and password:
                log("AWS IoT step: PASSWORD (6)")
                await client.write_gatt_char(
                    write_uuid, password_payload(password), response=True
                )
                await asyncio.sleep(WRITE_GAP_S)

            result["credentials_sent"] = True
            log("Credentials sent; waiting for Wi-Fi join / BLE drop (readme step 8)")

            # Android reads 1bb1 for BoardCommand.Response.CONNECTION (2).
            # Also poll CHECK_CONNECTION; firmware may drop BLE after join.
            poll_s = float(ble.get("ble_join_poll_s", 25))
            deadline = time.time() + poll_s
            explicit_failure = False
            while time.time() < deadline:
                try:
                    if not client.is_connected:
                        log("BLE link dropped after Wi-Fi join (expected for AWS IoT demo)")
                        result["ble_disconnected_after_provision"] = True
                        break
                    await client.write_gatt_char(write_uuid, status_payload(), response=True)
                    await asyncio.sleep(WRITE_GAP_S)
                    data = await client.read_gatt_char(read_uuid)
                    log("Status bytes: {0}".format(list(data)))
                    if len(data) >= 2 and data[0] == 0x02:
                        if data[1] == 0x01:
                            result["ok"] = True
                            if len(data) >= 14:
                                result["mac"] = ":".join(
                                    "{0:02X}".format(b) for b in data[3:9]
                                )
                                result["ip"] = ".".join(str(b) for b in data[10:14])
                            log(
                                "Join OK mac={0} ip={1}".format(
                                    result["mac"], result["ip"]
                                )
                            )
                        else:
                            explicit_failure = True
                            result["error"] = "DUT reported Wi-Fi join failure (0x02/0x00)"
                            log(result["error"])
                        break
                    if len(data) >= 2 and data[0] == 0x07 and data[1] == 0x01:
                        result["ok"] = True
                        log("DUT joined Wi-Fi (status 0x07)")
                        break
                except Exception as exc:  # noqa: BLE001
                    log("Join poll ended: {0}".format(exc))
                    result["ble_disconnected_after_provision"] = True
                    break
                await asyncio.sleep(1)

            if not result["ok"] and result.get("credentials_sent") and not explicit_failure:
                # Firmware may drop BLE before status is readable; UART confirms join.
                result["ok"] = True
                result["join_pending_uart"] = True
                log("Credentials delivered; run_test will confirm WLAN/IP from DUT UART")

        # Android AWS_DEMO waits 5s after join before opening AWSIOTDemoActivity.
        settle_after = float(ble.get("post_join_delay_s", 5))
        if result.get("ok") and settle_after > 0:
            log(
                "Post-join settle {0:.0f}s (Android AWS_DEMO delay before MQTT UI)".format(
                    settle_after
                )
            )
            await asyncio.sleep(settle_after)
    finally:
        await disconnect_quietly(client, notify_uuid)

    if not result["ok"]:
        raise RuntimeError(result.get("error") or "AWS IoT BLE Wi-Fi provisioning failed")
    return result


def main():
    # type: () -> int
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text())
    try:
        result = asyncio.get_event_loop().run_until_complete(provision(config))
    except Exception as exc:  # noqa: BLE001
        log("FAILED: {0}".format(exc))
        Path(args.result).write_text(
            json.dumps({"ok": False, "flow": "aws_iot", "error": str(exc)}, indent=2)
        )
        return 1
    Path(args.result).write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
