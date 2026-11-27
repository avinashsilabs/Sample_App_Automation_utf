#!/usr/bin/env python3
"""AWS DevKit BLE Wi-Fi provisioner (Si Connect AWS IoT demo only).

Entry used by run_test.py. This does NOT call the generic pi_ble_provisioner
used by other coexistence apps.

Flow (readme / Si Connect Android Demo -> AWS IoT):
    1. Find BLE_CONFIGURATOR (pin ble.address to the DUT)
    2. Connect, enable notify on 1cc1
    3. FW(8) -> CHECK(7) -> SCAN(3) -> SSID(2) -> SECURITY(5) -> PASSWORD(6)
    4. BLE disconnect after Wi-Fi join (expected)
    5. Host MQTT (.p12 role) is run_test.py, not this module

Pi backend deploys and runs ``aws_pi_ble_provisioner.py``.
Host backend runs the same command sequence locally with bleak.
"""

from __future__ import annotations

import asyncio
from typing import Any

# Si Connect Wi-Fi commissioning GATT (AWS IoT / WifiCommissioningActivity).
DEFAULT_DEVICE_NAME = "BLE_CONFIGURATOR"
DEFAULT_SERVICE_UUID = "0000aabb-0000-1000-8000-00805f9b34fb"
DEFAULT_WRITE_UUID = "00001aa1-0000-1000-8000-00805f9b34fb"
DEFAULT_READ_UUID = "00001bb1-0000-1000-8000-00805f9b34fb"
DEFAULT_NOTIFY_UUID = "00001cc1-0000-1000-8000-00805f9b34fb"

AWS_PI_SCRIPT = "aws_pi_ble_provisioner.py"
AWS_PI_DEPLOY = ("ble_protocol.py", "aws_pi_ble_provisioner.py")


def _ensure_aws_ble_defaults(config: dict[str, Any]) -> dict[str, Any]:
    ble = dict(config.get("ble") or {})
    wifi = dict(config.get("wifi") or {})

    ble.setdefault("device_name", DEFAULT_DEVICE_NAME)
    ble.setdefault("write_uuid", DEFAULT_WRITE_UUID)
    ble.setdefault("read_uuid", DEFAULT_READ_UUID)
    ble.setdefault("notify_uuid", DEFAULT_NOTIFY_UUID)
    # Lab Pi BlueZ: keep discovery on; restart bluetoothd on I/O errors.
    ble.setdefault("clear_bluez_cache", True)
    ble.setdefault("recover_adapter_on_connect_failure", True)
    ble.setdefault("restart_bluetooth_before_connect", True)
    ble.setdefault("connect_retries", 8)
    ble.setdefault("retry_delay_s", 5)
    ble.setdefault("drop_pinned_address_after", 0)
    ble.setdefault("pre_connect_delay_s", 2)
    ble.setdefault("ble_join_poll_s", 25)
    ble.setdefault("post_join_delay_s", 5)
    # Only connect after UART/config self MAC is known and present in the scan.
    ble.setdefault("require_self_identity", True)

    ssid = str(wifi.get("ssid") or "").strip()
    if not ssid:
        raise ValueError("Set wifi.ssid in config.local.json (AWS IoT Wi-Fi step)")
    security = int(wifi.get("security", 2))
    if security != 0 and not str(wifi.get("password") or ""):
        raise ValueError("Set wifi.password in config.local.json (AWS IoT Wi-Fi step)")

    out = dict(config)
    out["ble"] = ble
    out["wifi"] = wifi
    return out


def _backend(cfg: dict[str, Any]) -> str:
    configured = str(cfg.get("ble", {}).get("backend", "auto")).lower()
    has_pi = bool(str(cfg.get("pi", {}).get("host") or "").strip())
    if configured in ("pi", "raspberry_pi"):
        if not has_pi:
            raise ValueError("ble.backend is 'pi' but pi.host is not set")
        return "pi"
    if configured == "host":
        return "host"
    return "pi" if has_pi else "host"


async def _provision_host(cfg: dict[str, Any]) -> dict[str, Any]:
    """Run the AWS IoT BLE sequence on this PC's Bluetooth adapter."""
    from .aws_pi_ble_provisioner import provision as aws_provision

    result = await aws_provision(cfg)
    result["backend"] = "host"
    return result


def provision_wifi(config: dict[str, Any]) -> dict[str, Any]:
    """Commission Wi-Fi over BLE using the AWS IoT DevKit flow only."""
    cfg = _ensure_aws_ble_defaults(config)
    ble = cfg["ble"]
    wifi = cfg["wifi"]

    print(
        "[aws-ble] Si Connect AWS IoT Wi-Fi step: "
        f"device={ble.get('device_name')!r} SSID={wifi.get('ssid')!r}",
        flush=True,
    )
    print(
        "[aws-ble] Pi BlueZ connect keeps discovery active "
        "(lab Pi I/O error if scan is stopped); GATT steps still match Si Connect.",
        flush=True,
    )

    if _backend(cfg) == "pi":
        from .pi_ble import provision_via_pi

        print(
            f"[aws-ble] Using dedicated {AWS_PI_SCRIPT} on Pi "
            "(not generic pi_ble_provisioner.py)",
            flush=True,
        )
        result = provision_via_pi(
            cfg,
            script=AWS_PI_SCRIPT,
            deploy_files=AWS_PI_DEPLOY,
        )
    else:
        print("[aws-ble] Using host Bluetooth adapter with AWS IoT flow", flush=True)
        result = asyncio.run(_provision_host(cfg))

    result = dict(result or {})
    result.setdefault("ok", True)
    result["flow"] = "aws_iot"
    result["device_name"] = ble.get("device_name")
    result["ssid"] = wifi.get("ssid")
    result["write_uuid"] = ble.get("write_uuid")
    result["notify_uuid"] = ble.get("notify_uuid")

    print(
        "[aws-ble] Wi-Fi credentials sent; BLE disconnect after join is expected. "
        "run_test continues with .p12 / endpoint / topics / sensor / LED over MQTT.",
        flush=True,
    )
    return result
