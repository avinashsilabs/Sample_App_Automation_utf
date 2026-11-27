#!/usr/bin/env python3
"""Pieces every coexistence test needs: build/flash, serial, BLE, MQTT, buttons.

The example-specific scripts supply their own state object and serial parser;
everything here is common to any WLAN+BLE example driven through WiseConnect
Build Studio.
"""

from __future__ import annotations

import asyncio
import json
import queue
import re
import ssl
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .ble_protocol import (
    firmware_payload,
    password_payload,
    scan_payload,
    security_payload,
    ssid_payload,
    status_payload,
)

IPV4_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
UNIQUE_ID_RE = re.compile(r"Unique ID\s*[:=]\s*([0-9A-Fa-f]+)", re.IGNORECASE)
DEVICE_INFO_MAC_RE = re.compile(
    r"(?:MAC Address|Bluetooth Address|BLE Address)\s*[:=]\s*"
    r"([0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5})",
    re.IGNORECASE,
)

PLACEHOLDERS = {
    "C:/path/to/simplicity_sdk",
    "C:/path/to/wiseconnect/examples/snippets/wlan_ble",
    "YOUR_SSID",
    "YOUR_WIFI_PASSWORD",
}


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def load_config(path: Path) -> dict[str, Any]:
    """Read config.local.json and refuse the shipped placeholder values."""
    config = json.loads(path.read_text(encoding="utf-8"))
    required = (
        ("studio", "sdk_root"),
        ("studio", "examples_root"),
        ("wifi", "ssid"),
        ("ble", "write_uuid"),
        ("ble", "read_uuid"),
        ("ble", "notify_uuid"),
    )
    missing = [
        ".".join(keys)
        for keys in required
        if not str(config.get(keys[0], {}).get(keys[1], "")).strip()
    ]
    if missing:
        raise ValueError(f"Missing config values: {', '.join(missing)}")

    unresolved = [
        f"{section}.{key}"
        for section, key in (
            ("studio", "sdk_root"),
            ("studio", "examples_root"),
            ("wifi", "ssid"),
        )
        if str(config.get(section, {}).get(key, "")) in PLACEHOLDERS
    ]
    if (
        int(config.get("wifi", {}).get("security", 2)) != 0
        and str(config.get("wifi", {}).get("password", "")) in PLACEHOLDERS
    ):
        unresolved.append("wifi.password")
    if unresolved:
        raise ValueError(
            "Replace placeholder values in config.local.json: " + ", ".join(unresolved)
        )
    return config


# --------------------------------------------------------------------------
# Build Studio
# --------------------------------------------------------------------------


class StudioApi:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(
        self, method: str, path: str, payload: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} failed ({exc.code}): {detail}") from exc
        except URLError as exc:
            raise RuntimeError(
                f"Cannot reach WiseConnect Build Studio at {self.base_url}: {exc}"
            ) from exc

    def build_flash(
        self, app_id: str, cfg: dict[str, Any], extra: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        studio = cfg["studio"]
        payload = {
            "app_id": app_id,
            "target": "soc",
            "board": studio.get("board", "brd4338a"),
            "toolchain": studio.get("toolchain", "gcc"),
            "sdk_root": studio["sdk_root"],
            "ble_root": studio["examples_root"],
        }
        if studio.get("adapter_serial"):
            payload["adapter_serial"] = studio["adapter_serial"]
        payload.update({k: v for k, v in (extra or {}).items() if v not in (None, "")})

        started = self.request("POST", "/api/build-flash", payload)
        job_id = str(started["job_id"])
        seen = 0
        while True:
            job = self.request("GET", f"/api/build/{job_id}")
            logs = list(job.get("logs") or [])
            for line in logs[seen:]:
                print(f"[build] {line}", flush=True)
            seen = len(logs)
            if job.get("status") in ("success", "failed"):
                if job["status"] != "success":
                    raise RuntimeError(job.get("error") or "Build/flash failed")
                return job
            time.sleep(1)

    def device_info(self, adapter_serial: Optional[str] = None) -> dict[str, Any]:
        """Run Simplicity Commander `device info` through Build Studio."""
        path = "/api/device/info"
        if adapter_serial:
            path += f"?serial={quote(str(adapter_serial))}"
        return self.request("GET", path)


def unique_id_to_mac(unique_id: str) -> str:
    """Turn commander Unique ID hex into a colon MAC (last 6 bytes)."""
    hexid = re.sub(r"[^0-9A-Fa-f]", "", unique_id or "")
    if len(hexid) < 12:
        raise ValueError(f"Unique ID too short to form a MAC: {unique_id!r}")
    hexid = hexid[-12:].upper()
    return ":".join(hexid[i : i + 2] for i in range(0, 12, 2))


def parse_device_info_mac(output: str) -> dict[str, Optional[str]]:
    """Parse Unique ID / MAC from `commander device info` text."""
    text = output or ""
    mac_match = DEVICE_INFO_MAC_RE.search(text)
    unique_match = UNIQUE_ID_RE.search(text)
    unique_id = unique_match.group(1) if unique_match else None
    mac = None
    if mac_match:
        mac = mac_match.group(1).upper().replace("-", ":")
    elif unique_id:
        mac = unique_id_to_mac(unique_id)
    return {"unique_id": unique_id, "mac": mac}


class SerialWatcher:
    """Streams the DUT console and folds each line into an example's state."""

    def __init__(self, api: StudioApi, state: Any, parser: Callable[[Any, str], None]):
        self.api = api
        self.state = state
        self.parser = parser
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[Exception] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        since = 0
        try:
            while not self._stop.is_set():
                data = self.api.request("GET", f"/api/serial/lines?since={since}")
                lines = list(data.get("lines") or [])
                since = int(data.get("total", since + len(lines)))
                for line in lines:
                    print(f"[dut] {line}", flush=True)
                    self.parser(self.state, str(line))
                time.sleep(0.25)
        except Exception as exc:  # noqa: BLE001
            self._error = exc

    def wait_for(self, name: str, predicate, timeout: float) -> Any:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._error:
                raise RuntimeError(f"Serial polling failed: {self._error}")
            if getattr(self.state, "failure", None):
                raise RuntimeError(f"DUT reported failure: {self.state.failure}")
            if predicate(self.state):
                print(f"[pass] {name}", flush=True)
                return self.state
            time.sleep(0.25)
        raise TimeoutError(f"Timed out waiting for {name}: {asdict(self.state)}")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


# --------------------------------------------------------------------------
# BLE provisioning
# --------------------------------------------------------------------------


def ble_backend(cfg: dict[str, Any]) -> str:
    """Pick the BLE central: the lab Pi over SSH, or this host's own radio."""
    configured = str(cfg.get("ble", {}).get("backend", "auto")).lower()
    has_pi = bool(str(cfg.get("pi", {}).get("host") or "").strip())
    if configured in ("pi", "raspberry_pi"):
        if not has_pi:
            raise ValueError("ble.backend is 'pi' but pi.host is not set")
        return "pi"
    if configured == "host":
        return "host"
    return "pi" if has_pi else "host"


async def provision_wifi_host(cfg: dict[str, Any]) -> dict[str, Any]:
    try:
        from bleak import BleakClient, BleakScanner
    except ImportError as exc:
        raise RuntimeError(
            "BLE provisioning needs bleak; run: pip install -r requirements.txt"
        ) from exc

    ble = cfg["ble"]
    wifi = cfg["wifi"]
    name = str(ble.get("device_name", "BLE_CONFIGURATOR"))
    address = str(ble.get("address") or "").strip() or None
    timeout = float(ble.get("scan_timeout_s", 30))
    if address:
        print(f"[ble] Scanning for self MAC {address.upper()} ({name!r})...", flush=True)
        device = await BleakScanner.find_device_by_address(address, timeout=timeout)
        if device is None:
            raise RuntimeError(f"BLE advertiser {address} ({name!r}) not found")
    else:
        print(f"[ble] Scanning for {name!r}...", flush=True)
        device = await BleakScanner.find_device_by_filter(
            lambda dev, adv: dev.name == name
            or getattr(adv, "local_name", None) == name,
            timeout=timeout,
        )
        if device is None:
            raise RuntimeError(f"BLE advertiser {name!r} not found")

    aps: list[dict[str, Any]] = []
    notify_event = asyncio.Event()

    def on_notify(_sender, data: bytearray) -> None:
        if len(data) < 3:
            return
        ssid = bytes(data[2:]).decode("utf-8", errors="ignore").strip("\x00").strip()
        if ssid and ssid.isprintable():
            entry = {"security": int(data[0]), "ssid": ssid}
            if entry not in aps:
                aps.append(entry)
                print(f"[ble] AP: {ssid!r} security={data[0]}", flush=True)
        notify_event.set()

    async with BleakClient(
        device, timeout=float(ble.get("connect_timeout_s", 75))
    ) as client:
        await client.start_notify(ble["notify_uuid"], on_notify)
        await client.write_gatt_char(ble["write_uuid"], firmware_payload(), response=True)
        await asyncio.sleep(0.4)
        try:
            firmware = bytes(await client.read_gatt_char(ble["read_uuid"])).hex()
            print(f"[ble] Firmware/status bytes: {firmware}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[ble] Firmware read skipped: {exc}", flush=True)

        wanted = str(wifi["ssid"])
        found: Optional[dict[str, Any]] = None
        for attempt in range(1, int(ble.get("ssid_scan_retries", 3)) + 1):
            aps.clear()
            notify_event.clear()
            await client.write_gatt_char(ble["write_uuid"], scan_payload(), response=True)
            deadline = time.time() + timeout
            while time.time() < deadline:
                found = next((ap for ap in aps if ap["ssid"] == wanted), None)
                if found:
                    break
                try:
                    await asyncio.wait_for(notify_event.wait(), timeout=1)
                    notify_event.clear()
                except asyncio.TimeoutError:
                    pass
            if found:
                break
            print(f"[ble] SSID {wanted!r} absent on scan {attempt}", flush=True)
        if not found:
            raise RuntimeError(f"Configured SSID {wanted!r} not found; seen={aps}")

        security = int(wifi.get("security", found["security"]))
        await client.write_gatt_char(ble["write_uuid"], ssid_payload(wanted), response=True)
        await asyncio.sleep(0.5)
        await client.write_gatt_char(
            ble["write_uuid"], security_payload(security), response=True
        )
        await asyncio.sleep(0.5)
        if security and wifi.get("password"):
            await client.write_gatt_char(
                ble["write_uuid"], password_payload(str(wifi["password"])), response=True
            )
        await asyncio.sleep(1)
        try:
            await client.write_gatt_char(ble["write_uuid"], status_payload(), response=True)
        except Exception:  # noqa: BLE001
            # The application can disable BLE as WLAN starts.
            pass
    return {
        "ssid": wanted,
        "security": security,
        "advertiser": str(device.address),
        "backend": "host",
    }


def provision_wifi(cfg: dict[str, Any]) -> dict[str, Any]:
    """Commission the DUT onto Wi-Fi over BLE, from the Pi or this host."""
    if ble_backend(cfg) == "host":
        print("[ble] Using this host's Bluetooth adapter", flush=True)
        return asyncio.run(provision_wifi_host(cfg))

    pi = cfg["pi"]
    print(
        f"[ble] Using Raspberry Pi {pi.get('host')} as the BLE central (SSH)", flush=True
    )
    from .pi_ble import provision_via_pi

    return provision_via_pi(cfg)


# --------------------------------------------------------------------------
# MQTT verification (plain or mutual-TLS, e.g. AWS IoT)
# --------------------------------------------------------------------------


class MqttSession:
    """Host-side MQTT peer that mirrors what the DUT publishes and receives."""

    def __init__(self, cfg: dict[str, Any], client_prefix: str = "wcbs"):
        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:
            raise RuntimeError(
                "MQTT validation needs paho-mqtt; run: pip install -r requirements.txt"
            ) from exc
        self.mqtt = mqtt
        self.cfg = cfg
        self.connected = threading.Event()
        self.messages: queue.Queue[tuple[str, str]] = queue.Queue()
        client_id = f"{client_prefix}_{uuid.uuid4().hex[:8]}"
        try:
            self.client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
                protocol=mqtt.MQTTv311,
            )
        except AttributeError:
            self.client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)

        def on_connect(client, _userdata, _flags, reason_code, _properties=None):
            code = getattr(reason_code, "value", reason_code)
            if code == 0:
                self.connected.set()
                client.subscribe(self.cfg["dut_publish_topic"])

        def on_message(_client, _userdata, message):
            body = message.payload.decode("utf-8", errors="replace")
            print(f"[mqtt] RX {message.topic}: {body!r}", flush=True)
            self.messages.put((message.topic, body))

        self.client.on_connect = on_connect
        self.client.on_message = on_message

        tls = cfg.get("tls") or {}
        if tls.get("certfile") and tls.get("keyfile"):
            self.client.tls_set(
                ca_certs=tls.get("ca_certs") or None,
                certfile=str(tls["certfile"]),
                keyfile=str(tls["keyfile"]),
                cert_reqs=ssl.CERT_REQUIRED,
            )

    def __enter__(self) -> "MqttSession":
        host = self.cfg["broker_host"]
        port = int(self.cfg.get("broker_port", 1883))
        print(f"[mqtt] Host connecting to {host}:{port}", flush=True)
        self.client.connect(host, port, keepalive=60)
        self.client.loop_start()
        if not self.connected.wait(float(self.cfg.get("connect_timeout_s", 30))):
            raise TimeoutError(f"Host MQTT client could not connect to {host}:{port}")
        print(f"[mqtt] Host connected; subscribed to {self.cfg['dut_publish_topic']}", flush=True)
        return self

    def publish_to_dut(self, payload: Optional[str] = None) -> None:
        topic = self.cfg["dut_subscribe_topic"]
        body = payload or self.cfg.get("host_to_dut_payload", "message_host_to_dut")
        print(f"[mqtt] TX {topic}: {body!r}", flush=True)
        self.client.publish(topic, body, qos=0)

    def drain(self) -> None:
        while True:
            try:
                self.messages.get_nowait()
            except queue.Empty:
                return

    def wait_for_dut(self, timeout: float, expected: Optional[str] = None) -> tuple[str, str]:
        wanted = self.cfg.get("dut_publish_payload", "") if expected is None else expected
        self.drain()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                topic, body = self.messages.get(timeout=0.5)
            except queue.Empty:
                continue
            if not wanted or wanted in body:
                return topic, body
        raise TimeoutError(
            f"No DUT MQTT publish containing {wanted!r} within {timeout:.0f}s"
        )

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.client.loop_stop()
        self.client.disconnect()


# --------------------------------------------------------------------------
# MQTT relay (for brokers the lab network cannot reach directly)
# --------------------------------------------------------------------------


def start_mqtt_relay(config: dict[str, Any]) -> tuple[Any, Optional[str]]:
    """Give the DUT a route to the broker; return (relay, address for firmware).

    The lab network blocks outbound MQTT ports, so unless the broker is already
    on the LAN the DUT is pointed at this host, which forwards to the real
    broker over its corporate interface.
    """
    mqtt_cfg = config.get("mqtt", {})
    broker = str(mqtt_cfg.get("broker_host") or "")
    port = int(mqtt_cfg.get("broker_port", 1883))
    if IPV4_RE.fullmatch(broker):
        return None, broker

    mode = str(mqtt_cfg.get("relay", "auto")).lower()
    if mode in ("0", "false", "off", "none"):
        return None, None

    from .mqtt_relay import MqttRelay, host_address_towards

    peer = str(config.get("pi", {}).get("host") or "192.168.50.1")
    host_ip = host_address_towards(peer)
    relay = MqttRelay(target_host=broker, target_port=port, listen_port=port)
    relay.start()
    print(f"[relay] DUT will reach {broker}:{port} through {host_ip}:{port}", flush=True)
    return relay, host_ip


def check_relay_reachable(config: dict[str, Any], host_ip: str) -> None:
    """Confirm the lab network can open the relay port on this host."""
    pi = config.get("pi") or {}
    if not str(pi.get("host") or "").strip():
        return
    port = int(config.get("mqtt", {}).get("broker_port", 1883))
    from .pi_ble import probe_tcp_from_pi

    if probe_tcp_from_pi(pi, host_ip, port):
        print(f"[relay] Lab network can reach {host_ip}:{port}", flush=True)
        return
    raise RuntimeError(
        f"The lab network cannot reach this host at {host_ip}:{port}, so the DUT "
        f"cannot reach the MQTT broker. Allow it once from an elevated prompt:\n"
        f'  netsh advfirewall firewall add rule name="WCBS MQTT Relay" '
        f"dir=in action=allow protocol=TCP localport={port}"
    )


# --------------------------------------------------------------------------
# Buttons
# --------------------------------------------------------------------------


class ButtonPresser:
    """Presses a button while the main thread waits for the DUT's publish.

    The press is scheduled rather than done inline because the subscriber has
    to be listening first, otherwise the publish lands before we look for it.
    """

    def __init__(self, cfg: dict[str, Any], delay: float = 2.0):
        self.cfg = cfg
        self.delay = delay
        self.error: Optional[BaseException] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> "ButtonPresser":
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return self

    def _run(self) -> None:
        time.sleep(self.delay)
        from .wstk_button import press_button

        try:
            press_button(
                str(self.cfg["host"]),
                int(self.cfg.get("port", 4902)),
                int(self.cfg.get("index", 0)),
                float(self.cfg.get("hold_s", 1.5)),
            )
        except BaseException as exc:  # noqa: BLE001
            self.error = exc
            print(f"[button] Remote press failed: {exc}", flush=True)

    def check(self) -> None:
        if self.error is not None:
            raise RuntimeError(f"Remote button press failed: {self.error}")


class ManualPresser:
    def check(self) -> None:
        return None


def schedule_button_press(config: dict[str, Any], wait_s: float):
    """Press BTN0 over the WSTK admin console, or ask a human if not wired."""
    cfg = config.get("button") or {}
    host = str(cfg.get("host") or "").strip()
    if host and str(cfg.get("mode", "auto")).lower() != "manual":
        print(
            f"[button] Pressing BTN{int(cfg.get('index', 0))} via WSTK console "
            f"{host}:{int(cfg.get('port', 4902))}",
            flush=True,
        )
        return ButtonPresser(cfg).start()

    banner = "=" * 62
    print(
        f"\n{banner}\n"
        f"  ACTION REQUIRED: press BTN0 on the SiWG917 board now\n"
        f"  (waiting up to {wait_s:.0f}s for its MQTT publish)\n"
        f"{banner}\n",
        flush=True,
    )
    return ManualPresser()
