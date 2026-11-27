#!/usr/bin/env python3
"""Build, flash, provision, and validate the SiWG917 Out of Box Demo."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.harness import (  # noqa: E402
    MqttSession,
    SerialWatcher,
    StudioApi,
    check_relay_reachable,
    load_config,
    parse_device_info_mac,
    provision_wifi,
    schedule_button_press,
    start_mqtt_relay,
)

APP_ID = "out_of_box_demo"


@dataclass
class OobState:
    version: Optional[str] = None
    wifi_connected: bool = False
    ip_address: Optional[str] = None
    ble_self_name: Optional[str] = None
    ble_self_address: Optional[str] = None
    ping_started: bool = False
    ping_responses: int = 0
    mqtt_connected: bool = False
    mqtt_subscribed: bool = False
    mqtt_message_received: bool = False
    mqtt_publish_ok: bool = False
    nwp_sleep: bool = False
    failure: Optional[str] = None

    @property
    def ble_self_ready(self) -> bool:
        return bool(self.ble_self_address)


PRIVATE_IP_RE = re.compile(
    r"(?<!\d)(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)"
)


def parse_serial_line(state: OobState, line: str) -> None:
    low = line.strip().lower()
    if not low:
        return
    if "si917 oob demo" in low:
        match = re.search(r"si917\s+oob\s+demo\s+(v?\d+(?:\.\d+)*)", low)
        state.version = match.group(1) if match else "present"
    # Firmware prints: [BLE self] name=BLE_CONFIGURATOR address=AA:BB:CC:DD:EE:FF
    self_match = re.search(
        r"\[ble self\]\s*name=(\S+)\s+address=([0-9a-fA-F:]{11,17})",
        line,
        re.IGNORECASE,
    )
    if self_match:
        state.ble_self_name = self_match.group(1).strip()
        addr = self_match.group(2).strip().upper()
        if addr.lower() != "unknown":
            state.ble_self_address = addr
    elif "device advertising as" in low:
        name_match = re.search(r"device advertising as:\s*(\S+)", low)
        if name_match and not state.ble_self_name:
            state.ble_self_name = name_match.group(1).strip()
    if (
        "wlan connection success" in low
        or "wlan connection is successful" in low
        or ("ap joined" in low and "success" in low)
    ):
        state.wifi_connected = True
    ip_match = PRIVATE_IP_RE.search(line)
    if ip_match and ("ip" in low or state.wifi_connected):
        state.ip_address = ip_match.group(1)
    if "pinging www.silabs.com" in low:
        state.ping_started = True
    if "ping response from www.silabs.com" in low:
        state.ping_started = True
        state.ping_responses += 1
    if "mqtt connection established" in low or "mqtt connection done" in low:
        state.mqtt_connected = True
    if "subscribed to topic" in low:
        state.mqtt_connected = True
        state.mqtt_subscribed = True
    if "message received on topic" in low:
        state.mqtt_message_received = True
    if (
        "published message successfully on topic" in low
        or ("published" in low and ("mqtt" in low or "si917_app_status" in low))
    ):
        state.mqtt_publish_ok = True
    if "associated power save enabled" in low or "nwp lowpower enabled" in low:
        state.nwp_sleep = True
    failures = (
        "wlan connect failed",
        "wlan connection failed",
        "ip configuration failed",
        "failed to connect to mqtt",
        "mqtt connect failed",
    )
    if any(marker in low for marker in failures):
        state.failure = line.strip()


def run(config: dict[str, Any], *, skip_build: bool = False) -> dict[str, Any]:
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")
    relay, firmware_broker_ip = start_mqtt_relay(config)
    if relay is not None and firmware_broker_ip:
        check_relay_reachable(config, firmware_broker_ip)
    build = (
        None
        if skip_build
        else api.build_flash(APP_ID, config, {"mqtt_broker_ip": firmware_broker_ip})
    )

    watcher = SerialWatcher(api, OobState(), parse_serial_line)
    watcher.start()
    results: dict[str, Any] = {
        "app_id": APP_ID,
        "build_job_id": None if build is None else build.get("id"),
    }
    try:
        settle = float(config["ble"].get("post_flash_settle_s", 15))
        print(f"[test] Waiting {settle:.0f}s for BLE advertising...", flush=True)
        time.sleep(settle)

        ble_cfg = dict(config.get("ble") or {})
        adapter_serial = str(config.get("studio", {}).get("adapter_serial") or "").strip()
        device_mac = None
        unique_id = None
        last_info_error: Optional[str] = None
        for attempt in range(1, 4):
            try:
                info = api.device_info(adapter_serial or None)
                parsed = parse_device_info_mac(str(info.get("output") or ""))
                unique_id = parsed.get("unique_id")
                device_mac = parsed.get("mac")
                print(
                    "[ble] Device Info:\n"
                    + str(info.get("output") or "(no output)").rstrip(),
                    flush=True,
                )
                if unique_id or device_mac:
                    print(
                        f"[ble] Parsed Unique ID={unique_id} -> self MAC={device_mac}",
                        flush=True,
                    )
                break
            except Exception as exc:  # noqa: BLE001
                last_info_error = str(exc)
                print(
                    f"[ble] Device Info attempt {attempt}/3 failed: {exc}",
                    flush=True,
                )
                time.sleep(2)

        if watcher.state.ble_self_address:
            ble_cfg["address"] = watcher.state.ble_self_address
            print(
                f"[ble] UART self MAC {watcher.state.ble_self_address} "
                "overrides Device Info",
                flush=True,
            )
        elif device_mac:
            ble_cfg["address"] = device_mac
            watcher.state.ble_self_address = device_mac
        if watcher.state.ble_self_name:
            ble_cfg["device_name"] = watcher.state.ble_self_name
        ble_cfg.setdefault("device_name", "BLE_CONFIGURATOR")
        ble_cfg["require_self_identity"] = True
        if not ble_cfg.get("address"):
            detail = last_info_error or "Unique ID not present in commander output"
            raise RuntimeError(
                "DUT BLE self MAC unknown; Device Info did not yield a MAC "
                f"({detail})"
            )
        config = dict(config)
        config["ble"] = ble_cfg
        results["ble_self_name"] = ble_cfg.get("device_name")
        results["ble_self_address"] = ble_cfg.get("address")
        results["device_unique_id"] = unique_id
        print(
            f"[ble] Pi will filter scan for self name={ble_cfg.get('device_name')!r} "
            f"address={ble_cfg.get('address')!r} before provisioning",
            flush=True,
        )
        results["provision"] = provision_wifi(config)

        timeouts = config.get("timeouts", {})
        watcher.wait_for(
            "WLAN connection",
            lambda state: state.wifi_connected,
            float(timeouts.get("wlan_s", 60)),
        )
        watcher.wait_for(
            "DUT IPv4 address",
            lambda state: bool(state.ip_address),
            float(timeouts.get("ip_s", 60)),
        )
        watcher.wait_for(
            "www.silabs.com ping response",
            lambda state: state.ping_responses >= int(config.get("min_ping_responses", 1)),
            float(timeouts.get("ping_s", 90)),
        )
        watcher.wait_for(
            "MQTT connection",
            lambda state: state.mqtt_connected,
            float(timeouts.get("mqtt_s", 150)),
        )
        watcher.wait_for(
            "NWP connected sleep",
            lambda state: state.nwp_sleep,
            float(timeouts.get("sleep_s", 60)),
        )

        mqtt_cfg = config["mqtt"]
        # Repeat the exchange so a link that happens to work once isn't
        # mistaken for a link that holds up.
        rounds = max(1, int(mqtt_cfg.get("rounds", 5)))
        gap = float(mqtt_cfg.get("round_gap_s", 3))
        exchanges: list[dict[str, Any]] = []
        with MqttSession(mqtt_cfg, client_prefix="wcbs_oob") as mqtt:
            for round_no in range(1, rounds + 1):
                print(f"[mqtt] === exchange {round_no}/{rounds} ===", flush=True)
                watcher.state.mqtt_message_received = False
                mqtt.publish_to_dut()
                transfer_deadline = time.time() + float(
                    timeouts.get("mqtt_transfer_s", 60)
                )
                while (
                    time.time() < transfer_deadline
                    and not watcher.state.mqtt_message_received
                ):
                    time.sleep(2.5)
                    if not watcher.state.mqtt_message_received:
                        mqtt.publish_to_dut()
                if not watcher.state.mqtt_message_received:
                    raise TimeoutError(
                        f"DUT did not report host MQTT message reception on "
                        f"exchange {round_no}/{rounds}"
                    )
                print(
                    f"[pass] host-to-DUT MQTT reception ({round_no}/{rounds})",
                    flush=True,
                )
                exchange: dict[str, Any] = {"round": round_no, "host_to_dut": True}

                if bool(mqtt_cfg.get("verify_dut_publish", True)):
                    watcher.state.mqtt_publish_ok = False
                    button_s = float(timeouts.get("button_s", 90))
                    presser = schedule_button_press(config, button_s)
                    try:
                        topic, body = mqtt.wait_for_dut(button_s)
                    except TimeoutError as exc:
                        presser.check()
                        raise TimeoutError(
                            f"{exc} (exchange {round_no}/{rounds})"
                        ) from exc
                    presser.check()
                    watcher.wait_for(
                        f"DUT MQTT publish confirmation ({round_no}/{rounds})",
                        lambda state: state.mqtt_publish_ok,
                        15,
                    )
                    print(
                        f"[pass] DUT-to-host MQTT publish ({round_no}/{rounds})",
                        flush=True,
                    )
                    exchange["dut_publish"] = {"topic": topic, "payload": body}
                    results["dut_publish"] = exchange["dut_publish"]

                exchanges.append(exchange)
                if round_no < rounds and gap > 0:
                    time.sleep(gap)

        results["mqtt_exchanges"] = exchanges
        print(f"[pass] {len(exchanges)}/{rounds} MQTT exchanges completed", flush=True)

        results["serial"] = asdict(watcher.state)
        results["ok"] = True
        return results
    finally:
        watcher.stop()
        if relay is not None:
            relay.stop()


def parser_self_test() -> None:
    state = OobState()
    lines = (
        "Si917 OOB Demo v2.0",
        "[BLE self] name=BLE_CONFIGURATOR address=D4:48:67:DD:CF:8B",
        "WLAN Connection Success",
        "IP Address:192.168.50.21",
        "Pinging www.silabs.com",
        "Ping response from www.silabs.com",
        "MQTT connection established",
        "Associated power save enabled",
        "Message Received on Topic",
        "Published MQTT message",
    )
    for line in lines:
        parse_serial_line(state, line)
    assert state.version == "v2.0"
    assert state.ble_self_name == "BLE_CONFIGURATOR"
    assert state.ble_self_address == "D4:48:67:DD:CF:8B"
    assert state.ble_self_ready
    assert state.wifi_connected and state.ip_address == "192.168.50.21"
    assert state.ping_responses == 1 and state.mqtt_connected
    assert state.nwp_sleep and state.mqtt_message_received and state.mqtt_publish_ok

    sample_info = (
        "Part Number    : SiWG917M111MGTBA\n"
        "Product Rev    : B0\n"
        "Flash Size     : 8192 kB\n"
        "SRAM Size      : 672 kB\n"
        "Unique ID      : 000008ddecbf16c0\n"
        "DONE\n"
    )
    parsed = parse_device_info_mac(sample_info)
    assert parsed["unique_id"] == "000008ddecbf16c0"
    assert parsed["mac"] == "08:DD:EC:BF:16:C0"
    print("Parser self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("config.local.json"),
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        parser_self_test()
        return 0
    try:
        config = load_config(args.config)
        result = run(config, skip_build=args.skip_build)
        result_path = Path(__file__).with_name("last_result.json")
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nPASS: Out of Box Demo ({result_path})")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
