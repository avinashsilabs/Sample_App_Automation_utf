#!/usr/bin/env python3
"""Build, flash, provision over BLE, and validate AWS IoT MQTT on the SiWG917.

Follows the example readme: commission Wi-Fi over BLE with the same
Simplicity Connect GATT protocol the aws provision Demo uses, then confirm the
device loads its TLS material, reaches AWS IoT Core, subscribes to
`aws_status`, publishes on `si91x_status`, and enters associated power save.
The host joins the same AWS endpoint with the device's own certificate, so
both ends of every message are checked.
"""

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
    load_config,
    provision_wifi,
    schedule_button_press,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aws_certs import describe_certificate, export_client_identity  # noqa: E402

APP_ID = "wifi_station_ble_provisioning_aws"


@dataclass
class AwsState:
    wifi_connected: bool = False
    ip_address: Optional[str] = None
    mac_id: Optional[str] = None
    client_id: Optional[str] = None
    ca_loaded: bool = False
    client_cert_loaded: bool = False
    private_key_loaded: bool = False
    aws_connecting: bool = False
    aws_subscribed: bool = False
    aws_publish_ok: bool = False
    message_received: Optional[str] = None
    nwp_sleep: bool = False
    failure: Optional[str] = None

    @property
    def certificates_loaded(self) -> bool:
        return self.ca_loaded and self.client_cert_loaded and self.private_key_loaded


PRIVATE_IP_RE = re.compile(
    r"(?<!\d)(10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)"
)

FAILURES = (
    "wlan connect failed",
    "ip config failed",
    "mqtt connect failed",
    "mqtt init failed",
    "subscribe error",
    "mqtt publish for qos0 failed",
    "certificate loading failed",
    "loading tls ca certificate in to flash failed",
    "loading tls client certificate in to flash failed",
    "loading tls client private key in to flash failed",
)


def parse_serial_line(state: AwsState, line: str) -> None:
    text = line.strip()
    low = text.lower()
    if not low:
        return

    if "wlan connection success" in low:
        state.wifi_connected = True
    # The firmware prints the DHCP address bare, with no label.
    ip_match = PRIVATE_IP_RE.search(text)
    if ip_match and (state.wifi_connected or "ip" in low):
        state.ip_address = ip_match.group(1)

    mac_match = re.search(r"mac id:\s*([0-9a-f:]{11,})", low)
    if mac_match:
        state.mac_id = mac_match.group(1)
    client_match = re.search(r"client id:\s*(\S+)", low)
    if client_match:
        state.client_id = client_match.group(1)

    if "loading tls ca certificate" in low and "successfull" in low:
        state.ca_loaded = True
    if "loading tls client certificate" in low and "successfull" in low:
        state.client_cert_loaded = True
    if "loading tls client private key" in low and "successfull" in low:
        state.private_key_loaded = True
    if "certificate loading successful" in low:
        state.ca_loaded = True
        state.client_cert_loaded = True
        state.private_key_loaded = True

    if "aws iot mqtt connecting" in low:
        state.aws_connecting = True
    if "aws iot mqtt subscribe" in low:
        # The firmware only reaches the subscribe state after connect returns
        # success, so this line doubles as connection evidence.
        state.aws_connecting = True
        state.aws_subscribed = True
    if "mqtt publish successful" in low:
        state.aws_publish_ok = True
    received = re.search(r"data received\s*=\s*(.+)$", text, re.IGNORECASE)
    if received:
        state.message_received = received.group(1).strip()
    if "associated power save enabled" in low:
        state.nwp_sleep = True

    if any(marker in low for marker in FAILURES):
        state.failure = text


def aws_broker_config(cfg: dict[str, Any], certs: dict[str, str]) -> dict[str, Any]:
    """Host-side MQTT settings: same endpoint and identity as the device."""
    aws = cfg["aws"]
    return {
        "broker_host": aws["endpoint"],
        "broker_port": int(aws.get("host_port", 8883)),
        "dut_subscribe_topic": aws.get("dut_subscribe_topic", "aws_status"),
        "dut_publish_topic": aws.get("dut_publish_topic", "si91x_status"),
        "host_to_dut_payload": aws.get("host_to_dut_payload", "wcbs_host_to_dut"),
        "dut_publish_payload": aws.get("dut_publish_payload", "Hi from SiWx917"),
        "connect_timeout_s": float(aws.get("connect_timeout_s", 30)),
        "tls": {"certfile": certs["certfile"], "keyfile": certs["keyfile"]},
    }


def run(config: dict[str, Any], *, skip_build: bool = False) -> dict[str, Any]:
    aws = config["aws"]
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")

    certs = export_client_identity(aws, Path(__file__).with_name(".certs"))
    print(f"[aws] Device identity: {describe_certificate(certs['certfile'])}", flush=True)

    # Outbound 8883 is blocked on the bench, so the firmware talks to AWS on
    # 443; the SDK adds the x-amzn-mqtt-ca ALPN extension for that port.
    build = (
        None
        if skip_build
        else api.build_flash(
            APP_ID,
            config,
            {
                "aws_mqtt_port": int(aws.get("dut_port", 443)),
                "aws_endpoint": aws.get("endpoint"),
            },
        )
    )

    watcher = SerialWatcher(api, AwsState(), parse_serial_line)
    watcher.start()
    results: dict[str, Any] = {
        "app_id": APP_ID,
        "build_job_id": None if build is None else build.get("id"),
        "aws_endpoint": aws.get("endpoint"),
        "dut_port": int(aws.get("dut_port", 443)),
    }
    try:
        settle = float(config["ble"].get("post_flash_settle_s", 15))
        print(f"[test] Waiting {settle:.0f}s for BLE advertising...", flush=True)
        time.sleep(settle)

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
            "TLS certificates loaded in flash",
            lambda state: state.certificates_loaded,
            float(timeouts.get("certs_s", 90)),
        )
        watcher.wait_for(
            "AWS IoT MQTT connection and subscribe",
            lambda state: state.aws_subscribed,
            float(timeouts.get("aws_s", 150)),
        )
        watcher.wait_for(
            "DUT publish on the AWS topic",
            lambda state: state.aws_publish_ok,
            float(timeouts.get("publish_s", 90)),
        )
        watcher.wait_for(
            "Associated power save",
            lambda state: state.nwp_sleep,
            float(timeouts.get("sleep_s", 90)),
        )

        # Both directions, several times over, so a link that works once is
        # not mistaken for one that holds up.
        rounds = max(1, int(aws.get("rounds", 5)))
        gap = float(aws.get("round_gap_s", 3))
        broker = aws_broker_config(config, certs)
        exchanges: list[dict[str, Any]] = []

        with MqttSession(broker, client_prefix="wcbs_aws") as mqtt:
            for round_no in range(1, rounds + 1):
                print(f"[aws] === exchange {round_no}/{rounds} ===", flush=True)
                exchange: dict[str, Any] = {"round": round_no}

                if bool(aws.get("verify_dut_publish", True)):
                    presser = None
                    wait_s = float(timeouts.get("dut_publish_s", 120))
                    if bool(config.get("button", {}).get("press_each_round", True)):
                        # In associated power save the M4 sleeps between
                        # publishes; a button press wakes it on demand.
                        presser = schedule_button_press(config, wait_s)
                    topic, body = mqtt.wait_for_dut(wait_s)
                    if presser is not None:
                        presser.check()
                    print(
                        f"[pass] DUT-to-AWS publish ({round_no}/{rounds}): "
                        f"{topic} {body!r}",
                        flush=True,
                    )
                    exchange["dut_publish"] = {"topic": topic, "payload": body}
                    results["dut_publish"] = exchange["dut_publish"]

                watcher.state.message_received = None
                mqtt.publish_to_dut()
                deadline = time.time() + float(timeouts.get("host_publish_s", 60))
                while time.time() < deadline and not watcher.state.message_received:
                    time.sleep(2.5)
                    if not watcher.state.message_received:
                        mqtt.publish_to_dut()
                if not watcher.state.message_received:
                    raise TimeoutError(
                        f"DUT did not report the host's AWS message on exchange "
                        f"{round_no}/{rounds}"
                    )
                print(
                    f"[pass] AWS-to-DUT delivery ({round_no}/{rounds}): "
                    f"{watcher.state.message_received!r}",
                    flush=True,
                )
                exchange["host_to_dut"] = watcher.state.message_received

                exchanges.append(exchange)
                if round_no < rounds and gap > 0:
                    time.sleep(gap)

        results["aws_exchanges"] = exchanges
        print(f"[pass] {len(exchanges)}/{rounds} AWS exchanges completed", flush=True)

        results["serial"] = asdict(watcher.state)
        results["ok"] = True
        return results
    finally:
        watcher.stop()


def parser_self_test() -> None:
    state = AwsState()
    lines = (
        " WLAN Connection Success",
        "192.168.50.4",
        "Loading TLS CA certificate at index 0 Successfull",
        "Loading TLS Client certificate at index 0 Successfull",
        "Loading TLS Client private key at index 0 Successfull",
        "MAC ID: 08:dd:eb:cf:31:84 ",
        "Client ID: silabs_08ddebcf3184",
        "AWS IOT MQTT Connecting...",
        "AWS IOT MQTT Subscribe...",
        "Associated Power Save Enabled",
        "MQTT Publish Successful",
        " Data received = wcbs_host_to_dut",
    )
    for line in lines:
        parse_serial_line(state, line)
    assert state.wifi_connected and state.ip_address == "192.168.50.4"
    assert state.certificates_loaded, state
    assert state.client_id == "silabs_08ddebcf3184"
    assert state.aws_subscribed and state.aws_publish_ok and state.nwp_sleep
    assert state.message_received == "wcbs_host_to_dut"

    failed = AwsState()
    parse_serial_line(failed, "Mqtt Connect failed with error: -6")
    assert failed.failure
    print("Parser self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path(__file__).with_name("config.local.json")
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        parser_self_test()
        return 0
    try:
        config = load_config(args.config)
        if not str(config.get("aws", {}).get("endpoint", "")).strip():
            raise ValueError("Set aws.endpoint in config.local.json")
        result = run(config, skip_build=args.skip_build)
        result_path = Path(__file__).with_name("last_result.json")
        result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nPASS: BLE provisioning with AWS IoT MQTT ({result_path})")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"\nFAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
