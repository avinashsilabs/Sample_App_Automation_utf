#!/usr/bin/env python3
"""AWS DevKit automation — same steps as the example readme / Si Connect app.

Maps 1:1 to Si Connect Android (features/demo/awsiot + wifi_commissioning):
  1. Build/flash the example.
  2. Pi BLE = WifiCommissioningActivity AWS_DEMO
       (FW/CHECK/SCAN/SSID/SECURITY/PASSWORD over GATT aabb).
  3. Host MQTT = AWSIOTDemoActivity
       (.p12/PEM, endpoint, subscribe dut_si91x, publish dut_aws LED JSON).
  4. Validate sensor JSON on dut_si91x and LED JSON on dut_aws.

Associated power save is optional (stock firmware has ENABLE_NWP_POWER_SAVE=0).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.harness import (  # noqa: E402
    MqttSession,
    SerialWatcher,
    StudioApi,
    load_config,
    schedule_button_press,
)
from common.aws_ble_provisioner import provision_wifi

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aws_certs import (  # noqa: E402
    DEFAULT_P12_PASSWORD,
    describe_certificate,
    export_client_identity,
    export_pkcs12,
)

APP_ID = "wifi_ble_provisioning_aws_devkit"

# Keys emitted by sensor_app.c get_sensor_data().
SENSOR_TOP_LEVEL_KEYS = (
    "temperature",
    "ambient_light",
    "white_light",
    "humidity",
    "accelerometer",
    "gyro",
)
SENSOR_AXIS_KEYS = ("x", "y", "z")

# LED command JSON accepted by wifi_app.c iot_subscribe_callback_handler().
# Only one colour may be "on" at a time.
DEFAULT_LED_COMMANDS = (
    '{"red":"on","green":"off","blue":"off"}',
    '{"red":"off","green":"on","blue":"off"}',
    '{"red":"off","green":"off","blue":"on"}',
)


@dataclass
class AwsState:
    wifi_connected: bool = False
    ip_address: Optional[str] = None
    mac_id: Optional[str] = None
    client_id: Optional[str] = None
    ble_self_name: Optional[str] = None
    ble_self_address: Optional[str] = None
    ca_loaded: bool = False
    client_cert_loaded: bool = False
    private_key_loaded: bool = False
    aws_connecting: bool = False
    aws_subscribed: bool = False
    aws_publish_ok: bool = False
    message_received: Optional[str] = None
    published_payload: Optional[str] = None
    nwp_sleep: bool = False
    failure: Optional[str] = None
    sensor_samples: list[str] = field(default_factory=list)

    @property
    def certificates_loaded(self) -> bool:
        return self.ca_loaded and self.client_cert_loaded and self.private_key_loaded

    @property
    def ble_self_ready(self) -> bool:
        return bool(self.ble_self_address)


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

    # Firmware prints: [BLE self] name=BLE_CONFIGURATOR address=AA:BB:CC:DD:EE:FF
    self_match = re.search(
        r"\[ble self\]\s*name=(\S+)\s+address=([0-9a-fA-F:]{11,17})",
        text,
        re.IGNORECASE,
    )
    if self_match:
        state.ble_self_name = self_match.group(1).strip()
        addr = self_match.group(2).strip().upper()
        if addr.lower() != "unknown":
            state.ble_self_address = addr
    elif "ble advertising started as" in low:
        name_match = re.search(r"ble advertising started as\s+(\S+)", low)
        if name_match and not state.ble_self_name:
            state.ble_self_name = name_match.group(1).strip()

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

    published = re.search(r"data to be published:\s*(.+)$", text, re.IGNORECASE)
    if published:
        payload = published.group(1).strip()
        state.published_payload = payload
        state.sensor_samples.append(payload)

    # Current firmware: "Data received on the Subscribed Topic: {...}"
    # Legacy firmware:  "Data received = ..."
    received = re.search(
        r"data received(?:\s+on\s+the\s+subscribed\s+topic)?\s*[:=]\s*(.+)$",
        text,
        re.IGNORECASE,
    )
    if received:
        state.message_received = received.group(1).strip()

    if "associated power save enabled" in low:
        state.nwp_sleep = True

    if any(marker in low for marker in FAILURES):
        state.failure = text


def validate_sensor_payload(body: str) -> dict[str, Any]:
    """Require the JSON shape emitted by sensor_app.c get_sensor_data()."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError(f"DUT publish is not JSON sensor data: {body!r}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"DUT sensor payload must be a JSON object: {body!r}")

    missing = [key for key in SENSOR_TOP_LEVEL_KEYS if key not in data]
    if missing:
        raise ValueError(f"DUT sensor payload missing keys {missing}: {body!r}")

    for name in ("temperature", "humidity"):
        if not isinstance(data[name], (int, float)):
            raise ValueError(f"DUT sensor field {name!r} must be numeric: {data[name]!r}")

    for name in ("ambient_light", "white_light"):
        if not isinstance(data[name], (int, float)):
            raise ValueError(f"DUT sensor field {name!r} must be numeric: {data[name]!r}")

    for vector_name in ("accelerometer", "gyro"):
        vector = data[vector_name]
        if not isinstance(vector, dict):
            raise ValueError(f"DUT sensor field {vector_name!r} must be an object: {vector!r}")
        missing_axes = [axis for axis in SENSOR_AXIS_KEYS if axis not in vector]
        if missing_axes:
            raise ValueError(
                f"DUT sensor field {vector_name!r} missing axes {missing_axes}: {vector!r}"
            )
        for axis in SENSOR_AXIS_KEYS:
            if not isinstance(vector[axis], (int, float)):
                raise ValueError(
                    f"DUT sensor field {vector_name}.{axis} must be numeric: {vector[axis]!r}"
                )

    return data


def led_command_for_round(aws: dict[str, Any], round_no: int) -> str:
    """Pick the LED JSON the host publishes onto dut_aws this round."""
    configured = aws.get("host_to_dut_payload")
    if isinstance(configured, list) and configured:
        return str(configured[(round_no - 1) % len(configured)])
    if isinstance(configured, str) and configured.strip() and configured.strip() != "wcbs_host_to_dut":
        return configured
    return DEFAULT_LED_COMMANDS[(round_no - 1) % len(DEFAULT_LED_COMMANDS)]


def aws_broker_config(cfg: dict[str, Any], certs: dict[str, str]) -> dict[str, Any]:
    """Host-side MQTT settings: same endpoint and identity as the device."""
    aws = cfg["aws"]
    # Empty marker accepts any publish; validate_sensor_payload() checks the body.
    publish_marker = aws.get("dut_publish_payload", "")
    if publish_marker in (None, "Hi from SiWx917"):
        publish_marker = ""
    return {
        "broker_host": aws["endpoint"],
        "broker_port": int(aws.get("host_port", 8883)),
        "dut_subscribe_topic": aws.get("dut_subscribe_topic", "dut_aws"),
        "dut_publish_topic": aws.get("dut_publish_topic", "dut_si91x"),
        "host_to_dut_payload": led_command_for_round(aws, 1),
        "dut_publish_payload": publish_marker,
        "connect_timeout_s": float(aws.get("connect_timeout_s", 30)),
        "tls": {"certfile": certs["certfile"], "keyfile": certs["keyfile"]},
    }


def prepare_aws_identity(aws: dict[str, Any], out_dir: Path) -> dict[str, str]:
    """PEM for host MQTT + PKCS#12 for the Si Connect certificate step."""
    certs = export_client_identity(aws, out_dir)
    print(f"[aws] Device identity: {describe_certificate(certs['certfile'])}", flush=True)

    password = str(aws.get("p12_password") or DEFAULT_P12_PASSWORD)
    script_dir = Path(__file__).resolve().parent
    configured = str(aws.get("p12_path") or "").strip()
    candidates = []
    if configured:
        path = Path(configured).expanduser()
        if not path.is_absolute():
            path = script_dir / path
        candidates.append(path)
    candidates.append(script_dir / str(aws.get("p12_filename") or "aws_device_cert.p12"))

    existing = next((path for path in candidates if path.is_file()), None)
    if existing is not None:
        certs["p12file"] = str(existing.resolve())
        certs["p12_password"] = password
        print(
            f"[aws] Using existing PKCS#12: {existing} "
            f"(Si Connect certificate password from aws.p12_password; "
            f"endpoint={aws.get('endpoint')}, "
            f"subscriber={aws.get('dut_publish_topic', 'dut_si91x')}, "
            f"publisher={aws.get('dut_subscribe_topic', 'dut_aws')})",
            flush=True,
        )
        return certs

    try:
        p12 = export_pkcs12(
            certs["certfile"],
            certs["keyfile"],
            out_dir,
            password=password,
            filename=str(aws.get("p12_filename") or "aws_device_cert.p12"),
        )
        certs.update(p12)
        print(
            "[aws] PKCS#12 ready for Si Connect fields: "
            "Certificate file + Certificate password "
            f"(endpoint={aws.get('endpoint')}, "
            f"subscriber={aws.get('dut_publish_topic', 'dut_si91x')}, "
            f"publisher={aws.get('dut_subscribe_topic', 'dut_aws')})",
            flush=True,
        )
    except FileNotFoundError as exc:
        # OpenSSL missing on the bench must not block host MQTT verification.
        print(f"[warn] Skipping .p12 export: {exc}", flush=True)
    return certs


def run(config: dict[str, Any], *, skip_build: bool = False) -> dict[str, Any]:
    aws = config["aws"]
    api = StudioApi(config["studio"].get("url", "http://127.0.0.1:5050"))
    api.request("GET", "/api/health")

    certs = prepare_aws_identity(aws, Path(__file__).with_name(".certs"))

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
        "dut_subscribe_topic": aws.get("dut_subscribe_topic", "dut_aws"),
        "dut_publish_topic": aws.get("dut_publish_topic", "dut_si91x"),
        "wifi_ssid": config.get("wifi", {}).get("ssid"),
        "p12file": certs.get("p12file"),
    }
    try:
        settle = float(config["ble"].get("post_flash_settle_s", 15))
        print(f"[test] Waiting {settle:.0f}s for BLE advertising...", flush=True)
        time.sleep(settle)

        # Detect DUT self MAC/name from UART, then pin Pi scan to that identity.
        ble_cfg = dict(config.get("ble") or {})
        timeouts = config.get("timeouts", {})
        identity_timeout = float(
            ble_cfg.get(
                "self_identity_timeout_s",
                timeouts.get("ble_self_s", max(settle, 30.0)),
            )
        )
        if not ble_cfg.get("address"):
            print(
                f"[ble] Waiting up to {identity_timeout:.0f}s for UART "
                "'[BLE self] name=... address=...'",
                flush=True,
            )
            watcher.wait_for(
                "DUT BLE self identity (MAC + name)",
                lambda state: state.ble_self_ready,
                identity_timeout,
            )
        elif not watcher.state.ble_self_address:
            # Still try briefly; firmware print confirms advertising is up.
            try:
                watcher.wait_for(
                    "DUT BLE self identity (MAC + name)",
                    lambda state: state.ble_self_ready,
                    min(identity_timeout, 20.0),
                )
            except TimeoutError:
                print(
                    f"[ble] Using config ble.address={ble_cfg.get('address')!r} "
                    "(UART self identity not seen yet)",
                    flush=True,
                )

        if watcher.state.ble_self_address:
            ble_cfg["address"] = watcher.state.ble_self_address
        if watcher.state.ble_self_name:
            ble_cfg["device_name"] = watcher.state.ble_self_name
        ble_cfg["require_self_identity"] = True
        if not ble_cfg.get("address"):
            raise RuntimeError(
                "DUT BLE self MAC unknown; cannot filter Pi scan. "
                "Flash firmware that prints '[BLE self] name=... address=...' "
                "or set ble.address in config.local.json"
            )
        config = dict(config)
        config["ble"] = ble_cfg
        results["ble_self_name"] = ble_cfg.get("device_name")
        results["ble_self_address"] = ble_cfg.get("address")
        print(
            f"[ble] Pi will filter scan for self name={ble_cfg.get('device_name')!r} "
            f"address={ble_cfg.get('address')!r} before provisioning",
            flush=True,
        )

        print(
            f"[ble] Provisioning Wi-Fi SSID={config['wifi'].get('ssid')!r} "
            f"over {ble_cfg.get('device_name') or 'BLE_CONFIGURATOR'} "
            f"({ble_cfg.get('address')})...",
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

        require_power_save = bool(aws.get("require_power_save", False))
        if require_power_save:
            watcher.wait_for(
                "Associated power save",
                lambda state: state.nwp_sleep,
                float(timeouts.get("sleep_s", 90)),
            )
        else:
            try:
                watcher.wait_for(
                    "Associated power save",
                    lambda state: state.nwp_sleep,
                    float(timeouts.get("sleep_s", 10)),
                )
            except TimeoutError:
                print(
                    "[warn] Associated power save not observed "
                    "(stock firmware has ENABLE_NWP_POWER_SAVE=0); continuing",
                    flush=True,
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
                    sensor = validate_sensor_payload(body)
                    print(
                        f"[pass] DUT sensor publish ({round_no}/{rounds}) on {topic}: "
                        f"temp={sensor['temperature']} humidity={sensor['humidity']} "
                        f"ambient={sensor['ambient_light']} white={sensor['white_light']}",
                        flush=True,
                    )
                    exchange["dut_publish"] = {
                        "topic": topic,
                        "payload": body,
                        "sensor": sensor,
                    }
                    results["dut_publish"] = exchange["dut_publish"]

                    serial_payload = watcher.state.published_payload
                    if serial_payload and '"temperature"' in serial_payload:
                        try:
                            serial_sensor = validate_sensor_payload(serial_payload)
                            exchange["serial_sensor"] = serial_sensor
                            print(
                                "[pass] Serial 'Data to be published' matches sensor schema",
                                flush=True,
                            )
                        except ValueError as exc:
                            print(f"[warn] Serial publish line not usable: {exc}", flush=True)

                led_payload = led_command_for_round(aws, round_no)
                watcher.state.message_received = None
                mqtt.publish_to_dut(led_payload)
                deadline = time.time() + float(timeouts.get("host_publish_s", 60))
                while time.time() < deadline and not watcher.state.message_received:
                    time.sleep(2.5)
                    if not watcher.state.message_received:
                        mqtt.publish_to_dut(led_payload)
                if not watcher.state.message_received:
                    raise TimeoutError(
                        f"DUT did not report the host LED command on exchange "
                        f"{round_no}/{rounds}"
                    )
                received = watcher.state.message_received
                # Confirm the LED JSON (or at least the active colour key) landed.
                if "red" not in received and "green" not in received and "blue" not in received:
                    raise ValueError(
                        f"DUT subscribe callback did not echo LED JSON: {received!r}"
                    )
                print(
                    f"[pass] AWS-to-DUT LED command ({round_no}/{rounds}): {received!r}",
                    flush=True,
                )
                exchange["host_to_dut"] = received
                exchange["led_command"] = led_payload

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
    sample_sensor = (
        '{"temperature": 25, "ambient_light": 120.50, "white_light": 80.25, '
        '"humidity": 40, "accelerometer": {"x": 0.02, "y": -0.01, "z": 1.00}, '
        '"gyro": {"x": 0.10, "y": -0.05, "z": 0.00}}'
    )
    led_cmd = '{"red":"on","green":"off","blue":"off"}'
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
        f"Data to be published: {sample_sensor}",
        "MQTT Publish Successful",
        f"Data received on the Subscribed Topic: {led_cmd} ",
    )
    for line in lines:
        parse_serial_line(state, line)
    assert state.wifi_connected and state.ip_address == "192.168.50.4"
    assert state.certificates_loaded, state
    assert state.client_id == "silabs_08ddebcf3184"
    assert state.aws_subscribed and state.aws_publish_ok
    assert state.published_payload == sample_sensor
    assert state.message_received == led_cmd
    assert validate_sensor_payload(sample_sensor)["temperature"] == 25
    assert led_command_for_round({}, 1).startswith('{"red"')

    # Legacy serial format still parses.
    legacy = AwsState()
    parse_serial_line(legacy, " Data received = wcbs_host_to_dut")
    assert legacy.message_received == "wcbs_host_to_dut"

    failed = AwsState()
    parse_serial_line(failed, "Mqtt Connect failed with error: -6")
    assert failed.failure

    ble_id = AwsState()
    parse_serial_line(
        ble_id,
        "[BLE self] name=BLE_CONFIGURATOR address=D4:48:67:4A:36:70",
    )
    assert ble_id.ble_self_name == "BLE_CONFIGURATOR"
    assert ble_id.ble_self_address == "D4:48:67:4A:36:70"
    assert ble_id.ble_self_ready
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
