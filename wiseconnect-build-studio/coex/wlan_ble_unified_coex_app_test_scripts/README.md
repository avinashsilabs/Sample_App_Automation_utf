# WLAN BLE Unified Coex App automation

This isolated Build Studio test automates the SDK
`wlan_ble_unified_coex_app` example.

## What the default test proves

1. Builds and flashes the SoC project.
2. Patches the configured lab Wi-Fi SSID/password.
3. Enables `WLAN_TASK_ENABLE`, selects MQTT mode when available, configures one
   BLE slot per role, and disables interactive SMP prompts.
4. Makes the primary Raspberry Pi advertise as `SILABS_DEV` with the SDK test
   UUIDs (`AABB`, `1AA1`, `1BB1`).
5. Confirms the DUT starts BLE advertising and scanning.
6. Confirms the DUT connects to the Pi as a BLE central and performs MTU or
   profile discovery.
7. Requires at least two successful MQTT QoS1 publishes while that BLE link
   remains uninterrupted for at least 60 seconds.

The default scope matches the supplied `output2` log: DUT-central BLE role plus
Wi-Fi/AWS MQTT coexistence.

The runner patches and verifies both `rsi_common_app.h` and `ble_config.h`
before submitting the build. This also protects the run when Build Studio was
started before the latest `build_engine.py` was copied/reloaded. A successful
run prints `[prebuild] Verified WLAN task enabled ...` and
`[prebuild] Verified ble_config.h ...` before SLC generation. If either line
is absent, the test did not use this version of `run_test.py`.

## Full dual-role mode

A single Bluetooth controller cannot create two simultaneous opposite-role ACL
links to the same DUT. To validate both DUT roles, configure a second Raspberry
Pi in `config.local.json`:

```json
"central_pi": {
  "enabled": true,
  "host": "SECOND_PI_IP",
  "port": 22,
  "username": "pi",
  "password": "SECOND_PI_PASSWORD",
  "remote_workdir": "/var/tmp/wcbs_unified_coex"
}
```

The primary Pi remains the `SILABS_DEV` peripheral. The second Pi scans for and
connects to the DUT advertisement `BLE_8S2M_COEX_DEMO`. The runner then requires
two distinct DUT UART connection records and keeps both links alive through the
MQTT acceptance period.

## Prerequisites

- Build Studio running on the Windows test host.
- Primary Pi reachable through SSH with `bluetoothctl`, `hciconfig`, `hcitool`,
  and Python 3.
- A second Pi only for full dual-role mode.
- Valid AWS endpoint and device certificates already configured in the SDK
  example. The certificates shipped as SDK placeholders cannot establish AWS
  MQTT, as documented by the SDK README.
- The selected AP must provide internet access.

## Run

Normally select **WLAN BLE Unified Coex App** in Build Studio and use
**Build, Flash, Test**. Build Studio supplies the SDK, Wi-Fi, board, toolchain,
and primary Pi values automatically.

For a standalone run, copy `config.example.json` to `config.local.json`, fill
the values, then execute:

```bat
run.bat
```

Parser-only validation:

```bat
py -3 run_test.py --self-test
```

## Pass evidence

The test passes only after all required evidence is present:

- Wi-Fi initialization.
- BLE advertising and scanning.
- One BLE connection by default, or two in full dual-role mode.
- MTU exchange or profile discovery.
- Two `QoS1 publish is successful` messages.
- No BLE disconnect during the 60-second acceptance window.

Up to two link-establishment retries are allowed before the acceptance window.
Each retry resets both the BLE stability timer and MQTT publish baseline. The
test passes only after a subsequent BLE connection remains uninterrupted for a
fresh 60 seconds while the required new MQTT publishes occur. Repeated drops
still fail the test.

The SDK may print a transient `WLAN connection failed 10003` and retry. The
runner records this as diagnostic evidence but does not fail immediately; the
WLAN stage passes only when a subsequent connected state and IPv4 address are
observed. If recovery does not occur before `wifi_connect_s`, the test fails at
the WLAN stage with the retry details included in the captured state.

All Pi-side owners receive an explicit stop request during cleanup, and each Pi
controller is protected by `/tmp/wcbs_hci0.lock` so another BLE test cannot
reset it mid-run.
