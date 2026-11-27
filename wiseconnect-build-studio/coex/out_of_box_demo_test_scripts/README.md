# SiWG917 Out of Box Demo test

This folder automates the SDK example:

`examples/snippets/wlan_ble/out_of_box_demo/wifi_out_of_box_demo_soc.slcp`

It follows the example README and uses WiseConnect Build Studio for SLC
generation, CMake build, Commander flash, and DUT serial capture.

## Test sequence

1. Build and flash `out_of_box_demo` through `/api/build-flash`.
2. Find the `BLE_CONFIGURATOR` advertiser.
3. Use the Simplicity Connect commissioning GATT protocol to scan for the
   configured access point and send SSID/security/password.
4. Require DUT serial evidence for WLAN connection and a station IPv4 address.
5. Require at least one `www.silabs.com` ping response.
6. Require Mosquitto MQTT connection and NWP connected sleep.
7. Repeat `mqtt.rounds` times (5 by default), so a link that happens to work
   once is not mistaken for one that holds up:
   - Publish on `Si917_MQTT_RECEIVE` and require DUT UART reception.
   - Press BTN0 and require `Button is pressed` on `Si917_APP_STATUS`.

The BTN0 gate preserves the out-of-box firmware behavior from the SDK README;
the script does not patch application source. The press is issued over the
mainboard's admin console (`button.host`, telnet 4902) via `wstk_button.py`, so
runs are unattended; clear `button.host` to be prompted to press it by hand.

## Requirements

- WiseConnect Build Studio running at `http://127.0.0.1:5050`
- SiWG917 SoC board supported by the selected `.slcp`
- Internet-connected 2.4 GHz access point
- A BLE central: either the lab Raspberry Pi over SSH (`ble.backend: pi`, the
  default when `pi.host` is set) or a host adapter supported by Bleak
- Access to `test.mosquitto.org:1883` from this host

If the Pi discovers `BLE_CONFIGURATOR` but BlueZ reports
`org.bluez.Error.Failed: Input/output error` while connecting, the provisioner
now removes the stale device state and power-cycles the Pi adapter before the
next retry. Keep the default `ble.recover_adapter_on_connect_failure: true`.
If every retry still fails, ensure no phone, Simplicity Connect instance, or
other BLE central is connected to the DUT, then reset the DUT and retry.

### MQTT relay

The bench LAN blocks outbound MQTT: 1883, 1884, and 8883 time out to every
broker, while 443 and 8080 succeed. The test host reaches the broker on its
other interface, so with `mqtt.relay: "auto"` the run starts a TCP forwarder on
the host's lab address and builds the firmware pointing at it. The DUT still
speaks to the real `test.mosquitto.org`; only the path changes. Set
`mqtt.relay: false` to disable it, or set `mqtt.broker_host` to a LAN IP to have
the DUT connect straight to a broker on the bench.

If the Pi cannot open the relay port, Windows Firewall is blocking inbound
1883; the run stops with the exact `netsh` command to allow it.
- Python dependencies:

```powershell
pip install -r requirements.txt
```

## Configure and run

```powershell
Copy-Item config.example.json config.local.json
```

Edit `config.local.json`:

- `studio.sdk_root`: Simplicity SDK root accepted by Build Studio
- `studio.examples_root`: the WiSeConnect `examples/snippets/wlan_ble` folder
- `studio.board`: connected board, normally `brd4338a`
- `wifi`: test AP credentials (`security`: 0=open, 1=WPA, 2=WPA2, 3=WEP, 7=WPA3)

Start Build Studio:

```powershell
cd ..\..\..
python app.py
```

Run the test in another terminal:

```powershell
.\run.bat
```

Alternatively, set the Build Studio **Examples root** to
`examples/snippets/wlan_ble`, select **Out Of Box Demo**, and click
**Run WLAN + BLE Test**. The same `config.local.json` is used.

To validate the local serial parser without hardware:

```powershell
python run_test.py --self-test
```

To test already-flashed firmware:

```powershell
python run_test.py --config config.local.json --skip-build
```

Successful hardware runs write `last_result.json` in this folder.

## Source references

- SDK procedure: `out_of_box_demo/readme.md`
- Reference automation:
  - `opn_automation/lab/oob_app_sequence.py`
  - `opn_automation/lab/uart_monitor.py`
  - `opn_automation/lab/mosquitto_mqtt_verify.py`
  - `opn_automation/e2e_aws_ble/ble_protocol.py`
  - `opn_automation/e2e_aws_ble/pi_ble_provisioner.py`

The implementation is kept local to this example folder so additional WLAN+BLE
examples can be added as sibling `<example_full_name>_test_scripts` folders.
