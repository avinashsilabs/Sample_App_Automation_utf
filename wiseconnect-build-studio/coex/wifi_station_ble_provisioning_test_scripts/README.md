# SiWG917 Wi-Fi Client BLE Provisioning test

This folder automates the SDK example:

`examples/snippets/wlan_ble/wifi_station_ble_provisioning/wifi_station_ble_provisioning_soc.slcp`

It follows the example README and uses WiseConnect Build Studio for SLC
generation, CMake build, Commander flash, and DUT serial capture.

The BLE central is the same path as the working Out of Box runner: lab
Raspberry Pi over SSH (`pi_ble.py` / `pi_ble_provisioner.py` /
`ble_protocol.py`). After the DUT prints its STA IP and IPCONFIG done,
the NUC (if SSH password is set) or the Pi pings that IP. BLE disconnect
happens only after the ping. This app has no MQTT or button step.

## Test sequence

1. Build and flash `wifi_station_ble_provisioning` through `/api/build-flash`.
2. Wait for BLE advertising (`BLE_CONFIGURATOR`).
3. BLE connect, then Wifi-Commissioning scan for the configured AP.
4. Send SSID/security/password and keep the BLE link up.
5. Require UART evidence of Wi-Fi join, the obtained STA IPv4 (for example
   `192.168.50.34WIFI App ...`), and `IPCONFIG Done`.
6. From the NUC or Raspberry Pi, ping that DUT IP. Require at least
   `min_ping_responses` ICMP replies (default 1).
7. Disconnect BLE (`Disconnected - remote_dev_addr` / Started Advertising).

## Requirements

- WiseConnect Build Studio running at `http://127.0.0.1:5050`
- SiWG917 SoC board supported by the selected `.slcp` (lab: BRD4338A)
- Lab 2.4 GHz access point
- A BLE central: either the lab Raspberry Pi over SSH (`ble.backend: pi`, the
  default when `pi.host` is set) or a host adapter supported by Bleak

Python dependencies:

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
- `pi.host`: lab Raspberry Pi used as the BLE central

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
`examples/snippets/wlan_ble`, select **Wi-Fi Client BLE Provisioning**, and
click **Run WLAN + BLE Test**. Studio writes a temp config from the UI (SDK,
board, Pi IP) on top of `config.local.json`.

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

- SDK procedure: `wifi_station_ble_provisioning/readme.md`
- Working OOB runner this clones:
  - `out_of_box_demo_test_scripts/run_test.py`
  - `out_of_box_demo_test_scripts/pi_ble.py`
  - `out_of_box_demo_test_scripts/pi_ble_provisioner.py`
  - `out_of_box_demo_test_scripts/ble_protocol.py`

The implementation is kept local to this example folder so additional WLAN+BLE
examples can be added as sibling `<example_full_name>_test_scripts` folders.
