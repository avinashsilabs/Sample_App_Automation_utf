# SiWG917 HTTPS BLE Dual Role test

This folder automates the SDK example:

`examples/snippets/wlan_ble/wifi_https_ble_dual_role/wifi_https_ble_dual_role_soc.slcp`

It follows the example README and uses WiseConnect Build Studio for SLC
generation, CMake build, Commander flash, and DUT serial capture.

The download host is the lab **NUC** (`192.168.50.36`) when SSH works.
This Windows host cannot reach `192.168.50.x`, so NUC login is tried
directly, then jumped through the Pi (`10.207.18.79`). If NUC auth is
missing, the same `download_server.py` is started on the Pi's lab-AP
address (`192.168.50.57`) so the DUT can still fetch `index.html`.
The script does not run those servers on the Windows Build Studio host.

## Test sequence

Default `--mode both` is two build/flash cycles so HTTP and HTTPS are not
mistaken for each other:

1. Start the download server (`index.html`, SDK `server-cert.pem` /
   `server-key.pem`). On the NUC that is :80 / :443 as the readme. On
   the Pi fallback it is :8080 / :8443 (no root bind) and the firmware
   `SERVER_PORT` is patched to match. The helper closes TCP after the
   response because `wifi_http_s.c` treats server FIN (`ENOTCONN`) as
   end-of-file.
2. Confirm the lab Pi can open the download host:port on the DUT STA subnet.
3. Build and flash `wifi_https_ble_dual_role` through `/api/build-flash`
   with `SERVER_IP_ADDRESS` / `SERVER_PORT`, `HTTPS_DOWNLOAD` 0 or 1, and
   `CONTINUOUS_HTTP_DOWNLOAD` 1 (SDK default is 0; Studio patches it on).
4. Require DUT serial evidence:
   - `WLAN connected state` and a station IPv4 address
   - HTTPS only: `Load TLS CA certificate at index 0 Success`
   - `TCP Socket Connect Success`
   - `HTTP download started` or `HTTPS download started`
   - `HTTP/HTTPS download completed, total received bytes: N` (N > 0).
     A garbled `HTTP dInitiatingownload st BLE` line still counts.
   - `Advertising started` (`SI_COEX_MAX_DEMO`) and `Scanning started`
   - Pi BLE central connects to `SI_COEX_MAX_DEMO`, then UART
     `Number of central devices connected`
   - If `CONTINUOUS_HTTP_DOWNLOAD` is on, at least `min_download_cycles`
     completed prints (default 2), after BLE is up so the link is not blocked

BLE central/peripheral GATT data transfer (phone or dongle) is the rest of
the SDK README (steps 9–15) and is not part of this download pass.

## Requirements

- WiseConnect Build Studio running at `http://127.0.0.1:5050`
- SiWG917 SoC board supported by the selected `.slcp` (lab: BRD4338A)
- Lab 2.4 GHz access point (DUT and NUC on the same STA subnet)
- NUC over SSH with Python 3 and permission to bind 80/443
- Raspberry Pi on the same lab LAN (used only to probe that the NUC port
  is reachable, the same way OOB probes the MQTT relay)

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
- `nuc`: preferred download box `192.168.50.36` (`username` / `password`;
  ports 80/443 need sudo). `backend` is `auto` (NUC, then Pi), `nuc`,
  or `pi`
- `continuous_http_download`: `1` (default) sets SDK
  `CONTINUOUS_HTTP_DOWNLOAD` so the DUT keeps fetching after the first
  file. Set `0` for a single download.
- `min_download_cycles`: how many `download completed` prints are
  required (default 2)
- `pi.host`: Windows-reachable Pi used as SSH jump, BLE-LAN probe, and
  fallback HTTP/HTTPS server

Start Build Studio:

```powershell
cd ..\..\..
python app.py
```

Run the test in another terminal:

```powershell
.\run.bat
```

HTTP only or HTTPS only:

```powershell
.\run.bat --mode http
.\run.bat --mode https
```

Alternatively, set the Build Studio **Examples root** to
`examples/snippets/wlan_ble`, select **Https Ble Dual Role**, and click
**Run WLAN + BLE Test**. Studio writes `config.ui.json` from the UI (SDK,
board, NUC IP) on top of `config.local.json`.

To validate the local serial parser without hardware:

```powershell
python run_test.py --self-test
```

To test already-flashed firmware (NUC server is still started):

```powershell
python run_test.py --config config.local.json --skip-build --mode https
```

Successful hardware runs write `last_result.json` in this folder.

## Source references

- SDK procedure: `wifi_https_ble_dual_role/readme.md`
- SDK HTTP server: `resources/scripts/simple_http_server.py`
- SDK TLS files: `resources/certificates/server-cert.pem`, `server-key.pem`
- NUC helper in this folder: `download_server.py` (close-after-send)

The implementation is kept local to this example folder so additional WLAN+BLE
examples can be added as sibling `<example_full_name>_test_scripts` folders.
