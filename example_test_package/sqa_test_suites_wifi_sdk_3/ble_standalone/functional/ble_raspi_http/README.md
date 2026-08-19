# Raspberry Pi BLE HTTP API

HTTP control plane for BLE on a remote Raspberry Pi (BlueZ). Scan, connect, optional passkey bonding, GATT discovery, and notification receive.

| Item | Value |
| --- | --- |
| Test | `test_ble_raspi_http_passkey_notify.py` |
| Default base URL | `http://<raspberry-pi-ip>:5000` |
| Bind | `0.0.0.0` (host networking — do **not** use `localhost` from your PC) |
| Env overrides | `BLE_RASPI_HTTP_PORT`, `BLE_RASPI_HTTP_LIFETIME_SEC`, `BLE_RASPI_SERVICE_CLASSES` |

Set the base URL once in PowerShell:

```powershell
$base = "http://10.208.71.114:5000"   # replace with your Pi IP
```

---

## Endpoints

### `GET /health`

Liveness check. Also available as `GET /`.

```powershell
Invoke-RestMethod -Method GET -Uri "$base/health"
```

**Response (example)**

```json
{
  "ok": true,
  "service": "ble-raspi-http",
  "status": { "...": "same fields as /ble/status" }
}
```

---

### `GET /ble/status`

Current controller state: connection, bond, notifications, last error, registered local GATT service classes.

```powershell
Invoke-RestMethod -Method GET -Uri "$base/ble/status"
```

**Useful `status.state` values**

| State | Meaning |
| --- | --- |
| `ready` | Stack initialized, idle |
| `scanning` | LE scan in progress |
| `connecting` / `connected` | Link coming up / up |
| `awaiting_passkey` / `passkey_submitted` / `pairing` | SMP in progress |
| `bonded` / `stable` | Bond done / link stayed up |
| `notifications_ready` | CCCD subscribed |
| `connect_failed` / `pair_failed` / `gatt_failed` / `disconnected` | Error / drop |

---

### `POST /ble/scan`

Scan for BLE advertisers.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `timeout` | int | `10` | Scan duration (seconds) |
| `address` | string | — | Optional MAC to filter / wait for |

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/scan" -ContentType "application/json" `
  -Body (@{ timeout = 10; address = "D4:48:67:DD:E4:6E" } | ConvertTo-Json)
```

---

### `POST /ble/connect`

Connect to a peer. With `bond=true` (default), starts SMP via `pair_and_connect` and waits for `/ble/passkey`. With `bond=false`, plain connect only (no SMP).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | string | **required** | Peer MAC |
| `bond` | bool | `true` | `true` = passkey bonding; `false` = no SMP. Alias: `pair` |
| `capability` | string | `KeyboardOnly` (bond) / `NoInputNoOutput` (no bond) | BlueZ agent capability |
| `min_conn_interval` | int | — | LE connection interval min (units of 1.25 ms) |
| `max_conn_interval` | int | — | LE connection interval max |
| `conn_latency` | int | — | Slave latency |
| `supervision_timeout` | int | — | Supervision timeout (units of 10 ms) |

**With passkey (SMP)**

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/connect" -ContentType "application/json" `
  -Body (@{
    address             = "D4:48:67:DD:E4:6E"
    bond                = $true
    capability          = "KeyboardOnly"
    min_conn_interval   = 40
    max_conn_interval   = 40
    conn_latency        = 0
    supervision_timeout = 500
  } | ConvertTo-Json)
```

Then read the passkey on the peer/DUT and call `/ble/passkey`.

**Without SMP / passkey**

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/connect" -ContentType "application/json" `
  -Body (@{
    address             = "D4:48:67:DD:E4:6E"
    bond                = $false
    min_conn_interval   = 40
    max_conn_interval   = 40
    conn_latency        = 0
    supervision_timeout = 500
  } | ConvertTo-Json)
```

Skip `/ble/passkey` entirely when `bond=false`.

> Peer must have SMP enabled (e.g. `SMP_ENABLE_C1 1`) for passkey bonding. With SMP off on the peer, use `bond=false`.

---

### `POST /ble/passkey`

Submit the runtime passkey shown on the peer during bonding. Only used when `bond=true`.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `passkey` | string | **required** | 6-digit (or peer-defined) passkey. Aliases: `pin`, `pin_code` |

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/passkey" -ContentType "application/json" `
  -Body (@{ passkey = "123456" } | ConvertTo-Json)
```

Poll `/ble/status` until `bonded` / `stable` (or `pair_failed`).

---

### `GET /ble/services`

List GATT services and characteristics **on the connected peer only** (Pi local GATT services are filtered out).

```powershell
Invoke-RestMethod -Method GET -Uri "$base/ble/services" | ConvertTo-Json -Depth 6
```

**Response fields**

| Field | Description |
| --- | --- |
| `device_path` | BlueZ D-Bus path for the peer |
| `service_count` / `characteristic_count` | Counts under the peer |
| `services` | Map of UUID → path, primary flag, characteristics + flags |
| `service_paths` / `characteristic_paths` | Raw D-Bus paths |

Use this to pick the correct `service_uuid` / `char_uuid` for notifications.

---

### `POST /ble/notifications/enable`

Enable notifications (or indications) on a peer characteristic. Waits for BlueZ `ServicesResolved`, then writes the CCCD and subscribes.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `service_uuid` | string | auto | Service UUID. Optional; short forms `aabb`, `0xAABB` accepted |
| `char_uuid` | string | auto | Characteristic UUID. Optional; same short-form rules |
| `timeout` | int | `30` | Seconds to wait for `ServicesResolved` |

If UUIDs are omitted, the first **notify**-capable characteristic on the peer is preferred over **indicate**.

**Explicit UUIDs (recommended for custom SiLabs demo chars)**

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/notifications/enable" -ContentType "application/json" `
  -Body (@{
    service_uuid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uuid    = "00001aa1-0000-1000-8000-00805f9b34fb"
  } | ConvertTo-Json)
```

**Auto-pick**

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/notifications/enable" `
  -ContentType "application/json" -Body "{}"
```

**Success extras:** `flags`, `notifying` (should be `true` after CCCD write), `char_path`.

---

### `POST /ble/read`

GATT **Read** on a peer characteristic (BlueZ `ReadValue`). Used by **`gatt_long_read`** SERVER after connect — long attribute values (MTU‑sized) are returned as bytes.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `service_uuid` | string | yes | Short (`aabb`) or 128‑bit |
| `char_uuid` | string | yes | Short (`1aa1`) or 128‑bit |
| `timeout` | int | no | Services-resolved wait (default 30) |

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/read" -ContentType "application/json" `
  -Body (@{ service_uuid = "aabb"; char_uuid = "1aa1" } | ConvertTo-Json)
```

**Success:** `length`, `value_hex`, `value_preview`, `value_bytes` (first 128).

---

### `GET /ble/notifications`

Return buffered notification payloads for the subscribed characteristic.

```powershell
Invoke-RestMethod -Method GET -Uri "$base/ble/notifications" | ConvertTo-Json -Depth 5
```

| Field | Description |
| --- | --- |
| `char_uuid` | Characteristic currently subscribed |
| `notifications` | List of payloads (UTF-8 text, or hex for binary) |
| `count` | Number of buffered entries |
| `status` | Same object as `/ble/status` |

Binary payloads (bytes &gt; 0x7F) are stored as hex strings so the D-Bus handler does not crash.

---

### `POST /ble/notifications/clear`

Clear the in-memory notification buffer.

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/notifications/clear"
```

---

## Who advertises? (read this first)

| App | DUT role | Pi role | Does Pi need to advertise? |
| --- | --- | --- | --- |
| `ble_central` / `ble_accept_list` / `ble_ae_central` / `ble_longrange_2mbps` / `ble_datalength` | Central (scan+connect) | Peripheral | **Yes** — `SILABS_DEV` |
| `ble_ae_peripheral` / `ble_ibeacon` / `ble_heart_rate_profile` / `gatt_long_read` / `ble_hid_on_gatt` | Peripheral (advertises) | Central (scan+connect) | **No** — use `/ble/scan` + `/ble/connect` |

Build Studio / UTF already starts Pi advertising automatically for DUT-central apps. For manual lab use, call the advertise APIs below.

---

### `POST /ble/peripheral/advertise`

Start **Pi LE advertising only** (GATT server + LocalName). Does **not** wait for the DUT to connect. Use when DUT is central (`ble_central`, …).

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `local_name` | string | `SILABS_DEV` | Alias / AD name (alias: `name`) |
| `legacy_hci` | bool | `true` | Legacy ADV_IND for `rsi_ble_connect` peers (alias: `legacy`) |
| `capability` | string | `NoInputNoOutput` | BlueZ agent capability |
| `service_classes` | list/string | Heart Rate + demo set | Optional GATT override |

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/peripheral/advertise" `
  -ContentType "application/json" `
  -Body (@{ local_name = "SILABS_DEV"; legacy_hci = $true } | ConvertTo-Json)
```

Then poll `GET /ble/status` → `advertising_on: true`, note `local_address` (put that in DUT `RSI_BLE_DEV_ADDR` if not using name match).

Optional: `POST /ble/peripheral/expect-peer` with the DUT MAC, then wait until `connected: true`.

---

### `POST /ble/peripheral/advertise-and-connect`

One-shot helper for **DUT = central**, **Pi = peripheral** apps (`ble_central`, `ble_accept_list`, `ble_ae_central`, `ble_longrange_2mbps`, `ble_datalength`):

1. Starts connectable LE advertising on the Pi (`LocalName`, default `SILABS_DEV`)
2. Registers BlueZ GATT demo services (same set used by other UTF peripheral tests) so DUT profile discovery does **not** drop the link:
   - **HeartRateService** (`0x180D` / `0x2A37` notify) — also placed in the AD packet
   - ImmediateAlertService, HealthThermometerService, BatteryService
3. Registers the DUT MAC as the expected peer
4. Blocks until the DUT connects, or until `timeout`
5. On connect, starts local **Heart Rate Measurement** notifications (data transfer) unless disabled

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `address` | string | **required** | DUT MAC (alias: `dut_address`) |
| `local_name` | string | `SILABS_DEV` | Pi advertising / Alias name (alias: `name`) |
| `timeout` | int | `180` | Seconds to wait for DUT to connect (alias: `timeout_sec`) |
| `capability` | string | `NoInputNoOutput` | BlueZ agent capability |
| `service_classes` | list/string | Heart Rate + demo set | Override GATT classes (Heart Rate always forced in) |
| `start_hr_notify` | bool | `true` | Start HR notify after connect (alias: `hr_notify`) |

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/peripheral/advertise-and-connect" `
  -ContentType "application/json" `
  -Body (@{
    address    = "D4:48:67:DD:E4:6E"   # your DUT MAC
    local_name = "SILABS_DEV"
    timeout    = 180
  } | ConvertTo-Json)
```

**Success (example)**

```json
{
  "ok": true,
  "message": "Pi advertising with GATT; DUT connected (Heart Rate notify started)",
  "local_address": "D8:3A:DD:EF:A2:D6",
  "peripheral_local_name": "SILABS_DEV",
  "target_address": "D4:48:67:DD:E4:6E",
  "advertising_on": true,
  "connected": true,
  "service_classes": [
    "HeartRateService",
    "ImmediateAlertService",
    "HealthThermometerService",
    "BatteryService"
  ],
  "advertise_uuids": ["0x180D"],
  "heart_rate_notify_started": true,
  "waited_sec": 12.4,
  "status": { "...": "same as /ble/status" }
}
```

HTTP **408** on timeout (Pi still advertising; check DUT firmware peer macros).  
This call **blocks** for up to `timeout` seconds — raise your client timeout accordingly.

> DUT firmware must target the Pi: `RSI_REMOTE_DEVICE_NAME "SILABS_DEV"` or `RSI_BLE_DEV_ADDR` = `local_address`.

Lower-level split (same roles): `POST /ble/peripheral/advertise` → `POST /ble/peripheral/expect-peer` → poll `GET /ble/status`.

---

### `POST /ble/orchestration/complete` (Build Studio)

Gracefully ends orchestrated pytest: stops the HTTP server only (Bluetooth stays up; pytest is **not** killed).

Call **after** post-notify stability finishes (`GET /ble/status` → `post_notify_stability_done: true` and `post_notify_stability_ok: true`). Default stability window is **300 s** (`BLE_ORCHESTRATION_STABILITY_SEC`).

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/orchestration/complete" -ContentType "application/json" -Body "{}"
```

---

### `POST /ble/orchestration/abort` (force stop)

Force-stops the BLE HTTP server and ends the pytest as **failed** (report shows abort reason). Skips stability gates. Use when Build Studio errors or before relaunching UTF so a stale `/health` cannot stay green.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `reason` | string | `aborted by host` | Written into status / pytest failure (aliases: `error`, `message`) |

```powershell
Invoke-RestMethod -Method POST -Uri "$base/ble/orchestration/abort" `
  -ContentType "application/json" `
  -Body (@{ reason = "stopped from Build Studio" } | ConvertTo-Json)
```

Build Studio: **Stop Pi BLE Server** button → `POST /api/pi/abort-ble-http`. The **Build, Flash, Test** pipeline also aborts any leftover server before launching UTF, and aborts again on pipeline errors.
---

## Typical flows

### Passkey bonding

```text
1. POST /ble/scan
2. POST /ble/connect   { address, bond: true }
3. Read passkey on peer/DUT
4. POST /ble/passkey   { passkey }
5. GET  /ble/status    (wait for bonded / stable)
6. GET  /ble/services  (optional — pick UUIDs)
7. POST /ble/notifications/enable
8. GET  /ble/notifications
```

### Plain connect (no SMP)

```text
1. POST /ble/scan
2. POST /ble/connect   { address, bond: false }
3. GET  /ble/services  (optional)
4. POST /ble/notifications/enable
5. GET  /ble/notifications
```

### iBeacon advertiser (`ble_ibeacon` — Build Studio / UTF)

DUT runs peripheral iBeacon advertising only (no connect). Pi scans on an interval and checks the DUT MAC is still visible.

```text
1. Flash ble_ibeacon on DUT (advertising as "iBeacon" per SDK readme)
2. Launch UTF — test_ble_ibeacon_http_flow on Pi
3. Build Studio: resolve DUT MAC (serial or UI field)
4. Every 30s for 5 min: POST /ble/scan { "timeout": 12, "address": "<DUT_MAC>" }
   — require address_found: true each sample
5. POST /ble/orchestration/ibeacon-stability { "ok": true, "sample_count": N }
6. POST /ble/orchestration/complete
```

Env overrides: `BLE_IBEACON_SCAN_DURATION_SEC` (default 300), `BLE_IBEACON_SCAN_INTERVAL_SEC` (30).

### AE Central (`ble_ae_central` — Build Studio / UTF)

Matches SDK / manual-tester demo: **DUT = AE central**, **Pi = peripheral** (`SILABS_DEV`).  
**Pass = connect established.** No GATT data transfer, no Heart Rate / Battery profiles on the Pi, no 5‑minute soak. Pytest report should stay close to the DUT serial checklist below.

Expected DUT serial (same as Docklight checklist):

```text
Wi-Fi Initialization Success
Firmware version is: …
Local device address …
set ae scan params success
set ae scan enable success
… ae report rec for <Pi MAC> …
Initiating connect command
Remote device connected <Pi MAC>
```

```text
1. Launch UTF — Pi advertises as SILABS_DEV
2. Arm expect-peer (DUT MAC in UI) before flash
3. Build & flash ble_ae_central (peer name/MAC = Pi)
4. Wait for Pi connected=true  OR  DUT serial "Remote device connected"
5. Print short serial checklist → PASS → complete
```

Set `RSI_REMOTE_DEVICE_NAME` / `RSI_BLE_DEV_ADDR` to the Pi.  
Env: `BLE_AE_CENTRAL_PERIPHERAL_NAME` (default `SILABS_DEV`).

### AE Peripheral (`ble_ae_peripheral` — Build Studio / UTF)

Matches SDK `siwx91x_bluetooth_le_ae_peripheral_freertos` readme (phone as central):  
**DUT = AE peripheral** (extended advertising), **Pi = central** (scan + connect).  
Opposite roles of `ble_ae_central`. **Pass = connect established** — no GATT notify, no 5‑min soak.

SDK notes that matter for the lab:

- LocalName: `RSI_BLE_LOCAL_NAME` → `AE_PERIPHERAL`
- SET1 uses `LE_RANDOM_ADDRESS` from `RSI_BLE_SET_RAND_ADDR` (valid static random, e.g. `C1:44:33:AA:BB:CC`; `11:…` is invalid and often filtered)
- SET2 (`ADV_SET2=1`) uses the silicon **public** address — set that in the UI
- Central must support **extended** scanning (BlueZ on Pi does)
- Prefer `ENABLE_NWP_POWER_SAVE=0` in `app.c` (sample often ships with `1`)
- AE SL logging may be disabled — Pi `connected=true` is the pass signal

Expected host report (clean / simple):

```text
=== AE Peripheral (SDK siwx91x_bluetooth_le_ae_peripheral) ===
  DUT advertises as 'AE_PERIPHERAL' (extended AE)
  Pi = central scan+connect (bond=false)
PASS step: scan found …
PASS step: Pi connected to …
DUT serial checklist (SDK AE Peripheral demo):
  [OK/--] …
=== AE Peripheral RESULT: PASS (connect established) ===
```

```text
1. Launch UTF — test_ble_ae_peripheral_http_flow (Pi central)
2. Build & flash; set UI DUT MAC = public (SET2)
3. Host: scan by name AE_PERIPHERAL, then public / SET1 random
4. POST /ble/connect bond=false → PASS → complete
```

Uses `orchestration_kind: ae_peripheral` (dedicated; not the old 5‑min `gatt_connect` soak).

### BLE Central (`ble_central` — Build Studio / UTF)

Matches SDK `siwx91x_bluetooth_le_central_freertos` / `ble_central` readme.  
**This is not the AE-central path** — DUT uses legacy `rsi_ble_start_scanning` + `rsi_ble_connect`, so the Pi must use **legacy ADV_IND** (BlueZ extended LEAdvertisement works for `ble_ae_central` but causes DUT `Initiating connect cancel` here).

| Role | Device |
| --- | --- |
| Peripheral (advertiser) | Pi as `SILABS_DEV` via `start_smp_adv_with_hci_tool` |
| Central (scanner + connect) | DUT |

Readme peer requirements (phone → Pi):
- Connectable advertising
- **Complete Local Name** in advertising data **and** scan response
- Name = `RSI_REMOTE_DEVICE_NAME` (`SILABS_DEV`)

**Pass = connection established** (DUT serial `Module connected to address` preferred; Pi/hcitool also OK). No soak / GATT notify.

Expected DUT serial:

```text
Wi-Fi Initialization Success
Local device address …
Starting scan for 'SILABS_DEV' / <Pi MAC>
Started scanning
In Advertising Event (peer found)
Module connected to address : <Pi MAC>
```

```text
1. Launch UTF — test_ble_central_http_flow (legacy HCI ADV_IND, LocalName AD+scan rsp)
2. Arm expect-peer before flash (set DUT MAC in UI)
3. Build & flash; RSI_REMOTE_DEVICE_NAME / RSI_BLE_DEV_ADDR = Pi
4. Prefer ENABLE_NWP_POWER_SAVE=0 in app.c (sample often ships with 1; AE central uses 0)
5. Wait for DUT "Module connected" or Pi connected → checklist → PASS → complete
```

Uses `orchestration_kind: ble_central` (dedicated). Look for UTF:  
`Initializing BLE Central peripheral` / `start_smp_adv_with_hci_tool` / `LEGACY HCI advertising`.

### Accept List (`ble_accept_list` — Build Studio / UTF)

Matches SDK `siwx91x_bluetooth_le_accept_list_freertos` / `ble_accept_list`.  
Same Pi path as **ble_central** (legacy ADV_IND + LocalName `SILABS_DEV`), but the DUT only receives advertising reports for BD addresses on the **controller accept list** (`SCAN_FILTER_TYPE_ONLY_ACCEPT_LIST`).

| Role | Device |
| --- | --- |
| Peripheral (advertiser) | Pi as `SILABS_DEV` via `start_smp_adv_with_hci_tool` |
| Central (accept-list scan + connect) | DUT |

**Critical firmware (before flash):** Pi Bluetooth MAC from `GET /health` → `local_address` must be in:

- `ble_acceptlist_addr1` in the **same reverse-byte layout as the SDK sample**
  (e.g. `D8:3A:DD:EF:A2:D6` → `{0xD6, 0xA2, 0xEF, 0xDD, 0x3A, 0xD8}`), and
- `RSI_BLE_DEV_ADDR` (and/or name `RSI_REMOTE_DEVICE_NAME` = `SILABS_DEV`)

Name alone is **not** enough under accept-list scan filter — without the Pi MAC on the list, the DUT never sees adv reports / never connects.

Example (replace with your Pi MAC):

```c
uint8_t ble_acceptlist_addr1[6] = {0xD6, 0xA2, 0xEF, 0xDD, 0x3A, 0xD8};
#define RSI_BLE_DEV_ADDR "D8:3A:DD:EF:A2:D6"
#define RSI_REMOTE_DEVICE_NAME "SILABS_DEV"
```

**Pass = connection established** (DUT serial `Module connected to address` preferred; Pi link also OK). No soak / GATT notify.

```text
1. Launch UTF — test_ble_accept_list_http_flow (legacy HCI ADV_IND, LocalName AD+scan rsp)
2. Note Pi local_address from UTF /health; patch accept-list + RSI_BLE_DEV_ADDR; rebuild
3. Arm expect-peer before flash (set DUT MAC in UI)
4. Build & flash; prefer ENABLE_NWP_POWER_SAVE=0
5. Wait for DUT "Module connected" or Pi connected → checklist → PASS → complete
```

Uses `orchestration_kind: accept_list` (reuses ble_central host path). Host logs the exact `ble_acceptlist_addr1` byte tip from the live Pi MAC.

### Long Range / 2Mbps (`ble_longrange_2mbps` — Build Studio / UTF)

Matches SDK `ble_longrange_2mbps` readme (phone as peripheral → **Pi**):

| Role | Device |
| --- | --- |
| Peripheral (advertises `SILABS_DEV`) | **Pi** — legacy ADV_IND + LocalName AD + scan rsp |
| Central (scan + connect + PHY) | **DUT** |

**Pass = connection established** (readme steps 1–3). PHY (steps 4–5): prefer `RSI_DEVICE_DATA_RATE=BLE_2MBPS`; **Coded ignored on Pi**. With `RSI_SKIP_PHY_UPDATE_FOR_PI=1`, connect alone PASSes and the report notes the skip. No soak / no HR notify spam.

Expected host report:

```text
=== Long Range / 2Mbps (SDK ble_longrange_2mbps) ===
Manual steps (readme):
  1. Remote peripheral advertising as 'SILABS_DEV' @ <Pi MAC>
  2. DUT connects to RSI_REMOTE_DEVICE_NAME / RSI_BLE_DEV_ADDR
  3. Connection established
  4. After connect: read/set PHY (2Mbps; Coded ignored on Pi)
  5. Observe PHY update complete (or skip if firmware skips for Pi)
PASS step 3: …
Result (readme checklist):
  [OK] 1–3 …
  [OK] 4–5. Skipping PHY update …  OR  PHY … 2Mbps
=== Long Range / 2Mbps RESULT: PASS ===
```

```text
1. Launch UTF — test_ble_longrange_2mbps_http_flow (legacy HCI SILABS_DEV)
2. Build & flash; RSI_REMOTE_DEVICE_NAME / RSI_BLE_DEV_ADDR = Pi; BLE_2MBPS
3. Host: expect-peer → connect → PHY checklist → PASS → complete
```

Uses `orchestration_kind: longrange` (dedicated; not the old 5‑min `dut_central` soak).

### Data Length (`ble_datalength` — Build Studio / UTF)

Matches SDK `ble_datalength` readme (phone as peripheral → **Pi**):

| Role | Device |
| --- | --- |
| Peripheral (advertises `SILABS_DEV`) | **Pi** — legacy ADV_IND + LocalName AD + scan rsp |
| Central (scan + connect + set data length) | **DUT** |

**Pass = connection + LE Data Length Extension** (readme steps 1–6). Peer must support DLE (Pi usually does). No soak / no GATT notify spam.

Expected host report:

```text
=== Data Length (SDK ble_datalength) ===
Manual steps (readme):
  1. Remote peripheral advertising as 'SILABS_DEV' @ <Pi MAC>
  2. DUT initiates scanning
  3. DUT connects to RSI_REMOTE_DEVICE_NAME / RSI_BLE_DEV_ADDR
  4. Connection established
  5. DUT sets data length …
  6. Observe data length change event
PASS step 4: …
PASS step 6: …
Result (readme checklist):
  [OK] 1–6 …
=== Data Length RESULT: PASS ===
```

```text
1. Launch UTF — test_ble_datalength_http_flow (legacy HCI SILABS_DEV)
2. Build & flash; RSI_REMOTE_DEVICE_NAME / RSI_BLE_DEV_ADDR = Pi
3. Host: expect-peer → connect → DLE checklist → PASS → complete
```

Uses `orchestration_kind: datalength`.

### BLE Testmodes (`ble_testmodes` — Build Studio / UTF)

Matches SDK `ble_testmodes` readme (**Pi = Linux + BT dongle**; DUT = RF TX or RX). No advertising, no GATT, no notifications.

| Mode | DUT (`RSI_CONFIG_TEST_MODE`) | Pi (hcitool) |
| --- | --- | --- |
| **TX** (default) | `TRANSMIT` on channel `0x10` | `cmd 0x08 0x001D 0x10` → collect → `cmd 0x08 0x001F` → packets > 0 |
| **RX** | `RECEIVE` on channel `0x10` | `cmd 0x08 0x001E 0x10 0x20 0x01` → collect → `cmd 0x08 0x001F` |

HTTP (host-driven):

- `POST /ble/testmodes/le-receiver-test` `{"channel": 16}`
- `POST /ble/testmodes/le-transmitter-test` `{"channel": 16, "payload_len": 32, "payload_type": 1}`
- `POST /ble/testmodes/le-test-end` → `{ "packets": N }`

Expected host / UTF report (TX):

```text
=== BLE Testmodes (SDK ble_testmodes) ===
--- TX Testmodes Execution (readme) ---
[1] DUT transmitting on channel 0x10 …
[3] Pi LE Receiver Test: hcitool cmd 0x08 0x001D 0x10
[5] Pi LE Test End: hcitool cmd 0x08 0x001F
[6] Verify packets received: <N>
Result (readme checklist):
  [OK] 1–6 …
=== BLE Testmodes RESULT: PASS ===
```

For RX automation: set `testmodes_mode: "rx"` in the host profile **and** flash firmware with `RSI_CONFIG_TEST_MODE=RSI_BLE_TESTMODE_RECEIVE`.

Uses `orchestration_kind: testmodes`.

### BT Stack Bypass (`bt_stack_bypass` — Build Studio / UTF)

Matches SDK `bt_stack_bypass` readme: **Pi = Linux host**, **DUT = raw HCI over UART**.

| Need | Detail |
| --- | --- |
| Cable | USB‑UART WSTK ↔ Pi (SoC: **P35** Tx / **P33** Rx) |
| Device | `/dev/ttyUSB0` (override: env `BLE_STACK_BYPASS_UART` or profile `stack_bypass_uart`) |
| Pass | Wi‑Fi init → `btattach` → `hciconfig up` → `leadv` → `lescan` → detach |
| Phone | Optional — automation uses **BD_ADDR + leadv OK** instead of SiConnect |

HTTP: `/ble/stack-bypass/attach|hciconfig|up|leadv|lescan|detach`

Expected host / UTF report:

```text
=== BT Stack Bypass (SDK bt_stack_bypass) ===
[1] DUT running — UART HCI receive state
[2] Wi-Fi initialization complete [OK]
[3] Attach HCI UART … → hciX
[4] BD_ADDR = AA:BB:…
[5] Interface UP
[6a] leadv [OK]
[6b] lescan [OK]
[7] Phone would scan for BD_ADDR=… (automated)
[8] Detach
=== BT Stack Bypass RESULT: PASS ===
```

Uses `orchestration_kind: stack_bypass`.

### Secure Connection (`ble_secureconnection` — Build Studio / UTF)

Matches SDK `ble_secureconnection` readme: **DUT = peripheral** (`BLE_SMP_SC`), **Pi = central** (Simplicity Connect phone role). Pass = SMP encrypt + security keys. No GATT notify / no soak.

| Step (readme) | Automation |
| --- | --- |
| 1–2 DUT advertises + serial | Host waits Local device address |
| 3 Clear prior bond | `POST /ble/unpair` `{ "address": "<DUT>" }` |
| 4–5 Scan + connect | Scan name/`BLE_SMP_SC` or MAC → `bond=true` |
| 6–7 Pair + passkey | Parse `passkey: NNNNNN` from DUT serial → `POST /ble/passkey` |
| 8–9 Encrypt / keys | Wait `start encrypt status: 0` or `security keys event` |
| 10 Console prints | Short DUT serial checklist in host log |

Expected host report:

```text
=== BLE Secure Connection (SDK ble_secureconnection) ===
[1] DUT Local device address seen [OK]
[2] Serial console attached …
[3] Clear prior bond …
[4] Found DUT at AA:BB:… [OK]
[5] Connect accepted — awaiting SMP / passkey [OK]
[6] SMP pair in progress …
[7] Passkey 123456 submitted [OK]
[8] SMP procedure complete …
[9] SMP encrypt started / security keys …
[10] Console prints checklist …
=== BLE Secure Connection RESULT: PASS ===
```

Uses `orchestration_kind: secureconnection`. Env: `BLE_SECURECONNECTION_NAME` (default `BLE_SMP_SC`).

### Privacy (`ble_privacy` — Build Studio / UTF)

Matches SDK `ble_privacy` readme **PERIPHERAL_ROLE** (stock `RSI_DEVICE_ROLE`): **DUT = peripheral** (`SIMPLE_PRIVACY`), **Pi = central** (phone). Pass = SMP security keys → resolve list → Pi disconnect → DUT `Start Advertising`. No GATT notify.

| Step (readme) | Automation |
| --- | --- |
| 1–2 DUT advertises + serial | Wait Local device address / Start Advertising |
| 3–5 Scan + connect | Scan name/`SIMPLE_PRIVACY` → connect (peer SMP) |
| 6–9 Pair + passkey + keys | Parse passkey → `POST /ble/passkey` → wait `Sequrity keys event` |
| 10 Resolve list | DUT firmware after keys (IRK / resolution enable) |
| 11 Disconnect + re-adv | `POST /ble/disconnect` → wait disconnect + Start Advertising |
| 12 Console prints | Short DUT serial checklist |

Expected host report:

```text
=== BLE Privacy (SDK ble_privacy — PERIPHERAL_ROLE) ===
[1] DUT Local device address / advertising [OK]
…
[9] Security keys exchanged [OK]
[10] DUT adds IRKs to resolve list …
[11] DUT Start Advertising after disconnect [OK]
[12] Console prints checklist …
=== BLE Privacy RESULT: PASS ===
```

Uses `orchestration_kind: privacy`. Flash with **PERIPHERAL_ROLE** (default). Env: `BLE_PRIVACY_NAME` (default `SIMPLE_PRIVACY`).

### HID over GATT (`ble_hid_on_gatt` — Build Studio / UTF)

Matches SDK `ble_hid_on_gatt` readme with `GATT_ROLE` = **`SERVER`**: **DUT = HOGP keyboard peripheral** (`HID_OVER_GATT`), **Pi = central** (Simplicity Connect phone role). The DUT types `h`, `o`, `g`, `_` as HID input reports once the peer subscribes to the report characteristic.

| Step (readme) | Automation |
| --- | --- |
| 1–2 DUT advertises + serial | Host waits `Local device address` / `Start advertising` |
| 3 Forget device | `POST /ble/unpair` `{ "address": "<DUT>" }` |
| 4–5 Scan + connect | Scan name `HID_OVER_GATT` or MAC → plain Connect, agent armed `KeyboardOnly` |
| 5 Trigger SMP | `POST /ble/read { "service_uuid": "1812", "char_uuid": "2a4b" }` (report map) |
| 6 Passkey | Newest `smp passkey disp : NNNNNN` on DUT serial → `POST /ble/passkey` |
| 7 Encrypt | Wait `smp encrypt resp` on DUT serial |
| 8 Discover HID | `GET /ble/services` → HID service `0x1812`, report char `0x2A4D` |
| 9 Subscribe | `POST /ble/notifications/enable { "service_uuid": "1812", "char_uuid": "2a4d" }` |
| 10 Collect reports | `GET /ble/notifications` + DUT `Input report notify val: 1` |

Pass criteria: DUT `Module connected to address`, no `smp failed`, and **HID evidence** — at least one buffered report on `0x2A4D`, or the DUT print `Input report notify val: 1`, which only happens when the peer writes the report CCCD.

**Passkey timing (do not gate on Pi state):** the BlueZ agent blocks inside `RequestPasskey` for ~90 s waiting for `POST /ble/passkey`, and the DUT drops and re-pairs every ~30 s while it waits, each time displaying a *new* passkey. So the host submits the newest passkey as soon as DUT serial shows it, without waiting for `/ble/status` to report `awaiting_passkey` — the bond watchdog can already have moved to `pair_failed` over that churn, which used to deadlock against the agent's own timeout. The connect → SMP → passkey sequence retries `hid_pair_attempts` times (default 3), and each `POST /ble/connect` re-arms the agent sentinel.

**Why the report-map read instead of `Pair()`:** with `GATT_ROLE=SERVER` the DUT calls `rsi_ble_smp_pair_request` only under `#if (GATT_ROLE == CLIENT)`, so it never starts SMP itself. A `Device.Pair()` from the Pi fails with `org.bluez.Error.AuthenticationFailed` on this stack, so the automation connects plainly and then reads an encrypted HID attribute — the same thing a phone does — which makes the DUT run SMP and print its passkey.

**Why two sources of HID evidence:** BlueZ usually hands the HID service to its own input plugin (kernel `uhid`), so `0x1812` may not be exported over D‑Bus and the keystrokes never reach `/ble/notifications`. In that case the DUT print is authoritative, and the raw keystrokes can be read from `/dev/hidraw*` on the Pi (see `utf_core` `HidRecorder`). Start `bluetoothd` with `--noplugin=input` if you want the reports on the GATT/D‑Bus path instead.

Firmware (stock defaults are already correct):

```text
GATT_ROLE             = SERVER
RSI_BLE_APP_HIDS      = "HID_OVER_GATT"
ENABLE_NWP_POWER_SAVE = 0
RSI_BLE_SMP_IO_CAPABILITY = 0x01   (DUT displays passkey, Pi enters it)
```

Expected host report:

```text
=== BLE HID over GATT (SDK ble_hid_on_gatt) ===
[1] DUT Local device address seen [OK]
[4] Found DUT at AA:BB:… [OK]
[5] Link up — awaiting passkey request [OK]
[6] Passkey 123456 submitted [OK]
[7] Encryption enabled [OK]
[8] HID service 00001812-… report char 00002a4d-… flags=['read', 'notify'] [OK]
[9] Notifications on: notifying=True [OK]
[10] HID reports (4): 0000 0b00…, 0000 1200…
=== BLE HID over GATT RESULT: PASS ===
```

Uses `orchestration_kind: hid_on_gatt`. Env: `BLE_HID_ON_GATT_NAME` (default `HID_OVER_GATT`).

### Heart Rate Profile (`ble_heart_rate_profile` — Build Studio / UTF)

Matches SDK manual test with **DUT as GATT server** (`GATT_ROLE` = **`SERVER`** in `app.c`). Pi is BLE **central** (same as phone Simplicity Connect flow).

```text
1. Flash ble_heart_rate_profile with GATT_ROLE=SERVER (DUT advertises as BLE_HEART_RATE_PROFILE)
2. Launch UTF — test_ble_heart_rate_profile_http_flow on Pi
3. Resolve DUT MAC (serial or UI)
4. POST /ble/scan { "timeout": 10, "address": "<DUT_MAC>" }
5. POST /ble/connect { "address": "<DUT_MAC>", "bond": false, conn params… }
6. POST /ble/notifications/enable { "service_uuid": "180d", "char_uuid": "2a37" }
   — **optional** when UTF orchestration is on: Pi auto-enables notify after connect
   (`BLE_ORCHESTRATION_AUTO_ENABLE_NOTIFY=1`, default)
7. DUT pushes Heart Rate Measurement (0x2A37) notifications; Pi buffers them
8. 5 min post-notify stability (link up) → at least 1 notification required
9. POST /ble/orchestration/complete
```

No passkey (`bond=false`). **CLIENT** role on the DUT is not this flow (use Pi peripheral + `ble_ae_central`-style automation instead).

### GATT Long Read SERVER (`gatt_long_read` — Build Studio / UTF)

Matches SDK manual test with **DUT as GATT server** (`GATT_ROLE` = **`SERVER`**). Pi is BLE **central** (phone Simplicity Connect role).

```text
1. Flash gatt_long_read with GATT_ROLE=SERVER (DUT advertises as LONG_READ_TEST)
2. Launch UTF — test_gatt_long_read_http_flow on Pi
3. Resolve DUT MAC (serial or UI)
4. POST /ble/scan { "timeout": 10, "name": "LONG_READ_TEST" }  (or filter by MAC)
5. POST /ble/connect { "address": "<DUT_MAC>", "bond": false, conn params… }
6. Wait briefly for MTU exchange (DUT RSI_BLE_MTU_SIZE=100)
7. POST /ble/read { "service_uuid": "aabb", "char_uuid": "1aa1" }
8. Pass when length >= 21 (long attribute; typically ~98–100 bytes after MTU)
9. POST /ble/orchestration/ae-central-stability → POST /ble/orchestration/complete
```

Custom service **0xAABB** / characteristic **0x1AA1**. No passkey, no notify soak. **CLIENT** role is a separate automation (Pi as Battery Service peripheral).

Env: `BLE_GATT_LONG_READ_NAME` (default `LONG_READ_TEST`).

---

## Full PowerShell examples

### Passkey path

```powershell
$base = "http://10.208.71.114:5000"
$addr = "D4:48:67:DD:E4:6E"

Invoke-RestMethod -Method GET -Uri "$base/health"

Invoke-RestMethod -Method POST -Uri "$base/ble/scan" -ContentType "application/json" `
  -Body (@{ timeout = 10; address = $addr } | ConvertTo-Json)

Invoke-RestMethod -Method POST -Uri "$base/ble/connect" -ContentType "application/json" `
  -Body (@{
    address = $addr; bond = $true; capability = "KeyboardOnly"
    min_conn_interval = 40; max_conn_interval = 40
    conn_latency = 0; supervision_timeout = 500
  } | ConvertTo-Json)

# Replace with the passkey shown on the DUT
Invoke-RestMethod -Method POST -Uri "$base/ble/passkey" -ContentType "application/json" `
  -Body (@{ passkey = "123456" } | ConvertTo-Json)

Invoke-RestMethod -Method GET -Uri "$base/ble/status"
Invoke-RestMethod -Method GET -Uri "$base/ble/services" | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method POST -Uri "$base/ble/notifications/enable" -ContentType "application/json" `
  -Body (@{
    service_uuid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uuid    = "00001aa1-0000-1000-8000-00805f9b34fb"
  } | ConvertTo-Json)

Start-Sleep -Seconds 5
Invoke-RestMethod -Method GET -Uri "$base/ble/notifications" | ConvertTo-Json -Depth 5
```

### No-SMP path

```powershell
$base = "http://10.208.71.114:5000"
$addr = "D4:48:67:DD:E4:6E"

Invoke-RestMethod -Method POST -Uri "$base/ble/connect" -ContentType "application/json" `
  -Body (@{
    address = $addr; bond = $false
    min_conn_interval = 40; max_conn_interval = 40
    conn_latency = 0; supervision_timeout = 500
  } | ConvertTo-Json)

Invoke-RestMethod -Method POST -Uri "$base/ble/notifications/enable" -ContentType "application/json" `
  -Body (@{
    service_uuid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uuid    = "00001aa1-0000-1000-8000-00805f9b34fb"
  } | ConvertTo-Json)

Invoke-RestMethod -Method GET -Uri "$base/ble/notifications" | ConvertTo-Json -Depth 5
```

---

## Notes

- Access via the **Pi LAN IP**, not `localhost` on your Windows machine (container uses host networking).
- Bluetooth is **not** powered off or restarted after the one-time stack init (keeps the link stable).
- At startup the Pi registers a local GATT server (`HeartRate`, `ImmediateAlert`, `HealthThermometer`, `Battery`) so peers that run immediate profile discovery do not drop the link.
- `/ble/services` and notification enable resolve **peer** GATT objects only; local Pi services are excluded so they cannot shadow peer UUIDs.
- Common SiLabs custom notify characteristic used in lab demos: service `0xAABB`, char `0x1AA1` (notify). Do not confuse with service `0x1AA1` / char `0x1BB1` (indicate-only).
