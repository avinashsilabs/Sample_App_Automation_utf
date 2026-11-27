# WLAN BLE Unified AE Coex full validation

This folder automates the complete SoC validation documented for
`wlan_ble_unified_ae_coex_app`.

## What a PASS proves

1. The project builds and flashes with the configured Wi-Fi credentials.
2. Wi-Fi scans, joins the AP, receives an IPv4 address, connects to the TCP
   sink, and completes a non-zero `TCP_TX` throughput run.
3. BLE Extended Advertising set 1 and set 2 are enabled while Extended Scan is
   active.
4. The DUT simultaneously holds one link as BLE central and one as BLE
   peripheral.
5. Authenticated SMP/encryption succeeds on both connection IDs.
6. Profile discovery completes on both links.
7. The DUT receives Heart Rate notifications from `SILABS_DEV` and sends
   `AABB/1AA1` notifications to the second Linux BLE controller.
8. Neither established BLE link disconnects during a fresh 60-second stability
   window after TCP throughput completes.

Reconnects are deliberately disabled. An early peer exit or any disconnect in
the acceptance window fails the test.

## Important workload distinction

The SDK README says this AE application is verified with **TCP_TX**. It is not
an HTTP or HTTPS download application. The separate
`wifi_https_ble_dual_role_test_scripts` test remains HTTPS-only and is not
changed by this validation.

## Required topology

The full test needs two independent Linux Bluetooth controllers:

- `pi`: advertises `SILABS_DEV` with Heart Rate Service; the DUT connects as
  central and receives notifications.
- `central_pi`: uses the DUT public address reported on UART, pairs with the
  DUT, subscribes to `00001aa1-0000-1000-8000-00805f9b34fb`, and receives
  notifications. This avoids depending on a Local Name field in the AE data.

The supplied lab defaults use Raspberry Pi `10.207.18.79` for the peripheral
role and NUC `192.168.50.36` for the central role and TCP sink. The NUC must
have a free `hci0`. If it does not, set `central_pi.host` to a second Pi.

Both Linux peers require BlueZ, `python3-dbus`, and `python3-gi`. The central
peer also requires `python3-venv`; Bleak is installed automatically if absent.

The firmware prints a new six-digit SMP passkey on UART. The runner forwards
that exact value to a BlueZ `KeyboardOnly` agent; it does not use a fixed PIN.
The DUT-central/Pi-peripheral link is paired first, then the opposite-role link
is started, preventing the two passkey exchanges from racing.

## Firmware settings enforced by build_engine.py

- WLAN task enabled, throughput type `TCP_TX`, and server endpoint patched to
  the started TCP sink;
- Extended Advertising set 1 and set 2 plus Extended Scan enabled;
- one remote central and one remote peripheral;
- SMP, profile discovery, data transfer, RX notifications, and TX
  notifications enabled for C1 and P1;
- DUT central scan target changed to `SILABS_DEV`.

## Run

Copy `config.example.json` to `config.local.json`, set the two SDK paths, then:

```bat
run.bat
```

Parser-only verification:

```bat
run.bat --self-test
```

The runner starts the HRS peripheral before build/flash so the DUT sees it on
its initial scan. It starts the central peer immediately after flash. Existing
BlueZ bonds are removed before each run because this SDK example does not
persist bonding information.
