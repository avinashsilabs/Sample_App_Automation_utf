# Wi-Fi Concurrent NAT with BLE Provisioning automation

Automates the SoC example on BRD4338A using the existing Build Studio, lab
Raspberry Pi, and NUC.

## Validation sequence

1. Build and flash `wifi_concurrent_nat_ble_provisioning_soc.slcp`.
2. Connect the Pi BLE central to `BLE_CONFIGURATOR`.
3. Provision the upstream `Radha` WLAN credentials through GATT.
4. Require STA connection and DHCP IPv4 on the DUT.
5. Accept the firmware-initiated BLE disconnect as expected.
6. Require DUT SoftAP startup and `Enabled NAT` on UART.
7. Verify SSH management of the Pi does not use the Wi-Fi interface being switched.
8. Connect Pi `wlan0` to `SI91X_NAT_AP` and request a `192.168.10.x` DHCP lease.
9. Require DUT gateway `192.168.10.10` to respond.
10. Repeatedly connect through NAT to NUC `192.168.50.36:22` for 60 seconds.
11. Run 60-second TCP uplink and reverse/downlink `iperf3` tests through NAT.
12. Restore the Pi's original Wi-Fi connection in both pass and failure paths.

The run passes only when at least 90 percent of the 60-second TCP probes pass.
Because the SDK application deliberately disconnects BLE before bringing up
the SoftAP, that disconnect is expected and is not a failure.

Throughput is enabled by default. The runner starts `iperf3` on the configured
NUC, pins the NUC host route to Pi `wlan0` through the DUT gateway, then records
`uplink_mbps` and `downlink_mbps`. Install `iperf3` on both the Pi and NUC and
set `nuc.host`, `nuc.username`, and `nuc.password` in `config.local.json`.
Configurable minimum rates determine pass/fail.

The client tries every DHCP implementation available on the Pi (`dhcpcd`,
`dhclient`, then `udhcpc`) because the presence of a `dhcpcd` executable does
not guarantee that its daemon owns `wlan0`. If the DUT still does not issue a
lease, the default `dhcp_required: false` mode records `dhcp_ok: false` and
uses the explicit `static_client_cidr` only to continue gateway, NAT, and
throughput diagnosis. This does not disguise the firmware DHCP defect: a run
with `address_source: static_fallback` proves the data path, not DHCP. Set
`dhcp_required: true` when DHCP itself must be a pass criterion.
The DHCP phase is bounded by `dhcp_timeout_s` (20 seconds by default). If the
SoftAP link drops during that phase, the runner performs one directed
re-association before applying the fallback instead of repeatedly cycling the
connection.

The updated Build Studio also handles the Windows GCC path limit. Long example
paths are copied to `%TEMP%\wcbs_b\<job-id>` for SLC/CMake generation, avoiding
the `testCCompiler.c.obj.rsp: file not found` failure without moving the SDK.

Before BLE provisioning, the Pi script unblocks Bluetooth, restarts BlueZ,
resets `hci0`, and verifies `Powered: yes`. An exclusive adapter lock prevents
the HTTPS and NAT tests from resetting or using `hci0` at the same time. One
fresh controller recovery is attempted only for link-establishment failures.

## Install

Copy the three updated root files over the Build Studio checkout, preserving
their paths. Copy this complete test folder under `coex/`.

Create the private configuration:

```powershell
Copy-Item config.example.json config.local.json
```

Set the existing `Radha` password in `config.local.json`, then start Build
Studio and select **Wi-Fi Concurrent NAT BLE Provisioning** →
**Run WLAN + BLE Test**.

Command-line execution:

```powershell
.\run.bat
```

Parser-only validation:

```powershell
python run_test.py --self-test
```
