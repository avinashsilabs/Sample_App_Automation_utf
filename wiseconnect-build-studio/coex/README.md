# WLAN + BLE coexistence example tests

Each automated SDK example is isolated under:

`<example_full_name>_test_scripts/`

Current example:

- `out_of_box_demo_test_scripts` — SoC BLE Wi-Fi commissioning, WLAN/IP,
  `www.silabs.com` ping, Mosquitto MQTT, NWP sleep, and MQTT transfer checks.

Build Studio's existing application scanner accepts an explicit examples root.
Set **Examples root** to the SDK's `examples/snippets/wlan_ble` directory to
select and build these applications. For registered tests, the main button
changes to **Run WLAN + BLE Test** and launches the matching per-example script.
Unregistered WLAN+BLE examples are shown but cannot enter the BLE/Heart Rate
test workflow.

The SDK example folder is never generated into. Each build copies the example to
`~/.wiseconnect-build-studio/projects/coex/<app_id>/<target>_<toolchain>` and
runs SLC generate plus CMake there, so `gcc`, `gcc_lto`, and `llvm_lto` keep
separate project trees and the SDK source stays clean.
