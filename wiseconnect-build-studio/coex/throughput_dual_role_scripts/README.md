# Wi-Fi throughput + BLE dual-role automation

This suite implements the `wifi_throughput_ble_dual_role` README sequence for
**UDP_TX**: the DUT is the UDP client and the configured remote endpoint is the
UDP server. It performs one bounded attempt per stage: configure source, start
the UDP server, build/flash, connect BLE, enable notifications, then validate
the DUT UART for WLAN and UDP-TX throughput evidence.

Copy `config.example.json` to `config.local.json`. Set `udp.server_ip` to the
host which runs iPerf. It may be a different Pi than `pi.host` (the BLE
central); the runner uses the same supplied SSH account to start iPerf there.
The value is written to `SERVER_IP_ADDRESS`; do not use the DUT IP there.

Run `python -u run_test.py`. The script intentionally does not retry a build,
BLE connection, or throughput run: a failed stage reports its evidence and
stops, preventing misleading results.
