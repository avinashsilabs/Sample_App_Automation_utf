# wifi_ble_power_save — no isolated `run_test.py`

This folder keeps Pi helper stubs (`pi_ble.py`, `pi_ssl.py`) for reference only.
No `config.local.json` / `config.example.json` — nothing loads them without `run_test.py`.

Studio **Build, Flash, Test** requires `run_test.py` for the isolated path.
Because that file is intentionally absent here, Studio falls through to UTF:

`example_test_package/.../coex_raspi_http/test_coex_raspi_http.py::test_wifi_ble_power_save_http_flow`

Do not add an incomplete `run_test.py` — that would hide the UTF coex node
without providing Desktop-style coverage.
