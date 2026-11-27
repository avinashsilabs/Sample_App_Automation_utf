# Graph Report - wiseconnect-build-studio  (2026-08-26)

## Corpus Check
- 18 files · ~40,803 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 665 nodes · 1810 edges · 36 communities (35 shown, 1 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 30 edges (avg confidence: 0.51)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `47279de5`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- app.js
- app.py
- tool_finder.py
- LogFn
- sdk_manager.py
- app_catalog.py
- build_engine.py
- _http_json_retry
- WiseConnect Build Studio
- config.js
- WiseConnect Build Studio — Agent & Project Guide
- test_orchestrator.py
- 10. REST API reference
- 14. Adapting for another project
- 8. Build engine internals
- 3. Prerequisites
- 6. User workflows
- 12. Tool and SDK discovery
- 15. UI pages
- 7. Header editor (config)
- 9. Boards and toolchains
- orchestrate_hid_on_gatt_manual
- serial_monitor.py
- run_build_flash_test
- utf_runner.py
- post
- _serial_milestones_seen
- mark_serial_cursor
- _log_dut_readme_serial_block
- dut_serial_checklist.py
- pi_abort_ble_http
- _find_hid_service
- _is_transient_http_error
- config_page
- _accept_list_firmware_tip
- disable_cache

## God Nodes (most connected - your core abstractions)
1. `_log()` - 44 edges
2. `mark_serial_cursor()` - 29 edges
3. `api()` - 29 edges
4. `_execute_ble_connection()` - 29 edges
5. `_http_json_retry()` - 27 edges
6. `IntegrationJob` - 25 edges
7. `ensure_serial_monitor()` - 23 edges
8. `log()` - 20 edges
9. `showErrorDialog()` - 20 edges
10. `run_ble_debug_step()` - 20 edges

## Surprising Connections (you probably didn't know these)
- `Force-stop the Pi BLE RasPi HTTP pytest server (POST /ble/orchestration/abort)` --rationale_for--> `pi_abort_ble_http()`  [EXTRACTED]
  app.py → wiseconnect-build-studio/app.py
- `Full pipeline using per-app workflow from app_test_catalog (UTF → Pi ready → fla` --rationale_for--> `build_flash_test()`  [EXTRACTED]
  app.py → wiseconnect-build-studio/app.py
- `Launch UTF on Raspberry Pi only (docker deploy + app-specific pytest).` --rationale_for--> `launch_utf()`  [EXTRACTED]
  app.py → wiseconnect-build-studio/app.py
- `Parse DUT serial and drive Pi BLE HTTP connect / passkey / notifications.` --rationale_for--> `start_connection()`  [EXTRACTED]
  app.py → wiseconnect-build-studio/app.py
- `Single Pi BLE HTTP step for manual debugging (scan / connect / status / …).` --rationale_for--> `ble_debug_step()`  [EXTRACTED]
  app.py → wiseconnect-build-studio/app.py

## Import Cycles
- None detected.

## Communities (36 total, 1 thin omitted)

### Community 0 - "app.js"
Cohesion: 0.09
Nodes (80): api(), appendUtfLog(), applyProfileDefaults(), applyUrlParams(), appTestProfiles, bleConnectAfterScan(), bleConnectDirect(), bleDebugRequestBody() (+72 more)

### Community 1 - "app.py"
Cohesion: 0.12
Nodes (29): adapters(), app_header_read(), app_header_save(), app_headers(), boards(), build_status(), builds(), _conn_params_from_request() (+21 more)

### Community 2 - "tool_finder.py"
Cohesion: 0.13
Nodes (41): _archive_dirs(), _conan_dirs(), _conan_packages(), discover_tools(), _ensure_slc_java(), env_summary(), _exe(), find_cmake() (+33 more)

### Community 3 - "LogFn"
Cohesion: 0.15
Nodes (30): abort_pi_ble_http_server(), ble_debug_connect(), ble_debug_enable_notifications(), ble_debug_get_notifications(), ble_debug_scan(), ble_debug_status(), ble_debug_submit_passkey(), _http_json() (+22 more)

### Community 4 - "sdk_manager.py"
Cohesion: 0.12
Nodes (39): apps(), main(), sdks(), ble_root_for(), default_ble_root(), default_sdk_root(), discover_sdk_roots(), _display_name() (+31 more)

### Community 5 - "app_catalog.py"
Cohesion: 0.09
Nodes (46): apps_as_dicts(), BleApp, _canonical_app_id(), discover_apps(), _pick_slcp(), _pretty_name(), Path, Catalog of WiSeConnect BLE snippet applications. (+38 more)

### Community 6 - "build_engine.py"
Cohesion: 0.13
Nodes (33): _build_worker(), BuildJob, check_device(), _cmake_output_dir(), _collapse_include_paths(), _collect_artifacts(), _commander_cmd(), _commander_env() (+25 more)

### Community 7 - "_http_json_retry"
Cohesion: 0.11
Nodes (29): _ae_peripheral_address_candidates(), arm_dut_central_expect_peer(), _format_pi_peripheral_status(), _http_json_retry(), normalize_dut_address(), orchestrate_ae_central_link_stability(), orchestrate_ae_peripheral_simple_connect(), orchestrate_datalength_manual() (+21 more)

### Community 8 - "WiseConnect Build Studio"
Cohesion: 0.14
Nodes (13): API endpoints, Download from URL, Environment variables (all optional), Features, GCC-only missing headers on Windows, How discovery works, Notes, Prerequisites (+5 more)

### Community 9 - "config.js"
Cohesion: 0.29
Nodes (13): api(), bodyExtra(), dirty, headers, init(), originals, params, query() (+5 more)

### Community 10 - "WiseConnect Build Studio — Agent & Project Guide"
Cohesion: 0.15
Nodes (12): 11. BLE app catalog, 13. Common errors & fixes, 16. File outputs after build, 17. Minimal agent prompt (copy-paste), 18. Version notes (as of 2026-07), 1. What it is, 2. Repository layout, 4. Quick start (+4 more)

### Community 11 - "test_orchestrator.py"
Cohesion: 0.14
Nodes (25): Match, get_all_text(), Pattern, Block until regex matches serial lines (optionally only after since_index)., serial_cursor(), wait_for_pattern(), check_smp_failure(), orchestrate_passkey_pairing() (+17 more)

### Community 12 - "10. REST API reference"
Cohesion: 0.25
Nodes (8): 10. REST API reference, Apps & SDK, Build & flash, Example: build-flash, Hardware (Commander), Header config, Health & tools, Serial monitor

### Community 13 - "14. Adapting for another project"
Cohesion: 0.29
Nodes (7): 14. Adapting for another project, A. Different BLE examples path, B. Different SDK root or extension location, C. Add boards, D. Port / host, E. Replicate for non-BLE apps, F. Agent checklist when modifying

### Community 14 - "8. Build engine internals"
Cohesion: 0.33
Nodes (6): 8. Build engine internals, Build job phases, Environment per build, Flash artifacts, Output directory naming, SLC generate command (equivalent CLI)

### Community 15 - "3. Prerequisites"
Cohesion: 0.40
Nodes (5): 3. Prerequisites, Java, Python, SDK layout, SLT tools (`pkg.slt`)

### Community 16 - "6. User workflows"
Cohesion: 0.40
Nodes (5): 6.1 Recommended flow (config → build → flash → serial), 6.2 Build & Flash only, 6.3 Build only / Flash only, 6.4 Serial console, 6. User workflows

### Community 17 - "12. Tool and SDK discovery"
Cohesion: 0.67
Nodes (3): 12. Tool and SDK discovery, SDKs (`sdk_manager.py`), Tools (`tool_finder.py`)

### Community 18 - "15. UI pages"
Cohesion: 0.67
Nodes (3): 15. UI pages, Main buttons, postMessage protocol (config → main)

### Community 19 - "7. Header editor (config)"
Cohesion: 0.67
Nodes (3): 7. Header editor (config), Security, What files are listed

### Community 20 - "9. Boards and toolchains"
Cohesion: 0.67
Nodes (3): 9. Boards and toolchains, Boards (`config.py`), Toolchains

### Community 21 - "orchestrate_hid_on_gatt_manual"
Cohesion: 0.12
Nodes (20): connect_conn_params(), Connection interval/latency/timeout sent with /ble/connect (matches README examp, Connection interval/latency/timeout sent with /ble/connect (matches README examp, get_lines(), _describe_hid_report(), _hid_report_has_keystroke(), _latest_hid_passkey(), _merge_connect_payload() (+12 more)

### Community 22 - "serial_monitor.py"
Cohesion: 0.09
Nodes (28): serial_ports(), close_job_log(), open_job_log(), Path, On-disk copy of Build Console output for each integration job., Create one log file per job; never fail the run over logging., write_job_log(), _env_path() (+20 more)

### Community 23 - "run_build_flash_test"
Cohesion: 0.12
Nodes (17): build_flash_test(), _dut_address_from_request(), Full pipeline using per-app workflow from app_test_catalog (UTF → Pi ready → fla, Full pipeline using per-app workflow from app_test_catalog (UTF → Pi ready → fla, Parse DUT serial and drive Pi BLE HTTP connect / passkey / notifications., Parse DUT serial and drive Pi BLE HTTP connect / passkey / notifications., start_connection(), _force_host_orchestration_kind() (+9 more)

### Community 24 - "utf_runner.py"
Cohesion: 0.24
Nodes (14): _find_launcher(), get_utf_job(), _launch_command(), list_utf_jobs(), Path, UTF WiFi test runner — launch_utf_tests script with live log capture., First available launcher script in the executor folder., Command to run a launcher script on the current platform. (+6 more)

### Community 25 - "post"
Cohesion: 0.16
Nodes (16): ble_debug_step(), build(), build_flash(), _build_request(), launch_utf(), Launch UTF on Raspberry Pi only (docker deploy + app-specific pytest)., Launch UTF on Raspberry Pi only (docker deploy + app-specific pytest)., Single Pi BLE HTTP step for manual debugging (scan / connect / status / …). (+8 more)

### Community 26 - "_serial_milestones_seen"
Cohesion: 0.17
Nodes (12): _log_dut_central_serial_checklist(), orchestrate_stack_bypass_manual(), orchestrate_testmodes_manual(), Return which console milestones appear in DUT serial (after cursor)., Print a short readme-style checklist from DUT serial (manual-tester style)., Return which console milestones appear in DUT serial (after cursor)., Print a short readme-style checklist from DUT serial (manual-tester style)., SDK ble_testmodes readme — Pi replaces Linux + BT dongle (hcitool LE test). (+4 more)

### Community 27 - "mark_serial_cursor"
Cohesion: 0.09
Nodes (54): mark_serial_cursor(), Ignore serial lines before this index (avoids stale passkey/MAC after reboot)., _assert_expected_host_orchestration(), ensure_serial_monitor(), _execute_ae_central_orchestration(), _execute_ae_peripheral_orchestration(), _execute_ble_connection(), _execute_datalength_orchestration() (+46 more)

### Community 28 - "_log_dut_readme_serial_block"
Cohesion: 0.27
Nodes (10): format_checklist_block(), milestones_seen(), Append a multi-line readme block to the log file (no per-line timestamps)., serial_log_append_block(), _log_dut_readme_serial_block(), Print ordered DUT serial readme lines; append same block to the log file., Print ordered DUT serial readme lines; append same block to the log file., Append readme checklist to the serial log file only (not Build Console). (+2 more)

### Community 29 - "dut_serial_checklist.py"
Cohesion: 0.32
Nodes (7): serial_lines(), extract_checklist_lines(), filter_noise_lines(), DUT serial readme checklists — ordered milestone lines for manual testers., First matching DUT serial line per readme step, in order., First matching DUT serial line per readme step, in order., resolve_checklist_kind()

### Community 30 - "pi_abort_ble_http"
Cohesion: 0.27
Nodes (6): pi_abort_ble_http(), Force-stop the Pi BLE RasPi HTTP pytest server (POST /ble/orchestration/abort), Force-stop the Pi BLE RasPi HTTP pytest server (POST /ble/orchestration/abort), Validate button flow:      1. Check the user-entered SDK path has simplicity_sdk, Validate button flow:      1. Check the user-entered SDK path has simplicity_sdk, sdk_validate()

### Community 31 - "_find_hid_service"
Cohesion: 0.33
Nodes (6): _find_hid_service(), Match a BlueZ 128-bit UUID against a 16-bit short form (e.g. '1812')., Locate the HID service / report characteristic in GET /ble/services output., Match a BlueZ 128-bit UUID against a 16-bit short form (e.g. '1812')., Locate the HID service / report characteristic in GET /ble/services output., _uuid_is()

### Community 32 - "_is_transient_http_error"
Cohesion: 0.50
Nodes (4): BaseException, _is_transient_http_error(), Retry connection blips; do not retry HTTP 4xx application responses., Retry connection blips; do not retry HTTP 4xx application responses.

### Community 33 - "config_page"
Cohesion: 0.67
Nodes (3): config_page(), index(), route

### Community 34 - "_accept_list_firmware_tip"
Cohesion: 0.67
Nodes (3): _accept_list_firmware_tip(), Format ble_acceptlist_addr1 bytes + RSI_BLE_DEV_ADDR tip from Pi MAC.      SDK, Format ble_acceptlist_addr1 bytes + RSI_BLE_DEV_ADDR tip from Pi MAC.      SDK s

## Knowledge Gaps
- **60 isolated node(s):** `currentArtifacts`, `DEFAULT_BOARDS`, `boards`, `appTestProfiles`, `params` (+55 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run_utf_tests()` connect `utf_runner.py` to `app.py`, `test_orchestrator.py`, `post`, `run_build_flash_test`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._
- **Why does `connect_conn_params()` connect `orchestrate_hid_on_gatt_manual` to `app.py`, `LogFn`, `app_catalog.py`, `test_orchestrator.py`, `mark_serial_cursor`?**
  _High betweenness centrality (0.015) - this node is a cross-community bridge._
- **Why does `test_profile()` connect `app_catalog.py` to `app.py`, `LogFn`, `test_orchestrator.py`, `run_build_flash_test`, `mark_serial_cursor`?**
  _High betweenness centrality (0.015) - this node is a cross-community bridge._
- **What connects `currentArtifacts`, `DEFAULT_BOARDS`, `boards` to the rest of the system?**
  _60 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `app.js` be split into smaller, more focused modules?**
  _Cohesion score 0.08639435791948281 - nodes in this community are weakly interconnected._
- **Should `app.py` be split into smaller, more focused modules?**
  _Cohesion score 0.11827956989247312 - nodes in this community are weakly interconnected._
- **Should `tool_finder.py` be split into smaller, more focused modules?**
  _Cohesion score 0.12896405919661733 - nodes in this community are weakly interconnected._