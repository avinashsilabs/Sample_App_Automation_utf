# Graph Report - wiseconnect-build-studio  (2026-08-07)

## Corpus Check
- 16 files · ~31,759 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 531 nodes · 1502 edges · 26 communities (24 shown, 2 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 30 edges (avg confidence: 0.51)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `03902f55`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- app.js
- app.py
- tool_finder.py
- test_orchestrator.py
- sdk_manager.py
- app_catalog.py
- build_engine.py
- app_test_catalog.py
- WiseConnect Build Studio
- config.js
- WiseConnect Build Studio — Agent & Project Guide
- utf_runner.py
- 10. REST API reference
- 14. Adapting for another project
- 8. Build engine internals
- 3. Prerequisites
- 6. User workflows
- 12. Tool and SDK discovery
- 15. UI pages
- 7. Header editor (config)
- 9. Boards and toolchains
- post
- serial_monitor.py
- config_page
- disable_cache
- sdk_validate

## God Nodes (most connected - your core abstractions)
1. `_log()` - 34 edges
2. `api()` - 29 edges
3. `_execute_ble_connection()` - 24 edges
4. `mark_serial_cursor()` - 22 edges
5. `_http_json_retry()` - 22 edges
6. `log()` - 20 edges
7. `showErrorDialog()` - 20 edges
8. `buildFlashTest()` - 19 edges
9. `run_ble_debug_step()` - 19 edges
10. `IntegrationJob` - 19 edges

## Surprising Connections (you probably didn't know these)
- `pi_abort_ble_http()` --indirect_call--> `_log()`  [INFERRED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/sdk_manager.py
- `tools()` --calls--> `tool_status()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/tool_finder.py
- `apps()` --calls--> `apps_as_dicts()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/app_catalog.py
- `adapters()` --calls--> `list_adapters()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/build_engine.py
- `device_info_route()` --calls--> `device_info()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/build_engine.py

## Import Cycles
- None detected.

## Communities (26 total, 2 thin omitted)

### Community 0 - "app.js"
Cohesion: 0.09
Nodes (80): api(), appendUtfLog(), applyProfileDefaults(), applyUrlParams(), appTestProfiles, bleConnectAfterScan(), bleConnectDirect(), bleDebugRequestBody() (+72 more)

### Community 1 - "app.py"
Cohesion: 0.11
Nodes (32): adapters(), app_header_read(), app_header_save(), app_headers(), ble_debug_step(), boards(), build_status(), builds() (+24 more)

### Community 2 - "tool_finder.py"
Cohesion: 0.14
Nodes (39): _archive_dirs(), _conan_dirs(), _conan_packages(), discover_tools(), _ensure_slc_java(), _exe(), find_cmake(), find_commander() (+31 more)

### Community 3 - "test_orchestrator.py"
Cohesion: 0.07
Nodes (101): connect_conn_params(), Connection interval/latency/timeout sent with /ble/connect (matches README examp, BaseException, Match, Pattern, get_all_text(), mark_serial_cursor(), Block until regex matches serial lines (optionally only after since_index). (+93 more)

### Community 4 - "sdk_manager.py"
Cohesion: 0.10
Nodes (43): apps(), main(), sdks(), _env_path(), Path, Configuration for WiseConnect Build Studio.  Nothing here is machine specific:, Optional path from the environment, expanded but not required to exist., ble_root_for() (+35 more)

### Community 5 - "app_catalog.py"
Cohesion: 0.13
Nodes (33): apps_as_dicts(), BleApp, _canonical_app_id(), discover_apps(), _pick_slcp(), _pretty_name(), Path, Catalog of WiSeConnect BLE snippet applications. (+25 more)

### Community 6 - "build_engine.py"
Cohesion: 0.14
Nodes (31): _build_worker(), BuildJob, check_device(), _cmake_output_dir(), _collapse_include_paths(), _collect_artifacts(), _commander_cmd(), _commander_env() (+23 more)

### Community 7 - "app_test_catalog.py"
Cohesion: 0.36
Nodes (9): catalog_entry_for_app(), notifications_enable_payload(), notify_uuids(), pytest_command(), pytest_node(), pytest_test_name(), Map WiSeConnect BLE snippet apps to UTF pytest nodes., Body for POST /ble/notifications/enable — {} auto-picks notify char (README). (+1 more)

### Community 8 - "WiseConnect Build Studio"
Cohesion: 0.14
Nodes (13): API endpoints, Download from URL, Environment variables (all optional), Features, GCC-only missing headers on Windows, How discovery works, Notes, Prerequisites (+5 more)

### Community 9 - "config.js"
Cohesion: 0.29
Nodes (13): api(), bodyExtra(), dirty, headers, init(), originals, params, query() (+5 more)

### Community 10 - "WiseConnect Build Studio — Agent & Project Guide"
Cohesion: 0.15
Nodes (12): 11. BLE app catalog, 13. Common errors & fixes, 16. File outputs after build, 17. Minimal agent prompt (copy-paste), 18. Version notes (as of 2026-07), 1. What it is, 2. Repository layout, 4. Quick start (+4 more)

### Community 11 - "utf_runner.py"
Cohesion: 0.24
Nodes (14): utf_jobs(), _find_launcher(), get_utf_job(), _launch_command(), list_utf_jobs(), Path, UTF WiFi test runner — launch_utf_tests script with live log capture., First available launcher script in the executor folder. (+6 more)

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

### Community 21 - "post"
Cohesion: 0.12
Nodes (23): build(), build_flash(), build_flash_test(), _build_request(), _dut_address_from_request(), launch_utf(), pi_abort_ble_http(), Force-stop the Pi BLE RasPi HTTP pytest server (POST /ble/orchestration/abort) (+15 more)

### Community 22 - "serial_monitor.py"
Cohesion: 0.26
Nodes (11): serial_ports(), serial_start(), serial_stop(), guess_vcom_port(), list_serial_ports(), Serial port listing and background read for DUT logs., _reader_loop(), _require_pyserial() (+3 more)

### Community 23 - "config_page"
Cohesion: 0.67
Nodes (3): config_page(), index(), route

## Knowledge Gaps
- **60 isolated node(s):** `currentArtifacts`, `DEFAULT_BOARDS`, `boards`, `appTestProfiles`, `params` (+55 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run_utf_tests()` connect `utf_runner.py` to `app.py`, `test_orchestrator.py`, `post`?**
  _High betweenness centrality (0.016) - this node is a cross-community bridge._
- **Why does `run_ble_debug_step()` connect `test_orchestrator.py` to `app.py`?**
  _High betweenness centrality (0.013) - this node is a cross-community bridge._
- **Why does `test_profile()` connect `post` to `app.py`, `test_orchestrator.py`, `app_catalog.py`, `app_test_catalog.py`?**
  _High betweenness centrality (0.013) - this node is a cross-community bridge._
- **What connects `currentArtifacts`, `DEFAULT_BOARDS`, `boards` to the rest of the system?**
  _60 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `app.js` be split into smaller, more focused modules?**
  _Cohesion score 0.08639435791948281 - nodes in this community are weakly interconnected._
- **Should `app.py` be split into smaller, more focused modules?**
  _Cohesion score 0.11363636363636363 - nodes in this community are weakly interconnected._
- **Should `tool_finder.py` be split into smaller, more focused modules?**
  _Cohesion score 0.13821138211382114 - nodes in this community are weakly interconnected._