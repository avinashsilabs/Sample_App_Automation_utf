# Graph Report - wiseconnect-build-studio  (2026-07-30)

## Corpus Check
- 16 files · ~20,668 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 462 nodes · 1219 edges · 20 communities
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 29 edges (avg confidence: 0.5)
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
- editor_bridge.py
- build_engine.py
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

## God Nodes (most connected - your core abstractions)
1. `api()` - 28 edges
2. `showErrorDialog()` - 19 edges
3. `buildFlashTest()` - 19 edges
4. `WiseConnect Build Studio — Agent & Project Guide` - 19 edges
5. `log()` - 18 edges
6. `run_ble_debug_step()` - 18 edges
7. `discover_tools()` - 18 edges
8. `runBleDebugStep()` - 16 edges
9. `_log()` - 16 edges
10. `_build_worker()` - 15 edges

## Surprising Connections (you probably didn't know these)
- `apps()` --calls--> `apps_as_dicts()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/app_catalog.py
- `adapters()` --calls--> `list_adapters()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/build_engine.py
- `device_info_route()` --calls--> `device_info()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/build_engine.py
- `device_recover_route()` --calls--> `device_recover()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/build_engine.py
- `utf_run()` --calls--> `run_utf_tests()`  [EXTRACTED]
  wiseconnect-build-studio/app.py → wiseconnect-build-studio/utf_runner.py

## Import Cycles
- None detected.

## Communities (20 total, 0 thin omitted)

### Community 0 - "app.js"
Cohesion: 0.08
Nodes (79): api(), appendUtfLog(), applyProfileDefaults(), applyUrlParams(), appTestProfiles, bleConnectAfterScan(), bleConnectDirect(), bleDebugRequestBody() (+71 more)

### Community 1 - "app.py"
Cohesion: 0.06
Nodes (66): after_request, adapters(), app_header_read(), app_header_save(), app_headers(), ble_debug_step(), boards(), build() (+58 more)

### Community 2 - "tool_finder.py"
Cohesion: 0.13
Nodes (40): _archive_dirs(), build_env(), _conan_dirs(), _conan_packages(), discover_tools(), _ensure_slc_java(), _exe(), find_cmake() (+32 more)

### Community 3 - "test_orchestrator.py"
Cohesion: 0.09
Nodes (57): catalog_entry_for_app(), connect_conn_params(), notifications_enable_payload(), notify_uuids(), pytest_command(), pytest_node(), pytest_test_name(), Map WiSeConnect BLE snippet apps to UTF pytest nodes. (+49 more)

### Community 4 - "sdk_manager.py"
Cohesion: 0.13
Nodes (35): apps(), ble_root_for(), default_ble_root(), discover_sdk_roots(), _display_name(), _download(), _find_sdk_root(), _find_wiseconnect_in_archive() (+27 more)

### Community 5 - "editor_bridge.py"
Cohesion: 0.14
Nodes (30): apps_as_dicts(), BleApp, discover_apps(), _pretty_name(), Path, Catalog of WiSeConnect BLE snippet applications., resolve_slcp(), _app_folder() (+22 more)

### Community 6 - "build_engine.py"
Cohesion: 0.14
Nodes (30): _build_worker(), BuildJob, check_device(), _cmake_output_dir(), _collapse_include_paths(), _collect_artifacts(), _commander_cmd(), _commander_env() (+22 more)

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
Cohesion: 0.18
Nodes (17): _env_path(), Path, Configuration for WiseConnect Build Studio.  Nothing here is machine specific:, Optional path from the environment, expanded but not required to exist., _find_launcher(), get_utf_job(), _launch_command(), list_utf_jobs() (+9 more)

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

## Knowledge Gaps
- **60 isolated node(s):** `currentArtifacts`, `DEFAULT_BOARDS`, `boards`, `appTestProfiles`, `params` (+55 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run_ble_debug_step()` connect `test_orchestrator.py` to `app.py`?**
  _High betweenness centrality (0.017) - this node is a cross-community bridge._
- **Why does `run_utf_tests()` connect `utf_runner.py` to `app.py`, `test_orchestrator.py`?**
  _High betweenness centrality (0.014) - this node is a cross-community bridge._
- **Why does `default_ble_root()` connect `sdk_manager.py` to `app.py`, `editor_bridge.py`?**
  _High betweenness centrality (0.014) - this node is a cross-community bridge._
- **What connects `currentArtifacts`, `DEFAULT_BOARDS`, `boards` to the rest of the system?**
  _60 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `app.js` be split into smaller, more focused modules?**
  _Cohesion score 0.08491418247515808 - nodes in this community are weakly interconnected._
- **Should `app.py` be split into smaller, more focused modules?**
  _Cohesion score 0.06321334503950835 - nodes in this community are weakly interconnected._
- **Should `tool_finder.py` be split into smaller, more focused modules?**
  _Cohesion score 0.132890365448505 - nodes in this community are weakly interconnected._