# WiseConnect Build Studio — Agent & Project Guide

Portable reference for humans and AI agents. Use this document to run, extend, or replicate the **WiseConnect Build Studio** Flask app for Silicon Labs WiSeConnect BLE snippet builds.

---

## 1. What it is

A local web UI (mini Simplicity Studio v6) that:

- Discovers BLE snippet apps under `wiseconnect/examples/snippets/ble`
- Edits **application and project config headers** (`.h`)
- Runs **SLC generate → CMake build → Commander flash** in one flow
- Auto-detects **SLT tools** (cmake, slc, gcc, llvm, ninja, make, commander, java)
- Auto-detects the **Simplicity SDK** and **WiSeConnect extension**
- Shows **serial logs** from the DUT after flash (pyserial, default 115200)

**Default URL:** http://127.0.0.1:5050

**Portability rule:** no machine-specific path may be hardcoded anywhere in this
folder. Paths come from environment variables when set, otherwise from runtime
discovery in `tool_finder.py` and `sdk_manager.py`. Executable names are built
with `_exe()` / `_script()` so Windows, Linux and macOS all work.

---

## 2. Repository layout

```
wiseconnect-build-studio/
├── app.py              # Flask routes
├── build_engine.py     # SLC + CMake + flash orchestration
├── tool_finder.py      # Cross-platform tool discovery, build env
├── sdk_manager.py      # SDK/extension discovery, validate, cache, URL download
├── app_catalog.py      # Scan BLE apps (*_soc.slcp / *_ncp.slcp)
├── header_config.py    # List/read/save app .h files
├── serial_monitor.py   # COM port list + background serial reader
├── config.py           # Defaults, boards, ports
├── requirements.txt    # flask, pyserial
├── templates/
│   ├── index.html      # Main UI
│   └── config.html     # Header editor (separate window)
├── static/
│   ├── app.js / app.css
│   └── config.js / config.css
├── README.md           # Short user readme
└── AGENT_GUIDE.md      # This file
```

**Related docs:**

- Per-example CLI builds: `../ble_multiconnection_gatt_test/BUILD.md`
- Silicon Labs SLC CLI: https://docs.silabs.com/wiseconnect/latest/wiseconnect-developers-guide-developing-for-silabs-hosts/using-the-simplicity-studio-cli

---

## 3. Prerequisites

### SLT tools (`pkg.slt`)

```toml
version = "0"

[dependency]
simplicity-sdk = "~"
wiseconnect = "~"
cmake = "~"
commander = "~"
gcc-arm-none-eabi = "~"
llvm-arm-toolchain-for-embedded = "~"
ninja = "~"
slc-cli = "~"
```

```powershell
slt install pkg.slt
```

### Python

```powershell
pip install -r requirements.txt
# flask>=3.0.0, pyserial>=3.5
```

**Note:** Use Python 3.9+ compatible code. Do **not** use `Path.write_text(..., newline="\n")` on Python 3.9 (added in 3.10). Normalize line endings manually.

### SDK layout

```
<sdk_root>/
  simplicity_sdk.slcs
  extension/
    wiseconnect/
      wiseconnect.slce
      examples/snippets/ble/    # BLE examples (auto-derived)
```

### Java

SLC 6.x requires **Java 21** on PATH (auto-discovered via tool_finder).

---

## 4. Quick start

```bash
pip install -r requirements.txt
python app.py
```

The app can live anywhere; it does not need to sit inside the SDK tree. Open
http://127.0.0.1:5050 and hard-refresh (`Ctrl+Shift+R`) after code updates.

### Stop server

```powershell
# Windows
Get-NetTCPConnection -LocalPort 5050 -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
```

```bash
# Linux / macOS
kill $(lsof -ti tcp:5050)
```

---

## 5. Environment variables

All optional. Unset values are discovered at runtime.

| Variable | Default | Purpose |
|----------|---------|---------|
| `WC_BUILD_STUDIO_HOME` | `~/.wiseconnect-build-studio` | Cache workspace |
| `WC_DEFAULT_SDK` | auto-discovered | Preferred SDK root |
| `WC_WISECONNECT_ROOT` | auto-discovered | Extension folder outside the SDK |
| `WISECONNECT_BLE_EXAMPLES` | derived from extension | BLE apps root |
| `SILABS_SLT_ROOT` | `~/.silabs/slt/installs` | Non-default SLT installs |
| `WC_BUILD_STUDIO_HOST` | `127.0.0.1` | Bind address |
| `WC_BUILD_STUDIO_PORT` | `5050` | HTTP port |
| `WC_UTF_EXECUTOR_DIR` | `../executor` of this checkout | UTF executor |

---

## 6. User workflows

### 6.1 Recommended flow (config → build → flash → serial)

1. Confirm the auto-detected **SDK root** (or enter one) and validate
2. Select **BLE example**, **Target** (SoC/NCP), **Board**, **Toolchain**
3. Click **⚙ Config** → edit headers → **Save & Continue**
   - Triggers **Build & Flash** on the main window
   - Re-runs SDK signature trust + SLC generate (config changed)
4. Watch **Build Console** (build → device check → flash)
5. On success, **Serial Console** opens automatically (115200 baud)

### 6.2 Build & Flash only

Click **Build & Flash** without opening config first.

**Flash pre-check:**

1. `commander device info`
2. If fail → `commander device recover` **once**
3. Re-check device
4. `commander flash <image>`
5. On flash failure → modal error dialog, stop

### 6.3 Build only / Flash only

- **Build Only** — SLC + CMake, no flash
- **Flash Only** — requires prior successful build; uses auto-recover

### 6.4 Serial console

- Auto-selects COM port (J-Link / Silicon Labs / VCOM heuristics)
- Manual port + baud override + **Reconnect**
- **← Build Console** returns to build log view

---

## 7. Header editor (config)

### What files are listed

| Category | Location | When visible |
|----------|----------|--------------|
| **Application source** | `app.h`, `ble_config.h`, etc. in app folder | Always |
| **Project config** | `output_{target}_{toolchain}/config/*.h` | After at least one SLC generate for that target/toolchain |

Examples:

- `ble_heart_rate_profile` source: 2 files (`app.h`, `ble_config.h`)
- After SoC/GCC build: +21 config headers → **23 total**

Config window URL params: `app_id`, `sdk_root`, `ble_root`, `target`, `board`, `toolchain`

**Save & Continue** posts `wc-config-saved` to opener → auto **Build & Flash**.

### Security

- Only `.h` files under the app folder are editable
- Path traversal (`..`) is rejected

---

## 8. Build engine internals

### Output directory naming

```
output_{target}_{toolchain}/
  cmake_gcc/     # if toolchain == gcc
  cmake_llvm/    # if toolchain == llvm_lto
    build/
      default_config/   # SoC artifacts
      base/             # NCP artifacts
```

### SLC generate command (equivalent CLI)

`SDK_PACKAGE_PATH` below is `<sdk_root>,<wiseconnect_root>`, assembled by
`sdk_manager.sdk_info()`.

**SoC + GCC:**

```bash
slc signature trust --sdk-package-path="$SDK_PACKAGE_PATH"
slc generate --with brd4338a \
  --sdk-package-path="$SDK_PACKAGE_PATH" \
  ble_heart_rate_profile_soc.slcp -d output_soc_gcc
```

**SoC + LLVM+LTO:**

```bash
slc generate --with brd4338a,toolchain_llvm,toolchain_llvm_lto -tlcn=llvm \
  --sdk-package-path="$SDK_PACKAGE_PATH" \
  ble_heart_rate_profile_soc.slcp -d output_soc_llvm_lto
```

**CMake build:**

```bash
cd output_soc_gcc/cmake_gcc   # or cmake_llvm
cmake --workflow --preset project
```

Between generate and build, `build_engine._collapse_include_paths()` rewrites the
`"../../../../../../components/..."` entries in the generated `*.cmake` as normalized
absolute paths. CMake does not collapse `..` in include directories, and
`arm-none-eabi-gcc` cannot open files past the Windows 260-character `MAX_PATH`, so
without this step deep WiSeConnect headers fail to resolve under GCC while clang
(long-path aware) builds fine. Do not remove this step; see README Troubleshooting.

### Environment per build

`tool_finder.build_env()` prepends to PATH and sets:

- `ARM_GCC_DIR` / `ARM_LLVM_DIR`
- `NINJA_EXE_PATH`
- `POST_BUILD_EXE` (commander)

### Flash artifacts

| Target | Preferred flash file |
|--------|---------------------|
| SoC | `.rps` (then `.hex`) |
| NCP | `.hex` (then `.s37`) |

### Build job phases

| Phase | Description |
|-------|-------------|
| `build` | SLC trust + generate + CMake |
| `flash` | Device check, recover, commander flash |
| `serial` | Job success with serial port hint |

---

## 9. Boards and toolchains

### Boards (`config.py`)

| Target | Board IDs |
|--------|-----------|
| `soc` | `brd4338a`, `brd4346a` |
| `ncp` | `brd4186c`, `brd4180a` |

Default if empty: `brd4338a` (soc), `brd4186c` (ncp)

### Toolchains

| ID | CMake subdir | SLC `--with` extras |
|----|--------------|---------------------|
| `gcc` | `cmake_gcc` | board only |
| `gcc_lto` | `cmake_gcc` | board only; `-flto` injected through CMake environment |
| `llvm_lto` | `cmake_llvm` | `toolchain_llvm,toolchain_llvm_lto` + `-tlcn=llvm` |

---

## 10. REST API reference

Base: `http://127.0.0.1:5050`

### Health & tools

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Server status |
| GET | `/api/tools` | Tool discovery (`?refresh=true` optional) |

### Apps & SDK

| Method | Path | Query / body |
|--------|------|--------------|
| GET | `/api/apps` | `?sdk_root=&ble_root=` |
| GET | `/api/boards` | — |
| GET | `/api/toolchains` | — |
| GET | `/api/sdks` | `?local=<path>` validates SDK |
| POST | `/api/sdk/download` | `{ gecko_url, wiseconnect_url, name }` |
| GET | `/api/sdk/download/<job_id>` | Download job status |

### Hardware (Commander)

| Method | Path | Body |
|--------|------|------|
| GET | `/api/adapters` | — |
| GET | `/api/device/info` | `?serial=` |
| POST | `/api/device/recover` | `{ adapter_serial? }` |

### Header config

| Method | Path | Params / body |
|--------|------|---------------|
| GET | `/api/app/headers` | `app_id`, `ble_root?`, `target`, `toolchain` |
| GET | `/api/app/header` | `app_id`, `path`, `ble_root?` |
| PUT | `/api/app/header` | `{ app_id, path, content, ble_root? }` |

### Build & flash

| Method | Path | Body |
|--------|------|------|
| POST | `/api/build` | `{ app_id, target, board, toolchain, sdk_root, ble_root? }` |
| POST | `/api/build-flash` | Same + `adapter_serial?`, `artifact_path?` |
| GET | `/api/build/<job_id>` | Logs, artifacts, phase, status |
| GET | `/api/build` | List all jobs |
| POST | `/api/flash` | `{ job_id, adapter_serial?, artifact_path?, auto_recover? }` |

### Serial monitor

| Method | Path | Body |
|--------|------|------|
| GET | `/api/serial/ports` | Returns `ports`, `suggested`, `default_baud` |
| GET | `/api/serial/status` | Active port/baud |
| POST | `/api/serial/start` | `{ port, baud }` |
| POST | `/api/serial/stop` | — |
| GET | `/api/serial/lines` | `?since=<line_count>` incremental log |

### Example: build-flash

`sdk_root` and `board` may be omitted — the server discovers the SDK and falls
back to `DEFAULT_BOARD` for the target.

```powershell
$body = @{
  app_id = "ble_heart_rate_profile"
  target = "soc"
  toolchain = "gcc"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://127.0.0.1:5050/api/build-flash -Method POST -Body $body -ContentType "application/json"
```

Poll: `GET /api/build/<job_id>` until `status` is `success` or `failed`.

---

## 11. BLE app catalog

Apps are discovered by scanning `ble_root` for folders containing `*_soc.slcp` and/or `*_ncp.slcp`.

```python
# app_catalog.py
BleApp(id, name, folder, soc_slcp, ncp_slcp, label)
resolve_slcp(app_id, target, ble_root) -> Path
```

**App ID** = folder name (e.g. `ble_heart_rate_profile`, `ble_multiconnection_gatt_test`).

---

## 12. Tool and SDK discovery

### Tools (`tool_finder.py`)

Search order per tool:

1. SLT installs — `~/.silabs/slt/installs` (Conan packages + archives), `$SILABS_SLT_ROOT`, and the platform default (`%LOCALAPPDATA%\Silabs`, `/opt/silabs`, `~/Library/Application Support/Silabs`)
2. `slt where <tool>` when the SLT CLI is on `PATH`
3. System `PATH`
4. Platform install locations (Program Files, `/usr`, `/usr/local`, `/opt`, Homebrew)

Cross-platform helpers: `_exe("cmake")` → `cmake.exe` on Windows, `cmake`
elsewhere; `_script("slc")` → `slc.bat` vs `slc`. Commander also resolves from a
macOS app bundle.

`discover_tools(refresh=True)` re-scans and clears the `slt where` cache.
`ToolPaths.missing(toolchain)` names what a build still needs; the build engine
raises using that list instead of a generic message.

### SDKs (`sdk_manager.py`)

| Function | Purpose |
|----------|---------|
| `discover_sdk_roots()` | All SDK roots: `WC_DEFAULT_SDK`, workspace cache, SLT `simplicity-sdk` packages, Studio/manual installs |
| `find_wiseconnect_root(sdk)` | `<sdk>/extension/wiseconnect`, any SLT `wiseconnect` package, or `WC_WISECONNECT_ROOT` |
| `ble_root_for(wiseconnect)` | `<wiseconnect>/examples/snippets/ble` |
| `default_sdk_root()` / `default_ble_root()` | Best candidates for the UI |
| `validate_local_sdk(path)` | Raises a message naming the missing piece and the fix |

Markers: `simplicity_sdk.slcs` or `gecko_sdk.slcs` for the SDK,
`wiseconnect.slce` for the extension. The extension does **not** have to live
inside the SDK — `sdk_package_path` joins both locations.

---

## 13. Common errors & fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `No BLE examples found — check SDK root` | WiSeConnect extension not installed | `slt install pkg.slt` with `wiseconnect`, or set `WC_WISECONNECT_ROOT` |
| `WiSeConnect extension not found for <sdk>` | SDK present, extension absent | Same as above |
| `<path> is not a Simplicity SDK root` | Wrong folder selected | Error lists the SDK roots it did find; pick one |
| `Missing build tools: ...` | SLT packages not installed | Install the named packages or put them on `PATH` |
| `Missing field: board` | Empty board dropdown | Hard refresh; server falls back to `DEFAULT_BOARD` |
| `write_text() got an unexpected keyword argument 'newline'` | Python 3.9 | Use manual `\n` normalization in `save_header()` |
| `Referenced SDK Extension ... not found` | Extension missing from sdk-package-path | Ensure `find_wiseconnect_root()` resolves |
| Only source headers in config | No prior generate | Run build once; then config shows `output_*/config/*.h` |
| `Could not connect debugger` | Target not ready | `commander device recover` (auto in Build & Flash) |
| UI stuck / old behavior | Cached JS | `Ctrl+Shift+R`; cache disabled for `/` and `/static/` |
| Multiple servers on the port | Duplicate `python app.py` | Only the first bind wins — stop old listeners, start one instance |

### SDK trust (manual)

```bash
slc signature trust --sdk-package-path="<sdk_root>,<wiseconnect_root>"
```

Build engine runs this automatically before every generate.

---

## 14. Adapting for another project

### A. Different BLE examples path

Set env or UI **Examples root**:

```
WISECONNECT_BLE_EXAMPLES=/path/to/snippets/ble
```

### B. Different SDK root or extension location

```
WC_DEFAULT_SDK=/path/to/sdk
WC_WISECONNECT_ROOT=/path/to/wiseconnect
```

### C. Add boards

Edit `config.py` → `BOARDS` and `DEFAULT_BOARD`.

### D. Port / host

```
WC_BUILD_STUDIO_PORT=8080
```

### E. Replicate for non-BLE apps

1. Copy `wiseconnect-build-studio/` folder
2. Replace `app_catalog.py` to scan your `.slcp` pattern
3. Adjust `build_engine.py` output dir / cmake preset names if different
4. Point `WISECONNECT_BLE_EXAMPLES` at your examples root
5. Keep `tool_finder.py` and `sdk_manager.py` as-is (SDK-agnostic)

### F. Agent checklist when modifying

- [ ] No absolute machine paths, drive letters, or usernames in code
- [ ] Executable names go through `_exe()` / `_script()`, never a bare `.exe`
- [ ] Python 3.9 compatible (no `newline=` in `write_text`)
- [ ] Bump `app.js?v=N` / `config.js?v=N` after JS changes
- [ ] Restart Flask after `app.py` / backend changes
- [ ] Test `/api/health`, `/api/tools`, `/api/sdks`, `/api/apps`
- [ ] Verify single server on target port
- [ ] Config save → Build & Flash → serial flow end-to-end

---

## 15. UI pages

| Route | Template | Purpose |
|-------|----------|---------|
| `/` | `index.html` | Main studio |
| `/config` | `config.html` | Header editor popup |

### Main buttons

| Button | Action |
|--------|--------|
| ⚙ Config | Open `/config?...` |
| Build & Flash | `POST /api/build-flash` |
| Build Only | `POST /api/build` |
| Flash Only | `POST /api/flash` |

### postMessage protocol (config → main)

```javascript
window.opener.postMessage({
  type: "wc-config-saved",
  buildFlash: true,
  app_id, sdk_root, ble_root, target, board, toolchain
}, window.location.origin);
```

---

## 16. File outputs after build

| Artifact | SoC | NCP | Flashable |
|----------|-----|-----|-----------|
| `.rps` | Yes | No | Yes (SoC) |
| `.hex` | Yes | Yes | Yes |
| `.s37` | Yes | Yes | Yes |
| `.bin` | Yes | Yes | Yes |
| `.out` / `.map` | Yes | Yes | No |

Typical paths:

- SoC: `output_soc_gcc/cmake_gcc/build/default_config/*.rps`
- NCP: `output_ncp_gcc/cmake_gcc/build/base/*.hex`

---

## 17. Minimal agent prompt (copy-paste)

```
You are working on WiseConnect Build Studio (wiseconnect-build-studio/).

Stack: Flask + vanilla JS, SLC CLI, CMake, Simplicity Commander, pyserial.
Must run unchanged on Windows, Linux and macOS: never hardcode a machine path.

Key flows:
1. Config headers (app + output/config) → Save & Continue → Build & Flash
2. Build = slc signature trust + slc generate + collapse include paths + cmake --workflow --preset project
3. Flash = device info → recover once if needed → commander flash
4. Serial = pyserial on COM port @ 115200

SDK package path is <sdk_root>,<wiseconnect_root> from sdk_manager.sdk_info().
Tools and SDKs are auto-discovered; see sections 5 and 12.

Read AGENT_GUIDE.md in that folder before changing code.
Python 3.9: no Path.write_text(newline=...).
After JS changes bump ?v= cache buster. Restart python app.py after backend changes.
```

---

## 18. Version notes (as of 2026-07)

- Flask app on port **5050**
- Cross-platform: Windows, Linux, macOS; no hardcoded machine paths
- Simplicity SDK and WiSeConnect extension discovered at startup, extension may
  live outside the SDK tree
- Combined **Build & Flash**, header editor, serial console implemented
- SLC 6.x + Java 21 + CMake/Ninja/make from SLT Conan installs

---

*Generated for reuse across projects and AI agents. Keep this file updated when adding API routes or changing build flow.*
