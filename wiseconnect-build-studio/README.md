# WiseConnect Build Studio

A lightweight Flask web UI for building and flashing WiSeConnect BLE snippet applications — a minimal Simplicity Studio workflow driven by the SLC CLI.

Runs on **Windows, Linux and macOS**. No paths are hardcoded: tools, SDKs and examples are discovered at startup.

## Features

- Auto-discovers BLE snippet apps in the installed WiSeConnect extension
- **SoC / NCP** target selection, **GCC**, **GCC + LTO**, or **LLVM + LTO** toolchain, board selection
- **Build** (SLC generate + CMake) and **Flash** (`.rps` for SoC, `.hex` for NCP)
- Header editor for application and generated project config `.h` files
- Serial console for DUT logs after flash
- Live build console log

## Quick start

```bash
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5050**.

The startup banner tells you exactly what was found and what is missing:

```
WiseConnect Build Studio
  Platform     : Windows
  Workspace    : C:\Users\you\.wiseconnect-build-studio
  SDK root     : C:\Users\you\.silabs\slt\installs\conan\p\simpl.../p
  BLE examples : NOT FOUND
  Tools ready  : True (LLVM: True)
  SDK found but the WiSeConnect extension is missing. Add
    wiseconnect to pkg.slt, or set WC_WISECONNECT_ROOT.
```

## Prerequisites

Install the toolchain with **SLT** (Silicon Labs Tool). Create `pkg.slt`:

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

```bash
slt install pkg.slt
```

`wiseconnect` and `simplicity-sdk` are both required — without the WiSeConnect extension there are no BLE examples to build, and the build will refuse to start.

### How discovery works

Tools are located on every machine by scanning, in order:

1. SLT installs — `~/.silabs/slt/installs` (Conan packages and archives), `$SILABS_SLT_ROOT`, plus the platform default (`%LOCALAPPDATA%\Silabs`, `/opt/silabs`, `~/Library/Application Support/Silabs`)
2. `slt where <tool>` when the SLT CLI is on `PATH`
3. System `PATH`
4. Platform install locations (Program Files on Windows, `/usr`, `/usr/local`, `/opt`, Homebrew on Unix)

Executable names adapt to the platform automatically (`slc.bat` vs `slc`, `commander.exe` vs `commander` vs the macOS app bundle).

SDKs are located by looking for `simplicity_sdk.slcs` (or `gecko_sdk.slcs`) in:

1. `WC_DEFAULT_SDK`
2. Previously downloaded SDKs in the workspace cache
3. SLT `simplicity-sdk` packages
4. Simplicity Studio / manual installs

The WiSeConnect extension is found at `<sdk_root>/extension/wiseconnect`, or as its own SLT package, or via `WC_WISECONNECT_ROOT`. BLE examples are then derived as `<wiseconnect>/examples/snippets/ble`.

Before each build, discovered tool `bin` folders are prepended to a temporary `PATH`, and `ARM_GCC_DIR` / `ARM_LLVM_DIR` / `POST_BUILD_EXE` / `NINJA_EXE_PATH` / `JAVA_HOME` are set, so CMake works without manual setup.

## Environment variables (all optional)

| Variable | Purpose |
|----------|---------|
| `WC_DEFAULT_SDK` | SDK root to prefer over auto-discovery |
| `WC_WISECONNECT_ROOT` | WiSeConnect extension folder, when it lives outside the SDK |
| `WISECONNECT_BLE_EXAMPLES` | BLE examples root, overriding the derived path |
| `SILABS_SLT_ROOT` | Non-default SLT installs folder |
| `WC_BUILD_STUDIO_HOME` | Workspace for cache and downloaded SDKs |
| `WC_BUILD_STUDIO_HOST` / `WC_BUILD_STUDIO_PORT` | Bind address and port (default `127.0.0.1:5050`) |
| `WC_UTF_EXECUTOR_DIR` | UTF executor folder (defaults to `../executor` of this checkout) |
| `WC_UTF_TARGET` / `WC_UTF_HARNESS` | UTF run defaults |

## SDK layout

Whether installed, downloaded, or built by hand, the SDK should look like:

```
<sdk_root>/
  simplicity_sdk.slcs
  extension/
    wiseconnect/
      wiseconnect.slce
      examples/snippets/ble/
```

If your extension lives elsewhere, point `WC_WISECONNECT_ROOT` at it instead of restructuring; the SLC `--sdk-package-path` is assembled from both locations.

### Download from URL

Provide URLs to a **Simplicity SDK zip** and a **WiSeConnect zip**. The studio extracts both and stages the layout above under the workspace cache.

## Usage

1. Enter the **SDK root** for this PC (folder that contains `simplicity_sdk.slcs` and `extension/wiseconnect/`) — e.g. `C:\Users\<you>\new_Sdk`
2. Click **Validate & Trust SDK** — checks layout, runs `slc signature trust` for the SDK and WiSeConnect, then loads BLE examples
3. Choose a BLE application, target (SoC/NCP), board, and toolchain
4. **⚙ Config** to edit headers, or go straight to build
5. **Build & Flash** — SLC generate + CMake + Commander flash
6. Serial console opens on success at 115200 baud

The SDK path is different on every machine; that is expected. Always enter it and click Validate before building.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Server status |
| GET | `/api/tools` | Tool discovery (`?refresh=true`), includes `missing` |
| GET | `/api/apps` | BLE applications for an SDK or examples root |
| GET | `/api/boards`, `/api/toolchains` | UI options |
| GET | `/api/sdks` | Discovered SDKs; `?local=<path>` validates one |
| POST | `/api/sdk/download` | Download and stage an SDK |
| GET | `/api/adapters`, `/api/device/info` | Commander hardware queries |
| POST | `/api/device/recover` | Recover a locked device |
| GET/PUT | `/api/app/header(s)` | List, read and save `.h` files |
| POST | `/api/build`, `/api/build-flash` | Start a job (`sdk_root` optional — discovered if omitted) |
| GET | `/api/build/<id>` | Job status, logs, artifacts |
| POST | `/api/flash` | Flash a completed build |
| GET/POST | `/api/serial/*` | Ports, start/stop, incremental lines |
| GET/POST | `/api/utf/*` | UTF test runs |

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| Build button does nothing / job fails instantly | Read the error text: it names the missing SDK, extension or tool. Check the startup banner too. |
| `No BLE examples found — check SDK root` | WiSeConnect extension not installed. `slt install pkg.slt` with `wiseconnect`, or set `WC_WISECONNECT_ROOT`. |
| `Missing build tools: ...` | Install those packages with SLT or put them on `PATH`. |
| Stale UI behaviour | Hard refresh (`Ctrl+Shift+R`); caching is disabled for `/` and `/static/`. |
| Two servers on the port | Only one process may bind it; stop the old one before starting a new instance. |
| `Could not connect debugger` | Attach the debug adapter; Build & Flash runs `commander device recover` once automatically. |
| GCC build fails with `<header>.h: No such file or directory` while LLVM succeeds | Windows `MAX_PATH`. See below. |

### GCC-only missing headers on Windows

SLC writes WiSeConnect include directories relative to the generated CMake project,
as `../../../../../../components/.../inc`. CMake makes them absolute but never
collapses the `..` segments, so every include path carries
`<app>/output_<target>_<toolchain>/<cmake_sub>/` as dead weight — roughly 90 extra
characters. `arm-none-eabi-gcc` is built against the ANSI Win32 API and cannot open
a file whose path exceeds `MAX_PATH` (260 characters), so deep headers fail as
"No such file or directory". `clang` is long-path aware, which is why the same
project builds with `llvm_lto` but not `gcc`.

The build engine collapses these paths after every `slc generate` and before
invoking CMake, and logs the longest resulting include directory. If it still warns
that paths are near the limit, move the SDK to a shorter root such as `C:\sdk`.

## Notes

- `.rps` is produced for **SoC** builds only; NCP flashes `.hex` to the EFR32 host board
- Builds can take several minutes; watch the console panel
- The SDK signature is trusted automatically before every generate
- Python 3.9+ is supported
