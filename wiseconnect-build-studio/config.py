"""Configuration for WiseConnect Build Studio.

Nothing here is machine specific: paths come from environment variables when
set, otherwise they are discovered at runtime (see sdk_manager, tool_finder).
"""

import os
from pathlib import Path


def _env_path(name: str) -> Path:
    """Optional path from the environment, expanded but not required to exist."""
    value = os.environ.get(name, "").strip()
    return Path(value).expanduser() if value else None


WORKSPACE = _env_path("WC_BUILD_STUDIO_HOME") or (Path.home() / ".wiseconnect-build-studio")
SDK_CACHE = WORKSPACE / "sdks"
SERIAL_LOG_DIR = WORKSPACE / "serial-logs"
BUILD_CONSOLE_LOG_DIR = WORKSPACE / "build-console-logs"

# SDK and BLE examples paths are resolved by sdk_manager, which reads
# WC_DEFAULT_SDK / WC_WISECONNECT_ROOT / WISECONNECT_BLE_EXAMPLES when set.

BOARDS = {
    "soc": [
        {"id": "brd4338a", "label": "BRD4338A (SiWx917 SoC)"},
        {"id": "brd4343a", "label": "BRD4343A (SiWx917 SoC)"},
        {"id": "brd4346a", "label": "BRD4346A (SiWx917 SoC)"},
        {"id": "brd2605b", "label": "BRD2605B (SiWx917 SoC)"},
    ],
    "ncp": [
        {"id": "brd4186c", "label": "BRD4186C (EFR32 NCP Host)"},
        {"id": "brd4180a", "label": "BRD4180A (EFR32 NCP Host)"},
    ],
}

DEFAULT_BOARD = {"soc": "brd4338a", "ncp": "brd4186c"}

TOOLCHAINS = [
    {"id": "gcc", "label": "GCC (regular)"},
    {"id": "gcc_lto", "label": "GCC + LTO"},
    {"id": "llvm_lto", "label": "LLVM + LTO"},
]

HOST = os.environ.get("WC_BUILD_STUDIO_HOST", "127.0.0.1")
PORT = int(os.environ.get("WC_BUILD_STUDIO_PORT", "5050"))
# UTF test runner. Falls back to the executor folder of the checkout this app
# ships inside, so it resolves on any clone without configuration.
_LOCAL_EXECUTOR = Path(__file__).resolve().parent.parent / "executor"

_DEFAULT_UTF_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_UTF_WORKSPACE = _env_path("WC_UTF_WORKSPACE") or (
    _DEFAULT_UTF_ROOT if (_DEFAULT_UTF_ROOT / "executor").is_dir() else None
)
DEFAULT_UTF_EXECUTOR = _env_path("WC_UTF_EXECUTOR_DIR") or (
    (DEFAULT_UTF_WORKSPACE / "executor") if DEFAULT_UTF_WORKSPACE else None
)
if DEFAULT_UTF_EXECUTOR and not DEFAULT_UTF_EXECUTOR.is_dir():
    DEFAULT_UTF_EXECUTOR = _LOCAL_EXECUTOR if _LOCAL_EXECUTOR.is_dir() else None
elif not DEFAULT_UTF_EXECUTOR:
    DEFAULT_UTF_EXECUTOR = _LOCAL_EXECUTOR if _LOCAL_EXECUTOR.is_dir() else None
DEFAULT_UTF_TARGET = os.environ.get("WC_UTF_TARGET", "")
DEFAULT_UTF_HARNESS = os.environ.get("WC_UTF_HARNESS", "harness_example_si917.yaml")

# BLE Pi HTTP orchestration (override per lab / CI machine).
PI_HTTP_PORT = int(os.environ.get("WC_PI_HTTP_PORT", "5000"))
HEALTH_POLL_SEC = float(os.environ.get("WC_PI_HEALTH_POLL_SEC", "2"))
# Allow the Pi BLE HTTP service extra time to boot/restart on slower lab hosts.
# Override per machine with WC_PI_HEALTH_TIMEOUT_SEC when needed.
HEALTH_TIMEOUT_SEC = float(os.environ.get("WC_PI_HEALTH_TIMEOUT_SEC", "1000"))
MAC_PARSE_TIMEOUT_SEC = float(os.environ.get("WC_MAC_PARSE_TIMEOUT_SEC", "180"))
PASSKEY_PARSE_TIMEOUT_SEC = float(os.environ.get("WC_PASSKEY_PARSE_TIMEOUT_SEC", "90"))
PI_HTTP_RETRY_ATTEMPTS = int(os.environ.get("WC_PI_HTTP_RETRY_ATTEMPTS", "12"))
PI_HTTP_RETRY_SEC = float(os.environ.get("WC_PI_HTTP_RETRY_SEC", "3"))
