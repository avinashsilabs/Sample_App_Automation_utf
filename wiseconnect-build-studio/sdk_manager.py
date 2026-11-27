"""Locate, validate and download Simplicity SDK + WiSeConnect extension layouts."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable, List, Optional

from config import SDK_CACHE
from tool_finder import IS_WINDOWS, build_env, discover_tools, slt_package_dirs

LogFn = Optional[Callable[[str], None]]

# Marker that identifies a Simplicity/Gecko SDK root.
SDK_MARKERS = ("simplicity_sdk.slcs", "gecko_sdk.slcs")
WISECONNECT_MARKER = "wiseconnect.slce"
BLE_EXAMPLES_REL = Path("examples") / "snippets" / "ble"


def _log(fn: LogFn, msg: str) -> None:
    if fn:
        fn(msg)


def _is_sdk_root(path: Path) -> bool:
    return any((path / marker).is_file() for marker in SDK_MARKERS)


def _is_wiseconnect_root(path: Path) -> bool:
    return (path / WISECONNECT_MARKER).is_file()


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def _studio_sdk_roots() -> List[Path]:
    """Simplicity Studio / manual install locations, per platform."""
    home = Path.home()
    roots: List[Path] = [home / "SimplicityStudio" / "SDKs"]
    if IS_WINDOWS:
        roots += [
            Path("C:/SiliconLabs/SimplicityStudio"),
            Path("C:/SiliconLabs"),
        ]
    else:
        roots += [
            Path("/opt/SimplicityStudio"),
            Path("/opt/silabs"),
            home / ".simplicity_studio",
        ]
    return [r for r in roots if r.is_dir()]


def _scan_for_sdk(base: Path, depth: int = 3) -> List[Path]:
    """Find SDK roots at or below base, without walking the whole tree."""
    found: List[Path] = []
    if _is_sdk_root(base):
        found.append(base.resolve())
        return found
    if depth <= 0:
        return found
    try:
        children = sorted(p for p in base.iterdir() if p.is_dir())
    except OSError:
        return found
    for child in children:
        found.extend(_scan_for_sdk(child, depth - 1))
    return found


def discover_sdk_roots() -> List[Path]:
    """
    All Simplicity SDK roots visible on this machine, best candidate first.

    Order: explicit env override, previously downloaded SDKs, SLT packages,
    then Simplicity Studio / manual installs.
    """
    roots: List[Path] = []

    def add(path: Optional[Path]) -> None:
        if not path:
            return
        resolved = path.resolve()
        if _is_sdk_root(resolved) and resolved not in roots:
            roots.append(resolved)

    env_sdk = os.environ.get("WC_DEFAULT_SDK", "").strip()
    if env_sdk:
        add(Path(env_sdk).expanduser())

    if SDK_CACHE.is_dir():
        for entry in sorted(SDK_CACHE.iterdir(), reverse=True):
            if entry.is_dir():
                add(entry)

    for pkg in slt_package_dirs("simpl"):
        add(pkg)

    for base in _studio_sdk_roots():
        for candidate in _scan_for_sdk(base):
            add(candidate)

    return roots


def find_wiseconnect_root(sdk_root: Optional[Path] = None) -> Optional[Path]:
    """
    Locate the WiSeConnect extension.

    It normally lives at <sdk_root>/extension/wiseconnect, but SLT installs it
    as its own package, so fall back to scanning installed packages.
    """
    if sdk_root:
        sdk_root = Path(sdk_root).expanduser()
        candidates = [
            sdk_root / "extension" / "wiseconnect",
            sdk_root / "extension" / "wiseconnect3_sdk",
        ]
        for candidate in candidates:
            if _is_wiseconnect_root(candidate):
                return candidate.resolve()
        extension_dir = sdk_root / "extension"
        if extension_dir.is_dir():
            try:
                for child in sorted(extension_dir.iterdir()):
                    if child.is_dir() and _is_wiseconnect_root(child):
                        return child.resolve()
            except OSError:
                pass

    env_ext = os.environ.get("WC_WISECONNECT_ROOT", "").strip()
    if env_ext:
        candidate = Path(env_ext).expanduser()
        if _is_wiseconnect_root(candidate):
            return candidate.resolve()

    for pkg in slt_package_dirs("wise"):
        if _is_wiseconnect_root(pkg):
            return pkg
        nested = pkg / "wiseconnect"
        if _is_wiseconnect_root(nested):
            return nested.resolve()
    return None


def ble_root_for(wiseconnect_root: Optional[Path]) -> Optional[Path]:
    """BLE snippet examples folder inside a WiSeConnect extension."""
    if not wiseconnect_root:
        return None
    candidate = Path(wiseconnect_root) / BLE_EXAMPLES_REL
    return candidate.resolve() if candidate.is_dir() else None


def default_sdk_root() -> Optional[Path]:
    """Best SDK root to preselect — only ones that include WiSeConnect."""
    for root in discover_sdk_roots():
        if find_wiseconnect_root(root):
            return root
    return None


def default_ble_root() -> Optional[Path]:
    """BLE examples folder to preselect, from any discovered SDK."""
    explicit = os.environ.get("WISECONNECT_BLE_EXAMPLES", "").strip()
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_dir():
            return candidate.resolve()

    for root in discover_sdk_roots():
        ble = ble_root_for(find_wiseconnect_root(root))
        if ble:
            return ble
    return ble_root_for(find_wiseconnect_root(None))


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def sdk_info(sdk_root: Path, wiseconnect: Optional[Path] = None) -> dict:
    sdk_root = Path(sdk_root).expanduser().resolve()
    wise = Path(wiseconnect).resolve() if wiseconnect else find_wiseconnect_root(sdk_root)
    ble = ble_root_for(wise)
    package_parts = [str(sdk_root)] + ([str(wise)] if wise else [])
    return {
        "sdk_root": str(sdk_root),
        "wiseconnect": str(wise) if wise else None,
        "ble_root": str(ble) if ble else None,
        "sdk_package_path": ",".join(package_parts),
        "valid": bool(wise),
    }


def validate_local_sdk(path: Path) -> dict:
    """Raise a message that says exactly what is missing and how to fix it."""
    sdk_root = Path(path).expanduser().resolve()

    if not sdk_root.is_dir():
        raise FileNotFoundError(
            f"SDK folder does not exist: {sdk_root}\n"
            "Enter the path to a Simplicity SDK folder that contains "
            "simplicity_sdk.slcs and extension/wiseconnect/."
        )

    if not _is_sdk_root(sdk_root):
        raise FileNotFoundError(
            f"{sdk_root} is not a Simplicity SDK root "
            f"(expected one of {', '.join(SDK_MARKERS)}).\n"
            "Point the SDK root at the folder that contains simplicity_sdk.slcs."
        )

    wise = find_wiseconnect_root(sdk_root)
    if not wise:
        raise FileNotFoundError(
            "WiSeConnect extension not found under "
            f"{sdk_root}.\nExpected {sdk_root / 'extension' / 'wiseconnect' / WISECONNECT_MARKER}."
        )
    return sdk_info(sdk_root, wise)


def trust_sdk(sdk_info_dict: dict, log: LogFn = None) -> dict:
    """
    Run ``slc signature trust`` for the SDK and WiSeConnect extension.

    This is the step the Validate button performs after the layout check so
    later SLC generate/build can use the package without further prompting.
    """
    tools = discover_tools(refresh=True)
    if not tools.slc:
        raise RuntimeError(
            "SLC CLI not found. Install slc-cli with 'slt install pkg.slt' "
            "or put slc on PATH."
        )

    package = sdk_info_dict["sdk_package_path"]
    cmd = [
        str(tools.slc),
        "signature",
        "trust",
        f"--sdk-package-path={package}",
    ]
    _log(log, f"$ {' '.join(cmd)}")
    env = build_env("gcc", refresh=False)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        cwd=sdk_info_dict["sdk_root"],
    )
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    if output:
        _log(log, output)
    if result.returncode != 0:
        raise RuntimeError(
            f"slc signature trust failed (exit {result.returncode}):\n{output}"
        )
    return {
        "trusted": True,
        "command": " ".join(cmd),
        "output": output,
    }


def validate_and_trust(path: Path, log: LogFn = None) -> dict:
    """
    Full Validate flow used by the UI:

    1. Check SDK layout (simplicity_sdk.slcs + extension/wiseconnect)
    2. Trust the SDK and WiSeConnect packages with SLC
    3. Return paths so the UI can load BLE examples
    """
    info = validate_local_sdk(path)
    _log(log, f"SDK layout OK: {info['sdk_root']}")
    _log(log, f"WiSeConnect OK: {info['wiseconnect']}")
    if info.get("ble_root"):
        _log(log, f"BLE examples: {info['ble_root']}")
    else:
        _log(log, "WARNING: no examples/snippets/ble folder under WiSeConnect")

    trust = trust_sdk(info, log=log)
    return {
        **info,
        "trusted": trust["trusted"],
        "trust_output": trust["output"],
        "logs": [],  # filled by callers that collect log lines
    }


def _display_name(sdk_root: Path) -> str:
    """Readable label; Conan packages keep their payload in a folder named 'p'."""
    if sdk_root.name in ("p", "."):
        return sdk_root.parent.name or str(sdk_root)
    return sdk_root.name


def list_cached_sdks() -> list:
    """Every SDK discovered on this machine, including downloaded ones."""
    SDK_CACHE.mkdir(parents=True, exist_ok=True)
    return [
        {"name": _display_name(root), **sdk_info(root)}
        for root in discover_sdk_roots()
    ]


# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------

def _download(url: str, dest: Path, log: LogFn = None) -> Path:
    _log(log, f"Downloading {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=600) as resp, open(dest, "wb") as out:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)
            done += len(chunk)
            if total and log and done % (1024 * 1024) < len(chunk):
                _log(log, f"  ... {done * 100 // total}%")
    return dest


def _find_sdk_root(extracted: Path) -> Path:
    for candidate in _scan_for_sdk(extracted, depth=2):
        return candidate
    raise FileNotFoundError(
        f"None of {', '.join(SDK_MARKERS)} found in the Simplicity SDK archive"
    )


def _find_wiseconnect_in_archive(extracted: Path) -> Path:
    if _is_wiseconnect_root(extracted):
        return extracted
    for match in extracted.rglob(WISECONNECT_MARKER):
        return match.parent
    raise FileNotFoundError(f"{WISECONNECT_MARKER} not found in the WiSeConnect archive")


def prepare_sdk_from_urls(
    gecko_url: str,
    wiseconnect_url: str,
    dest_name: str = "downloaded_sdk",
    log: LogFn = None,
) -> dict:
    """Download both archives and stage <dest>/ + <dest>/extension/wiseconnect/."""
    dest = SDK_CACHE / dest_name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        gecko_zip = _download(gecko_url, tmp_path / "gecko-sdk.zip", log)
        wise_zip = _download(wiseconnect_url, tmp_path / "wiseconnect.zip", log)

        gecko_extract = tmp_path / "gecko"
        wise_extract = tmp_path / "wise"
        gecko_extract.mkdir()
        wise_extract.mkdir()

        _log(log, "Extracting gecko-sdk.zip ...")
        with zipfile.ZipFile(gecko_zip) as zf:
            zf.extractall(gecko_extract)
        _log(log, "Extracting wiseconnect.zip ...")
        with zipfile.ZipFile(wise_zip) as zf:
            zf.extractall(wise_extract)

        sdk_root = _find_sdk_root(gecko_extract)
        wise_root = _find_wiseconnect_in_archive(wise_extract)

        _log(log, f"Staging SDK at {dest}")
        for item in sdk_root.iterdir():
            target = dest / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)

        ext_dest = dest / "extension" / "wiseconnect"
        ext_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(wise_root, ext_dest)

    return sdk_info(dest)
