"""Discover and edit application header files for BLE snippets."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from app_catalog import discover_apps, resolve_slcp

_SKIP_DIRS = {
    "autogen",
    "build",
    "cmake_gcc",
    "cmake_llvm",
    ".git",
    ".vscode",
}

_SKIP_PREFIXES = ("output",)


def _is_skipped_dir(name: str) -> bool:
    if name in _SKIP_DIRS:
        return True
    return any(name.startswith(p) for p in _SKIP_PREFIXES)


def _app_folder(app_id: str, ble_root: Optional[Path] = None) -> Path:
    for app in discover_apps(ble_root):
        if app.id == app_id:
            folder = Path(app.folder)
            if folder.is_dir():
                return folder
            break
    raise FileNotFoundError(f"Application not found: {app_id}")


def _resolve_header_path(app_folder: Path, rel_path: str) -> Path:
    rel = Path(rel_path.replace("\\", "/").lstrip("/"))
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("Invalid header path")
    resolved = (app_folder / rel).resolve()
    app_resolved = app_folder.resolve()
    if not str(resolved).startswith(str(app_resolved)):
        raise ValueError("Path escapes application folder")
    if resolved.suffix.lower() != ".h":
        raise ValueError("Only .h files are editable")
    return resolved


def _add_header(headers: Dict[str, dict], path: Path, app_folder: Path, category: str) -> None:
    rel = str(path.relative_to(app_folder)).replace("\\", "/")
    if rel in headers:
        return
    headers[rel] = {
        "path": rel,
        "name": path.name,
        "size": path.stat().st_size,
        "category": category,
    }


def _headers_from_slcp(app_folder: Path, target: str, ble_root: Optional[Path]) -> List[Path]:
    paths: List[Path] = []
    try:
        # Prefer catalog id resolution; folder name works for both legacy and new SDKs.
        app_key = app_folder.name
        for app in discover_apps(ble_root):
            if Path(app.folder).resolve() == app_folder.resolve():
                app_key = app.id
                break
        slcp = resolve_slcp(app_key, target, ble_root)
        text = slcp.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"^\s*-\s*path:\s*(\S+\.h)\s*$", text, re.MULTILINE):
            candidate = app_folder / match.group(1)
            if candidate.is_file():
                paths.append(candidate)
    except Exception:
        pass
    return paths


def _output_config_dir(app_folder: Path, target: str, toolchain: str) -> Optional[Path]:
    primary = app_folder / f"output_{target}_{toolchain}" / "config"
    if primary.is_dir():
        return primary

    # Fallback: any output dir for this target with a config folder
    pattern = f"output_{target}_*"
    for output_dir in sorted(app_folder.glob(pattern)):
        config_dir = output_dir / "config"
        if config_dir.is_dir():
            return config_dir

    # Legacy naming (e.g. output_llvm_lto without target prefix)
    if toolchain == "llvm_lto":
        legacy = app_folder / "output_llvm_lto" / "config"
        if legacy.is_dir():
            return legacy
    legacy_gcc = app_folder / "output_gcc" / "config"
    if legacy_gcc.is_dir():
        return legacy_gcc

    return None


def list_app_headers(
    app_id: str,
    ble_root: Optional[Path] = None,
    target: Optional[str] = None,
    toolchain: Optional[str] = None,
) -> List[dict]:
    app_folder = _app_folder(app_id, ble_root)
    headers: Dict[str, dict] = {}

    # 1) Application source headers (app.h, ble_config.h, etc.)
    for path in sorted(app_folder.rglob("*.h")):
        rel = path.relative_to(app_folder)
        if any(_is_skipped_dir(part) for part in rel.parts[:-1]):
            continue
        _add_header(headers, path, app_folder, "source")

    # 2) Headers explicitly listed in the .slcp for this target
    if target:
        for path in _headers_from_slcp(app_folder, target, ble_root):
            _add_header(headers, path, app_folder, "source")

    # 3) Generated project config headers (after at least one SLC generate)
    if target and toolchain:
        config_dir = _output_config_dir(app_folder, target, toolchain)
        if config_dir:
            for path in sorted(config_dir.glob("*.h")):
                _add_header(headers, path, app_folder, "config")

    return sorted(headers.values(), key=lambda h: (h["category"], h["path"]))


def read_header(app_id: str, rel_path: str, ble_root: Optional[Path] = None) -> dict:
    app_folder = _app_folder(app_id, ble_root)
    path = _resolve_header_path(app_folder, rel_path)
    if not path.is_file():
        raise FileNotFoundError(f"Header not found: {rel_path}")
    return {
        "path": rel_path.replace("\\", "/"),
        "content": path.read_text(encoding="utf-8", errors="replace"),
    }


def save_header(
    app_id: str,
    rel_path: str,
    content: str,
    ble_root: Optional[Path] = None,
) -> dict:
    app_folder = _app_folder(app_id, ble_root)
    path = _resolve_header_path(app_folder, rel_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    path.write_text(normalized, encoding="utf-8")
    return {"path": rel_path.replace("\\", "/"), "saved": True}
