"""Temporary, idempotent pre-build configuration hook."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

_MARKER = "/* Build Studio prebuild demo marker */"
_CONFIG_START = "/* Build Studio prebuild demo configuration: BEGIN */"
_CONFIG_END = "/* Build Studio prebuild demo configuration: END */"
# Temporary demo scope: the five applications completed so far.
DEMO_APPLICATIONS = (
    "ble_accept_list",
    "ble_ae_central",
    "ble_ae_peripheral",
    "ble_datalength",
    "ble_central",
)


def apply_demo_configuration(app_c: Path, app_name: str) -> bool:
    text = app_c.read_text(encoding="utf-8")
    block = (
        f'{_CONFIG_START}\n#define WC_PREBUILD_DEMO_APP_NAME "{app_name}"\n'
        f'{_CONFIG_END}'
    )
    if _CONFIG_START in text and _CONFIG_END in text:
        start = text.index(_CONFIG_START)
        end = text.index(_CONFIG_END, start) + len(_CONFIG_END)
        old_block = text[start:end]
        if old_block == block:
            return False
        text = text[:start] + block + text[end:]
    elif _MARKER in text:
        text = text.replace(_MARKER, block, 1)
    else:
        text = block + "\n" + text
    app_c.write_text(text, encoding="utf-8")
    return True


def apply_prebuild_configurations(sdk_root: str | Path, app_id: Optional[str] = None) -> dict:
    root = Path(sdk_root).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"SDK root not found: {root}")
    roots = [root / "extension" / "wiseconnect" / "examples" / "snippets" / "ble",
             root / "examples" / "snippets" / "ble"]
    apps = [
        p for base in roots if base.is_dir()
        for p in base.iterdir()
        if p.is_dir() and p.name in DEMO_APPLICATIONS
    ]
    if app_id:
        apps = [p for p in apps if p.name == app_id]
    changed, skipped = [], []
    for app_dir in sorted(set(apps)):
        app_c = app_dir / "app.c"
        if not app_c.is_file():
            skipped.append(str(app_dir))
        elif apply_demo_configuration(app_c, app_dir.name):
            changed.append(str(app_c))
        else:
            skipped.append(str(app_c))
    return {"ok": True, "marker": _MARKER,
            "applications": list(DEMO_APPLICATIONS),
            "scope": app_id or "five completed BLE applications",
            "changed": changed, "skipped": skipped, "changed_count": len(changed),
            "application_count": len(apps)}
