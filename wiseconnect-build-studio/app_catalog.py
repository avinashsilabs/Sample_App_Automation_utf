"""Catalog of WiSeConnect BLE snippet applications."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Tuple

from sdk_manager import default_ble_root


@dataclass
class BleApp:
    id: str
    name: str
    folder: str
    soc_slcp: Optional[str]
    ncp_slcp: Optional[str]
    label: str


# New SDK (2026.12+) folder names → legacy ble_* ids used by test catalogs.
_NEW_FOLDER_TO_LEGACY_ID = {
    "siwx91x_bluetooth_le_accept_list_freertos": "ble_accept_list",
    "siwx91x_bluetooth_le_ae_central_freertos": "ble_ae_central",
    "siwx91x_bluetooth_le_ae_peripheral_freertos": "ble_ae_peripheral",
    "siwx91x_bluetooth_le_bypass_of_ble_stack_layer_freertos": "bt_stack_bypass",
    "siwx91x_bluetooth_le_central_freertos": "ble_central",
    "siwx91x_bluetooth_le_data_length_extension_freertos": "ble_datalength",
    "siwx91x_bluetooth_le_gain_table_configuration_freertos": "ble_update_gain_table",
    "siwx91x_bluetooth_le_gatt_long_read_freertos": "gatt_long_read",
    "siwx91x_bluetooth_le_heart_rate_profile_freertos": "ble_heart_rate_profile",
    "siwx91x_bluetooth_le_human_interface_device_profile_freertos": "ble_hid_on_gatt",
    "siwx91x_bluetooth_le_ibeacon_freertos": "ble_ibeacon",
    "siwx91x_bluetooth_le_interoperability_test_freertos": "ble_iop_test",
    "siwx91x_bluetooth_le_long_range_freertos": "ble_longrange_2mbps",
    "siwx91x_bluetooth_le_multi_connection_gatt_test_freertos": "ble_multiconnection_gatt_test",
    "siwx91x_bluetooth_le_ota_firmware_update_freertos": "ble_fw_ota_upgrade",
    "siwx91x_bluetooth_le_power_save_freertos": "ble_power_save",
    "siwx91x_bluetooth_le_privacy_freertos": "ble_privacy",
    "siwx91x_bluetooth_le_secure_connection_freertos": "ble_secureconnection",
    "siwx91x_bluetooth_le_test_modes_freertos": "ble_testmodes",
    "siwx91x_bluetooth_le_throughput_freertos": "ble_throughput_app",
    "siwx91x_bluetooth_le_unified_ae_freertos": "ble_unified_ae_coex_app",
    "siwx91x_bluetooth_le_unified_freertos": "ble_unified_coex_app",
}


def _pretty_name(folder: str) -> str:
    name = folder
    for prefix in (
        "siwx91x_bluetooth_le_",
        "siwx91x_bluetooth_",
        "ble_",
    ):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    if name.endswith("_freertos"):
        name = name[: -len("_freertos")]
    return name.replace("_", " ").title()


def _canonical_app_id(folder: str) -> str:
    return _NEW_FOLDER_TO_LEGACY_ID.get(folder, folder)


def _pick_slcp(entry: Path) -> Tuple[Optional[Path], Optional[Path]]:
    """
    Locate SoC / NCP project files.

    Legacy SDK:  *_soc.slcp / *_ncp.slcp
    New SDK:     *soc*.slcp (not psram) / *host*spi*.slcp (NCP host)
    """
    slcps = sorted(entry.glob("*.slcp"))
    if not slcps:
        return None, None

    # Legacy first
    soc = sorted(entry.glob("*_soc.slcp"))
    ncp = sorted(entry.glob("*_ncp.slcp"))
    if soc or ncp:
        return (soc[0] if soc else None, ncp[0] if ncp else None)

    # New naming: …_soc_<name>_freertos.slcp (exclude psram)
    soc_new = sorted(
        p
        for p in slcps
        if "_soc_" in p.name.lower() and "psram" not in p.name.lower()
    )
    # Prefer SPI host project as NCP; fall back to any host_*.slcp
    ncp_new = sorted(p for p in slcps if "_host_" in p.name.lower() and p.name.lower().endswith("_spi.slcp"))
    if not ncp_new:
        ncp_new = sorted(p for p in slcps if "_host_" in p.name.lower())

    soc_pick = soc_new[0] if soc_new else None
    ncp_pick = ncp_new[0] if ncp_new else None
    # Some SoC/dev-kit examples expose one unsuffixed project (for example
    # wifi_ble_provisioning_aws_devkit.slcp).
    if not soc_pick and not ncp_pick and len(slcps) == 1:
        only = slcps[0]
        if "ncp" in only.stem.lower():
            ncp_pick = only
        else:
            soc_pick = only
    return soc_pick, ncp_pick


def discover_apps(ble_root: Optional[Path] = None) -> List[BleApp]:
    root = Path(ble_root) if ble_root else default_ble_root()
    if not root or not root.is_dir():
        return []

    apps: List[BleApp] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        soc_path, ncp_path = _pick_slcp(entry)
        if not soc_path and not ncp_path:
            continue
        app_id = _canonical_app_id(entry.name)
        label = _pretty_name(entry.name)
        if app_id == "ble_hid_on_gatt":
            label = "Hid On Gatt Server"
        apps.append(
            BleApp(
                id=app_id,
                name=entry.name,
                folder=str(entry),
                soc_slcp=str(soc_path) if soc_path else None,
                ncp_slcp=str(ncp_path) if ncp_path else None,
                label=label,
            )
        )
    for app in list(apps):
        if app.id == "ble_hid_on_gatt":
            apps.append(
                BleApp(
                    id="ble_hid_on_gatt_client",
                    name=app.name,
                    folder=app.folder,
                    soc_slcp=app.soc_slcp,
                    ncp_slcp=app.ncp_slcp,
                    label="Hid On Gatt Client",
                )
            )
            break
    for app in list(apps):
        if app.id == "ble_heart_rate_profile":
            apps.append(
                BleApp(
                    id="ble_heart_rate_profile_client",
                    name=app.name,
                    folder=app.folder,
                    soc_slcp=app.soc_slcp,
                    ncp_slcp=app.ncp_slcp,
                    label="Heart Rate Profile Client",
                )
            )
            break
    return apps


def apps_as_dicts(ble_root: Optional[Path] = None) -> list:
    from app_test_catalog import pytest_test_name, test_profile

    root = Path(ble_root) if ble_root else default_ble_root()
    is_coex_root = bool(root and root.name.lower() == "wlan_ble")
    rows = []
    for app in discover_apps(ble_root):
        d = asdict(app)
        d["example_kind"] = "coex" if is_coex_root else "ble"
        if is_coex_root:
            d["test_function"] = (
                "coex/out_of_box_demo_test_scripts/run_test.py"
                if app.id == "out_of_box_demo"
                else ""
            )
            d["test_profile"] = {
                "workflow": [
                    "build_flash",
                    "ble_wifi_provision",
                    "wlan_ip",
                    "readme_validation",
                ],
                "supported": app.id == "out_of_box_demo",
            }
        else:
            d["test_function"] = pytest_test_name(app.id)
            d["test_profile"] = test_profile(app.id)
        rows.append(d)
    return rows


def resolve_slcp(app_id: str, target: str, ble_root: Optional[Path] = None) -> Path:
    for app in discover_apps(ble_root):
        if app.id != app_id and app.name != app_id:
            continue
        path = app.soc_slcp if target == "soc" else app.ncp_slcp
        if not path:
            raise FileNotFoundError(f"No {target.upper()} project for {app_id}")
        return Path(path)
    raise FileNotFoundError(f"Application not found: {app_id}")
