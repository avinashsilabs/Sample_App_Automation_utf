"""Map WiSeConnect BLE snippet apps to UTF pytest nodes."""

from __future__ import annotations

from typing import Dict, List, Optional

TEST_MODULE = (
    "example_test_package/sqa_test_suites_wifi_sdk_3/ble_standalone/"
    "functional/ble_raspi_http/test_ble_raspi_http_passkey_notify.py"
)
MANIFEST = "/app/manifest/blank_manifest.yaml"

# Per-app notification UUID hints (short form). None = use POST /ble/notifications/enable {} auto-pick.
APP_NOTIFY_UUIDS: Dict[str, tuple[Optional[str], Optional[str]]] = {
    "ble_multiconnection_gatt_test": (None, None),
    "ble_heart_rate_profile": ("180d", "2a37"),
    "ble_heart_rate_profile_client": ("180d", "2a37"),
    # Long-read SERVER: same UUIDs used for POST /ble/read (not notify).
    "gatt_long_read": ("aabb", "1aa1"),
    "ble_ae_peripheral": (None, None),
    "ble_datalength": (None, None),
    "ble_testmodes": (None, None),
    "bt_stack_bypass": (None, None),
    "ble_secureconnection": (None, None),
    "ble_privacy": (None, None),
    "ble_iop_test": (None, None),
    # HOGP keyboard: HID service / HID Report (input report carries the keystrokes).
    "ble_hid_on_gatt": ("1812", "2a4d"),
    "ble_hid_on_gatt_client": ("1812", "2a4d"),
}


# LE connection parameters for POST /ble/connect (hcitool lecup units — see README).
# Ordered pipeline phases for Build, Flash, Test (extend per app when timing differs).
WORKFLOW_LAUNCH_UTF = "launch_utf"
WORKFLOW_WAIT_PI = "wait_pi_health"
WORKFLOW_BUILD_FLASH = "build_flash"
WORKFLOW_START_CONNECTION = "start_connection"

# Pi BLE HTTP must be up before the DUT boots so pytest orchestration window is not wasted.
DEFAULT_WORKFLOW: List[str] = [
    WORKFLOW_LAUNCH_UTF,
    WORKFLOW_WAIT_PI,
    WORKFLOW_BUILD_FLASH,
    WORKFLOW_START_CONNECTION,
]

APP_TEST_PROFILES: Dict[str, dict] = {
    "ble_multiconnection_gatt_test": {
        "workflow": list(DEFAULT_WORKFLOW),
        "use_passkey_default": True,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 4,
    },
    "ble_heart_rate_profile": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "gatt_connect",
        "use_passkey_default": False,
        "scan_before_connect_default": True,
        "post_flash_delay_sec": 3,
        "min_notification_count": 1,
    },
    # SDK ble_heart_rate_profile GATT_ROLE=CLIENT: Pi = HRS peripheral (0x180D/0x2A37);
    # DUT central connects, discovers service, enables notify, receives HR measurements.
    "ble_heart_rate_profile_client": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "heart_rate_client",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 8,
        "require_notifications": False,
        "skip_hr_notify": True,
        "post_notify_stability_sec": 0,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 420,
        "ae_central_peripheral_name": "BLE_HEART_RATE_PROFILE",
        "ae_central_connect_timeout_sec": 180,
        "service_uuid": "180d",
        "char_uuid": "2a37",
        "hr_report_wait_sec": 90,
        "min_hr_report_count": 1,
    },
    # SDK gatt_long_read GATT_ROLE=SERVER: DUT advertises LONG_READ_TEST,
    # custom service 0xAABB / char 0x1AA1 (100-byte value). Pi = phone central.
    # Pass = connect + GATT Read length > 20 (long attribute). No notify soak.
    "gatt_long_read": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "gatt_long_read",
        "use_passkey_default": False,
        "scan_before_connect_default": True,
        "post_flash_delay_sec": 8,
        "require_notifications": False,
        "skip_hr_notify": True,
        "post_notify_stability_sec": 0,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 360,
        "ae_central_connect_timeout_sec": 180,
        "dut_advertising_name": "LONG_READ_TEST",
        "service_uuid": "aabb",
        "char_uuid": "1aa1",
        "min_gatt_read_len": 21,
    },
    "ble_ibeacon": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "ibeacon_scan",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 8,
        "ibeacon_scan_duration_sec": 300,
        "ibeacon_scan_interval_sec": 30,
        "ibeacon_per_scan_timeout_sec": 12,
        "orchestration_timeout_sec": 900,
    },
    # Manual-tester AE Central: Pi advertises → DUT AE scan/connect → pass on connect.
    # No GATT data transfer, no 5‑min link soak (matches SDK readme demo).
    "ble_ae_central": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "ae_central",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 12,
        "simple_connect_pass": True,
        "skip_hr_notify": True,
        "ibeacon_scan_duration_sec": 0,
        "ibeacon_scan_interval_sec": 30,
        "ae_central_peripheral_name": "SILABS_DEV",
        "ae_central_connect_timeout_sec": 180,
        "orchestration_timeout_sec": 360,
    },
    # SDK ble_central / siwx91x_bluetooth_le_central_freertos:
    # Pi = legacy connectable advertiser (LocalName in AD + scan rsp); DUT = rsi_ble_connect.
    # Distinct from ae_central (extended). Pass on "Module connected to address".
    "ble_central": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "ble_central",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 12,
        "simple_connect_pass": True,
        "skip_hr_notify": True,
        # Prefer DUT serial "Module connected"; Pi/hcitool link also PASSes.
        "require_dut_serial_connect": False,
        "ibeacon_scan_duration_sec": 0,
        "ibeacon_scan_interval_sec": 30,
        "ae_central_peripheral_name": "SILABS_DEV",
        "ae_central_connect_timeout_sec": 180,
        "orchestration_timeout_sec": 360,
    },
    # SDK ble_accept_list: DUT central + controller accept list (SCAN_FILTER_TYPE_ONLY_ACCEPT_LIST).
    # Same Pi legacy SILABS_DEV path as ble_central. Pass = Module connected.
    # Firmware MUST list Pi BT MAC in ble_acceptlist_addr1 (SDK sample byte order:
    # reverse of colon MAC) and RSI_BLE_DEV_ADDR (or name SILABS_DEV) before flash.
    "ble_accept_list": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "accept_list",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 12,
        "simple_connect_pass": True,
        "skip_hr_notify": True,
        "require_notifications": False,
        "require_dut_serial_connect": False,
        "ibeacon_scan_duration_sec": 0,
        "ibeacon_scan_interval_sec": 30,
        "ae_central_peripheral_name": "SILABS_DEV",
        "ae_central_connect_timeout_sec": 180,
        "orchestration_timeout_sec": 360,
    },
    # SDK ble_datalength: DUT central + LE Data Length Extension; Pi = SILABS_DEV.
    # Pass = connect + data-length-change (manual readme). No soak / no notify.
    "ble_datalength": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "datalength",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 15,
        "simple_connect_pass": True,
        "skip_hr_notify": True,
        "require_notifications": False,
        "ibeacon_scan_duration_sec": 0,
        "ae_central_peripheral_name": "SILABS_DEV",
        "ae_central_connect_timeout_sec": 180,
        "orchestration_timeout_sec": 360,
        "require_dut_serial_connect": False,
    },
    # SDK ble_longrange_2mbps: DUT central + PHY (2Mbps; Coded ignored on Pi).
    # Pass = connect (+ PHY if firmware does not skip). No soak / no HR notify.
    "ble_longrange_2mbps": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "longrange",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 15,
        "simple_connect_pass": True,
        "skip_hr_notify": True,
        "ibeacon_scan_duration_sec": 0,
        "ibeacon_scan_interval_sec": 30,
        "ae_central_peripheral_name": "SILABS_DEV",
        "ae_central_connect_timeout_sec": 180,
        "orchestration_timeout_sec": 360,
        "require_dut_serial_connect": False,
    },
    # SDK ble_ae_peripheral / siwx91x_bluetooth_le_ae_peripheral_freertos:
    # DUT = AE peripheral (AE_PERIPHERAL); Pi = central scan+connect (phone in readme).
    # Pass on connect — no GATT notify, no 5‑min soak (manual-tester style).
    "ble_ae_peripheral": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "ae_peripheral",
        "use_passkey_default": False,
        "scan_before_connect_default": True,
        "post_flash_delay_sec": 20,
        "simple_connect_pass": True,
        "require_notifications": False,
        "skip_hr_notify": True,
        "post_notify_stability_sec": 0,
        "ibeacon_scan_duration_sec": 0,
        "ae_central_connect_timeout_sec": 180,
        "orchestration_timeout_sec": 360,
        "dut_advertising_name": "AE_PERIPHERAL",
        # SDK ble_config.h RSI_BLE_SET_RAND_ADDR (SET1); must be valid static random.
        # SET2 uses public MAC from serial/UI.
        "dut_random_adv_addr": "C1:44:33:AA:BB:CC",
    },
    # SDK ble_testmodes: DUT RF TX/RX; Pi = Linux hcitool LE test (dongle in readme).
    # Default TX: DUT TX → Pi LE Receiver Test 0x001D → Test End 0x001F → packets > 0.
    # Set testmodes_mode="rx" when firmware RSI_CONFIG_TEST_MODE=RECEIVE.
    "ble_testmodes": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "testmodes",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 8,
        "require_notifications": False,
        "skip_hr_notify": True,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 300,
        "testmodes_mode": "tx",
        "testmodes_channel": 0x10,
        "testmodes_payload_len": 0x20,
        "testmodes_payload_type": 0x01,
        "testmodes_collect_sec": 8,
        "min_test_packets": 1,
    },
    # SDK bt_stack_bypass: DUT HCI UART → Pi btattach (Linux BlueZ owns DUT radio).
    # Pass = Wi-Fi init → attach → hci up → leadv → lescan. Phone step replaced by
    # BD_ADDR + leadv OK. Requires USB-UART cable (SoC: WSTK P35/P33 → Pi).
    "bt_stack_bypass": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "stack_bypass",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 10,
        "require_notifications": False,
        "skip_hr_notify": True,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 300,
        "stack_bypass_uart": "/dev/ttyUSB0",
        "stack_bypass_baud": 115200,
        "stack_bypass_lescan_sec": 5,
    },
    # SDK ble_secureconnection: DUT peripheral advertises BLE_SMP_SC; Pi = central
    # (phone in readme). Pass = scan → clear bond → connect bond → passkey → encrypt.
    "ble_secureconnection": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "secureconnection",
        "use_passkey_default": True,
        "scan_before_connect_default": True,
        "post_flash_delay_sec": 8,
        "require_notifications": False,
        "skip_hr_notify": True,
        "post_notify_stability_sec": 0,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 360,
        "dut_advertising_name": "BLE_SMP_SC",
        "ae_central_connect_timeout_sec": 180,
    },
    # SDK ble_privacy PERIPHERAL_ROLE (default): DUT advertises SIMPLE_PRIVACY;
    # Pi = phone central. Pass = SMP keys + resolve list + disconnect + re-adv.
    # No GATT notifications. CENTRAL_ROLE is a separate firmware build.
    "ble_privacy": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "privacy",
        "use_passkey_default": True,
        "scan_before_connect_default": True,
        "post_flash_delay_sec": 8,
        "require_notifications": False,
        "skip_hr_notify": True,
        "post_notify_stability_sec": 0,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 420,
        "dut_advertising_name": "SIMPLE_PRIVACY",
        "ae_central_connect_timeout_sec": 180,
    },
    # SDK ble_hid_on_gatt GATT_ROLE=SERVER: DUT advertises HID_OVER_GATT as a HOGP
    # keyboard; Pi = phone central (bond with passkey → subscribe HID report →
    # collect the "hog_" keystroke reports). No Heart Rate path, no soak.
    "ble_hid_on_gatt": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "hid_on_gatt",
        "use_passkey_default": True,
        "scan_before_connect_default": True,
        "post_flash_delay_sec": 8,
        "require_notifications": False,
        "skip_hr_notify": True,
        "post_notify_stability_sec": 0,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 420,
        "dut_advertising_name": "HID_OVER_GATT",
        "ae_central_connect_timeout_sec": 180,
        "service_uuid": "1812",
        "char_uuid": "2a4d",
        # Window to collect HID input reports after the CCCD write.
        "hid_report_wait_sec": 90,
        "min_hid_report_count": 1,
        # At least one notify must carry h/o/g/_ usage bytes (not all-zero release).
        "min_hid_key_reports": 1,
        # DUT drops the link and shows a new passkey per failed SMP attempt.
        "hid_pair_attempts": 3,
        # Pi BlueZ agent IO capability for /ble/connect (DUT = KeyboardDisplay).
        "smp_capability": "KeyboardDisplay",
    },
    # SDK ble_hid_on_gatt GATT_ROLE=CLIENT: Pi = HOGP keyboard peripheral;
    # DUT central scans for SILABS_DEV, discovers 0x1812, enables notify,
    # and receives demo keys. Keep the Pi name aligned with the SDK client.
    "ble_hid_on_gatt_client": {
        "workflow": list(DEFAULT_WORKFLOW),
        "orchestration_kind": "hid_on_gatt_client",
        "use_passkey_default": False,
        "scan_before_connect_default": False,
        "post_flash_delay_sec": 8,
        "require_notifications": False,
        "skip_hr_notify": True,
        "post_notify_stability_sec": 0,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 420,
        "ae_central_peripheral_name": "HID_OVER_GATT",
        "ae_central_connect_timeout_sec": 180,
        "service_uuid": "1812",
        "char_uuid": "2a4d",
        "hid_report_wait_sec": 90,
        "min_hid_report_count": 1,
    },
    # SDK BLE interoperability test: connect to the DUT and validate the link.
    # The peer profile is not fixed to Heart Rate, so do not force 0x180D/0x2A37.
    "ble_iop_test": {
        "workflow": list(DEFAULT_WORKFLOW),
        # IOP is a generic DUT peripheral: connect only, with no fixed GATT
        # profile or notification expectation.
        "orchestration_kind": "ae_peripheral",
        "use_passkey_default": False,
        "scan_before_connect_default": True,
        "post_flash_delay_sec": 3,
        "simple_connect_pass": True,
        "require_notifications": False,
        "skip_hr_notify": True,
        "post_notify_stability_sec": 0,
        "ibeacon_scan_duration_sec": 0,
        "orchestration_timeout_sec": 360,
        "dut_advertising_name": "IOP_Test_1",
        "ae_central_connect_timeout_sec": 180,
    },
}

DEFAULT_TEST_PROFILE: dict = {
    "workflow": list(DEFAULT_WORKFLOW),
    "orchestration_kind": "gatt_connect",
    "use_passkey_default": False,
    "scan_before_connect_default": False,
    "post_flash_delay_sec": 3,
    "post_notify_stability_sec": 300,
    "require_notifications": True,
    "ibeacon_scan_duration_sec": 300,
    "ibeacon_scan_interval_sec": 30,
    "ibeacon_per_scan_timeout_sec": 12,
    "orchestration_timeout_sec": 600,
}


def test_profile(app_id: str) -> dict:
    """Per-app UTF/BLE timing and workflow (catalog is the single place to extend)."""
    base = dict(DEFAULT_TEST_PROFILE)
    override = APP_TEST_PROFILES.get(app_id)
    if override:
        merged = {**base, **override}
        merged["workflow"] = list(override.get("workflow") or DEFAULT_WORKFLOW)
        return merged
    return base


DEFAULT_CONNECT_CONN_PARAMS: Dict[str, int] = {
    "min_conn_interval": 40,
    "max_conn_interval": 40,
    "conn_latency": 0,
    "supervision_timeout": 500,
}


def connect_conn_params(app_id: Optional[str] = None, override: Optional[dict] = None) -> dict:
    """Connection interval/latency/timeout sent with /ble/connect (matches README examples)."""
    _ = app_id  # reserved for per-app overrides later
    params = dict(DEFAULT_CONNECT_CONN_PARAMS)
    if override:
        for key in DEFAULT_CONNECT_CONN_PARAMS:
            if override.get(key) is not None:
                params[key] = int(override[key])
    return params


def notify_uuids(app_id: str) -> tuple[Optional[str], Optional[str]]:
    return APP_NOTIFY_UUIDS.get(app_id, ("180d", "2a37"))


def notifications_enable_payload(app_id: str, override: Optional[dict] = None) -> dict:
    """Body for POST /ble/notifications/enable — {} auto-picks notify char (README)."""
    service_uuid, char_uuid = notify_uuids(app_id)
    if override:
        if override.get("service_uuid") is not None:
            service_uuid = override.get("service_uuid")
        if override.get("char_uuid") is not None:
            char_uuid = override.get("char_uuid")
        if override.get("auto_pick") is True:
            service_uuid, char_uuid = None, None
    if not service_uuid and not char_uuid:
        return {}
    payload: dict = {}
    if service_uuid:
        payload["service_uuid"] = service_uuid
    if char_uuid:
        payload["char_uuid"] = char_uuid
    return payload


def pytest_test_name(app_id: str) -> str:
    return f"test_{app_id}_http_flow"


def pytest_node(app_id: str) -> str:
    return f"{TEST_MODULE}::{pytest_test_name(app_id)}"


def pytest_command(app_id: str) -> str:
    return f"pytest --tb=native {pytest_node(app_id)} --manifest {MANIFEST}"


def resolve_app_test(app_id: str) -> dict:
    return {
        "app_id": app_id,
        "test_function": pytest_test_name(app_id),
        "pytest_node": pytest_node(app_id),
        "pytest_command": pytest_command(app_id),
    }


def catalog_entry_for_app(app_id: str, label: str) -> dict:
    test = resolve_app_test(app_id)
    profile = test_profile(app_id)
    return {
        "id": app_id,
        "label": label,
        "test_function": test["test_function"],
        "pytest_command": test["pytest_command"],
        "test_profile": profile,
    }
