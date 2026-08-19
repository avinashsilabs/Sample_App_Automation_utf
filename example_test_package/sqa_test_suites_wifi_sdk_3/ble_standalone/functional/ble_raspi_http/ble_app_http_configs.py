"""Per-application BLE HTTP test metadata (notify UUIDs, timeouts)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class BleAppHttpConfig:
    app_id: str
    label: str
    service_uuid: Optional[str] = "180d"
    char_uuid: Optional[str] = "2a37"
    orchestration_timeout_sec: int = 600
    post_notify_stability_sec: int = 300
    # gatt_connect: Pi central → DUT peripheral (optional notify);
    # gatt_long_read: Pi central → DUT SERVER; GATT Read of long attr (no soak);
    # ibeacon_scan: repeated scan for advertiser only;
    # ae_central: Pi peripheral via BlueZ LEAdvertisement (extended OK);
    # ble_central / accept_list: Pi peripheral via legacy HCI ADV_IND
    #   (accept_list also requires Pi MAC on DUT controller accept list);
    # longrange / datalength: Pi peripheral + DUT procedure (no soak);
    # testmodes: Pi = HCI dongle (LE RX/TX test); DUT = RF testmodes;
    # stack_bypass: Pi attaches DUT HCI UART (btattach) — Linux BlueZ drives DUT;
    # secureconnection: Pi central + SMP passkey (DUT BLE_SMP_SC peripheral);
    # privacy: Pi central + SMP (DUT SIMPLE_PRIVACY) + resolve list + disconnect;
    # hid_on_gatt: Pi central + SMP passkey, then HID report notifications (0x1812/0x2A4D);
    orchestration_kind: str = "gatt_connect"
    # gatt_long_read: min bytes from POST /ble/read (SDK long attr > 20).
    min_gatt_read_len: int = 21
    # ble_testmodes: "tx" (DUT TX / Pi LE Receiver Test) or "rx" (DUT RX / Pi LE TX Test).
    testmodes_mode: str = "tx"
    testmodes_channel: int = 0x10
    testmodes_payload_len: int = 0x20
    testmodes_payload_type: int = 0x01
    testmodes_collect_sec: int = 8
    # bt_stack_bypass: USB-UART from WSTK to Pi (readme SoC pins P35/P33).
    stack_bypass_uart: str = "/dev/ttyUSB0"
    stack_bypass_baud: int = 115200
    stack_bypass_lescan_sec: int = 5
    # When False, link stay-up alone is enough — no GATT notify.
    require_notifications: bool = True
    ibeacon_scan_duration_sec: int = 300
    ibeacon_scan_interval_sec: int = 30
    ibeacon_per_scan_timeout_sec: int = 12
    ae_central_peripheral_name: str = "SILABS_DEV"
    ae_central_connect_timeout_sec: int = 180
    # Expected DUT LocalName for docs / pytest banner (SDK RSI_BLE_LOCAL_NAME).
    dut_advertising_name: str = ""
    # AE SET1 random addr (SDK RSI_BLE_SET_RAND_ADDR); SET2 uses public silicon MAC.
    dut_random_adv_addr: str = ""


# Defaults use Heart Rate (0x180D / 0x2A37) unless an app needs different UUIDs.
_DEFAULT = BleAppHttpConfig(app_id="", label="", service_uuid="180d", char_uuid="2a37")

_APP_ROWS = [
    ("ble_accept_list", "Accept List"),
    ("ble_ae_central", "Ae Central"),
    ("ble_ae_peripheral", "Ae Peripheral"),
    ("ble_central", "Central"),
    ("ble_datalength", "Datalength"),
    ("ble_fw_ota_upgrade", "Fw Ota Upgrade"),
    ("ble_heart_rate_profile", "Heart Rate Profile", "180d", "2a37"),
    ("ble_hid_on_gatt", "Hid On Gatt"),
    ("ble_ibeacon", "Ibeacon"),
    ("ble_iop_test", "Iop Test"),
    ("ble_longrange_2mbps", "Longrange 2mbps"),
    ("ble_multiconnection_gatt_test", "Multiconnection Gatt Test", None, None),
    ("ble_power_save", "Power Save"),
    ("ble_privacy", "Privacy"),
    ("ble_secureconnection", "Secureconnection"),
    ("ble_testmodes", "Testmodes"),
    ("ble_throughput_app", "Throughput App"),
    ("ble_unified_ae_coex_app", "Unified Ae Coex App"),
    ("ble_unified_coex_app", "Unified Coex App"),
    ("ble_update_gain_table", "Update Gain Table"),
    ("bt_stack_bypass", "Bt Stack Bypass"),
    ("gatt_long_read", "Gatt Long Read"),
]


def _build_configs() -> Dict[str, BleAppHttpConfig]:
    configs: Dict[str, BleAppHttpConfig] = {}
    for row in _APP_ROWS:
        app_id = row[0]
        label = row[1]
        svc = row[2] if len(row) > 2 else _DEFAULT.service_uuid
        ch = row[3] if len(row) > 3 else _DEFAULT.char_uuid
        configs[app_id] = BleAppHttpConfig(
            app_id=app_id,
            label=label,
            service_uuid=svc,
            char_uuid=ch,
        )
    return configs


BLE_APP_HTTP_CONFIGS: Dict[str, BleAppHttpConfig] = _build_configs()

# Per-app orchestration overrides (iBeacon = advertiser-only scan stability per SDK readme).
BLE_APP_HTTP_CONFIGS["ble_ibeacon"] = BleAppHttpConfig(
    app_id="ble_ibeacon",
    label="Ibeacon",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="ibeacon_scan",
    orchestration_timeout_sec=900,
    ibeacon_scan_duration_sec=300,
    ibeacon_scan_interval_sec=30,
    ibeacon_per_scan_timeout_sec=12,
)

# AE Central (SDK readme): DUT scans+connects; pass on connect — no soak / notify.
BLE_APP_HTTP_CONFIGS["ble_ae_central"] = BleAppHttpConfig(
    app_id="ble_ae_central",
    label="Ae Central",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="ae_central",
    orchestration_timeout_sec=360,
    ibeacon_scan_duration_sec=0,
    ibeacon_scan_interval_sec=30,
    ae_central_peripheral_name="SILABS_DEV",
    ae_central_connect_timeout_sec=180,
)

# ble_central (SDK siwx91x_bluetooth_le_central): DUT legacy central → Pi
# connectable legacy advertiser (Complete Local Name in AD + scan response).
# Pass on DUT serial "Module connected" — not the AE-central extended path.
BLE_APP_HTTP_CONFIGS["ble_central"] = BleAppHttpConfig(
    app_id="ble_central",
    label="Central",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="ble_central",
    orchestration_timeout_sec=360,
    ibeacon_scan_duration_sec=0,
    ibeacon_scan_interval_sec=30,
    ae_central_peripheral_name="SILABS_DEV",
    ae_central_connect_timeout_sec=180,
)

# Accept List (SDK ble_accept_list): same Pi path as ble_central (legacy SILABS_DEV),
# but DUT only receives adv reports for accept-listed BD addresses. Flash with Pi MAC
# in ble_acceptlist_addr1 (SDK reverse-byte layout) + RSI_BLE_DEV_ADDR / RSI_REMOTE_DEVICE_NAME.
BLE_APP_HTTP_CONFIGS["ble_accept_list"] = BleAppHttpConfig(
    app_id="ble_accept_list",
    label="Accept List",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="accept_list",
    orchestration_timeout_sec=360,
    post_notify_stability_sec=0,
    require_notifications=False,
    ibeacon_scan_duration_sec=0,
    ibeacon_scan_interval_sec=30,
    ae_central_peripheral_name="SILABS_DEV",
    ae_central_connect_timeout_sec=180,
)

# Data Length (SDK ble_datalength): DUT central + DLE after connect; Pi peripheral.
BLE_APP_HTTP_CONFIGS["ble_datalength"] = BleAppHttpConfig(
    app_id="ble_datalength",
    label="Datalength",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="datalength",
    orchestration_timeout_sec=360,
    ibeacon_scan_duration_sec=0,
    ibeacon_scan_interval_sec=30,
    ae_central_peripheral_name="SILABS_DEV",
    ae_central_connect_timeout_sec=180,
)

# Long Range / 2Mbps (SDK ble_longrange_2mbps): DUT central + PHY (2Mbps).
# Pi = SILABS_DEV peripheral. Pass on connect; Coded ignored on Pi. No soak.
BLE_APP_HTTP_CONFIGS["ble_longrange_2mbps"] = BleAppHttpConfig(
    app_id="ble_longrange_2mbps",
    label="Long Range 2Mbps",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="longrange",
    orchestration_timeout_sec=360,
    ibeacon_scan_duration_sec=0,
    ibeacon_scan_interval_sec=30,
    ae_central_peripheral_name="SILABS_DEV",
    ae_central_connect_timeout_sec=180,
)

# BLE Testmodes (SDK ble_testmodes): DUT RF TX/RX; Pi runs hcitool LE test cmds.
# Default matches sample RSI_CONFIG_TEST_MODE = TRANSMIT (Pi = LE Receiver Test).
BLE_APP_HTTP_CONFIGS["ble_testmodes"] = BleAppHttpConfig(
    app_id="ble_testmodes",
    label="Testmodes",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="testmodes",
    orchestration_timeout_sec=300,
    post_notify_stability_sec=0,
    require_notifications=False,
    ibeacon_scan_duration_sec=0,
    testmodes_mode="tx",
    testmodes_channel=0x10,
    testmodes_payload_len=0x20,
    testmodes_payload_type=0x01,
    testmodes_collect_sec=8,
)

# BT Stack Bypass (SDK bt_stack_bypass): DUT = raw HCI over UART; Pi = Linux host.
# Requires USB-UART cable WSTK↔Pi. Pass = attach → hci up → leadv → lescan → detach.
BLE_APP_HTTP_CONFIGS["bt_stack_bypass"] = BleAppHttpConfig(
    app_id="bt_stack_bypass",
    label="Bt Stack Bypass",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="stack_bypass",
    orchestration_timeout_sec=300,
    post_notify_stability_sec=0,
    require_notifications=False,
    ibeacon_scan_duration_sec=0,
    stack_bypass_uart="/dev/ttyUSB0",
    stack_bypass_baud=115200,
    stack_bypass_lescan_sec=5,
)

# Heart Rate: DUT SERVER + Pi central; UUIDs per Bluetooth HRS (SDK readme).
BLE_APP_HTTP_CONFIGS["ble_heart_rate_profile"] = BleAppHttpConfig(
    app_id="ble_heart_rate_profile",
    label="Heart Rate Profile",
    service_uuid="180d",
    char_uuid="2a37",
    orchestration_kind="gatt_connect",
    orchestration_timeout_sec=600,
    post_notify_stability_sec=300,
    require_notifications=True,
)

# GATT Long Read SERVER (SDK gatt_long_read GATT_ROLE=SERVER): DUT advertises
# LONG_READ_TEST with custom service 0xAABB / char 0x1AA1 (100-byte value).
# Pi = phone central: scan → connect → GATT Read (long) → PASS. No notify soak.
BLE_APP_HTTP_CONFIGS["gatt_long_read"] = BleAppHttpConfig(
    app_id="gatt_long_read",
    label="Gatt Long Read",
    service_uuid="aabb",
    char_uuid="1aa1",
    orchestration_kind="gatt_long_read",
    orchestration_timeout_sec=360,
    post_notify_stability_sec=0,
    require_notifications=False,
    ibeacon_scan_duration_sec=0,
    ae_central_connect_timeout_sec=180,
    dut_advertising_name="LONG_READ_TEST",
    min_gatt_read_len=21,
)

# Secure Connection (SDK ble_secureconnection): DUT advertises BLE_SMP_SC;
# Pi = central (Simplicity Connect phone role). Pass = SMP encrypt + security keys.
# No GATT notify / no soak.
BLE_APP_HTTP_CONFIGS["ble_secureconnection"] = BleAppHttpConfig(
    app_id="ble_secureconnection",
    label="Secureconnection",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="secureconnection",
    orchestration_timeout_sec=360,
    post_notify_stability_sec=0,
    require_notifications=False,
    ibeacon_scan_duration_sec=0,
    ae_central_connect_timeout_sec=180,
    dut_advertising_name="BLE_SMP_SC",
)

# Privacy (SDK ble_privacy PERIPHERAL_ROLE default): DUT advertises SIMPLE_PRIVACY;
# Pi = phone central. Pass = SMP keys → resolve list → Pi disconnect → DUT re-adv.
# No GATT notify. Flash with RSI_DEVICE_ROLE=PERIPHERAL_ROLE (stock).
BLE_APP_HTTP_CONFIGS["ble_privacy"] = BleAppHttpConfig(
    app_id="ble_privacy",
    label="Privacy",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="privacy",
    orchestration_timeout_sec=420,
    post_notify_stability_sec=0,
    require_notifications=False,
    ibeacon_scan_duration_sec=0,
    ae_central_connect_timeout_sec=180,
    dut_advertising_name="SIMPLE_PRIVACY",
)

# HID over GATT (SDK ble_hid_on_gatt GATT_ROLE=SERVER): DUT advertises HID_OVER_GATT
# as a HOGP keyboard. Pi = phone central: bond with the passkey shown on DUT serial,
# then subscribe to the HID report characteristic and collect the "hog_" reports.
BLE_APP_HTTP_CONFIGS["ble_hid_on_gatt"] = BleAppHttpConfig(
    app_id="ble_hid_on_gatt",
    label="Hid On Gatt",
    service_uuid="1812",
    char_uuid="2a4d",
    orchestration_kind="hid_on_gatt",
    orchestration_timeout_sec=420,
    post_notify_stability_sec=0,
    require_notifications=False,
    ibeacon_scan_duration_sec=0,
    ae_central_connect_timeout_sec=180,
    dut_advertising_name="HID_OVER_GATT",
)

# AE Peripheral (SDK siwx91x_bluetooth_le_ae_peripheral): DUT AE advertiser,
# Pi central scan+connect. Manual-tester pass on connect — not the 5‑min soak path.
BLE_APP_HTTP_CONFIGS["ble_ae_peripheral"] = BleAppHttpConfig(
    app_id="ble_ae_peripheral",
    label="Ae Peripheral",
    service_uuid=None,
    char_uuid=None,
    orchestration_kind="ae_peripheral",
    orchestration_timeout_sec=360,
    post_notify_stability_sec=0,
    require_notifications=False,
    ibeacon_scan_duration_sec=0,
    ibeacon_scan_interval_sec=30,
    ae_central_connect_timeout_sec=180,
    dut_advertising_name="AE_PERIPHERAL",
    dut_random_adv_addr="C1:44:33:AA:BB:CC",
)


def get_app_config(app_id: str) -> BleAppHttpConfig:
    if app_id not in BLE_APP_HTTP_CONFIGS:
        raise KeyError(f"Unknown BLE app test config: {app_id}")
    return BLE_APP_HTTP_CONFIGS[app_id]


def pytest_test_name(app_id: str) -> str:
    return f"test_{app_id}_http_flow"
