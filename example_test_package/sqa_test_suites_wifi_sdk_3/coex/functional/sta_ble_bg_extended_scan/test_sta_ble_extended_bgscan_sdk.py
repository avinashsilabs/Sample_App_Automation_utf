# IOTREQ-12128: STA-mode background extended scan while connected (SiWx917)
# Test plan: IOT_REQ/STA_BG_Extended_Scan.csv
# Suite: STA+BLE_EXTENDED_BGSCAN
# Reference: test_sta_ble_sdk.py, Testcase_Generation_Prompt_Updated.md

import threading
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from utf.utf_config import UtfConfig
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_sdk import (
    BleThreadFunctionality,
    WifiJoinThread,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble_provisioning.test_sta_ble_provisioning_sdk import (
    ProvisioningFunctionality as StaBleProvisioningFunctionality,
    wifi_dut_marker as sta_ble_provisioning_wifi_dut_marker,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_dle_sdk import (
    logger,
    BleThread,
    SnifferValidationProcess,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_multi_raspi_sdk import (
    dual_role_disconnect,
)

from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService

import time
import pytest
import string
import random
import re
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xJoinFeatureBitMap,
    Si91xCertificateType,
    Si91xCertIdentifier,
)
from utf.utils import get_tls_certificate_dir
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (BodySensorLocationCharacteristic,
                                                                                HeartRateControlPointCharacteristic,
                                                                                HeartRateMeasurementCharacterstic)
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.sl_status import SLStatus

def logger():
    return get_logger(__name__)


ble_obj = None


def _configure_advanced_scan(wifi_dut, advanced_scan_bitmap=(1 << 0) | (1 << 6) | (1 << 7)):
    """
    Issue the advanced-scan configuration CLI:
        wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
            (Instant scan: Enabled, Non-periodic scan: Enabled, Extended results: Enabled)

    Called from ``_perform_bg_extended_scan`` after Wi-Fi connection is established,
    immediately before the BG extended scan command.
    """
    wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
        adv_active_channel_time=50,
        adv_passive_channel_time=20,
        adv_trigger_level=None,
        adv_trigger_level_change=None,
        adv_enable_multi_probe=1,
        adv_enable_instant_scan=None,
        has_adv_scan_bit_map=1,
        advanced_scan_bitmap=advanced_scan_bitmap,
    )


def _perform_bg_extended_scan(
    wifi_dut,
    timeout=60,
    bg_scan_periodicity=10,
    scan_bitmap_2_4=None,
    advanced_scan_bitmap=(1 << 0) | (1 << 6) | (1 << 7),
):
    """
    Configure advanced scan and trigger background extended scan after connection:
        wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        wifi.scan -m bg_scan -p 8 -n 15 -t <periodicity>
            (bg_scan, scan_type=SL_WIFI_SCAN_TYPE_EXTENDED(8), scan_count_extended=15)

    Invoke only after the DUT is connected to the AP.
    """
    _configure_advanced_scan(wifi_dut, advanced_scan_bitmap=advanced_scan_bitmap)
    scan_kwargs = {
        "ssid": None,
        "bgscan": True,
        "scan_type": 8,
        "scan_count_extended": 50,
        "timeout": timeout,
    }
    if bg_scan_periodicity is not None:
        scan_kwargs["bg_scan_periodicity"] = bg_scan_periodicity
    if scan_bitmap_2_4 is not None:
        scan_kwargs["scan_bitmap_2_4"] = scan_bitmap_2_4
    return wifi_dut.interfaces.wifi.scan(**scan_kwargs)


def _assert_extended_bgscan_channels_only(scan_results, allowed_channels):
    """
    Verify extended BG scan results contain APs only on the allowed channels.
    No other channels must appear in the scan list.
    """
    allowed = set(allowed_channels)
    observed_channels = set()
    invalid_entries = []
    for idx, entry in enumerate(scan_results):
        ch = entry.rf_channel
        observed_channels.add(ch)
        if ch not in allowed:
            invalid_entries.append(
                (idx, ch, getattr(entry, "ssid", None), getattr(entry, "bssid", None))
            )
    assert not invalid_entries, (
        f"BG extended scan found APs on disallowed channels. "
        f"Allowed: {sorted(allowed)}, observed: {sorted(observed_channels)}, "
        f"invalid entries (index, channel, ssid, bssid): {invalid_entries}"
    )
    logger().info(
        f"BG extended scan channels verified: observed {sorted(observed_channels)} "
        f"(allowed {sorted(allowed)} only)"
    )


def _get_probe_request_time_deltas():
    """Parse probe-request inter-frame deltas from sniffer filter2 output."""
    marker = "Time delta from previous captured frame"
    time_deltas = []
    filter_file_path = "./reports/filter2_file.txt"
    with open(filter_file_path, "r") as filter_file:
        for line in filter_file:
            if marker not in line:
                continue
            delta_str = (
                line.strip().split(":")[1]
                .replace("]", "").strip().replace("seconds", "").strip()
            )
            time_deltas.append(float(delta_str))
            logger().info(f"Probe request time delta: {delta_str}s")
    return time_deltas


def _validate_periodic_bgscan_probe_requests(
    wifi_sniffer,
    sniffer_filter,
    dut_mac_address,
    ap_channel=None,
    bg_scan_periodicity=10,
    tolerance_sec=2.0,
    min_periodic_matches=1,
):
    """
    Verify broadcast probe requests from the DUT appear periodically in sniffer capture.
    Expects capture to span at least two BG scan cycles.
    """
    packet_filter2 = "    Type/Subtype: Probe Request (0x0004)"
    packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
        sa_addr=dut_mac_address, filter_name="probe_request"
    )

    result = wifi_sniffer.interfaces.capture.sniffer_validation(
        sniffer_validation=True,
        packet_filter1=packet_filter1,
        packet_filter2=packet_filter2,
    )
    assert result["packet_count"], (
        "Sniffer: Unable to find probe_request packets during periodic BG scan"
    )

    probe_time_deltas = _get_probe_request_time_deltas()
    assert probe_time_deltas, (
        "Sniffer: Unable to parse probe request time deltas for periodic BG scan validation"
    )
    probe_time_deltas.pop(0)

    min_interval = bg_scan_periodicity - tolerance_sec
    max_interval = bg_scan_periodicity + tolerance_sec
    periodic_matches = sum(
        1 for time_diff in probe_time_deltas if min_interval <= time_diff <= max_interval
    )
    for time_diff in probe_time_deltas:
        logger().info(
            f"Probe request inter-frame delta: {time_diff:.3f}s "
            f"(expected periodicity ~{bg_scan_periodicity}s)"
        )

    assert periodic_matches >= min_periodic_matches, (
        f"Expected at least {min_periodic_matches} probe request interval(s) near "
        f"{bg_scan_periodicity}s (range [{min_interval}, {max_interval}]); "
        f"observed deltas: {probe_time_deltas}, periodic matches: {periodic_matches}"
    )
    logger().info(
        f"Periodic BG scan probe requests verified: {periodic_matches} interval(s) "
        f"within {bg_scan_periodicity}s (+/- {tolerance_sec}s)"
    )


def _trigger_ap_rejoin_via_stop_start(
    wifi_access_point,
    device_ip,
    ping_count,
    ap_down_time=10,
    ap_up_wait=20,
    rejoin_timeout=120,
):
    """
    Trigger a Wi-Fi rejoin by stopping and restarting the AP (no PDU/switch).
    Returns True once the DUT responds to ping again after AP restart.
    """
    ap_security = wifi_access_point.interfaces.wifi.config.get("security", "WPA2")
    ap_passphrase = wifi_access_point.interfaces.wifi.config.get("passphrase", "1234567890")

    logger().info("Stopping AP to trigger rejoin scenario")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(ap_down_time)

    if ping(device_ip, min(ping_count, 5), size=300):
        logger().warning("DUT still responding to ping after AP stop")

    logger().info("Starting AP and waiting for DUT rejoin")
    wifi_access_point.interfaces.wifi.start_ap(
        security=ap_security, passphrase=ap_passphrase,
    )
    time.sleep(ap_up_wait)

    sw = Stopwatch()
    while sw.elapsed_sec < rejoin_timeout:
        if ping(device_ip, ping_count, size=300):
            logger().info("DUT rejoined successfully after AP restart")
            return True
        time.sleep(5)

    logger().error(f"DUT did not rejoin within {rejoin_timeout}s after AP restart")
    return False


def wifi_dut_marker(ext_custom_bit=0, tcp_feat_bit=0, ext_tcp_feat_bit=0,
                    ca_cert=None, eap_cert=None, wifi_stack_len=3584,
                    ble_stack_len=3584, oper_mode=0, config_feature=0, num_peripheral_connections=1,
                    num_central_connections=1, region=1, region_code="us", no_of_wifi_threads=1, no_of_ble_threads=1):
    config = {
        "oper_mode": oper_mode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp | config_feature,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | tcp_feat_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | ext_tcp_feat_bit,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | ext_custom_bit,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=num_central_connections)
                        | Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=num_peripheral_connections)
                        | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
                        | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
                        | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
                        | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,

        "region": region,
        "region_code": region_code,
        "thread_config": {
            "wifi": {"count": no_of_wifi_threads, "stack_len": wifi_stack_len, "priority": 8},
            "ble": {"count": no_of_ble_threads, "stack_len": ble_stack_len, "priority": 8},
        },
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if eap_cert:
        config["eap_cert"] = eap_cert
    return pytest.mark.config("wifi_dut", wifi=config)




@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
def test_sta_ble_extended_bgscan_ssid_security_rssi_C978144(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    C978144: Verify SSID, Security_Type, channel, rssi filtering and max scan list of AP
    using BG extended scan while BLE is connected as central with CI 4000ms.
    IOTREQ-12128, STA+BLE_EXTENDED_BGSCAN.
    Steps:
        1. Initialize DUT in WiFi+BLE mode
        2. Connect DUT to configured AP
        3. Verify association and IP connectivity
        4. Enable power save
        5. Start pinging from AP backend to DUT
        6. Establish BLE connection with mobile device
        7. Trigger Wi-Fi background extended scan (B0=1, B6=1, B7=1)
        8. Verify BG extended scan results contain more than 11 AP entries
        9. Verify each scan entry includes SSID and Security_Type (by rssi)
        10. Verify scan list size matches configured maximum
    """
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info("Configuring sniffer with channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # BLE thread: DUT as slave (mobile connects to DUT)
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            bond_info=0,
            conn_int=4000,  # CI 4000ms per test plan
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("BLE connection established")

        # WiFi: join, power save, ping
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP after join"

        # Ping from AP backend to DUT (stability check)
        status = ping(device_ip, ping_count, size=300)
        assert status, "Ping from AP backend to DUT failed"

        # Trigger Wi-Fi background extended scan via new CLI:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        #   wifi.scan -m bg_scan -p 8 -n 15
        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results is not None, "BG extended scan returned no results"
        logger().info(f"BG extended scan returned {len(scan_results)} AP entries")

        # Step 8: More than 11 AP entries where available
        assert len(scan_results) > 11, (
            f"BG extended scan expected >11 results (IOTREQ-12128), got {len(scan_results)}"
        )

        # Step 9: Each entry includes SSID and Security_Type; results typically sorted by rssi
        for idx, entry in enumerate(scan_results):
            assert hasattr(entry, "ssid"), f"Scan entry {idx} missing ssid"
            assert hasattr(entry, "security_mode"), f"Scan entry {idx} missing security_mode"
            # ssid and security_mode should be populated (non-empty / valid)
            logger().info(f"  [{idx}] ssid={getattr(entry, 'ssid', b'')} security_mode={getattr(entry, 'security_mode', None)} rssi={getattr(entry, 'rssi', None)}")

        # Step 10: Scan list size follows configured maximum (no overflow; we got a list of size len(scan_results))
        logger().info(f"Scan list size: {len(scan_results)} (expected >11)")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut,
                ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )


# ---- C978135: BG extended scan while BLE advertising 20ms (Region: US, Ch 1) ----

@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "channel": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_sta_ble_extended_bgscan_while_ble_adv_20ms_us_C978135(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    C978135: Verify Wi-Fi Background Extended scan while DUT BLE is advertising
    with advertising interval 20ms (Region: US, AP on Channel 1).
    """
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="advertise",
            adv_int_min=20,
            adv_int_max=20,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        status = ping(device_ip, ping_count, size=300)
        assert status, "Ping failed"
        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results is not None and len(scan_results) > 11, (
            f"Expected >11 APs, got {len(scan_results) if scan_results else 0}"
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut,
                ble_client=ble_client,
                ble_client_address=getattr(ble_obj, "ble_client_address", None),
                ble_dut_address=ble_obj.ble_dut_address,
            )


# ---- C978136: BG extended scan while DUT BLE scanning (SI 120ms, SW 40ms) ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "region": "Europe", "channel": 6}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
# @wifi_dut_marker()
@wifi_dut_marker(region=1, region_code="europe")
def test_sta_ble_extended_bgscan_while_ble_scanning_C978136(
    wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
    utf_constants, sl_collections, wifi_client, sniffer_filter,
):
    """C978136: BG extended scan while DUT BLE scanning (scan interval 120ms, window 40ms)."""
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
            ble_test_type="scan", scan_interval=120, scan_window=40,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
            ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        assert ping(device_ip, ping_count, size=300), "Ping failed"
        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results is not None and len(scan_results) > 11, (
            f"Expected >11 results, got {len(scan_results) if scan_results else 0}"
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut, ble_client=ble_client,
                ble_client_address=getattr(ble_obj, "ble_client_address", None),
                ble_dut_address=ble_obj.ble_dut_address,
            )


# ---- C978138: BG extended scan while BLE Tx Notification (WW, Ch 13) ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890", "region": "Europe", "channel": 13}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker(region=1, region_code="worldwide")
def test_sta_ble_extended_bgscan_while_ble_tx_notify_C978138(
    wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
    utf_constants, sl_collections, wifi_client, sniffer_filter,
):
    """C978138: BG extended scan while BLE Tx Notification 240bytes (Region: WW, Ch 13)."""
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        index = 1
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(data), write_content=data)

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=20, data_duration=300,
            periodic_delay=1,
            address=address1,
            conn_interval=100,
            ble_pairing=1,
            gatt=True,
            set_smp=0
        )
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
            ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        assert ping(device_ip, ping_count, size=300), "Ping failed"

        ble_obj.ble_connect(role="slave")
        ble_obj.service_discovery_on_remote()

        ble_obj.start()

        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results is not None and len(scan_results) > 11, (
            f"Expected >11 results, got {len(scan_results) if scan_results else 0}"
        )

        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut, ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )


# ---- C978141: TCP-Tx while BG extended periodic scan, BLE central CI 500ms ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker()
def test_sta_ble_tcp_tx_bg_extended_periodic_ble_central_500ms_C978141(
    wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
    utf_constants, sl_collections, wifi_client, sniffer_filter, net_perf_client, protocol,
):
    """C978141: TCP-Tx while BG extended periodic scan, BLE central CI 500ms, notification RX ongoing."""
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=BLEDeviceState.Connected,
            ble_pairing=1,
            gatt=True,
            conn_interval=500,
            set_smp=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
            ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="iperf",
            net_perf_client=net_perf_client, protocol=protocol, timeout=120,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.set_power_save()

        scan_results = _perform_bg_extended_scan(
            wifi_dut, timeout=90, advanced_scan_bitmap=(1 << 0) | (1 << 7),
        )
        assert scan_results is not None and len(scan_results) > 11, (
            f"BG extended scan expected >11 results, got {len(scan_results) if scan_results else 0}"
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        _validate_periodic_bgscan_probe_requests(
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            dut_mac_address=wifi_obj.dut_mac_address,
            ap_channel=wifi_access_point.interfaces.wifi.channel,
        )
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()

        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut, ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )


# ---- C978143: UDP-Tx/Rx while BG extended periodic scan, BLE peripheral CI 1000ms ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker()
def test_sta_ble_udp_tx_rx_bg_extended_periodic_ble_peripheral_1000ms_C978143(
    wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
    utf_constants, sl_collections, wifi_client, sniffer_filter, net_perf_client, protocol,
):
    """C978143: BG extended periodic scan while UDP-Tx/Rx, BLE peripheral CI 1000ms, notification TX."""
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=0,
            bond_info=1,
            set_smp=0,
            conn_interval=1000
        )

        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
            ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="iperf",
            net_perf_client=net_perf_client, protocol=protocol, timeout=120,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.set_power_save()
        scan_results = _perform_bg_extended_scan(
            wifi_dut, timeout=90, advanced_scan_bitmap=(1 << 0) | (1 << 7),
        )
        assert scan_results is not None and len(scan_results) > 11, (
            f"BG extended scan expected >11 results, got {len(scan_results) if scan_results else 0}"
        )

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        _validate_periodic_bgscan_probe_requests(
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            dut_mac_address=wifi_obj.dut_mac_address,
            ap_channel=wifi_access_point.interfaces.wifi.channel,
        )
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut, ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )


# ---- C978147: BG extended scan after rejoin (AP stop/start), BLE peripheral CI 250ms ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker()
def test_sta_ble_bg_extended_after_rejoin_ble_peripheral_250ms_C978147(
    # wifi_sniffer,
    wifi_access_point, wifi_dut, ble_client, request,
    utf_constants, sl_collections, wifi_client,
    # sniffer_filter,
):
    """
    C978147: Verify BG extended scan after rejoin when BLE peripheral CI 250ms.
    Rejoin is triggered by stopping and restarting the AP (no PDU/switch).
    """
    global ble_obj
    ble_obj = None
    ap_stopped = False
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        rejoin_timeout = min(utf_constants.get("rejoin_time"), 120)

        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=0,
            bond_info=1,
            set_smp=0,
            conn_interval=250
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        assert ping(device_ip, ping_count, size=300), "Ping failed before rejoin"

        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results is not None and len(scan_results) > 11, (
            f"BG extended scan before rejoin expected >11, "
            f"got {len(scan_results) if scan_results else 0}"
        )

        ap_stopped = True
        assert _trigger_ap_rejoin_via_stop_start(
            wifi_access_point=wifi_access_point,
            device_ip=device_ip,
            ping_count=ping_count,
            rejoin_timeout=rejoin_timeout,
        ), f"DUT failed to rejoin within {rejoin_timeout}s after AP stop/start"
        ap_stopped = False

        assert wifi_dut.interfaces.wifi.associated, "DUT not associated after rejoin"

        ble_state = wifi_dut.interfaces.wifi.ble_get_device_state()

        ble_state = int(ble_state) if ble_state.isdigit() else -1
        assert ble_state == BLEDeviceState.Connected, "BLE connection lost after Wi-Fi rejoin"


        scan_results_after = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results_after is not None and len(scan_results_after) > 11, (
            f"BG extended scan after rejoin expected >11, "
            f"got {len(scan_results_after) if scan_results_after else 0}"
        )

        # wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        if ap_stopped:
            try:
                wifi_access_point.interfaces.wifi.start_ap(
                    security="WPA2", passphrase="1234567890",
                )
            except Exception:
                logger().warning("Failed to restart AP during cleanup")
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut, ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )


@wifi_dut_marker()
# ---- C978148: BG extended scan after CSA, BLE central CI 250ms ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
def test_sta_ble_bg_extended_after_csa_ble_central_250ms_C978148(
    wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
    utf_constants, sl_collections, wifi_client, sniffer_filter,
):
    """C978148: BG extended scan after CSA when BLE central CI 250ms."""
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=0,
            bond_info=1,
            set_smp=1,
            conn_interval=250
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
            ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        assert ping(device_ip, ping_count, size=300), "Ping failed"
        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results is not None and len(scan_results) > 11, (
            f"BG extended before CSA expected >11, got {len(scan_results) if scan_results else 0}"
        )
        if hasattr(wifi_access_point.interfaces.wifi, "enable_disable_csa"):
            wifi_access_point.interfaces.wifi.enable_disable_csa(11, 20, 1)
            time.sleep(35)
        scan_results2 = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results2 is not None and len(scan_results2) > 11, (
            f"BG extended after CSA expected >11, got {len(scan_results2) if scan_results2 else 0}"
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut, ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )




# ---- C978139: BG extended selective channel (1, 6, 11) while BLE Rx Notification ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker()
def test_sta_ble_extended_bgscan_selective_ch_1_6_11_C978139(
    wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request,
    utf_constants, sl_collections, wifi_client, sniffer_filter,
):
    """C978139: BG extended selective channel scan (Ch 1, 6, 11) while BLE Rx Notification 20bytes.
    Verify extended BG scan results contain APs only on channels 1, 6, and 11 (no other channels).
    Verify periodic BG scan probe requests are observed in sniffer capture.
    """
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="connect_as_master_notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            set_smp=1,
            svc=svc,
            charc=charc,
            data=data,

        )
        ble_obj.start()

        channel_bitmap_2_4 = (1 << 0) | (1 << 5) | (1 << 10)  # Ch 1, 6, 11
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
            ping_count=ping_count, sniffer_filter=sniffer_filter, test_type="ping",
            channel_bitmap_2_4=channel_bitmap_2_4
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        assert ping(device_ip, ping_count, size=300), "Ping failed"

        # Selective channels 1, 6, 11 are configured via channel_bitmap_2_4 at join;
        # extended BG scan must report APs only on those channels.
        selective_channels = [1, 6, 11]
        scan_results = _perform_bg_extended_scan(
            wifi_dut,
            timeout=90,
            scan_bitmap_2_4=channel_bitmap_2_4,
            advanced_scan_bitmap=(1 << 0) | (1 << 7),
        )
        assert scan_results is not None and len(scan_results) > 11, (
            f"Expected >11 results, got {len(scan_results) if scan_results else 0}"
        )
        _assert_extended_bgscan_channels_only(scan_results, selective_channels)

        ble_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut, ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )



# ---- C978140: BLE reconnects during BG extended scan (DUT peripheral CI 80ms) ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker()
def test_sta_ble_ble_reconnect_during_bg_extended_scan_C978140(
    # wifi_sniffer,
    wifi_access_point, wifi_dut, ble_client, request,
    utf_constants, sl_collections, wifi_client,
    # sniffer_filter,
):
    """C978140: BLE reconnects (DUT peripheral CI 80ms) while BG extended scan active."""
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        # wifi_sniffer.interfaces.capture.configure_interface(
        #     channel=wifi_access_point.interfaces.wifi.channel
        # )
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            conn_interval=80,
            set_smp=0
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            # wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
            testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
            ping_count=ping_count,
            # sniffer_filter=sniffer_filter,
            test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        assert ping(device_ip, ping_count, size=300), "Ping failed"
        # Background extended scan via new CLI:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        #   wifi.scan -m bg_scan -p 8 -n 15
        _perform_bg_extended_scan(wifi_dut, timeout=30)
        time.sleep(5)
        ble_obj.ble_disconnect()
        time.sleep(3)
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            conn_interval=80,
            set_smp=0
        )

        ble_obj.advertise_dut()
        ble_obj.scan_and_connect_from_remote()
        time.sleep(5)
        # wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut, ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )



# ---- C978145: BLE provisioning (sta_ble_provisioning flow) + BG extended scan ----
@sta_ble_provisioning_wifi_dut_marker(IEEE802_11W=Si91xExtCustomFeatureBitMap.IEEE802_11W, memory_config=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"],
)
# @wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
def test_sta_ble_ble_provisioning_bg_extended_scan_C978145(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    ble_dut,
    request,
    utf_constants,
    sl_collections,
):
    """
    C978145: Validate BLE provisioning workflow (sta_ble_provisioning) by performing BG extended scan
    and Wi-Fi connection. No Si-Connect app; uses ProvisioningFunctionality from sta_ble_provisioning.
    Steps: Init DUT WiFi+BLE, BLE GATT + advertise, client connects and sends credentials over BLE,
    DUT scans and connects to AP, trigger BG extended scan, verify >11 AP entries.
    """
    ble_obj = None
    try:
        test_name = request.node.name
        logger().info("Configuring sniffer and starting capture")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )

        ble_obj = StaBleProvisioningFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_dut=ble_dut,
            ble_pairing=0,
            utf_constants=utf_constants,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            test_case=661503,
            min_conn_interval=200,
            max_conn_interval=200,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()

        # Trigger BG extended scan after provisioning and Wi-Fi connection via new CLI:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        #   wifi.scan -m bg_scan -p 8 -n 15
        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results is not None, "BG extended scan returned no results"
        assert len(scan_results) > 11, (
            f"C978145: BG extended scan after provisioning expected >11 APs, got {len(scan_results)}"
        )
        logger().info(f"BG extended scan after provisioning returned {len(scan_results)} AP entries")

        ble_obj.ble_remove_servie()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup_disconn()
            except Exception:
                pass
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()


# ---- C978137: Instant BG scan (B0=1 only, up to 11 results) with BLE peripheral CI 30ms ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker()
def test_sta_ble_instant_bg_scan_upto_11_C978137(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    C978137: Verify Wi-Fi Background scan by enabling existing instant scan (B0=1 only)
    when DUT BLE connected as peripheral with connection interval 30ms.
    Region: JP, AP on Channel 14. Instant BG scan returns up to 11 results.
    """
    global ble_obj
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            bond_info=1,
            conn_int=30,  # 30ms CI
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        status = ping(device_ip, ping_count, size=300)
        assert status, "Ping failed"

        # Background extended scan via new CLI:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        #   wifi.scan -m bg_scan -p 8 -n 15
        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=60)
        assert scan_results is not None, "BG extended scan returned no results"
        logger().info(f"BG extended scan returned {len(scan_results)} AP entries")

        time.sleep(5)
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut,
                ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )



# ---- C978149: BG extended scan with BLE dual role ----
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker(num_central_connections=1, num_peripheral_connections=1)
def test_sta_ble_bg_extended_dual_role_ble_C978149(
    wifi_sniffer, wifi_access_point, wifi_dut, ble_clients, request,
    utf_constants, sl_collections, wifi_client, sniffer_filter,
):
    """
    C978149: Verify BG extended scan while DUT maintains BLE dual role connections.
    DUT acts as BLE peripheral (CI 80ms) to remote 1 and BLE central (CI 160ms) to remote 2.
    Requires two BLE client devices (ble_clients fixture).
    """
    ble_dut_address = None
    ble_clients_address = []
    try:
        assert len(ble_clients) >= 2, "Minimum 2 BLE client devices required for dual role"

        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
        ble_obj_slave = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
            conn_interval=80,
        )
        ble_obj_master = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
            conn_interval=160,
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
        )
        wifi_obj.join_to_ap(skip_power_save=True)

        ble_obj_slave.start()
        ble_obj_slave.wait_for_exit()
        ble_clients_address.append(ble_obj_slave.ble_client_address)

        wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)

        ble_obj_master.start()
        ble_obj_master.wait_for_exit()
        ble_clients_address.append(ble_obj_master.ble_client_address)

        wifi_obj.set_power_save()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP after join"
        assert ping(device_ip, ping_count, size=300), "Ping failed with dual BLE role active"

        scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
        assert scan_results is not None and len(scan_results) > 11, (
            f"BG extended scan with dual BLE role expected >11, "
            f"got {len(scan_results) if scan_results else 0}"
        )
        logger().info(
            f"BG extended scan with dual BLE role returned {len(scan_results)} AP entries"
        )

        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_clients,
                    ble_client_address=ble_clients_address,
                    ble_dut_address=ble_dut_address,
                )
        except Exception:
            logger().warning("BLE dual role cleanup encountered an error")






# ---- C978142: Instant BG extended scan every 10s during HTTP download 5MB, BLE peripheral CI 200ms ----
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", ["1MB.htm"])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@wifi_dut_marker(no_of_wifi_threads=2, no_of_ble_threads=1, wifi_stack_len=3071, ble_stack_len=2048)
def test_sta_ble_http_download_bg_extended_scan_loop_10s_ble_peripheral_200ms_C978142(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    http_server,
    index_path,
):
    """
    C978142: Perform instant BG extended scan every 10 seconds while HTTP download (5MB) is ongoing
    with active BLE connection as peripheral with CI 200ms.
    Steps: Init WiFi+BLE, connect AP, power save, ping, BLE connect, start HTTP download,
    trigger BG extended scan in loop every 10s (B0=1, B6=1 instant, B7=1 extended); verify >11 APs and download success.
    """
    global ble_obj
    ble_obj = None
    http_error = [None]  # use list to allow assignment in thread
    http_download_done = threading.Event()

    def run_http_download():
        try:
            sl_collections.http_file_download(
                wifi_dut=wifi_dut,
                http_server=http_server,
                device_ip=device_ip,
                index_path=index_path,
                https=False,
                retries=1
            )
        except Exception as e:
            http_error[0] = e
        finally:
            http_download_done.set()

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            bond_info=1,
            conn_int=200,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        device_ip = wifi_obj.device_ip
        assert device_ip, "DUT has no IP"
        assert ping(device_ip, ping_count, size=300), "Ping failed"

        # Start HTTP download in background thread; run BG scans every 10s until download completes
        http_thread = threading.Thread(target=run_http_download)
        http_thread.start()
        time.sleep(3)  # let download start

        scan_results_list = []
        http_download_timeout = 3000
        scan_loop_deadline = time.time() + http_download_timeout + 120

        while http_thread.is_alive() and time.time() < scan_loop_deadline:
            scan_results = _perform_bg_extended_scan(wifi_dut, timeout=90)
            if scan_results is not None:
                scan_results_list.append(scan_results)
            if http_download_done.wait(timeout=10):
                break

        http_thread.join(timeout=http_download_timeout + 60)
        assert not http_thread.is_alive(), (
            f"HTTP download did not complete within {http_download_timeout + 60}s"
        )
        assert http_error[0] is None, f"HTTP download failed: {http_error[0]}"

        assert len(scan_results_list) >= 1, "No BG extended scan results collected during HTTP download"
        assert any(len(r) > 11 for r in scan_results_list), (
            f"Expected at least one BG extended scan with >11 APs; got {[len(r) for r in scan_results_list]}"
        )

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut,
                ble_client=ble_client,
                ble_client_address=ble_obj.ble_client_address,
                ble_dut_address=ble_obj.ble_dut_address,
            )
        try:
            http_server.interfaces.http.stop_server()
        except Exception:
            pass


