# IOTREQ-12128: Extended BG scan after SoftAP+BLE provisioning (C978150, C978151, C978152)
# Reference: test_ap_ble_provisioning_ble_set1_sdk.py, test_ap_ble_provisioning_ble_set3_sdk.py
# Test plan: IOT_REQ/STA_BG_Extended_Scan.csv

import time
import pytest
from utf.utils.logger import get_logger

from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.ap_ble_provisioning.test_ap_ble_provisioning_ble_set1_sdk import (
    ProvisioningFunctionality as ProvisioningFunctionalityBle,
    wifi_dut_marker as wifi_dut_marker_set1,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.ap_ble_provisioning.test_ap_ble_provisioning_ble_set3_sdk import (
    ProvisioningFunctionality as ProvisioningFunctionalityAp,
    wifi_dut_marker as wifi_dut_marker_set3,
)
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
)


def logger():
    return get_logger(__name__)


def _configure_advanced_scan(wifi_dut):
    """
    Issue the advanced-scan configuration CLI exactly as:
        wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
            (Instant scan: Enabled, Non-periodic scan: Enabled, Extended results: Enabled)

    This MUST be invoked before any wifi.scan or wifi connect/join command so the
    test agent has the extended scan parameters in place beforehand.
    All other CLI flags are passed as None so the agent receives exactly the
    documented command line.
    """
    wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
        adv_active_channel_time=50,
        adv_passive_channel_time=None,
        adv_trigger_level=None,
        adv_trigger_level_change=None,
        adv_enable_multi_probe=1,
        adv_enable_instant_scan=None,
        has_adv_scan_bit_map=1,
        advanced_scan_bitmap=None,
    )


def _perform_bg_extended_scan(wifi_dut, timeout=90, min_results=12):
    """
    Trigger the background extended scan using the new test-agent CLI form:
        wifi.scan -m bg_scan -p 8 -n 15
            (bg_scan, scan_type=SL_WIFI_SCAN_TYPE_EXTENDED(8), scan_count_extended=15)

    NOTE: Callers must have already invoked ``_configure_advanced_scan(wifi_dut)``
    earlier in the test (before scan/connect) so the advanced-scan configuration
    is in effect on the DUT.

    Asserts that at least ``min_results`` entries are returned when ``min_results``
    is not None; pass ``min_results=None`` to skip the count check.
    """
    scan_results = wifi_dut.interfaces.wifi.scan(
        ssid=None,
        bgscan=True,
        scan_type=8,
        scan_count_extended=15,
        timeout=timeout,
    )
    if min_results is not None:
        count = len(scan_results) if scan_results else 0
        assert scan_results is not None and count >= min_results, (
            f"BG extended scan expected >={min_results} APs, got {count}"
        )
    return scan_results


# ---- C978150: BLE path - Extended BG scan after BLE provisioning (periodic, B6=1) ----
@wifi_dut_marker_set1(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_ap_ble_provisioning_ble_path_bg_extended_scan_C978150(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """C978150: Verify extended BG scan after SoftAP+BLE provisioning through BLE path (periodic, B6=1, B7=1)."""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        # Configure advanced-scan settings BEFORE any scan or AP connect/join:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        _configure_advanced_scan(wifi_dut)

        ble_obj = ProvisioningFunctionalityBle(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter, min_conn_interval=200, max_conn_interval=200)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj.beacon_stop = 1
        ble_obj.ap_mode_start()
        ap_started = True
        time.sleep(10)
        ble_obj.check_no_beacon()
        ble_obj.scan_on_ap_interface()
        ble_obj.credentials_send_over_ble()
        ble_obj.sl_net_deinit()
        ap_started = False

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode=Si91xCoexMode.WLANOnly,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False, timeout=30)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        # C978150: Perform extended BG scan via new CLI:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        #   wifi.scan -m bg_scan -p 8 -n 15
        _perform_bg_extended_scan(wifi_dut, timeout=90, min_results=12)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started and ble_obj is not None:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")


# ---- C978151: AP path - Extended BG scan after AP provisioning (non-periodic, B6=1) ----
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker_set3(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_ap_ble_provisioning_ap_path_bg_extended_scan_C978151(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter, ap_channel):
    """C978151: Verify extended BG scan after SoftAP+BLE provisioning through AP path (non-periodic, B6=1, B7=1)."""

    try:
        test_name = request.node.name
        wifi_client_list = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        # Configure advanced-scan settings BEFORE any scan or AP connect/join:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        _configure_advanced_scan(wifi_dut)

        ble_obj = ProvisioningFunctionalityAp(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client_list,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter, adv_int=160)

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_provisioning()
        ble_obj.sl_net_deinit()

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

        # C978151: Perform extended BG scan via new CLI:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        #   wifi.scan -m bg_scan -p 8 -n 15
        _perform_bg_extended_scan(wifi_dut, timeout=90, min_results=12)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
        raise


# ---- C978152: WPS path - Extended BG scan after WPS connection (periodic, B6=0) ----
@wifi_dut_marker_set1(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_ap_ble_provisioning_wps_path_bg_extended_scan_C978152(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants,
        sniffer_filter):
    """C978152: Verify extended BG scan after SoftAP+BLE provisioning through WPS path (periodic B6=0, B7=1)."""

    ble_obj = None
    ap_started = False
    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        # Configure advanced-scan settings BEFORE any scan or AP connect/join:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        _configure_advanced_scan(wifi_dut)

        ble_obj = ProvisioningFunctionalityBle(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter, min_conn_interval=200, max_conn_interval=200)

        ble_obj.ap_mode_start()
        ble_obj.start_http_server()
        ap_started = True
        time.sleep(10)
        ble_obj.check_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        ble_obj.firmware_version()
        ble_obj.stop_http_server()
        ble_obj.stop_ap_interface()
        ap_started = False
        ble_obj.sl_net_deinit()

        # Re-init as STA and connect via WPS (WPS path - no BLE/HTTP credential send)
        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode=Si91xCoexMode.WLANOnly,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False, timeout=30)

        from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_wps_sdk import (
            join_to_wifi_network_via_wps,
        )
        wps_result = join_to_wifi_network_via_wps(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            power_save=False,
            ping_after_power_save=False,
            ping_before_power_save=True,
            associated=False,
            sl_collections=sl_collections,
        )
        assert wps_result is not None and wps_result.get("device_ip"), "WPS connection failed"

        # C978152: Perform extended BG scan via new CLI:
        #   wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
        #   wifi.scan -m bg_scan -p 8 -n 15
        _perform_bg_extended_scan(wifi_dut, timeout=90, min_results=12)

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()
        try:
            if ap_started and ble_obj is not None:
                logger().warning("AP mode active during exception, stopping it...")
                ble_obj.sl_net_deinit()
        except Exception as cleanup_ex:
            logger().error(f"Cleanup failed: {cleanup_ex}")
