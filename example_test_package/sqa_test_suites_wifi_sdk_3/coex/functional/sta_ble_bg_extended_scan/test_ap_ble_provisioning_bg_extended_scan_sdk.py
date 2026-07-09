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

from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.ap_ble_provisioning.test_ap_ble_provisioning_wps_pbc_sdk import ProvisioningFunctionality
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xOperatingMode

"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. set scan ,connect, data transfer


    Author: Swathi.Chinthala
"""

def logger():
    return get_logger(__name__)


def _configure_advanced_scan(wifi_dut):
    """
    Issue the advanced-scan configuration CLI exactly as:
        wifi.set_advanced_scan_configuration -i 50 -m 1 -o 1
            (Instant scan: Enabled, Non-periodic scan: Enabled, Extended results: Enabled)

    Must be applied only before the extended BG scan (wifi.scan -m bg_scan -p 8 -n 15),
    not during SoftAP provisioning. Applying it earlier breaks wifi.scan -i ap on the
    AP interface (SL_STATUS_INVALID_PARAMETER).
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

    Asserts that at least ``min_results`` entries are returned when ``min_results``
    is not None; pass ``min_results=None`` to skip the count check.
    """
    _configure_advanced_scan(wifi_dut)
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
                    wifi={"ssid": 'sw_test', "security": 'WPA2', "passphrase": '123456789', "channel": 8})
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

        # Match c887610: join in WLANOnly mode. WLAN+BLE coex during join causes
        # SL_STATUS_SI91X_AUTHENTICATION_TIMEOUT while BLE is still connected.
        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode=Si91xCoexMode.WLANOnly,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default,
        )
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False, timeout=30)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()

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




@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
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
@pytest.mark.end_state("wifi_dut", wifi=["reset"])
def test_ap_ble_provisioning_ap_path_bg_extended_scan_C978151(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter, ap_channel):

    """Verify Soft AP provisioning in WPA2 security and also check WLAN connection to the third party home AP with the
    received credentials on APUT."""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
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
            coex_mode=Si91xCoexMode.WLANOnly,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default)
        wifi_dut.interfaces.wifi.init(mode="client", config_required=True)
        wifi_dut.interfaces.wifi.scan()
        ble_obj.wifi_connect()
        _perform_bg_extended_scan(wifi_dut, timeout=90, min_results=12)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)

    # finally:
    #     wifi_dut.interfaces.wifi.reset()



def wifi_dut_marker(IEEE802_11W=0, memory_config=0, OpenMode=0):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator..
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072},
                          "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT | OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.NWP120MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | IEEE802_11W | memory_config
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    }
    return pytest.mark.config("wifi_dut", wifi=config)

@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "channel": "11",
        },
    }
)
@wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sharma123', "security": 'WPA2', "passphrase": '123456789', "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["sl_net_deinit_client"])
def test_ap_ble_provisioning_wps_path_bg_extended_scan_C978152(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter, ap_channel):
    """Verify DUT behavior with WPS path flow"""

    try:
        test_name = request.node.name
        wifi_client = [wifi_client]

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, set_smp=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            ssid='sharma_test', security='wpa2', psk='123456789', ap_channel=ap_channel, wifi_client=wifi_client,
            wifi_clients=wifi_clients, wiseconnect_web=wiseconnect_web, sniffer_filter=sniffer_filter, adv_int=160,
            associated=False, skip_scan=False, tcp_ip_bypass=False, ip_config_disable=False
        )

        ble_obj.ap_mode_start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        time.sleep(10)
        ble_obj.check_beacon()
        ble_obj.http_server_start()

        """ **** WPS Button press code - Workaround for WPS web configuration **** """
        logger().info(" ====== WPS button pressed and interrupt occurred and fallback to STA mode ====== ")

        ble_obj.stop_ap_interface()
        ble_obj.ble_stop_advertising()
        ble_obj.http_server_stop()

        ble_obj.sl_net_deinit()
        time.sleep(5)

        wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=0,
            coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            features=Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                     Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default | 0,
            ext_tcpip_features=Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                               | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                               | 0,
            custom_features=Si91xCustomFeatureBitMap.NWP120MHz
                            | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            ext_custom_features=Si91xExtCustomFeatureBitMap.Default
                                | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                                | 0,
            bt_features=Si91xBTFeatureBitMap.Default,
            ble_features=Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=1)
                         | Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=1)
                         | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
                         | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
                         | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
                         | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
                         | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
                         | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
                         | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            ble_custom_ext_features=Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                    | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                    | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            config_features=Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                            | Si91xConfigFeatureBitMap.EnahanceMaxPsp
        )

        time.sleep(5)

        # Use net.init to properly apply the wifi.set_config settings
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="client", config_required=False)

        # -------------------- WPS join (auto-connect ENABLED) --------------------
        logger().info("Starting WPS process with Auto Connect Enabled")
        wps_result = ble_obj.join_to_wifi_network_via_wps()
        logger().info(wps_result)
        _perform_bg_extended_scan(wifi_dut, timeout=90, min_results=12)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()




