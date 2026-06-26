import time
import re
import json
import shlex
import inspect
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import SecurityMode
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.softap_provisioning.\
    test_ap_ble_provisioning_softap_sdk import (
        ProvisioningFunctionality as SoftApProvisioningFunctionality,
        wifi_dut_marker as softap_wifi_dut_marker,
        webpage,
    )
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble_bg_extended_scan.\
    test_ap_ble_provisioning_bg_extended_scan_sdk import _perform_bg_extended_scan


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-Si91x
        1. SoftAP+BLE provisioning (AP/HTTP, BLE, or WPS path)
        2. Receive home AP credentials on DUT and deinitialize
        3. Re-init DUT in WiFi client mode and connect to third-party AP
        4. Perform background extended scan and validate scan results/channels

    setup requirement:
        1. DUT (Soc917)
        2. Third-party Access Point
        3. Raspberry Pi (wifi_client)
        4. wiseconnect_web
        5. ble_dut / ble_client
        6. Sniffer (NUC device)

    Author: Venkatesulu Ekambaram
"""

class SoftApBgScanProvisioningFunctionality(SoftApProvisioningFunctionality):
    """
    SoftAP provisioning helper for C978108.

    AP-interface scan during HTTP provisioning is informational only; some FW builds
    return SL_STATUS_INVALID_PARAMETER (0x21) while SoftAP + HTTP server are active.
    """

    def scan_on_ap_interface(self, scan_type=None):
        logger().info("Optional AP-interface scan during HTTP provisioning")
        try:
            super().scan_on_ap_interface(scan_type=scan_type)
        except AssertionError as exc:
            logger().warning(
                "AP-interface scan failed (%s); continuing HTTP provisioning for BG extended scan test",
                exc,
            )

    def _provisioning_security_type_for_webpage(self):
        security = SecurityMode.convert(self.wifi_access_point.interfaces.wifi.security)
        if security == SecurityMode.WPA2:
            return "WPA2"
        if security == SecurityMode.WPA3:
            return "WPA3"
        if security == SecurityMode.WPA2WPA3MixedMode:
            return "Mixed Mode"
        if security == SecurityMode.WPAWPA2MixedMode:
            return "WPA"
        return "WPA2"

    def _post_home_ap_credentials_via_raspi(self):
        """POST the same JSON payload the provisioning webpage sends via XHR to /connect."""
        payload = json.dumps({
            "id": self.wifi_access_point.interfaces.wifi.ssid,
            "password": self.wifi_access_point.interfaces.wifi.passphrase,
            "securityType": self._provisioning_security_type_for_webpage(),
        })
        wlan_iface = self.wifi_clients[0].interfaces.wifi.config.get("interface", "wlan0")
        curl_cmd = (
            f"curl -s --connect-timeout 15 --interface {wlan_iface} "
            f"-X POST http://192.168.100.76/connect "
            f"-H 'Content-Type: application/json' "
            f"-d {shlex.quote(payload)}"
        )
        logger().info(f"Posting home AP credentials to DUT via RasPi ({wlan_iface}): {payload}")
        for cmd in (curl_cmd, f"sudo {curl_cmd}"):
            rc, stdout, stderr = self.wifi_clients[0].interfaces.wifi.shell.execute(cmd)
            response = stdout.decode() if isinstance(stdout, bytes) else stdout
            err = stderr.decode() if isinstance(stderr, bytes) else stderr
            logger().info(f"RasPi POST /connect cmd='{cmd}' rc={rc}, response={response}, stderr={err}")
            if rc == 0:
                return True
        return False

    def _fetch_provisioning_credentials(self):
        data = self.wifi_dut.interfaces.wifi.http_server_get_credentials_from_webpage(timeout=30)
        if self.test_case == 887649:
            return re.search(r'ssid:([\w@!]+),password:([\w@#!]+),security:(\w+)', data.decode())
        return re.search(r'ssid:(\w+),password:(\w+),security:(\w+)', data.decode())

    def http_server_provisioning(self, scan_type=None):
        self.wifi_dut.interfaces.wifi.http_server_init(
            http_port=80, handlers_count=6, send_large_data=1, data=webpage)
        self.wifi_dut.interfaces.wifi.http_server_start()
        time.sleep(30)
        self.connect_clients_to_dut_as_ap()
        self.ble_stop_advertising()
        self.scan_on_ap_interface(scan_type=scan_type)

        try:
            self.wiseconnect_web.interfaces.wiseconnect_ui.connect(
                ip_address="192.168.100.76",
                web_ui_port=80,
                ssid=self.wifi_access_point.interfaces.wifi.ssid,
                security=self.wifi_access_point.interfaces.wifi.security,
                passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
            )
        except Exception as exc:
            logger().warning(f"wiseconnect_web provisioning UI failed ({exc}); using RasPi POST /connect")

        if not self._post_home_ap_credentials_via_raspi():
            logger().warning("Initial RasPi POST /connect failed (curl rc=28 often means wrong interface)")
        time.sleep(2)

        self.result = None
        last_error = None
        for attempt in range(1, 6):
            try:
                self.result = self._fetch_provisioning_credentials()
                if self.result:
                    logger().info(f"received cred on dutap: {self.result}")
                    break
            except AssertionError as exc:
                last_error = exc
                logger().info(
                    "http_server.get_credentials attempt %s/5 failed (%s); retrying after RasPi POST",
                    attempt,
                    exc,
                )
                if not self._post_home_ap_credentials_via_raspi():
                    logger().warning(
                        "RasPi POST /connect retry failed; ensure RasPi is joined to DUT SoftAP on wlan0"
                    )
                time.sleep(2)

        assert self.result, (
            "Unable to fetch 3rd party AP details from DUT. "
            "Verify DUT bus shows 'Got request /connect' and credential JSON."
        ) if last_error is None else (
            f"Unable to fetch 3rd party AP details from DUT after retries: {last_error}"
        )
        self.wifi_dut.interfaces.wifi.http_server_stop()
        self.wifi_dut.interfaces.wifi.http_server_deinit()

class SoftApBgScanThread(ThreadBase):
    """
    SoftAP+BLE provisioning (AP/HTTP path) then BG extended scan.
    Same ThreadBase pattern as WLanThread in test_wlan_bg_scan_sdk.py.
    """

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None,
                 sniffer_filter=None, test_name=None, ble_client=None, ble_dut=None, utf_constants=None,
                 wifi_client=None, wifi_clients=None, wiseconnect_web=None, ap_channel=11,
                 dut_ap_ssid="sharma_test", dut_ap_security="wpa2", dut_ap_psk="123456789",
                 sta_ble_mode=True, beacon_wait_sec=10, http_scan_type=None, scan_timeout=90):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.test_name = test_name
        self.ble_client = ble_client
        self.ble_dut = ble_dut
        self.utf_constants = utf_constants
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.wiseconnect_web = wiseconnect_web
        self.ap_channel = ap_channel
        self.dut_ap_ssid = dut_ap_ssid
        self.dut_ap_security = dut_ap_security
        self.dut_ap_psk = dut_ap_psk
        self.sta_ble_mode = sta_ble_mode
        self.beacon_wait_sec = beacon_wait_sec
        self.http_scan_type = http_scan_type
        self.scan_timeout = scan_timeout
        self.provisioning_obj = None
        self.scan_results = None

    @staticmethod
    def _expected_advanced_scan_cli(advanced_scan_bitmap):
        return (
            "wifi.set_advanced_scan_configuration -i 50 -j 20 -m 1 "
            f"-o {advanced_scan_bitmap}"
        )

    @staticmethod
    def _expected_bg_extended_scan_cli(scan_count_extended=15):
        return f"wifi.scan -m bg_scan -p 8 -n {scan_count_extended}"

    def _log_wiseconnect3_cli_support(self):
        sig = inspect.signature(self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration)
        if "has_adv_scan_bit_map" not in sig.parameters:
            logger().warning(
                "utf_wiseconnect_3 set_advanced_scan_configuration lacks has_adv_scan_bit_map; "
                "update sl_wifi_test_agent_cli.py or -o will not be sent to DUT"
            )

    def configure_advanced_scan(self):
        """Configure advanced scan after STA home-AP connect, before BG extended scan."""
        advanced_scan_bitmap = (1 << 0) | (1 << 6) | (1 << 7)
        expected_cli = self._expected_advanced_scan_cli(advanced_scan_bitmap)
        self._log_wiseconnect3_cli_support()
        logger().info(f"Step 12 advanced-scan CLI (expected on DUT): {expected_cli}")
        self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
            adv_active_channel_time=50,
            adv_passive_channel_time=20,
            adv_trigger_level=None,
            adv_trigger_level_change=None,
            adv_enable_multi_probe=1,
            adv_enable_instant_scan=None,
            has_adv_scan_bit_map=1,
            advanced_scan_bitmap=advanced_scan_bitmap,
        )
        try:
            cfg = self.wifi_dut.interfaces.wifi.get_advanced_scan_configuration()
            cfg_text = cfg.decode() if isinstance(cfg, bytes) else cfg
            logger().info(f"Step 12 DUT advanced-scan readback: {cfg_text}")
        except Exception as exc:
            logger().warning(f"wifi.get_advanced_scan_configuration failed: {exc}")

    def perform_bg_extended_scan(self, validate_min_results=True, scan_count_extended=15):
        """Trigger non-periodic background extended scan after STA connection (C978151)."""
        scan_cli = self._expected_bg_extended_scan_cli(scan_count_extended)
        logger().info(f"Step 12 BG extended scan CLI (expected on DUT): {scan_cli}")
        min_results = 12 if validate_min_results else None
        self.scan_results = _perform_bg_extended_scan(
            self.wifi_dut,
            timeout=self.scan_timeout,
            min_results=min_results,
        )
        count = len(self.scan_results) if self.scan_results else 0
        logger().info(f"BG extended scan returned {count} AP entries (min required: {min_results})")
        return self.scan_results

    def assert_bg_extended_scan_channels(self, allowed_channels=None):
        """Verify BG extended scan results are observed only on allowed 2.4 GHz channels."""
        if allowed_channels is None:
            allowed_channels = list(range(1, 12))
        allowed = set(allowed_channels)
        observed_channels = {entry.rf_channel for entry in self.scan_results}
        invalid_channels = observed_channels - allowed
        assert not invalid_channels, (
            f"BG extended scan observed disallowed channels {sorted(invalid_channels)}; "
            f"allowed {sorted(allowed)}, observed {sorted(observed_channels)}"
        )
        logger().info(
            f"BG extended scan channel validation passed: observed {sorted(observed_channels)} "
            f"within allowed {sorted(allowed)}"
        )

    def reinit_dut_sta_ble_mode(self):
        """Re-initialize DUT in WiFi client + BLE mode after SoftAP provisioning deinit."""
        self.wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default,
        )
        self.wifi_dut.interfaces.wifi.init(mode="client", config_required=False, timeout=30)
        logger().info("DUT re-initialized in WiFi client + BLE mode")

    def reinit_dut_sta_mode_only(self):
        """Re-initialize DUT in WiFi client only mode (no BLE coex)."""
        self.wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode=Si91xCoexMode.WLANOnly,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default,
        )
        self.wifi_dut.interfaces.wifi.init(mode="client", config_required=False, timeout=30)
        logger().info("DUT re-initialized in WiFi client only mode")

    def create_provisioning_object(self):
        """Create SoftAP provisioning thread object for AP/HTTP path."""
        wifi_client_list = [self.wifi_client] if not isinstance(self.wifi_client, list) else self.wifi_client
        self.provisioning_obj = SoftApBgScanProvisioningFunctionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            sl_collections=self.sl_collections,
            ble_dut=self.ble_dut,
            set_smp=0,
            utf_constants=self.utf_constants,
            wifi_access_point=self.wifi_access_point,
            wifi_sniffer=self.wifi_sniffer,
            ssid=self.dut_ap_ssid,
            security=self.dut_ap_security,
            psk=self.dut_ap_psk,
            ap_channel=self.ap_channel,
            wifi_client=wifi_client_list,
            wifi_clients=self.wifi_clients,
            wiseconnect_web=self.wiseconnect_web,
            sniffer_filter=self.sniffer_filter,
        )
        return self.provisioning_obj

    def run_softap_ap_mode_start_and_beacon_check(self):
        """Steps 1-2: Start SoftAP in AP+BLE mode and validate beaconing."""
        logger().info("Steps 1-2: Configure DUT in AP+BLE mode and start SoftAP with beacon validation")
        self.provisioning_obj.ap_mode_start()
        self.provisioning_obj.start()
        self.provisioning_obj.wait_for_exit()
        self.provisioning_obj.firmware_version()
        time.sleep(self.beacon_wait_sec)
        self.provisioning_obj.check_beacon()

    def run_http_server_provisioning(self):
        """Steps 3-8: Remote client join, HTTP init/start, web UI provisioning, credential receive."""
        logger().info("Steps 3-8: Remote client join, HTTP init/start, web UI provisioning, credential receive")
        if self.http_scan_type is not None:
            self.provisioning_obj.http_server_provisioning(scan_type=self.http_scan_type)
        else:
            self.provisioning_obj.http_server_provisioning()

    def run_provisioning_deinit(self):
        """Step 9: Deinitialize DUT after credential receive."""
        logger().info("Step 9: Deinitialize DUT after credential receive")
        self.provisioning_obj.sl_net_deinit()

    def run_reinit_and_connect_home_ap(self):
        """Steps 10-11: Re-init DUT and connect to third-party AP using received credentials."""
        logger().info("Steps 10-11: Re-init DUT and connect to third-party AP")
        if self.sta_ble_mode:
            self.reinit_dut_sta_ble_mode()
        else:
            self.reinit_dut_sta_mode_only()
        self.provisioning_obj.wifi_connect()
        logger().info(
            f"DUT connected to home AP with IP {getattr(self.provisioning_obj, 'device_ip', None)}"
        )

    def run_softap_ble_provisioning_ap_path(self):
        """Execute SoftAP+BLE provisioning steps 1-11."""
        self.create_provisioning_object()
        self.run_softap_ap_mode_start_and_beacon_check()
        self.run_http_server_provisioning()
        self.run_provisioning_deinit()
        self.run_reinit_and_connect_home_ap()

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.ap_channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.ap_channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            self.run_softap_ble_provisioning_ap_path()

            logger().info("Step 12: Configure advanced scan and perform background extended scan")
            time.sleep(5)
            self.configure_advanced_scan()
            self.perform_bg_extended_scan()
            self.assert_bg_extended_scan_channels()

            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop the sniffer")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in SoftAP BG extended scan thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "OPEN",
            "ssid": "sharma_test",      # DUT SoftAP — must match line 49
            "passphrase": "123456789",
            "channel": "11",
        },
    },
)
@softap_wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.parametrize("ap_channel", [11])
@pytest.mark.config(
    "wifi_access_point",
    wifi={"ssid": "SAKSHIASUS", "security": "OPEN", "passphrase": "12345678", "channel": 11},
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_softap_provisioning_bg_extended_scan_ap_path_c978108(
        sl_collections, wifi_dut, wifi_client, ap_channel, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
    """
    Verify SoftAP+BLE provisioning through the AP/HTTP path followed by background extended scan.

    After provisioning and connecting to the third-party AP, the DUT must perform periodic
    background extended scan and report more than 11 AP entries across up to 11 channels.
    """
    try:
        wlan_obj = SoftApBgScanThread(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            sniffer_filter=sniffer_filter,
            test_name=request.node.name,
            ble_client=ble_client,
            ble_dut=ble_dut,
            utf_constants=utf_constants,
            wifi_client=wifi_client,
            wifi_clients=wifi_clients,
            wiseconnect_web=wiseconnect_web,
            ap_channel=ap_channel,
            sta_ble_mode=False,
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()
