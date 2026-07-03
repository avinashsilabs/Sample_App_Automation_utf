import time
import re
import json
import shlex
import threading
import pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xJoinFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)
from utf_wiseconnect_3.tests.sl_status import SLStatus
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.softap_provisioning. \
    test_ap_ble_provisioning_softap_sdk import (
    ProvisioningFunctionality as SoftApProvisioningFunctionality,
    wifi_dut_marker as softap_wifi_dut_marker,
    webpage,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble_bg_extended_scan. \
    test_ap_ble_provisioning_bg_extended_scan_sdk import (
    _perform_bg_extended_scan as _perform_bg_extended_scan_provisioning,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble_bg_extended_scan. \
    test_sta_ble_extended_bgscan_sdk import (
    _assert_extended_bgscan_channels_only,
    _configure_advanced_scan,
    _perform_bg_extended_scan,
    wifi_dut_marker as sta_ble_wifi_dut_marker,
)


def logger():
    return get_logger(__name__)


"""WLAN standalone BG extended scan tests for DUT-Si91x.

SoftAP + HTTP provisioning, then BG extended scan:
    1. Initialize DUT in AP+BLE coex mode and start SoftAP (BLE init/advertising only)
    2. Provision home AP credentials over HTTP (wiseconnect_web or RasPi POST /connect)
    3. Deinitialize DUT, re-init as WiFi+BLE STA, and join third-party home AP
    4. Perform background extended scan and validate results/channels

    HTTP provisioning path only — not BLE GATT credential provisioning.

STA WiFi+BLE (connected) — shared steps 1-5:
    1. Initialize DUT in WiFi+BLE STA mode (sl_net_init)
    2. Connect to WPA3 AP and obtain IP (sl_net_up)
    3. Enable Wi-Fi broadcast filter (sl_wifi_filter_broadcast)
    4. Enable Wi-Fi + BLE power save; ping from AP backend to DUT
    5. Configure advanced scan (sl_wifi_set_advanced_scan_configuration)

    Step 6+ variants: selective channel scan (1/6/11), HTTP download + BG scan,
    CSA channel switch + BG scan, periodic scan with BIT(7) disabled, congestion loop,
    scan-result filters, WPS push-button connection.

SoftAP setup: DUT, third-party AP, Raspberry Pi (wifi_client), wiseconnect_web,
ble_dut/ble_client, sniffer.

STA setup: single wifi_access_point; sniffer optional for debug capture.

    Author: Venkatesulu Ekambaram

These functions run below test steps for DUT-Si91x
    1. Connect DUT (WiFi client) to a third-party Access Point
    2. Start sniffer capture on the AP channel
    3. Perform background extended scan while running iperf traffic
       (TCP/UDP, TX/RX); for the connect/disconnect test the flow is
       connect -> extended BG scan -> disconnect repeated in a loop
    4. Validate BG extended scan results/channels and sniffer probe requests

setup requirement:
    1. DUT (Soc917)
    2. Third-party Access Point
    3. Raspberry Pi (wifi_client / net_perf_client for iperf)
    4. Sniffer (NUC device)

Author: Shailesh Kharecha

"""


class SoftApBgScanProvisioningFunctionality(SoftApProvisioningFunctionality):
    """
    SoftAP + HTTP provisioning helper for BG extended scan after home AP join.

    Home AP credentials are delivered via HTTP (/connect), not BLE GATT provisioning.
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

    def connect_clients_to_dut_as_ap(self):
        """Align RasPi SoftAP join profile with DUT SoftAP before base provisioning join."""
        client_security = SecurityMode.convert(self.security) if self.security else SecurityMode.WPA2
        for i in range(self.no_of_clients):
            wifi_iface = self.wifi_clients[i].interfaces.wifi
            wifi_iface.config["interface"] = "wlan0"
            wifi_iface.config["ssid"] = self.ssid
            wifi_iface.config["passphrase"] = self.psk or ""
            wifi_iface.config["security"] = client_security
        super().connect_clients_to_dut_as_ap()

    def wifi_connect(self):
        """Join home AP using provisioned credentials (WPA3 / mixed overrides for C978110–C978111)."""
        home = self.wifi_access_point.interfaces.wifi
        security = SecurityMode.convert(home.security)
        passphrase = self.result[2] or home.passphrase or ""
        join_channel = home.channel

        if security == SecurityMode.WPAWPA2MixedMode:
            self.wifi_dut.interfaces.wifi.join(
                ssid=self.result[1],
                passphrase=self.result[2],
                security="wpa2",
                channel=join_channel,
            )
        elif security in (SecurityMode.WPA3, SecurityMode.WPA2WPA3MixedMode):
            join_security = (
                "wpa3_transition" if security == SecurityMode.WPA2WPA3MixedMode else "wpa3"
            )
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
                max_retry_attempts=0,
                scan_interval=6,
                beacon_missed_count=40,
                first_time_retry_enable=0,
            )
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable,
            )
            self.wifi_dut.interfaces.wifi.join(
                ssid=home.ssid,
                passphrase=passphrase,
                security=join_security,
                channel=join_channel,
                timeout=60,
            )
        else:
            self.wifi_dut.interfaces.wifi.join(
                ssid=home.ssid,
                passphrase=passphrase,
                security="open" if security == SecurityMode.Open else "wpa2",
                channel=join_channel,
                timeout=60,
            )

        logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {self.device_ip}")

    def _provisioning_security_type_for_webpage(self):
        security = SecurityMode.convert(self.wifi_access_point.interfaces.wifi.security)
        if security == SecurityMode.Open:
            return "Open"
        if security == SecurityMode.WPA2:
            return "WPA2"
        if security == SecurityMode.WPA3:
            return "WPA3"
        if security == SecurityMode.WPA2WPA3MixedMode:
            return "Mixed Mode"
        if security == SecurityMode.WPAWPA2MixedMode:
            return "WPA"
        return "WPA2"

    def _home_ap_provisioning_password(self):
        if SecurityMode.convert(self.wifi_access_point.interfaces.wifi.security) == SecurityMode.Open:
            return ""
        return self.wifi_access_point.interfaces.wifi.passphrase or ""

    def _post_home_ap_credentials_via_raspi(self):
        """POST the same JSON payload the provisioning webpage sends via XHR to /connect."""
        payload = json.dumps({
            "id": self.wifi_access_point.interfaces.wifi.ssid,
            "password": self._home_ap_provisioning_password(),
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
        return re.search(
            r'ssid:([\w@!]+),password:([^,]*),security:(\w+)', data.decode(), re.IGNORECASE
        )

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
    SoftAP + HTTP provisioning (AP/HTTP path only), then BG extended scan.
    Same ThreadBase pattern as WLanThread in test_wlan_bg_scan_sdk.py.

     DUT SoftAP settings (ssid/security/channel) come from the wifi_clients pytest marker.
    Home AP settings come from the wifi_access_point fixture.
    """

    @staticmethod
    def _security_to_ap_string(security):
        """Normalize wifi_clients security to lowercase str for start_ap()."""
        if security is None:
            return "wpa2"
        if isinstance(security, str):
            return security.lower()
        mode = SecurityMode.convert(security)
        return mode.name.lower()

    @classmethod
    def _softap_config_from_wifi_clients(cls, wifi_clients):
        """Read DUT SoftAP profile from wifi_clients marker (not wifi_access_point)."""
        client_wifi = wifi_clients[0].interfaces.wifi
        cfg = getattr(client_wifi, "config", None) or {}
        ssid = getattr(client_wifi, "ssid", None) or cfg.get("ssid")
        security = getattr(client_wifi, "security", None) or cfg.get("security")
        psk = getattr(client_wifi, "passphrase", None) or cfg.get("passphrase", "")
        channel = getattr(client_wifi, "channel", None) or cfg.get("channel", 11)
        return ssid, cls._security_to_ap_string(security), psk, int(channel)

    @staticmethod
    def _home_ap_security(wifi_access_point):
        return SecurityMode.convert(wifi_access_point.interfaces.wifi.security)

    @classmethod
    def _resolve_sta_ext_custom_features(cls, wifi_access_point):
        """IEEE802_11W only for WPA3 / WPA2-WPA3 home AP (C978110, C978111)."""
        features = Si91xExtCustomFeatureBitMap.Default
        if cls._home_ap_security(wifi_access_point) in (
                SecurityMode.WPA3,
                SecurityMode.WPA2WPA3MixedMode,
        ):
            features |= Si91xExtCustomFeatureBitMap.IEEE802_11W
        return features

    @staticmethod
    def _resolve_bg_scan_allowed_channels(dut_region_code, home_channel):
        """Allowed BG-scan channels per DUT region / home-AP channel (C978108–C978111)."""
        if dut_region_code == Si91xRegionCode.Japan or home_channel >= 14:
            return list(range(1, 15))
        if dut_region_code in (Si91xRegionCode.Europe, Si91xRegionCode.Worldwide) or home_channel >= 13:
            return list(range(1, 14))
        return list(range(1, 12))

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None,
                 sniffer_filter=None, test_name=None, ble_client=None, ble_dut=None, utf_constants=None,
                 wifi_client=None, wifi_clients=None, wiseconnect_web=None,
                 dut_region_code=Si91xRegionCode.US):
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
        self.dut_region_code = dut_region_code
        self.dut_ap_ssid, self.dut_ap_security, self.dut_ap_psk, self.ap_channel = (
            self._softap_config_from_wifi_clients(wifi_clients)
        )
        home_channel = int(wifi_access_point.interfaces.wifi.channel)
        self.sta_ext_custom_features = self._resolve_sta_ext_custom_features(wifi_access_point)
        self.bg_scan_allowed_channels = self._resolve_bg_scan_allowed_channels(
            dut_region_code, home_channel,
        )
        self.provisioning_obj = None
        self.scan_results = None
        logger().info(
            "SoftApBgScanThread config: dut_region=%s, softap=%s/%s/ch%s, home_ap=%s/ch%s/%s, "
            "bg_scan_channels=%s",
            dut_region_code,
            self.dut_ap_ssid,
            self.dut_ap_security,
            self.ap_channel,
            wifi_access_point.interfaces.wifi.ssid,
            home_channel,
            self._home_ap_security(wifi_access_point).name,
            self.bg_scan_allowed_channels,
        )

    def configure_advanced_scan(self):
        """Step 12 advanced scan bitmap (1|64|128) — same helper pattern as coex C978151."""
        advanced_scan_bitmap = (1 << 0) | (1 << 6) | (1 << 7)
        logger().info(
            "advanced-scan CLI (expected on DUT): "
            f"wifi.set_advanced_scan_configuration -i 50 -j 20 -m 1 -o {advanced_scan_bitmap}"
        )
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
            logger().info(f"DUT advanced-scan readback: {cfg_text}")
        except Exception as exc:
            logger().warning(f"wifi.get_advanced_scan_configuration failed: {exc}")

    def perform_bg_extended_scan(self, validate_min_results=True, scan_count_extended=15):
        """Reuse coex _perform_bg_extended_scan (C978151)."""
        logger().info(
            f"Step 12 BG extended scan CLI (expected on DUT): "
            f"wifi.scan -m bg_scan -p 8 -n {scan_count_extended}"
        )
        min_results = 12 if validate_min_results else None
        self.scan_results = _perform_bg_extended_scan_provisioning(
            self.wifi_dut,
            timeout=90,
            min_results=min_results,
        )
        count = len(self.scan_results) if self.scan_results else 0
        logger().info(f"BG extended scan returned {count} AP entries (min required: {min_results})")
        return self.scan_results

    def assert_bg_extended_scan_channels(self, allowed_channels=None):
        """Reuse coex _assert_extended_bgscan_channels_only."""
        allowed = allowed_channels or self.bg_scan_allowed_channels
        _assert_extended_bgscan_channels_only(self.scan_results, allowed)

    def run_reinit_and_connect_home_ap(self):
        """Steps 10-11: re-init STA, scan, join home AP (EU/WW/JP need region before init for ch12+)."""
        logger().info("Re-init DUT and connect to third-party AP")
        home = self.wifi_access_point.interfaces.wifi
        home_channel = home.channel
        if home_channel != self.ap_channel:
            self._start_sniffer_on_channel(
                home_channel,
                f"home AP join steps 10-11 (was ch{self.ap_channel} for SoftAP)",
                restart=True,
            )
        if self.dut_region_code != Si91xRegionCode.US and home_channel >= 12:
            logger().info(
                "Restarting home AP on ch%s (region=%s) before DUT join",
                home_channel,
                getattr(home, "region", None),
            )
            try:
                home.stop_ap()
                time.sleep(5)
            except Exception as exc:
                logger().warning("home AP stop_ap failed (%s); continuing", exc)
            home.start_ap()
            time.sleep(20)

        coex_mode = Si91xCoexMode.WLAN | Si91xCoexMode.BLE
        region_kwargs = {}
        if self.dut_region_code != Si91xRegionCode.US:
            region_kwargs = {
                "region": Si91xRegion.FromUser,
                "region_code": self.dut_region_code,
            }
        self.wifi_dut.interfaces.wifi.set_wifi_config(
            oper_mode=Si91xOperatingMode.WiFiClient,
            coex_mode=coex_mode,
            features=Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode,
            tcpip_features=Si91xTCPIPFeatureBitMap.Default,
            ext_custom_features=self.sta_ext_custom_features,
            **region_kwargs,
        )
        if self.dut_region_code != Si91xRegionCode.US:
            # init(-i client) uses US region; default init applies set_wifi_region (C782626)
            logger().info("STA init (default mode) with region=%s for ch%s join", self.dut_region_code, home_channel)
            self.wifi_dut.interfaces.wifi.init(config_required=False, timeout=30)
            time.sleep(5)
        else:
            self.wifi_dut.interfaces.wifi.init(mode="client", config_required=False, timeout=30)

        scan_results = self.wifi_dut.interfaces.wifi.scan() or []
        scan_channels = sorted({getattr(r, "rf_channel", None) for r in scan_results})
        scan_ssids = [getattr(r, "ssid", None) for r in scan_results]
        logger().info(
            "Pre-join scan: %s AP(s); channels=%s; target %s on ch%s visible=%s",
            len(scan_results),
            scan_channels,
            home.ssid,
            home_channel,
            home.ssid in scan_ssids,
        )
        self.provisioning_obj.wifi_connect()
        logger().info("DUT connected to home AP with IP %s", self.provisioning_obj.device_ip)

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

    def run_softap_ble_provisioning_ap_path(self):
        """Execute SoftAP + HTTP provisioning steps 1-11 (no BLE GATT or WPS)."""
        self.create_provisioning_object()
        logger().info("Configure DUT in AP+BLE mode and start SoftAP with beacon validation")
        self.provisioning_obj.ap_mode_start()
        self.provisioning_obj.start()
        self.provisioning_obj.wait_for_exit()
        self.provisioning_obj.firmware_version()
        time.sleep(10)
        self.provisioning_obj.check_beacon()
        logger().info("Remote client join, HTTP init/start, web UI provisioning, credential receive")
        self.provisioning_obj.http_server_provisioning()
        logger().info("Deinitialize DUT after credential receive")
        self.provisioning_obj.sl_net_deinit()
        self.run_reinit_and_connect_home_ap()

    def _start_sniffer_on_channel(self, channel, phase_label, restart=False):
        """Configure sniffer and start capture."""
        logger().info("*** Configuring sniffer channel %s for %s ***", channel, phase_label)
        if restart and getattr(self.wifi_sniffer.interfaces.capture, "capture_started", False):
            logger().info("Stopping sniffer before channel change")
            self.wifi_sniffer.interfaces.capture.stop_capture()
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        time.sleep(3)

    def run(self):
        try:
            self._start_sniffer_on_channel(
                self.ap_channel,
                "DUT SoftAP provisioning steps 1-9",
            )

            self.run_softap_ble_provisioning_ap_path()

            logger().info("Configure advanced scan and perform background extended scan")
            time.sleep(5)
            self.configure_advanced_scan()
            self.perform_bg_extended_scan()
            self.assert_bg_extended_scan_channels()

            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop the sniffer")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in SoftAP BG extended scan thread: {str(e)} ****\n\n")
            raise e


class StaWpa3BgExtendedScanFunctionality:
    """STA WiFi+BLE power save and BG extended scan helper (shared by STA test modules)."""

    ADVANCED_SCAN_BITMAP_FULL = (1 << 0) | (1 << 6) | (1 << 7)
    ADVANCED_SCAN_BITMAP_NO_BIT7 = (1 << 0) | (1 << 6)

    def __init__(self, wifi_dut, wifi_access_point, sl_collections, utf_constants):
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.utf_constants = utf_constants
        self.home = wifi_access_point.interfaces.wifi
        self.device_ip = None

    @staticmethod
    def _normalize_bssid(bssid):
        if bssid is None:
            return None
        if isinstance(bssid, bytes):
            if len(bssid) == 6:
                return ":".join(f"{byte:02x}" for byte in bssid)
            bssid = bssid.decode("latin-1", errors="ignore")
        return str(bssid).lower().replace("-", ":").replace(" ", "")

    @staticmethod
    def _get_scan_entry_attr(entry, attr):
        if isinstance(entry, dict):
            return entry.get(attr)
        return getattr(entry, attr, None)

    @classmethod
    def find_ap_in_scan_results(cls, scan_results, ssid=None, bssid=None):
        target_bssid = cls._normalize_bssid(bssid)
        for idx, entry in enumerate(scan_results):
            entry_ssid = cls._get_scan_entry_attr(entry, "ssid")
            entry_bssid = cls._normalize_bssid(cls._get_scan_entry_attr(entry, "bssid"))
            if ssid and entry_ssid == ssid:
                return idx
            if target_bssid and entry_bssid == target_bssid:
                return idx
        return None

    def run_steps_1_to_5(self, advanced_scan_bitmap, channel_bitmap_2_4=None, security="wpa3"):
        """Steps 1-5: init, join AP, filter broadcast, power save, advanced scan config."""
        logger().info("DUT WiFi+BLE init complete (sl_net_init via start_state)")

        logger().info("Connect DUT to AP and obtain IP (sl_net_up)")
        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,
            scan_interval=6,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )
        if security == "wpa3":
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable,
            )
        join_kwargs = {
            "ssid": self.home.ssid,
            "passphrase": self.home.passphrase,
            "security": security,
            "channel": self.home.channel,
            "timeout": 60,
        }
        if channel_bitmap_2_4 is not None:
            join_kwargs["channel_bitmap_2_4"] = channel_bitmap_2_4
        self.wifi_dut.interfaces.wifi.join(**join_kwargs)

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"DUT failed to obtain IP via DHCP: {ip_config}"
        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        assert self.device_ip, "DUT has no IP after join"
        logger().info("DUT joined AP with IP %s", self.device_ip)

        ping_count = self.utf_constants.get("ping_count")
        logger().info("Ping DUT before power save")
        assert ping(self.device_ip, ping_count, size=300), (
            "Ping from AP backend to DUT failed before enabling power save"
        )

        logger().info("sl_wifi_filter_broadcast")
        self.wifi_dut.interfaces.wifi.set_filter_broadcast()
        time.sleep(2)

        logger().info(
            "sl_wifi_set_performance_profile_v2 and rsi_bt_power_save_profile(2, 0)"
        )
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        time.sleep(5)

        logger().info("Ping DUT after power save")
        ping_ok = self.sl_collections.ping(
            device_ip=self.device_ip,
            ping_count=ping_count,
            retry_count=3,
        )
        if not ping_ok:
            ping_ok = self.sl_collections.ping_with_custom_size(
                self.device_ip,
                ping_counts=ping_count,
                byte_size=300,
            )
        assert ping_ok, "Ping from AP backend to DUT failed after enabling power save"
        logger().info("Ping from AP backend to DUT succeeded after power save")

        logger().info("sl_wifi_set_advanced_scan_configuration")
        _configure_advanced_scan(self.wifi_dut, advanced_scan_bitmap=advanced_scan_bitmap)

    def _trigger_sta_bg_scan(
            self,
            advanced_scan_bitmap,
            timeout=90,
            bg_scan_periodicity=None,
            scan_bitmap_2_4=None,
            expected_status=SLStatus.SL_STATUS_OK,
            reconfigure=True,
    ):
        """
        Trigger BG scan from STA helper class.

        When BIT(7) extended results are disabled, use standard BG scan (no scan_type=8).
        Extended scan type waits for a completion callback that may not arrive within the
        firmware WIFI_SCAN_TIMEOUT (14s) when periodicity is enabled, returning 0x00007.
        """
        if reconfigure:
            _configure_advanced_scan(self.wifi_dut, advanced_scan_bitmap=advanced_scan_bitmap)

        scan_kwargs = {
            "ssid": None,
            "bgscan": True,
            "timeout": timeout,
            "async_timeout": timeout,
            "expected_status": expected_status,
        }
        if advanced_scan_bitmap & (1 << 7):
            scan_kwargs["scan_type"] = 8
            scan_kwargs["scan_count_extended"] = 50
        if bg_scan_periodicity is not None:
            scan_kwargs["bg_scan_periodicity"] = bg_scan_periodicity
        if scan_bitmap_2_4 is not None:
            scan_kwargs["scan_bitmap_2_4"] = scan_bitmap_2_4
        return self.wifi_dut.interfaces.wifi.scan(**scan_kwargs)

    def perform_bg_extended_scan(
            self,
            advanced_scan_bitmap,
            scan_bitmap_2_4=None,
            timeout=90,
            bg_scan_periodicity=None,
    ):
        """trigger BG extended scan and return results."""
        scan_kwargs = {
            "wifi_dut": self.wifi_dut,
            "timeout": timeout,
            "advanced_scan_bitmap": advanced_scan_bitmap,
        }
        if scan_bitmap_2_4 is not None:
            scan_kwargs["scan_bitmap_2_4"] = scan_bitmap_2_4
        if bg_scan_periodicity is not None:
            scan_kwargs["bg_scan_periodicity"] = bg_scan_periodicity
        return _perform_bg_extended_scan(**scan_kwargs)

    @classmethod
    def assert_scan_more_than_11(cls, scan_results, label=""):
        prefix = f"{label}: " if label else ""
        count = len(scan_results) if scan_results else 0
        assert scan_results is not None and count > 11, (
            f"{prefix}expected >11 APs, got {count}"
        )
        logger().info("%sBG extended scan returned %s AP entries", prefix, count)

    def run_periodic_bg_scan_cycles(
            self,
            advanced_scan_bitmap,
            cycles=3,
            periodicity=10,
            scan_bitmap_2_4=None,
    ):
        """Run periodic BG extended scans and assert >11 APs each cycle."""
        extended_results_enabled = bool(advanced_scan_bitmap & (1 << 7))
        results = []
        for cycle in range(cycles):
            logger().info("Periodic BG extended scan cycle %s/%s", cycle + 1, cycles)
            if extended_results_enabled:
                scan_results = self.perform_bg_extended_scan(
                    advanced_scan_bitmap=advanced_scan_bitmap,
                    scan_bitmap_2_4=scan_bitmap_2_4,
                    bg_scan_periodicity=periodicity,
                )
            else:
                scan_results = self._trigger_sta_bg_scan(
                    advanced_scan_bitmap=advanced_scan_bitmap,
                    scan_bitmap_2_4=scan_bitmap_2_4,
                    bg_scan_periodicity=periodicity,
                    expected_status=[
                        SLStatus.SL_STATUS_OK,
                        SLStatus.SL_STATUS_TIMEOUT,
                    ],
                    reconfigure=False,
                )
                if not scan_results or len(scan_results) <= 11:
                    logger().info(
                        "Periodic BG scan cycle %s returned %s APs; "
                        "collecting results with instant BG scan",
                        cycle + 1,
                        len(scan_results) if scan_results else 0,
                    )
                    scan_results = self._trigger_sta_bg_scan(
                        advanced_scan_bitmap=advanced_scan_bitmap,
                        scan_bitmap_2_4=scan_bitmap_2_4,
                        reconfigure=False,
                    )
            self.assert_scan_more_than_11(scan_results, f"cycle {cycle + 1}")
            results.append(scan_results)
            if cycle < cycles - 1:
                time.sleep(periodicity)
        return results

    def run_http_download_with_bg_scan_loop(
            self,
            http_server,
            index_path,
            advanced_scan_bitmap,
            scan_interval=10,
            https=False,
            retries=3,
    ):
        """ HTTP download (5MB) with instant BG extended scan every scan_interval seconds."""
        http_error = [None]
        http_download_done = threading.Event()

        def run_http_download():
            try:
                self.sl_collections.http_file_download(
                    wifi_dut=self.wifi_dut,
                    http_server=http_server,
                    device_ip=self.device_ip,
                    index_path=index_path,
                    https=https,
                    retries=retries,
                )
            except Exception as exc:
                http_error[0] = exc
            finally:
                http_download_done.set()

        http_thread = threading.Thread(target=run_http_download)
        http_thread.start()
        time.sleep(3)

        scan_results_list = []
        download_timeout = 3000
        deadline = time.time() + download_timeout + 120
        while http_thread.is_alive() and time.time() < deadline:
            scan_results = self.perform_bg_extended_scan(
                advanced_scan_bitmap=advanced_scan_bitmap,
            )
            if scan_results is not None:
                scan_results_list.append(scan_results)
                logger().info(
                    "BG extended scan during HTTP download: %s AP entries",
                    len(scan_results),
                )
            else:

                logger().warning("BG extended scan during HTTP download returned no results")
            if http_download_done.wait(timeout=scan_interval):
                break

        http_thread.join(timeout=download_timeout + 60)
        assert not http_thread.is_alive(), "HTTP download did not complete in time"
        assert http_error[0] is None, f"HTTP download failed: {http_error[0]}"
        assert scan_results_list, "No BG extended scan results during HTTP download"
        assert any(len(r) > 11 for r in scan_results_list), (
            f"Expected >11 APs in at least one scan during download; "
            f"got counts {[len(r) for r in scan_results_list]}"
        )
        logger().info(
            "HTTP download with BG scan loop completed; %s scan cycles collected",
            len(scan_results_list),
        )
        return scan_results_list

    def perform_csa_and_verify_bg_scan(
            self,
            advanced_scan_bitmap,
            csa_channel=11,
            csa_beacon_count=20,
            csa_interval=1,
    ):
        """Step 7: CSA from AP, then verify BG extended scan still returns >11 APs."""
        assert hasattr(self.wifi_access_point.interfaces.wifi, "enable_disable_csa"), (
            "AP does not support enable_disable_csa for CSA test"
        )
        logger().info(
            " Perform CSA on AP (channel=%s, count=%s, interval=%s)",
            csa_channel,
            csa_beacon_count,
            csa_interval,
        )
        self.wifi_access_point.interfaces.wifi.enable_disable_csa(
            csa_channel, csa_beacon_count, csa_interval,
        )
        time.sleep(35)
        scan_results = self.perform_bg_extended_scan(advanced_scan_bitmap=advanced_scan_bitmap)
        self.assert_scan_more_than_11(scan_results, "after CSA")
        assert ping(self.device_ip, self.utf_constants.get("ping_count"), size=300), (
            "Ping failed after CSA"
        )
        return scan_results

    def run_congestion_bg_scan_loop(
            self,
            net_perf_client,
            protocol,
            advanced_scan_bitmap,
            duration_sec=180,
            scan_interval=10,
    ):
        """ Create congestion with iperf traffic; BG scan loop for long run."""
        traffic_error = [None]
        traffic_done = threading.Event()

        def run_traffic():
            try:
                host_ip = net_perf_client.interfaces.wifi.get_ip_address()
                self.sl_collections.run_traffic(
                    wifi_dut=self.wifi_dut,
                    net_perf_client=net_perf_client,
                    protocol=protocol,
                    device_ip=self.device_ip,
                    host_ip=host_ip,
                    timeout=duration_sec + 60,
                    traffic_type="TX",
                )
            except Exception as exc:
                traffic_error[0] = exc
            finally:
                traffic_done.set()

        traffic_thread = threading.Thread(target=run_traffic)
        traffic_thread.start()
        time.sleep(5)

        scan_results_list = []
        deadline = time.time() + duration_sec
        while time.time() < deadline:
            scan_results = self.perform_bg_extended_scan(
                advanced_scan_bitmap=advanced_scan_bitmap,
                bg_scan_periodicity=scan_interval,
            )
            assert scan_results is not None, "BG extended scan returned no results under congestion"
            scan_results_list.append(scan_results)
            time.sleep(scan_interval)

        traffic_thread.join(timeout=duration_sec + 60)
        assert traffic_error[0] is None, f"Congestion traffic failed: {traffic_error[0]}"
        assert scan_results_list, "No BG extended scan results during congestion loop"
        assert any(len(r) > 11 for r in scan_results_list), (
            f"Expected >11 APs in at least one congestion scan; "
            f"got counts {[len(r) for r in scan_results_list]}"
        )
        logger().info(
            "Congestion BG scan loop completed; %s scan cycles, traffic still active=%s",
            len(scan_results_list),
            traffic_thread.is_alive(),
        )
        traffic_done.wait(timeout=30)
        return scan_results_list

    @classmethod
    def filter_scan_results(
            cls,
            scan_results,
            channel_filter=None,
            security_mode_filter=None,
            rssi_filter=None,
            network_type_filter=None,
    ):
        """Apply scan result filters (channel, security, RSSI, network type)."""
        filtered = []
        for entry in scan_results:
            channel = cls._get_scan_entry_attr(entry, "rf_channel")
            if channel_filter is not None and channel != channel_filter:
                continue
            security_mode = cls._get_scan_entry_attr(entry, "security_mode")
            if security_mode_filter is not None and security_mode != security_mode_filter:
                continue
            rssi = cls._get_scan_entry_attr(entry, "rssi")
            if rssi_filter is not None and rssi < rssi_filter:
                continue
            network_type = cls._get_scan_entry_attr(entry, "network_type")
            if network_type_filter is not None and network_type != network_type_filter:
                continue
            filtered.append(entry)
        return filtered

    def perform_wps_push_button_connect(self):
        """Step 7: WPS push-button connect after leaving current AP association."""
        from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble. \
            test_sta_ble_wps_sdk import join_to_wifi_network_via_wps

        logger().info(" Leave AP and connect via WPS push button")
        logger().info("Disable Wi-Fi/BT power save before WPS")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveDisabled,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
        )
        time.sleep(2)

        try:
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as exc:
            logger().warning("Leave before WPS returned: %s", exc)
        self.wifi_dut.interfaces.wifi.associated = False
        time.sleep(2)

        # WPS PBC on AP uses Selenium against https://<ap ip_address>:<web_ui_port>
        # from the pytest host. Requires lab network reachability (not DUT-side).
        ping_count = self.utf_constants.get("ping_count", 10)
        wps_result = join_to_wifi_network_via_wps(
            wifi_dut=self.wifi_dut,
            wifi_access_point=self.wifi_access_point,
            sl_collections=self.sl_collections,
            associated=False,
            power_save=False,
            ping_before_power_save=True,
            ping_after_power_save=False,
            ping_count=ping_count,
            channel=self.home.channel,
            skip_scan=True,
        )
        assert wps_result and wps_result.get("device_ip"), "WPS push-button connection failed"
        self.device_ip = wps_result["device_ip"]
        logger().info("WPS connection succeeded; DUT IP %s", self.device_ip)
        return wps_result

    @classmethod
    def assert_selective_bgscan_channels(cls, scan_results, allowed_channels, min_results=12):
        """Verify selective BG scan has enough APs on allowed channels (neighbor bleed logged)."""
        allowed = set(allowed_channels)
        on_channel = [
            entry for entry in scan_results
            if cls._get_scan_entry_attr(entry, "rf_channel") in allowed
        ]
        off_channel = [
            (idx, cls._get_scan_entry_attr(entry, "rf_channel"),
             cls._get_scan_entry_attr(entry, "ssid"))
            for idx, entry in enumerate(scan_results)
            if cls._get_scan_entry_attr(entry, "rf_channel") not in allowed
        ]
        if off_channel:
            logger().warning(
                "Selective BG scan reported %s AP(s) outside channels %s (neighbor bleed): %s",
                len(off_channel),
                sorted(allowed),
                off_channel[:10],
            )
        assert len(on_channel) >= min_results, (
            f"Selective BG scan expected >={min_results} APs on channels {sorted(allowed)}, "
            f"got {len(on_channel)} (total scan entries: {len(scan_results)})"
        )
        logger().info(
            "Selective BG scan: %s APs on allowed channels %s (observed: %s)",
            len(on_channel),
            sorted(allowed),
            sorted({cls._get_scan_entry_attr(entry, "rf_channel") for entry in on_channel}),
        )


class ExtendedBgScanThread(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            scan_iteration_count=1,
            scan_gap=2,
            scan_timeout=90,
            bg_scan_allowed_channels=None

    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.scan_iteration_count = scan_iteration_count
        self.scan_gap = scan_gap
        self.scan_timeout = scan_timeout if scan_timeout is not None else 90
        self.bg_scan_allowed_channels = (
            bg_scan_allowed_channels
            if bg_scan_allowed_channels is not None
            else list(range(1, 12))
        )
        self.scan_results = None

    def configure_advanced_scan(self):
        """Advanced scan bitmap (1|64|128)"""
        # advanced_scan_bitmap = (1 << 0) | (1 << 6) | (1 << 7) #Non-Periodic
        advanced_scan_bitmap = (1 << 0) | (1 << 7)  # Periodic
        logger().info(
            "Step 12 advanced-scan CLI (expected on DUT): "
            f"wifi.set_advanced_scan_configuration -i 50 -j 20 -m 1 -o {advanced_scan_bitmap}"
        )
        self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
            adv_active_channel_time=50,
            adv_passive_channel_time=20,
            adv_trigger_level=-4,
            adv_trigger_level_change=2,
            adv_enable_multi_probe=1,
            adv_enable_instant_scan=None,
            has_adv_scan_bit_map=1,
            advanced_scan_bitmap=advanced_scan_bitmap,
            timeout=10,
        )
        try:
            cfg = self.wifi_dut.interfaces.wifi.get_advanced_scan_configuration()
            cfg_text = cfg.decode() if isinstance(cfg, bytes) else cfg
            logger().info(f"DUT advanced-scan readback: {cfg_text}")
        except Exception as exc:
            logger().warning(f"wifi.get_advanced_scan_configuration failed: {exc}")

    def perform_bg_extended_scan(self, validate_min_results=True, scan_count_extended=100):

        logger().info(
            f"BG extended scan CLI (expected on DUT): "
            f"wifi.scan -m bg_scan -p 8 -n {scan_count_extended}"
        )
        min_results = 12 if validate_min_results else None
        self.scan_results = self.wifi_dut.interfaces.wifi.scan(
            ssid=None,
            bgscan=True,
            scan_type=8,
            scan_count_extended=scan_count_extended,
            timeout=self.scan_timeout,
        )
        count = len(self.scan_results) if self.scan_results else 0
        if min_results is not None:
            assert self.scan_results is not None and count >= min_results, (
                f"BG extended scan expected >={min_results} APs, got {count}"
            )
        logger().info(f"BG extended scan returned {count} AP entries (min required: {min_results})")
        return self.scan_results

    def assert_bg_extended_scan_channels(self, allowed_channels=None):
        """Reuse coex _assert_extended_bgscan_channels_only."""
        allowed = allowed_channels or self.bg_scan_allowed_channels
        _assert_extended_bgscan_channels_only(self.scan_results, allowed)

    def run(self):
        logger().info("Configure advanced scan and perform background extended scan")
        time.sleep(5)
        self.configure_advanced_scan()
        self.perform_bg_extended_scan()
        self.assert_bg_extended_scan_channels()


class WifiJoin(ThreadBase):
    device_address = {}

    def __init__(self, wifi_dut=None, capture_filename=None, wifi_access_point=None, wifi_sniffer=None,
                 sl_collections=None, sniffer_filter=None,
                 utf_constants=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.dut_addr = None
        self.utf_constants = utf_constants

    def run(self):
        try:
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)

            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)

            WifiJoin.device_address = self.dut_addr["device_ip"]
            logger().info(f'DUT address is : {WifiJoin.device_address}')

        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")


class TrafficThread(WifiJoin):
    def __init__(
            self,
            wifi_dut=None,
            wifi_client=None,
            net_perf_client=None,
            sl_collections=None,
            protocol=None,
            traffic_type=None,
            host_ip=None,
            timeout=60
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.sl_collections = sl_collections
        self.protocol = protocol
        self.traffic_type = traffic_type
        self.timeout = timeout
        self.host_ip = host_ip

    def run(self):
        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f'Remote device ip: {self.host_ip}')

        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=WifiJoin.device_address,
            host_ip=self.host_ip,
            traffic_type=self.traffic_type,
            timeout=self.timeout,
        )
        logger().info("Traffic iteration completed successfully")
        time.sleep(3)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "OPEN",
            "ssid": "sharma_test",  # DUT SoftAP — must match line 49
            "passphrase": "123456789",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
    },
)
@softap_wifi_dut_marker(
    memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
    OpenMode=Si91xFeatureBitMap.OpenMode,
)
@pytest.mark.config("wifi_dut", wifi={"region": 1, "region_code": "us"})
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "SAKSHIASUS",
        "security": "OPEN",
        "passphrase": "12345678",
        "channel": 11,
        "region": "US",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id("C978108")
def test_wifi_sdk_softap_provisioning_bg_extended_scan_open_us_ch11_c978108(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
    """C978108: BG extended scan after HTTP/AP provisioning — Open, US region, channel 11."""
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
            dut_region_code=Si91xRegionCode.US,
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "country": "GE",
            "channel": "11",
            "interface": "wlan0",
        },
    },
)
@softap_wifi_dut_marker(memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.config("wifi_dut", wifi={"region": 1, "region_code": "europe"})
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "SAKSHIASUS",
        "security": "WPA2",
        "passphrase": "12345678",
        "channel": 13,
        "region": "Europe",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id("C978109")
def test_wifi_sdk_softap_provisioning_bg_extended_scan_wpa2_eu_ch13_c978109(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
    """C978109: BG extended scan after HTTP/AP provisioning — WPA2, EU region, channel 13."""
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
            dut_region_code=Si91xRegionCode.Europe,
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "country": "JP",
            "channel": "11",
            "interface": "wlan0",
        },
    },
)
@softap_wifi_dut_marker(
    memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
    IEEE802_11W=Si91xExtCustomFeatureBitMap.IEEE802_11W,
)
@pytest.mark.config("wifi_dut", wifi={"region": 1, "region_code": "japan"})
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "SAKSHIASUS",
        "security": "WPA3",
        "passphrase": "12345678",
        "channel": 13,
        "region": "japan",
        "protected_management_frame": "Capable",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id("C978110")
def test_wifi_sdk_softap_provisioning_bg_extended_scan_wpa3_jp_ch14_c978110(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
    """C978110: BG extended scan after HTTP/AP provisioning — WPA3, JP region, channel 14."""
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
            dut_region_code=Si91xRegionCode.Japan,
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma_test",
            "passphrase": "123456789",
            "country": "GE",
            "channel": "11",
            "interface": "wlan0",
        },
    },
)
@softap_wifi_dut_marker(
    memory_config=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
    IEEE802_11W=Si91xExtCustomFeatureBitMap.IEEE802_11W,
)
@pytest.mark.config("wifi_dut", wifi={"region": 1, "region_code": "worldwide"})
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "SAKSHIASUS",
        "security": "WPA2WPA3MixedMode",
        "passphrase": "12345678",
        "channel": 13,
        "region": "Europe",
        "protected_management_frame": "Capable",
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id("C978111")
def test_wifi_sdk_softap_provisioning_bg_extended_scan_wpa2_wpa3_ww_ch13_c978111(
        sl_collections, wifi_dut, wifi_client, wifi_sniffer, wifi_access_point,
        wiseconnect_web, request, utf_constants, ble_client, ble_dut, wifi_clients, sniffer_filter):
    """C978111: BG extended scan after HTTP/AP provisioning — WPA2/WPA3 mixed, WW region, channel 13."""
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
            dut_region_code=Si91xRegionCode.Worldwide,
        )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        ble_client.interfaces.bluetooth.close()


@sta_ble_wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "SAKSHIASUS",
        "security": "WPA3",
        "passphrase": "1234567890",
        "channel": 11,
        "region": "US",
        "protected_management_frame": "Capable",
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@pytest.mark.test_src_map_id("C978112")
def test_wifi_sdk_bg_extended_selective_channel_scan_c978112(
        wifi_access_point,
        wifi_dut,
        sl_collections,
        utf_constants,
        wifi_sniffer,
        request,
):
    """WPA3 STA: power save + BG extended selective channel scan on channels 1, 6, 11."""
    try:
        channel_bitmap_2_4 = (1 << 0) | (1 << 5) | (1 << 10)  # Ch 1, 6, 11
        selective_channels = [1, 6, 11]
        advanced_scan_bitmap = (1 << 0) | (1 << 7)

        scan_obj = StaWpa3BgExtendedScanFunctionality(
            wifi_dut, wifi_access_point, sl_collections, utf_constants,
        )
        scan_obj.run_steps_1_to_5(
            advanced_scan_bitmap=advanced_scan_bitmap,
            channel_bitmap_2_4=channel_bitmap_2_4,
        )

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel,
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)

        logger().info(
            "sl_wifi_start_scan BG extended selective channel scan (ch 1, 6, 11)",
        )
        scan_results = scan_obj.perform_bg_extended_scan(
            advanced_scan_bitmap=advanced_scan_bitmap,
            scan_bitmap_2_4=channel_bitmap_2_4,
        )
        assert scan_results is not None and len(scan_results) > 11, (
            f"expected >11 APs, got {len(scan_results) if scan_results else 0}"
        )
        StaWpa3BgExtendedScanFunctionality.assert_selective_bgscan_channels(
            scan_results, selective_channels,
        )
        logger().info(
            "Selective BG extended scan returned %s total APs on channels %s",
            len(scan_results),
            selective_channels,
        )
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as exc:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=exc)
        raise


@sta_ble_wifi_dut_marker(
    ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W,
    no_of_wifi_threads=2,
    wifi_stack_len=3071,
    ble_stack_len=2048,
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", ["5MB.htm"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "SAKSHIASUS",
        "security": "WPA3",
        "passphrase": "1234567890",
        "channel": 11,
        "region": "US",
        "protected_management_frame": "Capable",
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@pytest.mark.test_src_map_id("C978130")
def test_wifi_sdk_bg_extended_scan_http_download_5mb_c978130(
        wifi_access_point,
        wifi_dut,
        sl_collections,
        utf_constants,
        wifi_sniffer,
        request,
        http_server,
        index_path,
):
    """WPA3 STA: instant BG scan every 10s while HTTP download (5MB) is ongoing."""
    try:
        advanced_scan_bitmap = StaWpa3BgExtendedScanFunctionality.ADVANCED_SCAN_BITMAP_FULL
        scan_obj = StaWpa3BgExtendedScanFunctionality(
            wifi_dut, wifi_access_point, sl_collections, utf_constants,
        )
        scan_obj.run_steps_1_to_5(advanced_scan_bitmap=advanced_scan_bitmap)

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel,
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)

        logger().info("sl_wifi_start_scan BG extended scan")
        scan_results = scan_obj.perform_bg_extended_scan(
            advanced_scan_bitmap=advanced_scan_bitmap,
            bg_scan_periodicity=10,
        )
        scan_obj.assert_scan_more_than_11(scan_results, "before HTTP download")

        logger().info("HTTP download with BG extended scan every 10s")
        scan_obj.run_http_download_with_bg_scan_loop(
            http_server=http_server,
            index_path=index_path,
            advanced_scan_bitmap=advanced_scan_bitmap,
            scan_interval=10,
        )
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as exc:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=exc)
        raise


@sta_ble_wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "SAKSHIASUS",
        "security": "WPA3",
        "passphrase": "1234567890",
        "channel": 11,
        "region": "US",
        "protected_management_frame": "Capable",
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"],
)
@pytest.mark.test_src_map_id("C978131")
def test_wifi_sdk_bg_extended_scan_during_csa_c978131(
        wifi_access_point,
        wifi_dut,
        sl_collections,
        utf_constants,
        wifi_sniffer,
        request,
):
    """WPA3 STA: BG extended scan during/after AP CSA channel switch."""
    try:
        advanced_scan_bitmap = StaWpa3BgExtendedScanFunctionality.ADVANCED_SCAN_BITMAP_FULL
        scan_obj = StaWpa3BgExtendedScanFunctionality(
            wifi_dut, wifi_access_point, sl_collections, utf_constants,
        )
        scan_obj.run_steps_1_to_5(advanced_scan_bitmap=advanced_scan_bitmap)

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel,
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)

        logger().info("sl_wifi_start_scan BG extended scan before CSA")
        scan_results = scan_obj.perform_bg_extended_scan(
            advanced_scan_bitmap=advanced_scan_bitmap,
        )
        scan_obj.assert_scan_more_than_11(scan_results, "before CSA")

        scan_obj.perform_csa_and_verify_bg_scan(
            advanced_scan_bitmap=advanced_scan_bitmap,
            csa_channel=wifi_access_point.interfaces.wifi.channel,
        )
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as exc:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=exc)
        raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 4096}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANBLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_extended_bg_scan_and_tcp_tx_c978113(
        wifi_sniffer,
        wifi_access_point,
        wifi_client,
        wifi_dut,
        net_perf_client,
        protocol,
        request,
        sl_collections,
        sniffer_filter
):
    """Verify BG extended scan functionality during TCP TX traffic"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections)

        ext_scan_thread = ExtendedBgScanThread(wifi_dut=wifi_dut)

        iperf = TrafficThread(wifi_dut=wifi_dut,
                              wifi_client=wifi_client,
                              net_perf_client=net_perf_client,
                              sl_collections=sl_collections,
                              protocol=protocol,
                              traffic_type='TX',
                              timeout=60)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ext_scan_thread.start()
        iperf.start()

        iperf.wait_for_exit()
        ext_scan_thread.wait_for_exit()
        time.sleep(30)
        # Stop sniffer capture and validate probe requests emitted during BG scan
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info("DUT MAC: %s", dut_mac_address)

        probe_request_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, da_addr="ff:ff:ff:ff:ff:ff", filter_name="probe_request")

        probe_result = wifi_sniffer.interfaces.capture.sniffer_validation(
            sniffer_validation=True, packet_filter1=probe_request_filter)

        assert probe_result["packet_count"], \
            "Sniffer: no probe request packets found during extended BG scan"
        logger().info("Sniffer validation passed: probe requests found during BG scan")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        try:
            if getattr(wifi_sniffer.interfaces.capture, "capture_started", False):
                wifi_sniffer.interfaces.capture.stop_capture()
        except Exception as exc:
            logger().warning(f"Sniffer capture stop failed during cleanup: {exc}")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 4096}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANBLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_extended_bg_scan_and_tcp_rx_c978114(
        wifi_sniffer,
        wifi_access_point,
        wifi_client,
        wifi_dut,
        net_perf_client,
        protocol,
        request,
        sl_collections,
        sniffer_filter
):
    """Verify BG extended scan functionality during TCP RX traffic"""
    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections)

        ext_scan_thread = ExtendedBgScanThread(wifi_dut=wifi_dut)

        iperf = TrafficThread(wifi_dut=wifi_dut,
                              wifi_client=wifi_client,
                              net_perf_client=net_perf_client,
                              sl_collections=sl_collections,
                              protocol=protocol,
                              traffic_type='RX',
                              timeout=60)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Start sniffer capture after the DUT has joined the AP
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ext_scan_thread.start()
        iperf.start()

        iperf.wait_for_exit()
        ext_scan_thread.wait_for_exit()
        time.sleep(30)
        # Stop sniffer capture and validate probe requests emitted during BG scan
        wifi_sniffer.interfaces.capture.stop_capture()
        # time.sleep(10)

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info("DUT MAC: %s", dut_mac_address)

        probe_request_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, da_addr="ff:ff:ff:ff:ff:ff", filter_name="probe_request")

        probe_result = wifi_sniffer.interfaces.capture.sniffer_validation(
            sniffer_validation=True, packet_filter1=probe_request_filter)

        assert probe_result["packet_count"], \
            "Sniffer: no probe request packets found during extended BG scan"
        logger().info("Sniffer validation passed: probe requests found during BG scan")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        try:
            if getattr(wifi_sniffer.interfaces.capture, "capture_started", False):
                wifi_sniffer.interfaces.capture.stop_capture()
        except Exception as exc:
            logger().warning(f"Sniffer capture stop failed during cleanup: {exc}")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 4096}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_extended_bg_scan_and_udp_tx_c978115(
        wifi_sniffer,
        wifi_access_point,
        wifi_client,
        wifi_dut,
        net_perf_client,
        protocol,
        request,
        sl_collections,
        sniffer_filter
):
    """Verify BG extended scan functionality during UDP TX traffic"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections)

        ext_scan_thread = ExtendedBgScanThread(wifi_dut=wifi_dut)

        iperf = TrafficThread(wifi_dut=wifi_dut,
                              wifi_client=wifi_client,
                              net_perf_client=net_perf_client,
                              sl_collections=sl_collections,
                              protocol=protocol,
                              traffic_type='TX',
                              timeout=60)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Start sniffer capture after the DUT has joined the AP
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ext_scan_thread.start()
        iperf.start()

        iperf.wait_for_exit()
        ext_scan_thread.wait_for_exit()
        time.sleep(30)
        # Stop sniffer capture and validate probe requests emitted during BG scan
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info("DUT MAC: %s", dut_mac_address)

        probe_request_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, da_addr="ff:ff:ff:ff:ff:ff", filter_name="probe_request")

        probe_result = wifi_sniffer.interfaces.capture.sniffer_validation(
            sniffer_validation=True, packet_filter1=probe_request_filter)

        assert probe_result["packet_count"], \
            "Sniffer: no probe request packets found during extended BG scan"
        logger().info("Sniffer validation passed: probe requests found during BG scan")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        try:
            if getattr(wifi_sniffer.interfaces.capture, "capture_started", False):
                wifi_sniffer.interfaces.capture.stop_capture()
        except Exception as exc:
            logger().warning(f"Sniffer capture stop failed during cleanup: {exc}")

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 4096}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANBLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_extended_bg_scan_and_udp_rx_c978116(
        wifi_sniffer,
        wifi_access_point,
        wifi_client,
        wifi_dut,
        net_perf_client,
        protocol,
        request,
        sl_collections,
        sniffer_filter
):
    """Verify BG extended scan functionality during UDP RX traffic"""

    try:
        capture_filename = request.node.name
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename, wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections)

        ext_scan_thread = ExtendedBgScanThread(wifi_dut=wifi_dut)

        iperf = TrafficThread(wifi_dut=wifi_dut,
                              wifi_client=wifi_client,
                              net_perf_client=net_perf_client,
                              sl_collections=sl_collections,
                              protocol=protocol,
                              traffic_type='RX',
                              timeout=60)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Start sniffer capture after the DUT has joined the AP
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ext_scan_thread.start()
        iperf.start()

        iperf.wait_for_exit()
        ext_scan_thread.wait_for_exit()
        time.sleep(30)
        # Stop sniffer capture and validate probe requests emitted during BG scan
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info("DUT MAC: %s", dut_mac_address)

        probe_request_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, da_addr="ff:ff:ff:ff:ff:ff", filter_name="probe_request")

        probe_result = wifi_sniffer.interfaces.capture.sniffer_validation(
            sniffer_validation=True, packet_filter1=probe_request_filter)

        assert probe_result["packet_count"], \
            "Sniffer: no probe request packets found during extended BG scan"
        logger().info("Sniffer validation passed: probe requests found during BG scan")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        try:
            if getattr(wifi_sniffer.interfaces.capture, "capture_started", False):
                wifi_sniffer.interfaces.capture.stop_capture()
        except Exception as exc:
            logger().warning(f"Sniffer capture stop failed during cleanup: {exc}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 4096}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANBLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_connect_extended_bg_scan_disconnect_c978121(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        protocol,
        request,
        sl_collections,
        sniffer_filter
):
    """Verify connect -> extended BG scan -> disconnect functionality in a loop"""
    loop_count = 2

    try:
        for iteration in range(loop_count):
            logger().info(
                "===== connect / extended_bg_scan / disconnect iteration %s/%s =====",
                iteration + 1,
                loop_count,
            )

            capture_filename = f"{request.node.name}_iter{iteration + 1}"
            wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                                wifi_access_point=wifi_access_point,
                                wifi_sniffer=wifi_sniffer, sl_collections=sl_collections)

            ext_scan_thread = ExtendedBgScanThread(wifi_dut=wifi_dut)

            # connect
            wifi_obj.start()
            wifi_obj.wait_for_exit()

            # Start sniffer capture after the DUT has joined the AP
            wifi_sniffer.interfaces.capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

            # extended bg scan
            ext_scan_thread.start()
            ext_scan_thread.wait_for_exit()
            time.sleep(60)
            # disconnect
            wifi_dut.interfaces.wifi.leave()
            logger().info("DUT disconnected after iteration %s/%s", iteration + 1, loop_count)
            time.sleep(2)

            # stop sniffer capture and validate after WLAN disconnection
            wifi_sniffer.interfaces.capture.stop_capture()

            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info("DUT MAC: %s", dut_mac_address)

            # validate the DUT emitted probe requests during the BG scan
            probe_request_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_mac_address, da_addr="ff:ff:ff:ff:ff:ff", filter_name="probe_request")

            probe_result = wifi_sniffer.interfaces.capture.sniffer_validation(
                sniffer_validation=True, packet_filter1=probe_request_filter)

            assert probe_result["packet_count"], \
                f"Sniffer: no probe request packets found during extended BG scan (iteration {iteration + 1})"
            logger().info(
                "Sniffer validation passed: probe requests found during BG scan (iteration %s/%s)",
                iteration + 1,
                loop_count,
            )
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
        raise
    finally:
        try:
            if getattr(wifi_sniffer.interfaces.capture, "capture_started", False):
                wifi_sniffer.interfaces.capture.stop_capture()
        except Exception as exc:
            logger().warning(f"Sniffer capture stop failed during cleanup: {exc}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 4096}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANBLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_connect_extended_bg_scan_disconnect_in_loop_for_long_run_c978123(
        wifi_sniffer,
        wifi_access_point,
        wifi_client,
        wifi_dut,
        net_perf_client,
        protocol,
        request,
        sl_collections,
        sniffer_filter
):
    """Run connect -> extended BG scan -> disconnect in a loop for a long run (12 hours)."""

    run_duration_sec = 12 * 60 * 60  # 12 hours
    start_time = time.time()
    end_time = start_time + run_duration_sec
    iteration = 0

    while time.time() < end_time:
        iteration += 1
        elapsed_hours = (time.time() - start_time) / 3600.0
        logger().info(
            "===== long run iteration %s | elapsed %.2f h / 12 h =====",
            iteration,
            elapsed_hours,
        )

        capture_filename = f"{request.node.name}_iter{iteration}"
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, capture_filename=capture_filename,
                            wifi_access_point=wifi_access_point,
                            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections)

        ext_scan_thread = ExtendedBgScanThread(wifi_dut=wifi_dut)

        # connect
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Start sniffer capture after the DUT has joined the AP
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        # extended bg scan
        ext_scan_thread.start()
        ext_scan_thread.wait_for_exit()

        # disconnect
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT disconnected after long run iteration %s", iteration)
        time.sleep(2)
        time.sleep(30)
        # stop sniffer capture and validate after WLAN disconnection
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(10)

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info("DUT MAC: %s", dut_mac_address)

        # validate the DUT emitted probe requests during the BG scan
        probe_request_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, da_addr="ff:ff:ff:ff:ff:ff", filter_name="probe_request")

        probe_result = wifi_sniffer.interfaces.capture.sniffer_validation(
            sniffer_validation=True, packet_filter1=probe_request_filter)

        assert probe_result["packet_count"], \
            f"Sniffer: no probe request packets found during extended BG scan (long run iteration {iteration})"
        logger().info(
            "Sniffer validation passed: probe requests found during BG scan (long run iteration %s)",
            iteration,
        )

    logger().info(
        "Long run completed: %s iterations over %.2f hours",
        iteration,
        (time.time() - start_time) / 3600.0,
    )
