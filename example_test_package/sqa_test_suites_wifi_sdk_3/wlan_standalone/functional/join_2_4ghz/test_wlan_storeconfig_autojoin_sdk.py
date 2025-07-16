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
)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import (
    AsyncEventIdentifiers,
)
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


class Functionality:
    SCAN = "scan"
    PING = "ping"
    IPERF = "iperf"
    HTTP = "http"
    HTTP_GET = "http_get"


class WLANAutoJoinThread(ThreadBase):

    def __init__(
        self,
        wifi_sniffer=None,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_client=None,
        net_perf_client=None,
        protocol=None,
        test_type=None,
        sl_collections=None,
        ping_count=None,
        sniffer_filter=None,
        region=None,
        switch=None,
        pmk_enable=False,
        traffic_type="TX",
        tcp_ip_bypass=False,
        enc="ccmp",
        timeout=60,
        http_server=None,
        index_path=None,
        http_client=None,
        https=0,
        scan_count=5,
        mac=None,
        async_socket=0,
        address=None,
        profiles=None,
    ):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.region = region
        self.switch = switch
        self.pmk_enable = pmk_enable
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.traffic_type = traffic_type
        self.tcp_ip_bypass = tcp_ip_bypass
        self.enc = enc
        self.mac = mac
        self.timeout = timeout
        self.http_client = http_client
        self.http_server = http_server
        self.https = https
        self.index_path = index_path
        self.scan_count = scan_count
        self.async_socket = async_socket
        self.throughput_remote = None
        self.throughput_dut = None
        self.profiles = profiles
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        self.address = address
        logger().info(f"\n POWER SAVE FLAG IN HARNESS : {self.power_save}")

    def check_scan_functionality(self):
        for count in range(0, self.scan_count):
            scan_status, scan_results = self.sl_collections.scan(
                self.wifi_dut, scan_status=False, retry_count=3, channel=0
            )
            logger().info(f"Scan Results : {scan_results}")
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {self.dut_mac_address}")

    def run_traffic(self):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"DEVICE IP :{host_ip}")
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=self.device_ip,
            host_ip=host_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            async_socket=self.async_socket,
        )

    def run_http_download(self):

        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut,
            http_server=self.http_server,
            index_path=self.index_path,
            device_ip=self.device_ip,
            https=self.https,
        )

    def http_get(self):
        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=self.https)

        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
            self.http_server.interfaces.http,
            self.index_path,
            server_port=self.http_server.interfaces.http.port,
            url_address=self.address,
            timeout=100,
        )
        status_client, content_client = self.http_client.interfaces.http.http_get(
            self.http_server.interfaces.http, self.index_path
        )

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert (
            content_dut == content_client
        ), "fetched data is not same as expected data"
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.http_client_deinit()

    def set_power_save(self):

        if self.power_save:

            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
            )
        else:
            logger().info(
                "skipping power save beacuse power save flag set to be false in harness"
            )

    def set_rejoin_params(self):
        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=1,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )

    def set_profiles_and_credentials(
        self, profiles, expect_error=False, error_code=None
    ):

        logger().info(
            f"PROFILES ARE: {profiles} AND NUMBER OF PROFILES: {len(profiles)}"
        )

        for _ in range(len(profiles)):
            logger().info(f"PROFILE -> {_ + 1}")
            logger().info(f"SSID : {profiles[_]['ssid']}")
            logger().info(f"SECURITY : {profiles[_]['security']}")
            logger().info(f"PASSPHARASE : {profiles[_]['passphrase']}")
            self.wifi_dut.interfaces.wifi.sl_net_set_profile(
                ssid=profiles[_]["ssid"],
                security=Map_security[profiles[_]["security"]],
                credential_id=_ + 1,
                priority=_ + 1,
                profile_id=_,
                encryption=profiles[_]["encryption_type"],
                expected_status="SL_STATUS_OK" if not expect_error else error_code,
            )
            self.wifi_dut.interfaces.wifi.sl_net_set_credential(
                credential=profiles[_]["passphrase"], cred_id=_ + 1
            )

    def verify_auto_join_functionality(self, skip_power_save=False):

        if len(self.profiles) > 1:
            custom_order = list(range(1, len(self.profiles))) + [0]
            for i in custom_order:
                logger().info(f"Profile : {i} ")
                logger().info(f"SSID : {self.profiles[i]['ssid']}")
                logger().info(f"Security : {self.profiles[i]['security']}")
                logger().info(f"Passphrase : {self.profiles[i]['passphrase']}")
                self.wifi_access_point.interfaces.wifi.start_ap(
                    ssid=self.profiles[i]["ssid"],
                    security=self.profiles[i]["security"],
                    passphrase=self.profiles[i]["passphrase"],
                    channel=self.profiles[i]["channel"],
                )
                logger().info("Waiting for 60 seconds for AP to come up")
                since_time = time.perf_counter_ns()
                time.sleep(60)
                logger().info("DUT should auto join to saved profile after AP is up")
                auto_join_status = False
                events = self.wifi_dut.interfaces.wifi.get_async_events(
                    since_time=since_time
                )
                for event in events:
                    logger().info(
                        f"---------------->Event Data: {event.event_data}<----------------"
                    )
                    event_data = event.event_data
                    if "IN PROGRESS" in event_data:
                        logger().info(
                            f"Auto join process started with event: {event_data} for profile {i}"
                        )
                    if "CONNECTED TO AP" in event_data:
                        logger().info(f"DUT connected to AP with profile {i}")
                        auto_join_status = True
                        break
                assert (
                    auto_join_status
                ), f"DUT failed to auto join AP with profile {i}...."
                logger().info(f"DUT Auto joined to AP with profile {i} successfully")

        if len(self.profiles) == 1:
            logger().info(f"Turn OF AP")
            self.wifi_access_point.interfaces.wifi.stop_ap()
            logger().info("Turn ON AP with Same profile")
            self.wifi_access_point.interfaces.wifi.start_ap()
            logger().info("DUT JOINS TO SAME PROFILE AFTER AP IS UP")
            since_time = time.perf_counter_ns()
            time.sleep(60)
            logger().info("DUT JOINS TO SAME PROFILE AFTER AP IS UP")
            auto_join_status = False
            events = self.wifi_dut.interfaces.wifi.get_async_events(
                since_time=since_time
            )
            for event in events:
                logger().info(
                    f"---------------->Event Data: {event.event_data}<----------------"
                )
                event_data = event.event_data
                if "IN PROGRESS" in event_data:
                    logger().info(f"AUTO JOIN PROCESS STARTED: {event_data}")
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO AP WITH SAME PROFILE")
                    auto_join_status = True
                    break
            assert (
                auto_join_status
            ), f"DUT FAILED TO AUTO JOIN TO THE AP WHEN SINGLE PROFILE CONFIGURED...."

    def join_to_ap(self, skip_power_save=False):

        if skip_power_save:
            pwr_save = False
        else:
            pwr_save = self.power_save
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin
            )
        for count in range(0, 3):
            try:
                self.wifi_dut.interfaces.wifi.sl_net_up(mode="client", profile_id=0xFF)
                self.wifi_dut.interfaces.wifi.associated = True
                break
            except Exception as e:
                logger().info(f"Exception while bringing up the Wi-Fi interface: {e}")
                self.wifi_dut.interfaces.wifi.associated = False
                time.sleep(5)
        assert (
            self.wifi_dut.interfaces.wifi.associated
        ), "DUT NOT ASSOCIATED TO AP......"
        logger().info("\n DUT Associated to AP successfully \n")

        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP_BSSID : {self.ap_mac_address}")

        self.wifi_dut.interfaces.wifi.is_external_stack_enabled = False

        ip_status, ip_config = self.sl_collections.configure_ip(
            self.wifi_dut, ip_status=False, retry_count=3, ip_version="ipv4"
        )

        assert (
            ip_status
        ), f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Device IP Address: {self.device_ip}")
        status = self.sl_collections.ping(
            device_ip=self.device_ip, ping_count=self.ping_count
        )
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def sniffer_validation(self, power_save=False):
        self.sl_collections.basic_sniffer_validation_11ax(
            self.wifi_access_point,
            self.wifi_sniffer,
            self.dut_mac_address,
            self.ap_mac_address,
            self.sniffer_filter,
        )

        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name="probe_req_response",
            )
        )
        packet_filter2 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name="assoc_req_resp_eapol_4_way_handshake",
            )
        )
        packet_filter3 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name="power_mgmt_bit",
            )
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )[
            "packet_count"
        ], "Sniffer: Unable to find probe_req_response packet in sniffer"
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2
        )[
            "packet_count"
        ], "Sniffer: Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer"
        if power_save:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter3
            )[
                "packet_count"
            ], "Sniffer: Unable to find power management bit 1 in sniffer "

    def sniffer_validation_with_relative_time(
        self, relative_time=None, power_save=False
    ):
        packet_filter2 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name="assoc_req_resp_eapol_4_way_handshake",
            )
        )
        packet_filter3 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name="power_mgmt_bit",
            )
        )
        if relative_time:
            packet_filter2 = (
                packet_filter2 + f" and frame.time_relative >= {relative_time}"
            )
            packet_filter3 = (
                packet_filter3 + f" and frame.time_relative >= {relative_time}"
            )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2
        )[
            "packet_count"
        ], "Sniffer: Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer"
        if power_save:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter3
            )[
                "packet_count"
            ], "Sniffer: Unable to find power management bit 1 in sniffer "

    def get_deauthentication_timestamp(self):
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address, filter_name="deauthentication"
            )
        )
        timestamps = self.wifi_sniffer.interfaces.capture.fetch_packet_time_stamp(
            packet_filter=packet_filter1
        )
        logger().info(f"\n The timestamps are {timestamps}\n")
        return timestamps

    def ping(self):
        logger().info("Initiating ping from Raspi to DUT to check stability")
        status = ping(self.device_ip, 30, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def run(self):

        if self.test_type == "scan":
            logger().info("Running scan in a thread for multiple times")
            self.check_scan_functionality()

        if self.test_type == "ping":
            logger().info("\n PINGING FROM RASPBERRY PI TO DUT\n")
            status = ping(self.device_ip, 30, size=300)
            assert status, "\n DUT NOT RESPONDING FOR PING REQUEST......\n"

        if self.test_type == "iperf":
            self.join_to_ap()
            logger().info("Running data transfer")
            self.run_traffic(protocol=self.protocol, traffic_type=self.traffic_type)

        if self.test_type == "http":
            if not self.wifi_dut.interfaces.wifi.associated:
                self.join_to_ap()
            logger().info("http download")
            self.run_http_download()
        if self.test_type == "http_get":
            self.join_to_ap()
            self.http_get()


def wifi_dut_marker(
    ext_custom_bit=0,
    tcp_feat_bit=0,
    ext_tcp_feat_bit=0,
    ca_cert=None,
    eap_cert=None,
    wifi_stack_len=3072,
    ble_stack_len=2048,
    oper_mode=0,
):
    config = {
        "oper_mode": oper_mode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | tcp_feat_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | ext_tcp_feat_bit,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | ext_custom_bit,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": wifi_stack_len, "priority": 8},
        },
        "is_sl_net_enabled": True,
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if eap_cert:
        config["eap_cert"] = eap_cert
    return pytest.mark.config("wifi_dut", wifi=config)


Map_security = {
    "OPEN": 0,
    "WPA": 1,
    "WPA2": 2,
    "WEP": 3,
    "WPA_ENTERPRISE": 4,
    "WPA2_ENTERPRISE": 5,
    "WPA_WPA2_MIXED": 6,
    "WPA3": 7,
    "WPA3_TRANSITION": 8,
    "WPA3_ENTERPRISE": 9,
    "WPA3_TRANSITION_ENTERPRISE": 10,
}


@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2",
                "passphrase": "1234567890",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
def test_wifi_sdk_autojoin_with_one_profile_and_one_credential_C769960(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    profiles,
):

    try:
        iter_count = utf_constants.get("iter_count")
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)

        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=Functionality.PING,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation(power_save=True)
        wifi_obj.verify_auto_join_functionality()
        deauth_timestamp = wifi_obj.get_deauthentication_timestamp()
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation_with_relative_time(
            relative_time=deauth_timestamp[1]
        )
        wifi_obj.ping()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2",
                "passphrase": "1234567890",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile2",
                "channel": 1,
                "security": "WPA2",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
    },
)
def test_wifi_sdk_auto_join_with_wpa2_wpa_two_profiles_c769961(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    profiles,
):

    try:
        iter_count = utf_constants.get("iter_count")
        ping_count = utf_constants.get("ping_count")

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)

        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=Functionality.PING,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation(power_save=True)
        wifi_obj.verify_auto_join_functionality()
        deauth_timestamp = wifi_obj.get_deauthentication_timestamp()
        deauth_timestamp.pop(
            0
        )  # Remove the first timestamp as it is Deauthentication Request Received On Connecting Initially
        wifi_obj.set_power_save()
        for timestamp in deauth_timestamp:
            wifi_obj.sniffer_validation_with_relative_time(relative_time=timestamp)
        wifi_obj.ping()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2",
                "passphrase": "1234567890",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "channel": 1,
        "security": "WPA2",
        "passphrase": "1234567890",
    },
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_autojoin_while_doing_TCP_TX_data_transfer_c769970(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    profiles,
    net_perf_client,
    protocol,
):

    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
            traffic_type="TX",
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.run_traffic()
        wifi_obj.verify_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_obj.run_traffic()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
