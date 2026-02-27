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
    Si91xJoinFeatureBitMap
)
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (BodySensorLocationCharacteristic,
                                                                                HeartRateControlPointCharacteristic,
                                                                                HeartRateMeasurementCharacterstic)
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point -ASUS-RTAX3000 (Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. set Region ,scan ,connect, data transfer
        6. BLE slave/master connection
        7. BLE scan
        8. BLE Advertise

    Author: Swathi.Chinthala

"""
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_dle_sdk import (
    logger,
    BleThread,
    WifiJoinThread,
    SnifferValidationProcess
)


# this thread used for Wi-Fi join
class WlanOtaf(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""

    def __init__(
            self,
            wifi_dut=None,
            wifi_access_point=None,
            testcase=None,
            wifi_client=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            timeout=60,
            http_server=None,
            index_path=None,
            http_client=None,
            https=0,
            http_addr=None,
    ):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.timeout = timeout
        self.http_client = http_client
        self.http_server = http_server
        self.https = https
        self.index_path = index_path
        self.http_addr = http_addr
        self.fw_before_upgrade = None
        self.fw_after_upgrade = None

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def firmware_upgrade_otaf(self):

        self.fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
        logger().info(f" ***** FW before upgrade: {self.fw_before_upgrade} *****")

        logger().info("fetching server ip....")
        host_ip = self.http_server.interfaces.http.hostname_or_ip_address
        logger().info(f"server ip is {host_ip}")
        start_time = time.time()
        logger().info(f" start firmware upgrade: {start_time}")
        logger().info("performing firmware upgrade....")
        self.wifi_dut.interfaces.wifi.firmware_upgrade(ip_address=host_ip, host_name=host_ip, url_address=self.http_addr,
                                                       timeout=200, async_timeout=300)
        finish_time = time.time()
        logger().info(f"firmware upgraded : {finish_time}")
        time_duration = (finish_time - start_time)
        logger().info(f"Time taken to upgrade firmware is: {time_duration}")

        if time_duration > 40:
            logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
        else:
            logger().info(f"time taken to upgrade firmware using http otaf {time_duration} seconds")

    def check_fw_version_after_upgrade(self):
        self.wifi_dut.interfaces.wifi.memory_free(self.http_addr)
        self.wifi_dut.interfaces.wifi.reset()
        time.sleep(15)
        logger().info("Initialising DUT after the reset....")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init(load_certificate=False)
        self.wifi_dut.interfaces.wifi.initialize_thread()
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        self.fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        time.sleep(5)
        logger().info(f"\n\n ***firmware versions before otaf:{self.fw_before_upgrade}"
                      f" firmware version after loading through otaf :{self.fw_after_upgrade}")
        assert self.fw_before_upgrade != self.fw_after_upgrade, f"firmware versions should not match after loading"\
                                                                f" firmware through otaf"

    def run(self):
        self.firmware_upgrade_otaf()



# this thread used for Wi-Fi join
class WifiAutoJoinThread(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            testcase=None,
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
            profiles=None
    ):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
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
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def check_scan_functionality(self):
        for count in range(0, self.scan_count):
            logger().info("Initiating wlan scan")
            # enables the scan in dut on channel
            scan_status, scan_results = self.sl_collections.scan(self.wifi_dut, scan_status=False, retry_count=3,
                                                                 channel=0)
            logger().info(f"scan results : {scan_results}")
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC ADDRESS :  {self.dut_mac_address}")

    def run_traffic(self):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
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

        logger().info("http download")
        self.sl_collections.http_file_download(
            wifi_dut=self.wifi_dut,
            http_server=self.http_server,
            index_path=self.index_path,
            device_ip=self.device_ip,
            https=self.https
        )

    def http_get(self):
        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.wifi.http_client_init(https_enable=self.https)

        status_dut, content_dut = self.wifi_dut.interfaces.http.http_get(
            self.http_server.interfaces.http,
            self.index_path,
            server_port=self.http_server.interfaces.http.port,
            url_address=self.address,
            timeout=100)
        status_client, content_client = self.http_client.interfaces.http.http_get(
            self.http_server.interfaces.http, self.index_path)

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"
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
            logger().info("skipping power save beacuse power save flag set to be false in harness")

    def set_rejoin_params(self):
        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=1,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )

    def get_profiles_and_credentials(self, num_profiles):
        for _ in range(num_profiles):
            try:
                profile_id = self.wifi_dut.interfaces.wifi.sl_net_get_profile(_)
                credential_id = self.wifi_dut.interfaces.wifi.sl_net_get_credential(
                    _ + 1
                )
                logger().info(
                    f"\n Profile ID: {profile_id} and Credential ID: {credential_id} \n"
                )
            except Exception as e:
                logger().info(f"Exception while getting profiles: {e}")
                break

    def set_profiles_and_credentials(self, profiles, expect_error=False, error_code=None):

            logger().info("profiles :{profiles}")
            logger().info(f"length of profiles :{len(profiles)}")

            for i in range(len(profiles)):
                logger().info(f"Profile {i + 1} :")
                logger().info(f"SSID : {profiles[i]['ssid']}")
                logger().info(f"Security : {profiles[i]['security']}")
                logger().info(f"Passphrase : {profiles[i]['passphrase']}")
                self.wifi_dut.interfaces.wifi.sl_net_set_profile(
                    ssid=profiles[i]['ssid'],
                    # channel=profiles[i]['channel'],
                    security=Map_secrity[profiles[i]['security']],
                    credential_id=i + 1,
                    priority=i + 1,
                    profile_id=i,
                    encryption=profiles[i]['encryption_type'],
                    expected_status="SL_STATUS_OK" if not expect_error else error_code,
                ),
                self.wifi_dut.interfaces.wifi.sl_net_set_credential(credential=profiles[i]['passphrase'], cred_id=i + 1)


    def verfiy_auto_join_functionality(self, skip_power_save=False):

        logger().info("verifying auto join functionality")

        if len(self.profiles) > 1:
            custom_order = list(range(1, len(self.profiles))) + [0]

            for i in custom_order:

                logger().info("deinitializing the wlan interface in client mode")
                self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.cleanup_ble()
                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                self.wifi_dut.interfaces.wifi.init(mode="client")
                self.wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=3584, buffer_len=1600,
                                                                priority=8)
                self.wifi_dut.interfaces.wifi.initialize_thread(thread_id=1, stack_len=3584, buffer_len=1600,
                                                                priority=8)
                self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

                # self.wifi_dut.interfaces.wifi.init(mode="client")

                self.set_rejoin_params()

                self.set_profiles_and_credentials(profiles=[self.profiles[0]])

                self.get_profiles_and_credentials(num_profiles=len(self.profiles))

                logger().info(f"Profile {i} :")
                logger().info(f"SSID : {self.profiles[i]['ssid']}")
                logger().info(f"Security : {self.profiles[i]['security']}")
                logger().info(f"Passphrase : {self.profiles[i]['passphrase']}")
                self.wifi_access_point.interfaces.wifi.start_ap(ssid=self.profiles[i]['ssid'],
                                                       security=self.profiles[i]['security'],
                                                       passphrase=self.profiles[i]['passphrase'],
                                                       channel=self.profiles[i]['channel'])
                logger().info("waiting for 60 seconds for AP to come up")
                time.sleep(60)
                self.join_to_ap()

                if i!=0:

                    tw = Stopwatch()
                    auto_join_status = False

                    logger().info("DUT should auto join to saved profile after AP is up")

                    while tw.elapsed_sec < 120:
                        events = self.wifi_dut.interfaces.wifi.get_async_events()
                        for event in events:
                            logger().info(f"---------------->Event Data: {event.event_data}")
                            event_data = event.event_data
                            if "CONNECTED TO AP" in event_data:
                                logger().info(f"DUT connected to AP with profile {i}")
                                auto_join_status = True
                                break

                            if "FAILED TO CONNECT TO AP" in event_data:
                                logger().info(f"DUT Failed to connect to AP with profile {i}")
                                auto_join_status = False
                                break
                            time.sleep(0.1)
                        if auto_join_status:
                            break
                    assert auto_join_status, f"DUT failed to auto join AP with profile {i}...."

        if len(self.profiles) == 1:
            logger().info("deinitializing the wlan interface in client mode")
            self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")

            self.wifi_dut.interfaces.wifi.cleanup_ble()

            time.sleep(10)

            logger().info("Initialising DUT after the reset....")
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True
            self.wifi_dut.interfaces.wifi.init(mode="client")
            # self.wifi_dut.interfaces.wifi.initialize_thread()

            self.wifi_dut.interfaces.wifi.initialize_thread(thread_id=0, stack_len=3584, buffer_len=1600,
                                                            priority=8)
            self.wifi_dut.interfaces.wifi.initialize_thread(thread_id=1, stack_len=3584, buffer_len=1600,
                                                            priority=8)
            self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True

            self.set_profiles_and_credentials(profiles=[self.profiles[0]])


            self.get_profiles_and_credentials(num_profiles=len(self.profiles))

            self.wifi_access_point.interfaces.wifi.stop_ap()
            logger().info("Turn ON AP with same profile")
            # self.wifi_access_point.interfaces.wifi.disconnect_devices(
            #     mac_address=self.dut_mac_address
            # )

            self.wifi_access_point.interfaces.wifi.start_ap(ssid=self.profiles[0]['ssid'],
                                                            security=self.profiles[0]['security'],
                                                            passphrase=self.profiles[0]['passphrase'],
                                                            channel=self.profiles[0]['channel'])
            logger().info("waiting for 20 seconds for AP to come up")

            logger().info(f"Turn OF AP ")
            self.join_to_ap()

    def set_join_feature_bitmap(self):

        self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                  Si91xJoinFeatureBitMap.ListenIntervalFromJoin)

    def join_to_ap(self):
        logger().info("Joining to the access point")
        for count in range(0, 3):
            try:
                self.wifi_dut.interfaces.wifi.sl_net_up(mode="client", profile_id=0xFF)
                self.wifi_dut.interfaces.wifi.associated = True
                break
            except Exception as e:
                logger().info(f"Exception while bringing up the Wi-Fi interface: {e}")
                self.wifi_dut.interfaces.wifi.associated = False
                time.sleep(5)
        assert self.wifi_dut.interfaces.wifi.associated, "DUT NOT ASSOCIATED TO AP......"
        logger().info("DUT Associated to AP successfully")

        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"ap_bssid : {self.ap_mac_address}")

        self.wifi_dut.interfaces.wifi.is_external_stack_enabled = False

        ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=3,
                                                                ip_version="ipv4")

        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Device IP Address: {self.device_ip}")
        status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=self.ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"


    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def sniffer_validation_join(self, de_auth=False):
        sniff_obj = SnifferValidationProcess(
            wifi_sniffer=self.wifi_sniffer,
            wifi_access_point=self.wifi_access_point,
            dut_mac_address=self.dut_mac_address,
            ap_mac_address=self.ap_mac_address,
            sniffer_filter=self.sniffer_filter,
            sl_collections=self.sl_collections,
        )
        sniff_obj.sniffer_validation_join(tcp_ip_bypass=self.tcp_ip_bypass)
        if de_auth:
            sniff_obj.sniffer_validation_deauth()

    def sniffer_validation_scan(self):
        sniff_obj = SnifferValidationProcess(
            wifi_sniffer=self.wifi_sniffer,
            wifi_access_point=self.wifi_access_point,
            dut_mac_address=self.dut_mac_address,
            ap_mac_address=self.ap_mac_address,
            sniffer_filter=self.sniffer_filter,
            sl_collections=self.sl_collections,
        )
        sniff_obj.sniffer_validation_scan()

    def ping(self):
        logger().info("Initiating ping from Raspi to DUT to check stability")
        status = ping(self.device_ip, 30, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def run(self):

        if self.test_type == "scan":
            logger().info("Running scan in a thread for multiple times")
            self.check_scan_functionality()

        if self.test_type == "ping":
            logger().info("Initiating ping from Raspi to DUT to check stability")
            status = ping(self.device_ip, 30, size=300)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type == "iperf":
            self.join_to_ap()
            logger().info("Running data transfer")
            self.run_traffic()

        if self.test_type == "http":
            if not self.wifi_dut.interfaces.wifi.associated:
                self.join_to_ap()
            logger().info("http download")
            self.run_http_download()
        if self.test_type == "http_get":
            self.join_to_ap()
            self.http_get()


def wifi_dut_marker(ext_custom_bit=0, tcp_feat_bit=0, ext_tcp_feat_bit=0,
                    ca_cert=None, eap_cert=None, wifi_stack_len=3584,
                    ble_stack_len=3584, oper_mode=0):
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
            "ble": {"count": 1, "stack_len": ble_stack_len, "priority": 8},
        },
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if eap_cert:
        config["eap_cert"] = eap_cert
    return pytest.mark.config("wifi_dut", wifi=config)


Map_secrity = {"OPEN": 0, "WPA": 1, "WPA2": 2, "WEP": 3, "WPA_ENTERPRISE": 4,  "WPA2_ENTERPRISE": 5,
               "WPA_WPA2_MIXED": 6, "WPA3": 7, "WPA3_TRANSITION": 8, "WPA3_ENTERPRISE": 9,
               "WPA3_TRANSITION_ENTERPRISE": 10}



@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client",  "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "ssid_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "ssid_profile1", "security": "WPA2", "passphrase": "1234567890", "channel": 1}
)
def test_sta_ble_store_config_1_profile_ble_adv_nvm3_C769742(wifi_dut, wifi_access_point,
                                                          wifi_sniffer, sl_collections, sniffer_filter,
                                                          utf_constants, ble_client, request,
                                                          wifi_client, profiles):
    """
       Test Case: test_sta_ble_store_config_1_profile_ble_adv_20ms_C769724

       Description:
           This test validates auto join functionality of DUT with single saved profile while performing
            BLE advertising with a 20ms interval.

       Test Steps:
           1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
           2. Perform BLE advertising with a 20ms interval.
           3. Set advanced Wi-Fi client configurations on the DUT.
           4. Start the access point with the specified profile configuration.
           5. Store 1 Wi-Fi profile on the DUT with SSID, security, and passphrase.
           6. Bring up the Wi-Fi interface on the DUT using the stored profile.
           7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
           8. Perform a ping test to verify network connectivity.
           9. Enable power save and check ping
           10. Turn OFF AP and immediately TURN ON AP with the same profile.
           11. Validate the DUT's ability to reconnect to the access point and obtain an IP address via DHCP.
           12. Perform a ping test to verify network connectivity after reconnection.
           9. clean up resources.

       """


    try:
        test_name = "test_sta_ble_store_config_1_profile_ble_adv_20ms_nvm3"
        test_type = "ping"
        logger().info("Starting test: " + test_name)
        iter_count = utf_constants.get("iter_count")
        ping_count = utf_constants.get("ping_count")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            profiles=profiles,
        )

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_from_remote_device",
            ble_adv_int_max=20,
            ble_adv_int_min=20
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        ble_obj.advertise_dut()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        wifi_obj.join_to_ap()
        logger().info("DUT should auto join to saved profile after AP is up")
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_from_remote_device",
            ble_adv_int_max=20,
            ble_adv_int_min=20
        )
        ble_obj.advertise_dut()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)




@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client",  "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA3", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "12345678",
                               "protected_management_frame": "Required"
                               }
)
def test_sta_ble_store_config_2_profiles_ble_scan_C769743(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles):

    try:
        test_name = "test_sta_ble_store_config_2_profiles_ble_scan_si_10240ms_sw_3413_C769726"
        logger().info("Starting test: " + test_name)
        test_type = "ping"
        iter_count = utf_constants.get("iter_count")
        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            profiles=profiles,
        )

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            ble_scan_interval=120,
            ble_scan_window=40,

        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.join_to_ap()
        logger().info("DUT should auto join to saved profile after AP is up")
        wifi_obj.verfiy_auto_join_functionality()
        ble_client.interfaces.bluetooth.stop_advertising()
        ble_client.interfaces.bluetooth.close()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            ble_scan_interval=10240,
            ble_scan_window=3413,

        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        logger().info("Initiating stop scan from dut")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating stop advertise from Remote device")
        ble_client.interfaces.bluetooth.stop_advertising()
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:

        if ble_obj is not None:
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA3", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "12345678",
                               "protected_management_frame": "Required"
                               }
)

def test_sta_ble_store_config_2_profiles_ble_peripheral_200ms_nvm3_C769740(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles):


    try:
        test_name = "test_sta_ble_store_config_2_profiles_ble_peripheral_200ms_nvm3_C769740"
        logger().info("Starting test: " + test_name)
        test_type = "ping"
        iter_count = utf_constants.get("iter_count")
        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            profiles=profiles,
        )

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_interval=200,
            set_smp=0,
            ble_pairing=1
        )

        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.join_to_ap()
        logger().info("DUT should auto join to saved profile after AP is up")
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_interval=200,
            set_smp=0,
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="remote")
        wifi_obj.ping()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)




@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA3", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "12345678",
                               "protected_management_frame": "Required"
                               }
)

def test_sta_ble_store_config_2_profiles_ble_central_250ms_nvm3_C769741(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles):


    try:
        test_name = "test_sta_ble_store_config_2_profiles_ble_peripheral_250ms_nvm3_C769740"
        logger().info("Starting test: " + test_name)
        test_type = "ping"
        iter_count = utf_constants.get("iter_count")
        ping_count = utf_constants.get("ping_count")

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            profiles=profiles,
        )

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            conn_interval=250,
            set_smp=1,
            ble_pairing=1
        )

        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.join_to_ap()
        logger().info("DUT should auto join to saved profile after AP is up")
        wifi_obj.verfiy_auto_join_functionality()
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        wifi_obj.set_power_save()
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            conn_interval=250,
            set_smp=1,
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_obj.ping()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)

