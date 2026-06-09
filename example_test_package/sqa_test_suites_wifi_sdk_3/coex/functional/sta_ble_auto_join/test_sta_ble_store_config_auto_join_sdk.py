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
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.sl_status import SLStatus

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

# from test_sta_ble_dle_sdk import (
#     logger,
#     BleThread,
#     WifiJoinThread,
#     SnifferValidationProcess
# )

from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_dle_sdk import (logger,
    BleThread,
    WifiJoinThread,
    SnifferValidationProcess)
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble_provisioning.test_sta_ble_provisioning_sdk import (
    ProvisioningFunctionality)
from random import randint
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xMqttQos
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService


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
                channel=profiles[i]['channel'],
                security=Map_security[profiles[i]['security'].upper()],
                credential_id=i + 1,
                priority=i + 1,
                profile_id=i,
                encryption=profiles[i]['encryption_type'],
                expected_status="SL_STATUS_OK" if not expect_error else error_code,
            ),
            self.wifi_dut.interfaces.wifi.sl_net_set_credential(credential=profiles[i]['passphrase'], cred_id=i + 1)

    def get_profiles_and_credentials(self, num_profiles):
        for j in range(num_profiles):
            try:
                profile_id = self.wifi_dut.interfaces.wifi.sl_net_get_profile(j)
                credential_id = self.wifi_dut.interfaces.wifi.sl_net_get_credential(
                    j + 1
                )
                logger().info(
                    f"\n Profile ID: {profile_id} and Credential ID: {credential_id} \n"
                )
            except Exception as e:
                logger().info(f"Exception while getting profiles: {e}")
                break

    def verfiy_auto_join_functionality(self, skip_profile0=False):

        if len(self.profiles) > 1:
            if skip_profile0:
                custom_order = list(range(1, len(self.profiles)))
            else:
                custom_order = list(range(1, len(self.profiles))) + [0]
            for i in custom_order:
                logger().info(f"Profile {i} :")
                logger().info(f"SSID : {self.profiles[i]['ssid']}")
                logger().info(f"Security : {self.profiles[i]['security']}")
                logger().info(f"Passphrase : {self.profiles[i]['passphrase']}")
                since_time = time.perf_counter_ns()
                # self.wifi_access_point.interfaces.wifi.stop_ap()
                # self.wifi_access_point.interfaces.wifi.disconnect_devices(
                #     mac_address=self.dut_mac_address
                # )
                self.wifi_access_point.interfaces.wifi.start_ap(ssid=self.profiles[i]['ssid'],
                                                       security=self.profiles[i]['security'],
                                                       passphrase=self.profiles[i]['passphrase'],
                                                       channel=self.profiles[i]['channel'])

                tw = Stopwatch()
                auto_join_status = False

                logger().info("DUT should auto join to saved profile after AP is up")

                while tw.elapsed_sec < 120:
                    events = self.wifi_dut.interfaces.wifi.get_async_events()
                    for event in events:
                        logger().info(f"---------------->Event Data: {event.event_data}")
                        event_data = event.event_data
                        # logger().info(f"Event found: {event_data}")
                        # if "IN PROGRESS" in event_data:
                        #     logger().info(f"Auto join process started with event: {event_data} for profile {i}")
                        if "CONNECTED TO AP" in event_data:
                            logger().info(f"DUT connected to AP with profile {i}")
                            auto_join_status = True
                            break

                        if "FAILED TO CONNECT TO AP" in event_data:
                            logger().info(f"DUT Failed to connect to AP with profile {i}")
                            # self.wifi_access_point.interfaces.wifi.disconnect_devices(
                            #     mac_address=self.dut_mac_address
                            # )
                            auto_join_status = False
                            continue
                        time.sleep(0.1)
                    if auto_join_status:
                        break
                assert auto_join_status, f"DUT failed to auto join AP with profile {i}...."
                time.sleep(10)
                self.ping()

        if len(self.profiles) == 1:
            logger().info(f"Turn OF AP ")
            self.wifi_access_point.interfaces.wifi.stop_ap()
            logger().info("Turn ON AP with same profile")
            self.wifi_access_point.interfaces.wifi.start_ap()
            logger().info("DUT should auto join to saved profile after AP is up")
            tw = Stopwatch()
            auto_join_status = False

            logger().info("DUT should auto join to saved profile after AP is up")

            while tw.elapsed_sec < 120:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    logger().info(f"---------------->Event Data: {event.event_data}")
                    event_data = event.event_data
                    # logger().info(f"Event found: {event_data}")
                    # if "IN PROGRESS" in event_data:
                    #     logger().info(f"Auto join process started with event: {event_data} for profile {i}")
                    if "CONNECTED TO AP" in event_data:
                        logger().info(f"DUT connected to AP with same profile ")
                        auto_join_status = True
                        break

                    if "FAILED TO CONNECT TO AP" in event_data:
                        logger().info(f"DUT Failed to connect to AP with same profile")
                        auto_join_status = False
                        break
                    time.sleep(0.1)
                if auto_join_status:
                    break
            assert auto_join_status, f"DUT failed to auto join AP with same profile...."


    def join_to_ap(self, skip_power_save=False):

            # if skip_power_save:
            #     pwr_save = False
            # else:
            #     pwr_save = self.power_save
            #     self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
            #                                                           Si91xJoinFeatureBitMap.ListenIntervalFromJoin)

            # self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            #     join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
            for count in range(0, 3):
                try:
                    self.wifi_dut.interfaces.wifi.sl_net_up(mode="client", profile_id=0xFF)
                    self.wifi_dut.interfaces.wifi.associated = True
                    break
                except Exception as e:
                    logger().info(f"Exception while bringing up the Wi-Fi interface: {e}")
                    self.wifi_dut.interfaces.wifi.associated = False
                    time.sleep(5)
                    # if count == 2:
                    #     self.wifi_dut.interfaces.wifi.is_dut_bad_state = True
                    #     raise
            if not self.wifi_dut.interfaces.wifi.associated:
                self.wifi_dut.interfaces.wifi.is_dut_bad_state = True

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

            self.wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()


    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")

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
        # logger().info("Initiating ping from Raspi to DUT to check stability")
        # status = ping(self.device_ip, 30, size=300)
        # assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        for count in range(0, 3):
            logger().info(f"=======>>>>>Pinging the DUT from remote side....")
            status = ping(self.device_ip, 30, size=300)
            if status:
                break
            else:
                client_interface = self.wifi_client.interfaces.wifi.config["interface"]
                logger().info(f"=======>>>>>DUT NOT RESPONDING FOR PING REQUEST......")
                logger().info(f"=======>>>>>Disabling the ethernet adaptor at remote side....")
                self.wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {client_interface} down")
                time.sleep(10)
                logger().info(f"=======>>>>>Enabling the ethernet adaptor at remote side....")
                self.wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {client_interface} up")
                self.wifi_client.interfaces.wifi.shell.execute(f"sudo iptables -F")
                time.sleep(20)

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
            self.run_traffic(protocol=self.protocol, traffic_type=self.traffic_type)

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
                    ble_stack_len=3584, oper_mode=0, config_feature=0, num_peripheral_connections=1,
                    num_central_connections=1):
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
        "thread_config": {
            "wifi": {"count": 1, "stack_len": wifi_stack_len, "priority": 8},
            "ble": {"count": 1, "stack_len": ble_stack_len, "priority": 8},
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
    "WPAEnterprise": 4,
    "WPA2Enterprise": 5,
    "WPA_WPA2_MIXED": 6,
    "WPA3": 7,
    "WPA3_TRANSITION": 8,
    "WPA3Enterprise": 9,
    "WPA3_TRANSITION_ENTERPRISE": 10,
}


@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client","cleanup_ble"]
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
@pytest.mark.test_src_map_id('C769724')
def test_sta_ble_store_config_1_profile_ble_adv_20ms_C769724(wifi_dut, wifi_access_point,
                                                             wifi_sniffer,
                                                             sl_collections,
                                                             sniffer_filter,
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
        test_name = "test_sta_ble_store_config_profile1_ble_adv_20ms_C769724"
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
        ble_obj.advertise_dut()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        wifi_sniffer.interfaces.capture.stop_capture()

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
@pytest.mark.test_src_map_id('C769725')
def test_sta_ble_store_config_2_profiles_ble_adv_500ms_C769725(wifi_dut, wifi_access_point,
                                                                 wifi_sniffer, sl_collections, sniffer_filter,
                                                                 utf_constants, ble_client, request,
                                                                 wifi_client, profiles):
    """
    Test Case: test_sta_ble_store_config_2_profiles_ble_adv_500ms_C769725

    Description:
        This test validates the ability of the DUT to store multiple Wi-Fi profiles and perform BLE advertising
        with a 500ms interval while maintaining connectivity to an access point.

     Test Steps:
           1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
           2. Perform BLE advertising with a 500ms interval.
           3. Set advanced Wi-Fi client configurations on the DUT.
           4. Start the access point with the specified profile configuration.
           5. Store 1 Wi-Fi profile on the DUT with SSID, security, and passphrase.
           6. Bring up the Wi-Fi interface on the DUT using the stored profile.
           7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
           8. Perform a ping test to verify network connectivity.
           9. Enable power save and check ping
           10. Turn OFF AP and immediately TURN ON AP with the 2nd profile.
           11. Validate the DUT's ability to reconnect to the access point with profile2 and obtain an IP address via DHCP.
           12. Perform a ping test to verify network connectivity after reconnection.
           9. clean up resources.

    """

    try:
        test_name = "test_sta_ble_store_config_2_profiles_ble_adv_500ms_C769725"
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
            ble_test_type="scan_from_remote_device",
            ble_adv_int_max=500,
            ble_adv_int_min=500
        )
        ble_obj.advertise_dut()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        wifi_obj.join_to_ap()
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        if ble_obj is not None:
            # ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
@pytest.mark.test_src_map_id('C769726')
def test_sta_ble_store_config_2_profiles_ble_scan_si_10240ms_sw_3413_C769726(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles):

    """
    Test Case: test_sta_ble_store_config_2_profiles_ble_scan_si_10240ms_sw_3413_C769726

    Description:
        This test validates the ability of the DUT to store multiple Wi-Fi profiles and perform BLE scanning
        with a scan interval of 10240ms and a scan window of 3413ms while maintaining connectivity to an access point.

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Perform BLE scanning with a scan interval of 10240ms and a scan window of 3413ms.
        3. Set advanced Wi-Fi client configurations on the DUT.
        4. Start the access point with the specified profile configuration.
        5. Store multiple Wi-Fi profiles on the DUT with SSID, security, and passphrase.
        6. Bring up the Wi-Fi interface on the DUT using the stored profiles.
        7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
        8. Perform a ping test to verify network connectivity.
        9. Enable power save and check ping.
        10. Validate the DUT's ability to reconnect to the access point with the stored profiles.
        11. Perform a ping test to verify network connectivity after reconnection.
        12. Stop BLE scanning and advertising.
        13. Perform sniffer validation for join functionality.
        14. Clean up resources.

    """

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
            ble_scan_interval=10240,
            ble_scan_window=3413,

        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.join_to_ap()
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
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
            # ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W, wifi_stack_len=3584, ble_stack_len=3584)
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
@pytest.mark.test_src_map_id('C769727')
def test_sta_ble_store_config_2_profiles_ble_master_250ms_C769727(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles):

    """
    Test Case: test_sta_ble_store_config_2_profiles_ble_master_250ms_C769727

    Description:
        This test validates the ability of the DUT to store multiple Wi-Fi profiles
         after BLE connection with connection interval of 250ms
         while maintaining connectivity to an access point.

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Connect DUT as BLE master with connection interval os 250ms.
        3. Set advanced Wi-Fi client configurations on the DUT.
        4. Start the access point with the specified profile configuration.
        5. Store multiple Wi-Fi profiles on the DUT with SSID, security, and passphrase.
        6. Bring up the Wi-Fi interface on the DUT using the stored profiles.
        7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
        8. Perform a ping test to verify network connectivity.
        9. Enable power save and check ping.
        10. Validate the DUT's ability to reconnect to the access point with the stored profiles.
        11. Perform a ping test to verify network connectivity after reconnection.
        12. Stop BLE scanning and advertising.
        13. Perform sniffer validation for join functionality.
        14. Clean up resources.

    """
    try:
        test_name = "test_sta_ble_store_config_2_profiles_ble_master_250ms_C769727"
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
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.join_to_ap()
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        ble_obj.ble_disconnect(disconnect_from="dut")
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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

@pytest.mark.test_src_map_id('C769728')
def test_sta_ble_store_config_2_profiles_ble_slave_30ms_C769728(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles):

    """
    Test Case: test_sta_ble_store_config_2_profiles_ble_slave_30ms_C769728

    Description:
        This test validates the ability of the DUT to store multiple Wi-Fi profiles
         after BLE connection as slave with connection interval of 30ms
         while maintaining connectivity to an access point.

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Connect DUT as BLE slave with connection interval os 30ms.
        3. Set advanced Wi-Fi client configurations on the DUT.
        4. Start the access point with the specified profile configuration.
        5. Store multiple Wi-Fi profiles on the DUT with SSID, security, and passphrase.
        6. Bring up the Wi-Fi interface on the DUT using the stored profiles.
        7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
        8. Perform a ping test to verify network connectivity.
        9. Enable power save and check ping.
        10. Validate the DUT's ability to reconnect to the access point with the stored profiles.
        11. Perform a ping test to verify network connectivity after reconnection.
        12. Stop BLE scanning and advertising.
        13. Perform sniffer validation for join functionality.
        14. Clean up resources.

    """
    try:
        test_name = "test_sta_ble_store_config_2_profiles_ble_slave_30ms_C769728"
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
            conn_interval=30,
            set_smp=0,
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        wifi_obj.join_to_ap()
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        ble_obj.ble_disconnect(disconnect_from="remote")
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:

        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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

@pytest.mark.test_src_map_id('C769730')
def test_sta_ble_store_config_2_profiles_ble_slave_100ms_notify_C769730(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles):

    """
    Test Case: test_sta_ble_store_config_2_profiles_ble_slave_100ms_notify_C769730

    Description:
        This test validates the ability of the DUT to store multiple Wi-Fi profiles
         after BLE connection as slave with connection interval of 100ms and enable notification
         while maintaining connectivity to an access point.

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Connect DUT as BLE slave with connection interval os 100ms and start notifications.
        3. Set advanced Wi-Fi client configurations on the DUT.
        4. Start the access point with the specified profile configuration.
        5. Store multiple Wi-Fi profiles on the DUT with SSID, security, and passphrase.
        6. Bring up the Wi-Fi interface on the DUT using the stored profiles.
        7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
        8. Perform a ping test to verify network connectivity.
        9. Enable power save and check ping.
        10. Validate the DUT's ability to reconnect to the access point with the stored profiles.
        11. Perform a ping test to verify network connectivity after reconnection.
        12. Perform sniffer validation for join functionality.
        13. Clean up resources.

    """
    try:
        test_name = "test_sta_ble_store_config_2_profiles_ble_slave_100ms_notify_C769730"
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

        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )

        ble_obj.ble_connect(role="slave")
        ble_obj.service_discovery_on_remote()
        ble_obj.start()
        wifi_obj.join_to_ap()
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        wifi_dut.interfaces.wifi.memory_free(address1)
        ble_obj.ble_disconnect(disconnect_from="remote")
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C769731')
def test_sta_ble_store_config_2_profiles_TCP_TX_ble_slave_45ms_C769731(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles,  net_perf_client,
                                      protocol,):

    """
    Test Case: test_sta_ble_store_config_2_profiles_TCP_TX_ble_slave_45ms_C769731

    Description:
        This test validates the ability of the DUT to store multiple Wi-Fi profiles
         after BLE connection as slave with connection interval of 45ms
         while maintaining connectivity to an access point along with TCP TX data transfer.

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Connect DUT as BLE slave with connection interval os 30ms.
        3. Set advanced Wi-Fi client configurations on the DUT.
        4. Start the access point with the specified profile configuration.
        5. Store multiple Wi-Fi profiles on the DUT with SSID, security, and passphrase.
        6. Bring up the Wi-Fi interface on the DUT using the stored profiles.
        7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
        8. Perform a ping test to verify network connectivity.
        9. Enable power save and check ping.
        10. Run TCP TX data trnsfer from DUT to remote device.
        11. Validate the DUT's ability to reconnect to the access point with the stored profiles.
        12. Perform a ping test to verify network connectivity after reconnection.
        13. Again perform TCP TX data transfer from DUT to remote device.
        14. Perform sniffer validation for join functionality.
        15. Clean up resources.

    """
    try:
        test_name = "test_sta_ble_store_config_2_profiles_TCP_TX_ble_slave_45ms_C769731"
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
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
            traffic_type="TX",
            profiles=profiles,
        )

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_interval=45,
            ble_pairing=1,
            set_smp=0
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        wifi_obj.join_to_ap()
        wifi_obj.run_traffic()
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_obj.run_traffic()
        ble_obj.ble_disconnect(disconnect_from="remote")
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

        # wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")


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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.test_src_map_id('C769732')
def test_sta_ble_store_config_2_profiles_UDP_RX_ble_slave_45ms_C769732(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles,  net_perf_client,
                                      protocol,):

    """
    Test Case: test_sta_ble_store_config_2_profiles_UDP_RX_ble_slave_45ms_C769732

    Description:
        This test validates the ability of the DUT to store multiple Wi-Fi profiles
         after BLE connection as slave with connection interval of 45ms
         while maintaining connectivity to an access point along with UDP RX data transfer.

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Connect DUT as BLE slave with connection interval os 30ms.
        3. Set advanced Wi-Fi client configurations on the DUT.
        4. Start the access point with the specified profile configuration.
        5. Store multiple Wi-Fi profiles on the DUT with SSID, security, and passphrase.
        6. Bring up the Wi-Fi interface on the DUT using the stored profiles.
        7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
        8. Perform a ping test to verify network connectivity.
        9. Enable power save and check ping.
        10. Run UDP RX data trnsfer from DUT to remote device.
        11. Validate the DUT's ability to reconnect to the access point with the stored profiles.
        12. Perform a ping test to verify network connectivity after reconnection.
        13. Again perform UDP RX data transfer from DUT to remote device.
        14. Perform sniffer validation for join functionality.
        15. Clean up resources.

    """
    try:
        test_name = "test_sta_ble_store_config_2_profiles_TCP_TX_ble_slave_45ms_C769731"
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
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
            traffic_type="RX",
            profiles=profiles,
        )

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_interval=45,
            ble_pairing=1,
            set_smp=0
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        wifi_obj.join_to_ap()
        wifi_obj.run_traffic()
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_obj.run_traffic()
        ble_obj.ble_disconnect(disconnect_from="remote")
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:

        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)



@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["sl_net_deinit_client", "clear_certs", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "ssid_profile1", "channel": 1, "security": "WPA2Enterprise", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_EAP_TLS_ENCRYPTION"},
            {"ssid": "ssid_profile2", "channel": 1, "security": "WPA2Enterprise", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_EAP_TTLS_ENCRYPTION"},
        ),
    ],
)
@wifi_dut_marker(oper_mode=Si91xOperatingMode.EAPWiFiClient,
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 config_feature=Si91xConfigFeatureBitMap.TLS_V2,
                 # eap_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
                 wifi_stack_len=3584, ble_stack_len=3584)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "ssid_profile1", "security": "WPA2Enterprise", "passphrase": "12345678",
                               "channel": 1}
)
@pytest.mark.test_src_map_id('C769737')
def test_sta_ble_store_config_2_profiles_eap_ble_slave_200ms_C769737(wifi_dut, wifi_access_point,
                                      wifi_sniffer,
                                      sl_collections,
                                      sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles, radius_server):

    """
    Test Case: test_sta_ble_store_config_2_profiles_ble_slave_200ms_C769736

    Description:
        This test validates the ability of the DUT to store multiple Wi-Fi profiles
         after BLE connection as slave with connection interval of 200ms
         while maintaining connectivity to an access point.

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Connect DUT as BLE slave with connection interval os 30ms.
        3. Set advanced Wi-Fi client configurations on the DUT.
        4. Start the access point with the specified profile configuration.
        5. Store multiple Wi-Fi profiles on the DUT with SSID, security, and passphrase.
        6. Bring up the Wi-Fi interface on the DUT using the stored profiles.
        7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
        8. Perform a ping test to verify network connectivity.
        9. Enable power save and check ping.
        10. Validate the DUT's ability to reconnect to the access point with the stored profiles.
        11. Perform a ping test to verify network connectivity after reconnection.
        12. Stop BLE scanning and advertising.
        13. Perform sniffer validation for join functionality.
        14. Clean up resources.

    """
    try:
        test_name = "test_sta_ble_store_config_2_profiles_eap_ble_slave_200ms_C769737"
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
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.sl_net_set_profile(
            ssid=profiles[0]["ssid"],
            security=Map_security[profiles[0]["security"]],
            credential_id=5,
            priority=1,
            profile_id=0,
            channel=profiles[0]["channel"],
            encryption=5,
            expected_status="SL_STATUS_OK",
        )
        wifi_dut.interfaces.wifi.sl_net_set_profile(
            ssid=profiles[1]["ssid"],
            security=Map_security[profiles[1]["security"]],
            credential_id=5,
            priority=2,
            profile_id=1,
            channel=profiles[1]["channel"],
            encryption=6,
            expected_status="SL_STATUS_OK",
        )
        wifi_dut.interfaces.wifi.sl_net_set_eap_credential(
            username="user1",
            password="12345678",
            certificate_id=1,
            eap_flags=0,
            credential_id=5,
        )

        profile_id_0 = wifi_dut.interfaces.wifi.sl_net_get_profile(profile_id=0)
        profile_id_1 = wifi_dut.interfaces.wifi.sl_net_get_profile(profile_id=1)
        logger().info(
            f"\n The Profile ID 0: {profile_id_0} and Profile ID 1: {profile_id_1}"
        )
        wifi_dut.interfaces.wifi.set_ssl_certificate(
            str(get_tls_certificate_dir().joinpath("wifi-user.pem")),
            Si91xCertificateType.SL_NET_CERTIFICATE,
            Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID,
            cert_index=0,
        )
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()

        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()
        ble_obj.ble_disconnect(disconnect_from="remote")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)





@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.test_src_map_id('C769746')
def test_sta_ble_store_config_2_profiles_no_AP_configured_ble_peripheral_C769746(wifi_dut, wifi_access_point,
                                                                                   sl_collections,
                                                                                   utf_constants, ble_client,
                                                                                   request, wifi_client, profiles):
    """
    Test Case: test_sta_ble_store_config_2_profiles_no_AP_configured_ble_peripheral_C769746

    Description:
        This is a negative test case that validates DUT behavior when no AP is configured
        with saved credentials when DUT is connected as peripheral.

    Test Steps:
        1. Initialize wifi client interface using sl_net_init.
        2. Connect DUT as peripheral.
        3. Set credentials and profiles.
        4. Connect to AP.
        5. Turn OFF all APs.
        6. DUT will iterate through all profiles and credentials.
        7. DUT should throw error after iterating through all profiles.
        8. Check BLE connection stability and disconnect.

    """
    ble_obj = None
    try:
        test_name = "test_sta_ble_store_config_2_profiles_no_AP_configured_ble_peripheral_C769746"
        logger().info("Starting test: " + test_name)
        ping_count = utf_constants.get("ping_count")

        # Step 1-2: Connect DUT as peripheral
        logger().info("Step 1-2: Connecting DUT as peripheral")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1, bond_info=0)
        assert ble_dut_address is not None, "BLE initialization failed"

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_interval=30,  # 30ms
            set_smp=0,
            ble_pairing=1,
        )

        ble_obj.ble_connect(role="slave")

        # Step 3: Set credentials and profiles
        logger().info("Step 3: Setting credentials and profiles")
        for i in range(len(profiles)):
            wifi_dut.interfaces.wifi.sl_net_set_profile(
                ssid=profiles[i]['ssid'],
                channel=profiles[i]['channel'],
                security=Map_security[profiles[i]['security'].upper()],
                credential_id=i + 1,
                priority=i + 1,
                profile_id=i,
                encryption=profiles[i]['encryption_type'],
                expected_status="SL_STATUS_OK",
            )
            wifi_dut.interfaces.wifi.sl_net_set_credential(credential=profiles[i]['passphrase'], cred_id=i + 1)

        # Step 4: Connect to AP
        logger().info("Step 4: Connecting to AP")
        # wifi_dut.interfaces.wifi.sl_net_start_auto_join()
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=1,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )
        since_time = time.perf_counter_ns()
        # Step 6-7: DUT will iterate through all profiles and should throw error
        logger().info("Step 6-7: DUT will iterate through all profiles and should throw error")
        wifi_dut.interfaces.wifi.sl_net_up(mode="client", profile_id=0xFF, expected_status=SLStatus.SL_STATUS_FAIL)


        error_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 10:  # Wait up to 3 minutes for iteration through all profiles
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                logger().info(f"Event: {event_data}")
                if "FAILED TO CONNECT TO AP" in event_data or "ERROR" in event_data.upper():
                    logger().info(f"DUT threw error after iterating through all profiles: {event_data}")
                    error_found = True
                    break
            if error_found:
                break
            time.sleep(1)

        assert error_found, "DUT should throw error after iterating through all profiles when no APs are available"

        # Step 8: Check BLE connection stability and disconnect
        logger().info("Step 8: Checking BLE connection stability and disconnecting")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection should remain stable"
        ble_obj.ble_disconnect()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj:
            try:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                          ble_client_address=ble_obj.ble_client_address,
                                          ble_dut_address=ble_obj.ble_dut_address)
            except:
                pass
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)





@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "ssid_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "ssid_profile2", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "ssid_profile3", "channel": 1, "security": "WPA2", "passphrase": "123456789",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "ssid_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.test_src_map_id('C769745')
def test_sta_ble_store_config_more_than_max_profiles_ble_adv_20ms_C769745(wifi_dut, wifi_access_point,
                                      wifi_sniffer, sl_collections, sniffer_filter,
                                      utf_constants, ble_client, request,
                                      wifi_client, profiles):
    """
    Test Case: test_sta_ble_store_config_max_profiles_ble_adv_20ms_C769738

    Description:
        This test validates the ability of the DUT to store more than maximum number of Wi-Fi profiles (2 profiles)
        while performing BLE advertising with a 20ms interval.

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Perform BLE advertising with a 20ms interval.
        3. Set advanced Wi-Fi client configurations on the DUT.
        4. Start the access point with the specified profile configuration.
        5. Store 8 Wi-Fi profiles on the DUT with SSID, security, and passphrase.
        6. Bring up the Wi-Fi interface on the DUT using the stored profiles.
        7. Validate the DUT's ability to connect to the access point and obtain an IP address via DHCP.
        8. Perform a ping test to verify network connectivity.
        9. Enable power save and check ping.
        10. Turn OFF AP and immediately TURN ON AP with the same profile.
        11. Validate the DUT's ability to reconnect to the access point and obtain an IP address via DHCP.
        12. Perform a ping test to verify network connectivity after reconnection.
        13. Clean up resources.
    """
    try:
        test_name = "test_sta_ble_store_config_max_profiles_ble_adv_20ms_C769738"
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
        wifi_obj.set_profiles_and_credentials(profiles=profiles, expect_error=True,
                                              error_code="0x0027")  # SL_STATUS_INVALID_INDEX

        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:

        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
        for _ in range(2):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)



@wifi_dut_marker(num_peripheral_connections=1, num_central_connections=1, wifi_stack_len=2048, ble_stack_len=3584)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.test_src_map_id('C769729')
def test_sta_ble_store_config_2_profiles_ble_dual_role_80ms_160ms_C769729(wifi_dut, wifi_access_point,
                                                                          wifi_sniffer, sl_collections,
                                                                          sniffer_filter, utf_constants,
                                                                          ble_clients, request,
                                                                          wifi_client, profiles):
    """
    Test Case: test_sta_ble_store_config_2_profiles_ble_dual_role_80ms_160ms_C769729

    Description:
        This test validates auto join functionality of DUT with 2 saved profiles while performing
        BLE dual role connection (peripheral 80ms, central 160ms).

    Test Steps:
        1. Configure the DUT in WLAN coexistence mode for 2.4GHz.
        2. Store 2 profiles and credentials.
        3. Start auto join using sl_net_start_auto_join.
        4. Connect to AP using sl_net_up.
        5. Enable WLAN & BLE power save mode.
        6. Perform ping traffic.
        7. Connect DUT as peripheral with connection interval 80ms.
        8. Connect DUT as central with connection interval 160ms.
        9. Turn off connected AP (disconnect event).
        10. DUT should try connecting to other saved profiles.
        11. After connection, check DUT goes to power save mode and do ping.
        12. Disconnect remote BLE devices.
        13. Do sl_net_deinit.

    """
    ble_obj = None
    ble_obj_rx = None
    ble_obj_tx = None
    try:
        test_name = "test_sta_ble_store_config_2_profiles_ble_dual_role_80ms_160ms_C769729"
        logger().info("Starting test: " + test_name)
        test_type = "ping"
        ping_count = utf_constants.get("ping_count")

        # Step 7-8: Setup BLE dual role connections
        logger().info("Step 7-8: Setting up BLE dual role connections (peripheral 80ms, central 160ms)")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1, bond_info=0)
        assert ble_dut_address is not None, "BLE initialization failed"

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

        # Step 1-2: Store profiles and credentials
        logger().info("Step 1-2: Storing 2 profiles and credentials")
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))

        # Step 3-4: Start auto join and connect to AP
        logger().info("Step 3-4: Starting auto join and connecting to AP")
        # wifi_dut.interfaces.wifi.sl_net_start_auto_join()
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()

        # Step 5-6: Enable power save and perform ping
        logger().info("Step 5-6: Enabling power save and performing ping")
        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Create BleThread for Rx notifications (master/central role - 160ms)
        ble_obj_rx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=BLEDeviceState.Connected,
            data_duration=120,
            gatt=True,
            ble_pairing=1,
            bond_info=1,
            set_smp=1,
            ble_init_required=False,
            conn_interval=160,
            ble_dut_address=ble_dut_address,
        )

        # Create BleThread for Tx notifications (slave/peripheral role - 80ms)
        ble_obj_tx = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=BLEDeviceState.Connected,
            ble_pairing=1,
            gatt=True,
            conn_interval=80,  # 80ms in BLE units (80/1.25)
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        # Connect Rx thread (master) - ble_connect() handles all connection setup
        logger().info("Connecting as central (master) with 160ms interval")
        ble_obj_rx.ble_connect(role="master")

        # Connect Tx thread (slave) - ble_connect() handles all connection setup
        logger().info("Connecting as peripheral (slave) with 80ms interval")
        ble_obj_tx.ble_connect(role="slave")


        # Step 9-10: Turn off AP and verify auto join
        logger().info("Step 9-10: Turning off AP and verifying auto join functionality")
        wifi_obj.verfiy_auto_join_functionality()

        # Step 11: Verify power save and ping after reconnection
        logger().info("Step 11: Verifying power save and ping after reconnection")
        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Step 12: Disconnect BLE devices
        logger().info("Step 12: Disconnecting BLE devices")
        if ble_obj_rx:
            ble_obj_rx.ble_disconnect()
        if ble_obj_tx:
            ble_obj_tx.ble_disconnect()


    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj_rx:
            try:
                ble_clients[0].interfaces.bluetooth.remove_device(ble_obj_rx.ble_dut_address)
            except:
                pass
        if ble_obj_tx:
            try:
                ble_clients[1].interfaces.bluetooth.remove_device(ble_obj_tx.ble_dut_address)
            except:
                pass
        if ble_clients:
            try:
                ble_clients[0].interfaces.bluetooth.close()
            except:
                pass
        if ble_obj:
            try:
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                          ble_client_address=ble_obj.ble_client_address,
                                          ble_dut_address=ble_obj.ble_dut_address)
            except:
                pass
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
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
@pytest.mark.test_src_map_id('C769734')
def test_sta_ble_store_config_2_profiles_HTTP_download_ble_central_500ms_C769734(wifi_dut, wifi_access_point,
                                                                                 wifi_sniffer, sl_collections,
                                                                                 sniffer_filter, utf_constants,
                                                                                 ble_client, request,
                                                                                 wifi_client, profiles,
                                                                                 http_server, index_path):
    """
    Test Case: test_sta_ble_store_config_2_profiles_HTTP_download_ble_central_500ms_C769734

    Description:
        This test validates auto join functionality of DUT with 2 saved profiles while performing
        HTTP file download with BLE central connection (500ms connection interval).

    Test Steps:
        1. Initialize wifi client interface using sl_net_init.
        2. Store 2 profiles and credentials.
        3. Start auto join using sl_net_start_auto_join.
        4. Connect to AP using sl_net_up.
        5. Enable WLAN & BLE power save mode.
        6. Perform ping traffic.
        7. Connect DUT as central with connection interval 500ms.
        8. While data transfer is happening, turn off AP (disconnect event from AP1).
        9. DUT should try connecting to AP2 using saved profile and credentials.
        10. After connection, do ping.
        11. Start downloading 5MB file through HTTP.
        12. Check BLE connection state and disconnect.
        13. Do sl_net_deinit.

    """
    ble_obj = None
    try:
        test_name = "test_sta_ble_store_config_2_profiles_HTTP_download_ble_central_500ms_C769734"
        logger().info("Starting test: " + test_name)
        ping_count = utf_constants.get("ping_count")

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="http",
            profiles=profiles,
            http_server=http_server,
            index_path=index_path,
        )
        # Step 7: Connect DUT as central with 500ms connection interval
        logger().info("Step 7: Connecting DUT as central with 500ms connection interval")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1, bond_info=0)
        assert ble_dut_address is not None, "BLE initialization failed"

        data_rx = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=BLEDeviceState.Connected,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            data=data_rx,
            svc=svc,
            charc=charc,
            conn_interval=500,  # 500ms in BLE units (500/1.25)
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        # Step 1-2: Store profiles and credentials
        logger().info("Step 1-2: Storing 2 profiles and credentials")
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))

        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.ping()

        ble_obj.ble_connect(role="master")
        ble_obj.service_discovery_on_dut()
        ble_obj.start()

        # Step 8: While HTTP download is happening, turn off AP
        logger().info("Step 8: Starting HTTP download and turning off AP")
        # Start HTTP download in a thread
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        # Step 9-10: Verify auto join to AP2 and ping
        logger().info("Step 9-10: Verifying auto join to AP2 and ping")
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Step 11: Start downloading 5MB file through HTTP
        logger().info("Step 11: Starting HTTP download of 5MB file")
        wifi_obj.run_http_download()

        ble_obj.wait_for_exit()

        # Step 12: Check BLE connection state and disconnect
        logger().info("Step 12: Checking BLE connection state and disconnecting")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost"
        ble_obj.ble_disconnect()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj:
            try:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                          ble_client_address=ble_obj.ble_client_address,
                                          ble_dut_address=ble_obj.ble_dut_address)
            except:
                pass
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W, wifi_stack_len=3584, ble_stack_len=3584)
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
@pytest.mark.test_src_map_id('C769736')
def test_sta_ble_store_config_2_profiles_WPA2_WPA3_ble_peripheral_connect_disconnect_C769736(wifi_dut, wifi_access_point,
                                                                                             wifi_sniffer, sl_collections,
                                                                                             sniffer_filter, utf_constants,
                                                                                             ble_client, request,
                                                                                             wifi_client, profiles):
    """
    Test Case: test_sta_ble_store_config_2_profiles_WPA2_WPA3_ble_peripheral_connect_disconnect_C769736

    Description:
        This test validates auto join functionality of DUT with 2 saved profiles (WPA2, WPA3)
        while connecting and disconnecting BLE peripheral in a loop.

    Test Steps:
        1. Initialize wifi client interface using sl_net_init.
        2. Store 2 profiles and credentials (WPA2, WPA3).
        3. Connect DUT as peripheral.
        4. Start auto join using sl_net_start_auto_join.
        5. Connect to AP using sl_net_up.
        6. Enable WLAN & BLE power save mode.
        7. Advertise DUT and scan from remote device.
        8. Initiate connection from Remote with connection interval 30ms.
        9. Perform ping traffic.
        10. Do disconnect and connect BLE device in a loop.
        11. Turn off connected AP (disconnect event).
        12. DUT should try connecting to other saved profiles.
        13. After connection, check DUT goes to power save mode and do ping.
        14. Do sl_net_deinit.

    """
    ble_obj = None
    try:
        test_name = "test_sta_ble_store_config_2_profiles_WPA2_WPA3_ble_peripheral_connect_disconnect_C769736"
        logger().info("Starting test: " + test_name)
        ping_count = utf_constants.get("ping_count")


        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
            profiles=profiles,
        )

        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        wifi_obj.join_to_ap()

        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Step 3: Connect DUT as peripheral
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_interval=30,
            set_smp=0,
            ble_pairing=1,
            bond_info=0
        )

        ble_obj.ble_connect(role="slave")

        # Step 9: Perform ping traffic
        logger().info("Step 9: Performing ping traffic")
        wifi_obj.ping()

        auto_join = Thread(target=wifi_obj.verfiy_auto_join_functionality, args=(), )

        auto_join.start()

        # Step 10: Do disconnect and connect BLE device in a loop
        logger().info("Step 10: Disconnecting and connecting BLE device in a loop")
        for i in range(3):
            logger().info(f"BLE disconnect/connect iteration {i+1}")
            ble_obj.ble_disconnect()
            time.sleep(2)
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            time.sleep(10)
            # Step 3: Connect DUT as peripheral
            ble_obj = BleThread(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                sl_collections=sl_collections,
                ble_test_type="slave",
                conn_interval=30,
                set_smp=0,
                ble_pairing=1,
                bond_info=0
            )

            ble_obj.ble_connect(role="slave")
            time.sleep(2)
            # Verify BLE connection is stable
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, f"BLE connection lost during iteration {i+1}"

        auto_join.join()
        wifi_obj.set_power_save()
        wifi_obj.ping()

        ble_obj.ble_disconnect()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj:
            try:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                          ble_client_address=ble_obj.ble_client_address,
                                          ble_dut_address=ble_obj.ble_dut_address)
            except:
                pass
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)


@pytest.mark.mqtt_server("raspi_mosquitto")
@wifi_dut_marker(ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.test_src_map_id('C769738')
def test_sta_ble_store_config_2_profiles_MQTT_ble_central_C769738(wifi_dut, wifi_access_point,
                                                                  wifi_sniffer, sl_collections,
                                                                  sniffer_filter, utf_constants,
                                                                  ble_client, request,
                                                                  wifi_client, profiles,
                                                                  mqtt_server, mqtt_client):
    """
    Test Case: test_sta_ble_store_config_2_profiles_MQTT_ble_central_C769738

    Description:
        This test validates auto join functionality of DUT with 2 saved profiles while performing
        MQTT data transfer with BLE central connection.

    Test Steps:
        1. Initialize wifi client interface using sl_net_init.
        2. Connect DUT as central.
        3. Store 2 profiles and credentials.
        4. Get profiles and credentials.
        5. Start auto join using sl_net_start_auto_join.
        6. Connect to AP using sl_net_up.
        7. Enable WLAN & BLE power save mode.
        8. Perform ping traffic.
        9. Do MQTT publish in while loop.
        10. While data transfer is happening, turn off AP (disconnect event).
        11. DUT should try connecting back to AP using saved profile and credentials.
        12. After connection, do ping.
        13. Do MQTT publish for 3 iterations.
        14. Check BLE connection state and disconnect.
        15. Do sl_net_deinit.

    """
    ble_obj = None
    try:
        test_name = "test_sta_ble_store_config_2_profiles_MQTT_ble_central_C769738"
        logger().info("Starting test: " + test_name)
        ping_count = utf_constants.get("ping_count")
        topic = "mytesttopic"
        message = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
            profiles=profiles,
        )

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            set_smp=1,
            ble_pairing=1,
        )

        ble_obj.start()
        ble_obj.wait_for_exit()

        # Step 3-8: Store profiles, start auto join, connect to AP, enable power save, ping
        logger().info("Step 3-8: Storing profiles, starting auto join, connecting to AP, enabling power save, ping")
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.ping()

        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()

        sw = Stopwatch()
        while sw.elapsed_sec <= 60:

            logger().info("DUT publishes message over the topic")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                         timeout=20)
            mq = Stopwatch()
            match = None
            while mq.elapsed_sec < 20:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                for m in msgs:
                    if (
                        m.topic == topic
                        and m.qos == Si91xMqttQos.QOS1
                        and m.payload.decode() == message
                    ):
                        match = m
                        break
                if match:
                    break
            assert match is not None, (
                "No message is received by mqtt-client on subscribed topic or message received is wrong"
            )
            mqtt_client.interfaces.mqtt.received_messages.clear()

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()

        # Step 11-12: Verify auto join, ping
        logger().info("Step 11-12: Verifying auto join and ping")
        wifi_obj.verfiy_auto_join_functionality()
        wifi_obj.set_power_save()
        wifi_obj.ping()


        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))

        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)

        time.sleep(5)
        mqtt_client.interfaces.mqtt.received_messages.clear()

        tw = Stopwatch()
        while tw.elapsed_sec <= 60:

            logger().info("DUT publishes message over the topic")
            mqtt_client.interfaces.mqtt.received_messages.clear()
            wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1,
                                                         timeout=20)
            mq = Stopwatch()
            match = None
            while mq.elapsed_sec < 20:
                time.sleep(0.1)
                msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                for m in msgs:
                    if (
                        m.topic == topic
                        and m.qos == Si91xMqttQos.QOS1
                        and m.payload.decode() == message
                    ):
                        match = m
                        break
                if match:
                    break
            assert match is not None, (
                "No message is received by mqtt-client on subscribed topic or message received is wrong"
            )
            mqtt_client.interfaces.mqtt.received_messages.clear()

        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)

        wifi_dut.interfaces.mqtt.mqtt_client_disconnect()

        # Step 14: Check BLE connection state and disconnect
        logger().info("Step 14: Checking BLE connection state and disconnecting")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost"
        ble_obj.ble_disconnect()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj:
            try:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                          ble_client_address=ble_obj.ble_client_address,
                                          ble_dut_address=ble_obj.ble_dut_address)
            except:
                pass

        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)





@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 wifi_stack_len=3584,
                 ble_stack_len=3584,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
                 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.test_src_map_id('C769733')
def test_sta_ble_store_config_2_profiles_SSL_RX_ble_central_4s_C769733(wifi_dut, wifi_access_point,
                                                                      wifi_sniffer, sl_collections,
                                                                      sniffer_filter, utf_constants,
                                                                      ble_client, request,
                                                                      wifi_client, profiles, ssl_server):
    """
    Test Case: test_sta_ble_store_config_2_profiles_SSL_RX_ble_central_4s_C769733

    Description:
        This test validates auto join functionality of DUT with 2 saved profiles while performing
        SSL RX data transfer with BLE central connection (4s connection interval).

    Test Steps:
        1. Initialize wifi client interface using sl_net_init.
        2. Store 2 profiles and credentials.
        3. Connect DUT as central with connection interval 4s.
        4. Start auto join using sl_net_start_auto_join.
        5. Connect to AP using sl_net_up.
        6. Enable WLAN & BLE power save mode.
        7. Perform ping traffic.
        8. Create SSL socket, connect to server, receive data transfer in while loop.
        9. While data transfer is happening, turn off AP (disconnect event).
        10. DUT should try connecting to AP2 using saved profile and credentials.
        11. After connection, do ping.
        12. Again create SSL socket, connect to server, send 100 data packets.
        13. Check BLE connection state and disconnect.
        14. Do sl_net_deinit.

    """
    ble_obj = None
    try:
        test_name = "test_sta_ble_store_config_2_profiles_SSL_RX_ble_central_4s_C769733"
        logger().info("Starting test: " + test_name)
        ping_count = utf_constants.get("ping_count")

        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
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
            conn_interval=4000
        )

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
            profiles=profiles,
        )

        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )

        ble_obj.ble_connect(role="master")
        ble_obj.service_discovery_on_dut()
        ble_obj.start()

        # Step 4-7: Start auto join, connect to AP, enable power save, ping
        logger().info("Step 4-7: Starting auto join, connecting to AP, enabling power save, ping")
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Step 8: Create SSL socket and perform SSL RX data transfer
        logger().info("Step 8: Creating SSL socket and performing SSL RX data transfer")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip: {server_ip}")

        # Open SSL client socket in DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable SSL option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=local_port, timeout=15)
        # SSL socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)

        # Step 9: While data transfer is happening, turn off AP
        logger().info("Step 9: Turning off AP while SSL RX data transfer is happening")
        sw = Stopwatch()
        ssl_transfer_started = False
        while sw.elapsed_sec < 60:
            if not ssl_transfer_started:
                # Start SSL RX data transfer
                buffer_length = 100
                pkt_count = 1
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
                ssl_server.interfaces.ssl.send_data(1, pkt_count, buffer_length, message=tx_buffer)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
                assert tx_buffer == buffer_rx, f"Buffer sent by remote peer and received on socket {sock} is not matched"
                ssl_transfer_started = True
                logger().info("SSL RX data transfer started successfully")

            # Turn off AP after some data transfer
            if sw.elapsed_sec > 10:
                logger().info("Disconnecting from AP to trigger auto join")
                wifi_access_point.interfaces.wifi.disconnect_devices(mac_address=wifi_obj.dut_mac_address)
                break

            time.sleep(1)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()

        # Step 10: Verify auto join to AP2
        logger().info("Step 10: Verifying auto join to AP2")
        wifi_obj.verfiy_auto_join_functionality()

        # Step 11: Verify power save and ping after reconnection
        logger().info("Step 11: Verifying power save and ping after reconnection")
        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Step 12: Again create SSL socket and send 100 data packets
        logger().info("Step 12: Creating SSL socket again and sending 100 data packets")
        ssl_server.interfaces.ssl.start_server(port=port1)
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)

        # Send 100 data packets
        for i in range(100):
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(0.1)
            server_socket_no = 1
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
            assert data == data_receive.decode(), f"Data sent by DUT and received on server is not matching for packet {i+1}"

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()

        # Step 13: Check BLE connection state and disconnect
        logger().info("Step 13: Checking BLE connection state and disconnecting")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost"
        ble_obj.ble_disconnect()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj:
            try:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                          ble_client_address=ble_obj.ble_client_address,
                                          ble_dut_address=ble_obj.ble_dut_address)
            except:
                pass
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)





@wifi_dut_marker(ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.HTTPClient)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["load_default_fw"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.test_src_map_id('C769735')
def test_sta_ble_store_config_otaf_2_profiles_ble_slave_45ms_C769735(wifi_dut, wifi_access_point,
                                                                     wifi_sniffer, sl_collections,
                                                                     sniffer_filter, utf_constants,
                                                                     ble_client, request,
                                                                     wifi_client, profiles, http_server):
    """
    Test Case: test_sta_ble_store_config_otaf_2_profiles_ble_slave_45ms_C769735

    Description:
        This test validates auto join functionality of DUT with 2 saved profiles when DUT is
        connected as a peripheral with connection interval 45ms and then performs HTTP OTA
        firmware upgrade along with BLE notifications.

    Test Steps:
        1. Initialize wifi client interface using sl_net_init.
        2. Store 2 profiles and credentials.
        3. Connect DUT as peripheral with connection interval 45ms.
        4. Start auto join using sl_net_start_auto_join.
        5. Connect to AP using sl_net_up.
        6. Enable WLAN & BLE power save mode.
        7. Perform ping traffic.
        8. Perform HTTP OTA firmware upgrade along with BLE notifications.
        9. While OTAF is happening, turn off AP (disconnect event).
        10. DUT should try connecting to AP2 using saved profile and credentials.
        11. After connection, do ping.
        12. Check BLE connection stability and disconnect.
        13. Do sl_net_deinit.

    """
    ble_obj = None
    otaf_obj = None
    http_addr = None
    try:
        test_name = "test_sta_ble_store_config_otaf_2_profiles_ble_slave_45ms_C769735"
        logger().info("Starting test: " + test_name)
        ping_count = utf_constants.get("ping_count")

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
            profiles=profiles,
        )

        # Step 1-2: Store profiles and credentials
        logger().info("Step 1-2: Storing 2 profiles and credentials")
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))

        # Step 3: Connect DUT as peripheral with 45ms connection interval
        logger().info("Step 3: Connecting DUT as peripheral with 45ms connection interval")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=1, bond_info=0)
        assert ble_dut_address is not None, "BLE initialization failed"

        data_tx = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        allocated_mem_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(data_tx))
        wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data_tx), write_content=data_tx)

        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

        wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=BLEDeviceState.Connected,
            char_path=None,
            char_uid=char_uid,
            data=data_tx,
            service_uid=service_uid,
            data_length=20,
            data_duration=300,
            periodic_delay=0,
            ble_pairing=1,
            gatt=True,
            address=allocated_mem_addr,
            conn_interval=45,  # 45ms in BLE units (45/1.25)
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        ble_obj.ble_connect(role="slave")
        ble_obj.service_discovery_on_remote()

        # Step 4-7: Start auto join, connect to AP, enable power save, ping
        logger().info("Step 4-7: Starting auto join, connecting to AP, enabling power save, ping")

        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Step 8: Prepare HTTP OTAF
        logger().info("Step 8: Preparing HTTP OTA firmware upgrade")
        http_url = UtfConfig.instance().defaults["wifi"].get("http_url", None)
        assert http_url is not None, "http_url not configured in defaults"
        http_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(http_url) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=http_addr, size=len(http_url), write_content=http_url)

        fw_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f" ***** FW before upgrade: {fw_before_upgrade} *****")

        ble_obj.start()  # Start BLE notifications

        # Start OTAF in a thread
        otaf_obj = WlanOtaf(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            test_type="ping",
            sl_collections=sl_collections,
            ping_count=ping_count,
            timeout=300,
            http_server=http_server,
            https=0,
            http_addr=http_addr,
        )

        otaf_obj.start()

        # Step 10-11: Verify auto join to AP2 and ping
        logger().info("Step 10-11: Verifying auto join to AP2 and ping")
        wifi_obj.verfiy_auto_join_functionality(skip_profile0=True)

        try:
            otaf_obj.wait_for_exit()
        except Exception as e:
            logger().info("After auto join existing sockets may close , this is expected")

        wifi_obj.set_power_save()
        wifi_obj.ping()

        otaf_obj.start()
        otaf_obj.wait_for_exit()
        ble_obj.wait_for_exit()

        # Verify BLE notifications are still working
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost during OTAF"

        # Step 12: Check BLE connection stability and disconnect
        logger().info("Step 12: Checking BLE connection stability and disconnecting")
        ble_obj.ble_disconnect()

        otaf_obj.check_fw_version_after_upgrade()

        # Step 13: Deinit
        logger().info("Step 13: Performing sl_net_deinit")
        if http_addr:
            wifi_dut.interfaces.wifi.memory_free(http_addr)
        # wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if ble_obj:
            try:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                          ble_client_address=ble_obj.ble_client_address,
                                          ble_dut_address=ble_obj.ble_dut_address)
            except:
                pass

        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)




@wifi_dut_marker(wifi_stack_len=2041, ble_stack_len=3584)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "sl_net_deinit_client", "cleanup_ble"]
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
            {"ssid": "store_profile2", "channel": 1, "security": "WPA2", "passphrase": "12345678",
             "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION"},
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "store_profile1", "channel": 1, "security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.test_src_map_id('C769744')
def test_sta_ble_store_config_2_profiles_BLE_provisioning_peripheral_C769744(wifi_dut, wifi_access_point,
                                                                             wifi_sniffer, sl_collections,
                                                                             sniffer_filter, utf_constants,
                                                                             ble_client, request,
                                                                             wifi_client, profiles):
    """
    Test Case: test_sta_ble_store_config_2_profiles_BLE_provisioning_peripheral_C769744

    Description:
        This test validates auto join functionality through BLE provisioning when DUT is connected as peripheral.

    Test Steps:
        1. Initialize wifi client interface using sl_net_init.
        2. Connect DUT as peripheral.
        3. Send data with AP2 profile credentials through BLE notifications.
        4. Save the credentials in DUT with fetched credentials from BLE notifications.
        5. In sl_net_up, select auto join.
        6. Connect to AP1 using sl_net_up.
        7. Enable WLAN & BLE power save mode, perform ping traffic.
        8. Turn off AP1 (disconnect event) and turn on AP2.
        9. DUT should try connecting back to AP using saved profile and credentials.
        10. After connection, do ping.
        11. Check BLE connection stability and disconnect.
        12. Do sl_net_deinit.

    """
    ble_obj = None
    provisioning_obj = None
    try:
        test_name = "test_sta_ble_store_config_2_profiles_BLE_provisioning_peripheral_C769744"
        logger().info("Starting test: " + test_name)
        ping_count = utf_constants.get("ping_count")
        wifi_dut.interfaces["bluetooth"] = wifi_dut.interfaces.wifi

        wifi_obj = WifiAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ping",
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()

        # Step 3-4: Send AP2 profile credentials through BLE provisioning
        logger().info("Step 3-4: Sending AP2 profile credentials through BLE provisioning")
        provisioning_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            test_case=661503,
            ble_dut=wifi_dut,
            ble_pairing=0,
            utf_constants=utf_constants,
            wifi_access_point=wifi_access_point,
            # bt_dut_address=ble_dut_address,
            credentials={"ssid": profiles[0]["ssid"], "passphrase": profiles[0]["passphrase"],
                        "security": profiles[0]["security"]}
        )
        provisioning_obj.start()
        provisioning_obj.wait_for_exit()
        provisioning_obj.ble_remove_servie()

        # Verify credentials were saved
        logger().info("Verifying credentials were saved")
        profile_id = wifi_dut.interfaces.wifi.sl_net_get_profile(profile_id=0)
        credential_id = wifi_dut.interfaces.wifi.sl_net_get_credential(cred_id=1)
        logger().info(f"Profile ID: {profile_id}, Credential ID: {credential_id}")

        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Step 8-9: Reconfigure AP from profile 1 to profile 2; DUT should auto-join on the 2nd saved profile.
        logger().info("Step 8-9: Switching AP to store_profile2; waiting for DUT auto-join")
        since_time = time.perf_counter_ns()
        wifi_access_point.interfaces.wifi.start_ap(
            ssid=profiles[1]["ssid"],
            security=profiles[1]["security"],
            passphrase=profiles[1]["passphrase"],
            channel=profiles[1]["channel"],
        )

        auto_join_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 120 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if event_data and "CONNECTED TO AP" in event_data.upper():
                    logger().info("DUT connected to AP2 via auto join")
                    auto_join_status = True
                    break
            time.sleep(0.1)

        assert auto_join_status, "DUT failed to auto-join to AP2"
        wifi_dut.interfaces.wifi.associated = True

        # Configure IP after auto join
        ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False, retry_count=3, ip_version="ipv4")
        assert ip_status, f"Unable to assign IP ADDRESS: {ip_config}"
        wifi_obj.device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Device IP Address after auto join: {wifi_obj.device_ip}")

        # Step 10: After connection, do ping
        logger().info("Step 10: Performing ping after auto join")
        wifi_obj.set_power_save()
        wifi_obj.ping()

        # Step 11: Check BLE connection stability and disconnect
        logger().info("Step 11: Checking BLE connection stability and disconnecting")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost"
        # BLE connection is maintained through provisioning, disconnect if needed
        if provisioning_obj:
            try:
                ble_client.interfaces.bluetooth.disconnect_device(provisioning_obj.ble_client_address)
            except:
                pass

        # # Step 12: Deinit
        # logger().info("Step 12: Performing sl_net_deinit")
        # wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        if provisioning_obj:
            try:
                ble_client.interfaces.bluetooth.remove_device(provisioning_obj.ble_client_address)
            except:
                pass
        if ble_client:
            try:
                ble_client.interfaces.bluetooth.close()
            except:
                pass
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)



