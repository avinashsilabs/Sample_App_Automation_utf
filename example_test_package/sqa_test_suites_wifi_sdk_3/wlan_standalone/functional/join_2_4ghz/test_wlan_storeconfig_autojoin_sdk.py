import time
import pytest
import string
import random
import re
from threading import Thread
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
from utf.utils import get_tls_certificate_dir
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xJoinFeatureBitMap,
    Si91xMqttQos,
    Si91xOperatingMode,
    Si91xCertificateType,
    Si91xCertIdentifier,
)
from utf.interfaces.wifi import (
    SecurityMode,
    Standard,
    CountryCode,
)
from utf.utils.logger import get_logger
from utf import UtfDatabaseProperties
from utf_wiseconnect_3.tests.sl_status import SLStatus
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.security_enhancements.test_wlan_sta_enterprise_sdk import (
    SnifferValidationProcess,
)


def logger():
    return get_logger(__name__)


pytestmark = [
    pytest.mark.database_properties(
        UtfDatabaseProperties(
            test_result_type="FUNCTIONAL",
            feature_name="autojoin",
            module_name="wlan_storeconfig_autojoin",
            tool_chain="gcc",
            test_creation_date="2024-01-01",
            test_description="Wi-Fi store-config and auto-join (RAM/NVM) functional tests",
            iot_req_id="na",
            req_id="na",
        )
    ),
]



"""
Author: Achal Raghav

Description:
This file contains test cases for validating the Wi-Fi auto-join functionality and store configuration 
capabilities of the Wi-Fi SDK. The tests ensure the Device Under Test (DUT) can properly store 
Wi-Fi profiles and credentials, and automatically rejoin to access points when network conditions change.

Test Cases Overview:
- C769960: RAM auto-join with one profile and one credential (WPA2)
- C769961: RAM auto-join with WPA2/WPA two profiles
- C769962: RAM auto-join with WPA2/OPEN two profiles
- C769963: RAM auto-join after sl_net_deinit with WPA3
- C769994: RAM auto-join with WPA3 enterprise TLS PEAP security
- C769995: RAM auto-join with WPA2 enterprise TLS TTLS security
- C769974: RAM auto-join while doing SNTP data transfer
- C769975: RAM auto-join while doing MQTT over SSL data transfer
- C769980: RAM auto-join with incorrect PSK first try
- C769982: RAM auto-join with two profiles MBSSID
- C769984: RAM auto-join error with invalid credential
- C769985: RAM auto-join error with three profiles and credentials
- C769987: NVM auto-join with one profile and one credential (WPA2)
- C769988: NVM auto-join with WPA2/WPA two profiles
- C769989: NVM auto-join with WPA2/OPEN two profiles
- C769990: NVM auto-join after sl_net_deinit with WPA3
- C770001: NVM auto-join while doing SNTP data transfer
- C770002: NVM auto-join while doing MQTT over SSL data transfer
- C770007: NVM auto-join with incorrect PSK first try
- C770009: NVM auto-join with two profiles MBSSID
- C770011: NVM auto-join error with invalid credential
- C770012: NVM auto-join error with three profiles and credentials
- C769994: NVM auto-join with WPA3 enterprise TLS PEAP security
- C769995: NVM auto-join with WPA2 enterprise TLS TTLS security

Key Features Tested:
- Profile and credential storage in RAM vs NVM
- Auto-join functionality with multiple security types (WPA2, WPA3, OPEN)
- Auto-join during active data transfers (SNTP, MQTT)
- MBSSID (Multiple Basic Service Set Identifier) support
- Error handling for invalid credentials
- Power save mode integration
- Sniffer validation for connection establishment
- WPA3 management frame protection (PMF)
- Enterprise security (WPA2/WPA3 Enterprise)
- Firmware upgrade over-the-air (OTAF)
- AWS IoT shadow updates

Requirements:
- Python 3.x
- Pytest framework
- Wi-Fi DUT with auto-join and profile storage capabilities
- Access point and sniffer setup
- UTF test framework and dependencies
- MQTT server for SSL/TLS tests
- SNTP client functionality
- HTTP server for OTAF tests
- AWS IoT services for cloud connectivity tests
- Radius server for enterprise authentication
"""


class WLANAutoJoinThread(ThreadBase):

    def __init__(
        self,
        wifi_sniffer=None,
        wifi_dut=None,
        wifi_access_point=None,
        wifi_client=None,
        net_perf_client=None,
        protocol=None,
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
        aws_s3=None,
        index_path=None,
        http_client=None,
        https=0,
        scan_count=5,
        mac=None,
        async_socket=0,
        address=None,
        profiles=None,
        ssl_server=None,
        mqtt_server=None,
        mqtt_client=None,
        test_type=None,
        request=None,
        remote_socket_factory=None,
        http_addr=None,
        iter_count=None,
    ):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
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
        self.aws_s3 = aws_s3
        self.https = https
        self.index_path = index_path
        self.scan_count = scan_count
        self.async_socket = async_socket
        self.throughput_remote = None
        self.throughput_dut = None
        self.profiles = profiles
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        self.address = address
        self.ssl_server = ssl_server
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.request = request
        self.test_type = test_type
        self.remote_socket_factory = remote_socket_factory
        self.http_addr = http_addr
        self.status = None
        self.error_data = None
        self.topic = "mytesttopic"
        self.message = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=100)
        )
        self.iter_count = iter_count
        self.message_address = None
        self.topic_address = None
        self.server_port = None
        self.is_connection_encrypted = True
        self.address_dict = {
            "topic": [],
            "message": [],
        }
        self.sleep_time = None
        self.aws_host_name = "httpotaf.s3.us-east-2.amazonaws.com"
        logger().info(f"\n POWER SAVE FLAG IN HARNESS : {self.power_save}")

    def run(self):
        try:
            if self.test_type == "sntp":
                self.get_sntp_info()
                self.status = True
            if self.test_type == "iperf":
                self.transmit_data()
                self.status = True
            if self.test_type == "mqtt":
                self.mqtt_publish()
                self.status = True
            if self.test_type == "ssl":
                self.run_ssl_tx_traffic()
                self.status = True
            if self.test_type == "otaf":
                self.firmware_upgrade_otaf()
                self.status = True
        except Exception as exception:
            self.status = False
            self.error_data = exception

    def find_ssid_list_from_dut_scan(self, scan_type=False):
        # collect all ssid from DUT scan list
        ssid_list = []
        if scan_type:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan(
                channel=0,
                ssid=None,
                scan_bitmap_2_4=0,
                scan_type=2,
                bg_scan_periodicity=10,
            )
            logger().info(
                f"\n\n *** Start to collect all available ssid in DUT scan list ***\n\n"
            )
        else:
            self.scan_list = self.wifi_dut.interfaces.wifi.scan()
            logger().info(
                f"\n\n *** Start to collect all available ssid in DUT scan list ***\n\n"
            )

        for i in range(0, len(self.scan_list)):
            ssid_list.append(self.scan_list[i].ssid)
        return ssid_list

    def verify_T_and_NT_based_mbssid_in_dut_list(self, scan_type=False):
        # Validation for T and NT based MBSSID in DUT scan list & sniffer capture
        packet_filter2 = "                    SSID:"
        ssid_list = self.find_ssid_list_from_dut_scan(scan_type=scan_type)
        # Check the ssid list from DUT scan list
        assert len(ssid_list) > 0, "DUT scan list is empty"
        return ssid_list

    def mqtt_connect_to_server(self):
        self.address_dict = {
            "topic": [],
            "message": [],
        }
        for i in range(self.iter_count):
            if self.message is not None:
                self.message_address = self.wifi_dut.interfaces.wifi.allocate_memory(
                    size=len(self.message) + 1
                )
                self.wifi_dut.interfaces.wifi.load_memory(
                    address=self.message_address,
                    size=len(self.message),
                    write_content=self.message,
                )
                self.address_dict["message"].append(self.message_address)
            if self.topic is not None:
                self.topic_address = self.wifi_dut.interfaces.wifi.allocate_memory(
                    size=len(self.topic) + 1
                )
                self.wifi_dut.interfaces.wifi.load_memory(
                    address=self.topic_address,
                    size=len(self.topic),
                    write_content=self.topic,
                )
                self.address_dict["topic"].append(self.topic_address)

        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client",
            server_port=8883,
            qos=1,
            is_connection_encrypted=True,
        )
        logger().info(".....DUT connects to MQTT server.....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(15)
        logger().info(".....MQTT Client connects to MQTT server.....")
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(5)
        logger().info("MQTT Client subscribes to the topic")
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=1)

    def mqtt_publish(self):
        for topic_address, message_address in zip(
            self.address_dict["topic"], self.address_dict["message"]
        ):

            self.wifi_dut.interfaces.mqtt.mqtt_client_publish_allocate_mem(
                topic=self.topic,
                message=self.message,
                qos=1,
                timeout=100,
                load_mem=True,
                message_address=message_address,
                topic_address=topic_address,
            )

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = (
                    self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                )

            assert (
                msgs[0].topic == self.topic
            ), "No message received by mqtt-client on subscribed topic"
            assert (
                msgs[0].qos == Si91xMqttQos.QOS1
            ), "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[0].payload.decode() == self.message, (
                "No message is received by mqtt-client on subscribed topic or "
                "message received is wrong"
            )

    def get_sntp_info(self):
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            sntp_time, sntp_date = self.wifi_dut.interfaces.wifi.sntp_get_time_data()
            logger().info(f"**************** SNTP TIME **************** '{sntp_time}'")
            logger().info(
                f"**************** SNTP DATE **************** '{sntp_date}'\n"
            )
            ip_version, sntp_method, sntp_server_address = (
                self.wifi_dut.interfaces.wifi.sntp_get_server_info()
            )
            logger().info(f"**************** SNTP SERVER IP VERSION: {ip_version}")
            logger().info(
                f"**************** SNTP SERVER ADDRESS: {sntp_server_address}"
            )
            logger().info(f"**************** SNTP METHOD: {sntp_method}\n")

    def set_power_save(self, ble_power_save_enable=True):

        if self.power_save:

            self.wifi_dut.interfaces.wifi.set_performance_profile(
                mode="power_save_low_latency"
            )
            if ble_power_save_enable:
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                    psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
                )
        else:
            logger().info(
                "\n Skipping Power Save, as Power Save is disabled in Harness \n"
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
            logger().info(f"PASSPHRASE : {profiles[_]['passphrase']}")
            self.wifi_dut.interfaces.wifi.sl_net_set_profile(
                ssid=profiles[_]["ssid"],
                security=Map_security[profiles[_]["security"]],
                credential_id=(
                    _ + 1 if Map_security[profiles[_]["security"]] != 0 else 0
                ),
                priority=_ + 1,
                profile_id=_,
                channel=profiles[_]["channel"],
                encryption=profiles[_]["encryption_type"],
                expected_status="SL_STATUS_OK" if not expect_error else error_code,
            )
            self.wifi_dut.interfaces.wifi.sl_net_set_credential(
                credential=profiles[_]["passphrase"], cred_id=_ + 1
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

    def verify_auto_join_functionality(self, profile):
        self.wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=self.dut_mac_address
        )
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=profile["channel"]
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=self.request.node.name + f"channel_{profile['channel']}"
        )
        logger().info(f"Profile {profile} :")
        logger().info(f"SSID : {profile['ssid']}")
        logger().info(f"Security : {profile['security']}")
        logger().info(f"Passphrase : {profile['passphrase']}")
        self.wifi_access_point.interfaces.wifi.start_ap(
            ssid=profile["ssid"],
            security=profile["security"],
            passphrase=profile["passphrase"],
            channel=profile["channel"],
        )
        since_time = time.perf_counter_ns()
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = self.wifi_dut.interfaces.wifi.get_async_events(
                since_time=since_time
            )
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE {profile}"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE {profile}")
                    auto_join_status = True
                    break
        self.wifi_dut.interfaces.wifi.associated = auto_join_status
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE {profile}...."
        self.set_power_save()
        self.sniffer_validation(profile=profile)

    def join_to_ap(self, skip_power_save=False):

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
        logger().info(
            f"\n DUT MAC ADDRESS: {self.dut_mac_address},  AP_BSSID: {self.ap_mac_address}"
        )

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
        self.wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def configure_ip(self):
        ip_status, ip_config = self.sl_collections.configure_ip(
            self.wifi_dut, ip_status=False, retry_count=3, ip_version="ipv4"
        )

        assert (
            ip_status
        ), f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Device IP Address: {self.device_ip}")

    def sniffer_validation(self, profile=None):
        logger().info(f"\n Sniffer Validation for Profile : {profile} \n")
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
        if profile["security"].lower() != "open":
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter2
            )[
                "packet_count"
            ], "Sniffer: Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer"
        if self.power_save:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter3
            )[
                "packet_count"
            ], "Sniffer: Unable to find power management bit 1 in sniffer "

    def wpa3_sniffer_validation(self, profile=None):
        logger().info(f"\n Sniffer Validation for Profile : {profile} \n")
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                wlan_addr=self.dut_mac_address,
                filter_name="wpa3_confirm_commit_message",
            )
        )
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        packet_filter2 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name="power_mgmt_bit",
            )
        )

        packet_filter3 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                wlan_addr=self.dut_mac_address,
                filter_name="wpa3_4_way_handshake_message",
            )
        )
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")

        if self.power_save:
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter2
            )[
                "packet_count"
            ], "Sniffer: Unable to find power management bit 1 in sniffer "

        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"]
        assert snif_pkt_count, "Unable to find the commit & confirm packets."

        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter3
        )["packet_count"]
        assert snif_pkt_count, "Unable to find association & ea pols packets."

    def verify_wpa3_enterprise_sniffer_validation(self):
        packet_filter1 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
                da_addr=self.dut_mac_address,
                filter_name="beacon_wpa2_entr_akms_check_with_pmf_req",
            )
        )
        logger().info(
            f"Validating akms type 5 and pmf bit capable & required in sniffer"
        )
        packet_filter2 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name="assoc_req_resp_eapol_4_way_handshake_wpa3_eap",
            )
        )
        packet_filter3 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                da_addr=self.ap_mac_address,
                filter_name="power_mgmt_bit",
            )
        )

        packet_filter4 = (
            self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address,
                ta_addr=self.dut_mac_address,
                filter_name="null_data_powersave",
            )
        )

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], "Unable to find akms value in beacon packet"
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2
        )[
            "packet_count"
        ], "Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer"
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter3
        )[
            "packet_count"
        ], "Unable to find power management bit in QOS null frames in sniffer capture"
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter4
        )["packet_count"], "Unable to find ps polls in sniffer capture"

    def ping(self):
        logger().info("Initiating ping from Raspi to DUT to check stability")
        status = ping(self.device_ip, 30, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def firmware_upgrade_otaf(self):

        logger().info(" DOWNLOADING FIRMWARE FROM AWS SERVER.... ")
        self.url = self.fw_download_from_aws_server(
            aws_s3=self.aws_s3, rps_path=self.rps_path
        )
        logger().info(f" FIRMWARE URL OBTAINED: {self.url}")

        self.fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
        logger().info(f" ***** FW BEFORE UPGRADE: {self.fw_before_upgrade} *****")

        result = self.wifi_dut.interfaces.wifi.dns_get(
            domain_name=self.aws_host_name, query_timeout=20000, timeout=100
        )
        logger().info(f"**** HOST IP: {result}")
        self.host_ip = (result.decode()).strip()

        logger().info(" PINGING TO SERVER IP.... ")
        status = ping(self.host_ip, 10)
        logger().info(f"PING STATUS = {status}")

        logger().info(" DUT FIRMWARE VERSION BEFORE UPGRADE.... ")
        self.fw_version_before_upgrade = self.wifi_dut.interfaces.wifi.version()
        logger().info(
            f"*** DUT FIRMWARE VERSION BEFORE UPGRADE = {self.fw_version_before_upgrade} ***"
        )
        self.wifi_dut.interfaces.wifi.firmware_upgrade(
            flags=1,
            ip_address=self.host_ip,
            port=443,
            host_name=self.aws_host_name,
            extended_header='""',
            username='""',
            password='""',
            http_url="rps_path",
            async_timeout=500,
        )

    def fw_download_from_aws_server(self, aws_s3, rps_path):

        logger().info(
            f"****** FIRMWARE FILE NAME UPLOADING TO AWS SERVER {rps_path}*********"
        )
        rps_path_final = "/app/manifest/" + rps_path
        status = aws_s3.interfaces.s3.upload_file(
            rps_path_final, "httpotaf", "rps_path"
        )
        assert status is True, f"unable to upload"
        logger().info(f"upload successful")
        url = aws_s3.interfaces.s3.get_file_url("httpotaf", "us-east-2", "rps_path")
        logger().info(f"aws url is :{url}")
        return url

    def check_fw_version_after_upgrade(self):
        self.wifi_dut.interfaces.wifi.memory_free(self.http_addr)
        self.wifi_dut.interfaces.wifi.reset()
        time.sleep(15)
        logger().info("INITIALIZING DUT AFTER THE RESET....")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        self.wifi_dut.interfaces.wifi.init(load_certificate=False)
        self.wifi_dut.interfaces.wifi.initialize_thread()
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        self.fw_after_upgrade = self.wifi_dut.interfaces.wifi.version()
        time.sleep(5)
        logger().info(
            f"\n\n ***FIRMWARE VERSIONS BEFORE OTAF:{self.fw_before_upgrade}"
            f" FIRMWARE VERSION AFTER LOADING THROUGH OTAF :{self.fw_after_upgrade}"
        )
        assert self.fw_before_upgrade != self.fw_after_upgrade, (
            f"FIRMWARE VERSIONS SHOULD NOT MATCH AFTER LOADING"
            f" FIRMWARE THROUGH OTAF"
        )


def wifi_dut_marker(
    ext_custom_bit=0,
    tcp_feat_bit=0,
    ext_tcp_feat_bit=0,
    ca_cert=None,
    eap_cert=None,
    wifi_stack_len=3072,
    oper_mode=0,
    config_feature=0,
    coex_mode=Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
):
    config = {
        "oper_mode": oper_mode,
        "coex_mode": coex_mode,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp
        | config_feature,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | tcp_feat_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | ext_tcp_feat_bit,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
        | ext_custom_bit,
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
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
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
@pytest.mark.deployed_25q4
@pytest.mark.WLAN_Dev_sanity_917
@pytest.mark.test_src_map_id('C769960')
def test_RAM_autojoin_with_one_profile_and_one_credential_c769960(
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769960")

        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="c769960" + f"capture_on_channel_{profiles[0]}"
        )
        since_time = time.perf_counter_ns()
        logger().info(f"PROFILE : {0} ")
        logger().info(f"SSID : {profiles[0]['ssid']}")
        logger().info(f"SECURITY : {profiles[0]['security']}")
        logger().info(f"PASSPHRASE : {profiles[0]['passphrase']}")
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        wifi_access_point.interfaces.wifi.start_ap(
            ssid=profiles[0]["ssid"],
            security=(profiles[0]["security"]),
            passphrase=profiles[0]["passphrase"],
            channel=profiles[0]["channel"],
        )
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE ID: 0"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE ID: 0")
                    auto_join_status = True
                    break
        wifi_dut.interfaces.wifi.associated = auto_join_status
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {0}...."
        logger().info(f"DUT AUTO-JOINED WITH PROFILE ID:  {0} SUCCESSFULLY")
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_obj.sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client", "reset"])
@pytest.mark.config(
    "wifi_client", wifi={"interface": "wlan0", "ip_address": "192.168.0.1"}
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
                "channel": 6,
                "security": "WPA",
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
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769961')
def test_RAM_autojoin_with_wpa2_wpa_two_profiles_c769961(
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769961")
        wifi_client.interfaces.wifi.start_ap(
            ssid=profiles[1]["ssid"],
            security=SecurityMode.WPA,
            passphrase=profiles[1]["passphrase"],
            channel=profiles[1]["channel"],
            standard=Standard.n,
            region=CountryCode.US,
        )
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        for _ in range(0, 3):
            try:
                wifi_dut.interfaces.wifi.sl_net_up(mode="client", profile_id=0xFF)
                wifi_dut.interfaces.wifi.associated = True
                break
            except Exception as e:
                logger().info(f"Exception while bringing up the Wi-Fi interface: {e}")
                wifi_dut.interfaces.wifi.associated = False
                time.sleep(5)
        assert wifi_dut.interfaces.wifi.associated, "DUT NOT ASSOCIATED TO AP......"
        logger().info("\n DUT Associated to AP successfully \n")

        wifi_obj.dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        wifi_obj.ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False

        ip_status, ip_config = sl_collections.configure_ip(
            wifi_dut, ip_status=False, retry_count=3, ip_version="ipv4"
        )

        assert (
            ip_status
        ), f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        wifi_obj.device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Device IP Address: {wifi_obj.device_ip}")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -I eth1 -c 10 {wifi_obj.device_ip}"
        )
        assert rc == 0, "Raspberry Pi client failed to ping DUT"
        logger().info(
            f"Ping Results:\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n"
        )
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()
        since_time = time.perf_counter_ns()
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="c769961" + f"channel_{profiles[1]['channel']}"
        )
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        logger().info(f"Profile {profiles[1]} :")
        logger().info(f"SSID : {profiles[1]['ssid']}")
        logger().info(f"Security : {profiles[1]['security']}")
        logger().info(f"Passphrase : {profiles[1]['passphrase']}")
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE {profiles[1]}"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE {profiles[1]}")
                    auto_join_status = True
                    break
        wifi_dut.interfaces.wifi.associated = auto_join_status
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE {profile}...."
        wifi_obj.set_power_save()
        wifi_obj.ap_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        wifi_obj.sniffer_validation(profile=profiles[1])
        ip_status, ip_config = sl_collections.configure_ip(
            wifi_dut, ip_status=False, retry_count=3, ip_version="ipv4"
        )

        assert (
            ip_status
        ), f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        wifi_obj.device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Device IP Address: {wifi_obj.device_ip}")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -I wlan0 -c 10 {wifi_obj.device_ip}"
        )
        assert rc == 0, "Raspberry Pi client failed to ping DUT"
        logger().info(
            f"Ping Results:\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n"
        )
        wifi_dut.interfaces.wifi.sl_net_down(mode="client")
        wifi_client.interfaces.wifi.stop_ap()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        wifi_client.interfaces.wifi.stop_ap()
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "net_down"]
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
                "channel": 6,
                "security": "OPEN",
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
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.test_src_map_id('C769962')
def test_RAM_autojoin_auto_join_with_wpa2_open_two_profiles_c769962(
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769962")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
        logger().info(
            f"\n <---------------- Set Profiles: {profiles} ---------------->\n"
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        logger().info(
            f"\n <---------------- Get Profiles: {profiles} ---------------->\n"
        )
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        logger().info(f"\n <---------------- Set Rejoin Parameters ---------------->\n")
        wifi_obj.set_rejoin_params()
        logger().info(
            f"\n <---------------- Join to Access Point with profile: {profiles[0]} ---------------->\n"
        )
        wifi_obj.join_to_ap()
        logger().info(f"\n <---------------- Enable Power Save ---------------->\n")
        wifi_obj.set_power_save()
        logger().info(
            f"\n <---------------- Sniffer Validation with Profile: {profiles[0]} ---------------->\n"
        )
        wifi_obj.sniffer_validation(
            profile=profiles[0],
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.ping()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(
    wifi_stack_len=3584,
    oper_mode=Si91xOperatingMode.EAPWiFiClient,
    ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W,
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "net_down", "clear_certs"],
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA3Enterprise",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_EAP_TLS_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA3Enterprise",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_PEAP_MSCHAPV2_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2Enterprise",
        "passphrase": "12345678",
        "channel": 1,
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769967')
def test_RAM_autojoin_with_wpa3_enterprise_tls_peap_security_c769967(
    wifi_dut,
    radius_server,
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
        wifi_access_point.interfaces.wifi.config["protected_management_frame"] = (
            "Required"
        )
        wifi_access_point.interfaces.wifi.start_ap()
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769967")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
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
            encryption=8,
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
        wifi_obj.set_power_save()
        wifi_obj.verify_wpa3_enterprise_sniffer_validation()
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="eap_type_tls_verification",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"], "\n Unable to find EAP frames sent from AP in sniffer \n"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="c769967" + f"channel_{profiles[1]['channel']}"
        )
        logger().info(f"SSID : {profiles[1]['ssid']}")
        logger().info(f"Security : {profiles[1]['security']}")
        logger().info(f"Passphrase : {profiles[1]['passphrase']}")
        wifi_access_point.interfaces.wifi.config["protected_management_frame"] = (
            "Required"
        )
        wifi_access_point.interfaces.wifi.start_ap(
            ssid=profiles[1]["ssid"],
            security="WPA2Enterprise",
            passphrase=profiles[1]["passphrase"],
            channel=profiles[1]["channel"],
        )
        since_time = time.perf_counter_ns()
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE {profiles[1]}"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE {profiles[1]}")
                    auto_join_status = True
                    break
        wifi_dut.interfaces.wifi.associated = auto_join_status
        assert (
            auto_join_status
        ), f"DUT FAILED TO AUTO-JOIN WITH PROFILE {profiles[1]}...."
        wifi_obj.set_power_save()
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="eap_type_peap_verification",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"], "Unable to find EAP frames sent from AP in sniffer"

        logger().info(f"\n Validating for Power Management Bit \n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="power_mgmt_bit",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )[
            "packet_count"
        ], "Unable to find power management bit in QOS null frames in sniffer capture"
        wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_obj.ping()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(
    wifi_stack_len=3584,
    oper_mode=Si91xOperatingMode.EAPWiFiClient,
    config_feature=Si91xConfigFeatureBitMap.TLS_V2,
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "net_down", "clear_certs"],
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2Enterprise",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_EAP_TLS_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA2Enterprise",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_EAP_TLS_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2Enterprise",
        "passphrase": "12345678",
        "channel": 1,
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769968')
def test_RAM_autojoin_with_wpa2_enterprise_tls_ttls_security_c769968(
    wifi_dut,
    radius_server,
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

        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769968")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
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
        wifi_obj.set_power_save()
        sniffer_verification = SnifferValidationProcess(
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            wifi_access_point=wifi_access_point,
            dut_mac_address=wifi_obj.dut_mac_address,
            ap_mac_address=wifi_obj.ap_mac_address,
        )
        sniffer_verification.verify_sniffer_validation()
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="eap_type_tls_verification",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"], "\n Unable to find EAP frames sent from AP in sniffer \n"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="eap_type_ttls_verification",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"], "\n Unable to find EAP frames sent from AP in sniffer \n"
        wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_obj.ping()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA3",
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
        "security": "WPA3",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769963')
def test_RAM_autojoin_after_sl_net_deinit_with_wpa3_c769963(
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769963")

        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
            | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.wpa3_sniffer_validation(profile=profiles[0])
        logger().info("\n ---- DEINITIALIZING DEVICE ---- \n")
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="c769963" + f"capture_on_channel_{profiles[0]}"
        )
        logger().info(f"\n ---- INITIALIZING DEVICE AGAIN ---- \n")
        since_time = time.perf_counter_ns()
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.join_to_ap()
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE ID: 0"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE ID: 0")
                    auto_join_status = True
                    break
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {0}...."
        logger().info(f"\n Received the CONNECTED_TO_AP ASYNC PRINT \n")
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_obj.wpa3_sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SNTPClient)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
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
                "channel": 6,
                "security": "OPEN",
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
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769974')
def test_RAM_autojoin_while_doing_SNTP_data_transfer_c769974(
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769974")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
            test_type="sntp",
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation(
            profile=profiles[0],
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.sntp_client_start()
        wifi_obj.start()
        time.sleep(5)
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        assert (
            not wifi_obj.status
        ), f"\n SNTP Traffic Not Failed, Expected Behaviour is SNTP Data Transfer Fails during Auto-Join \n"
        logger().info(
            f"\n SNTP Transfer Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_dut.interfaces.wifi.sntp_client_start()
        time.sleep(5)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.sntp_client_stop()
        assert (
            wifi_obj.status
        ), f"\n SNTP Transfer Failed for the Profile: {profiles[1]}"
        logger().info(
            f"\n SNTP Data Transfer Successfully Done for Profile: {profiles[1]} \n"
        )
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@wifi_dut_marker(
    ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W,
    ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
    ca_cert=[
        "ca-chain.cert.pem",
        "SL_NET_SIGNING_CERTIFICATE",
        "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ],
    wifi_stack_len=4096,
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
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
                "channel": 6,
                "security": "OPEN",
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
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769975')
def test_RAM_autojoin_while_doing_MQTTS_data_transfer_c769975(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    profiles,
    mqtt_server,
    mqtt_client,
):
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769975")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
            test_type="mqtt",
            mqtt_client=mqtt_client,
            mqtt_server=mqtt_server,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        logger().info(
            f"\n <---------------- Sniffer Validation with Profile: {profiles[0]} ---------------->\n"
        )
        wifi_obj.sniffer_validation(
            profile=profiles[0],
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.iter_count = 3
        wifi_obj.mqtt_connect_to_server()
        wifi_obj.start()
        time.sleep(10)
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        assert (
            not wifi_obj.status
        ), f"\n MQTT Traffic Not Failed, Expected Behaviour is MQTT Data Transfer Fails during Auto-Join \n"
        logger().info(
            f"\n MQTT Transfer Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_obj.mqtt_connect_to_server()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert (
            wifi_obj.status
        ), f"\n MQTT Transfer Failed for the Profile: {profiles[1]}"
        logger().info(
            f"\n MQTT Data Transfer Successfully Done for Profile: {profiles[1]} \n"
        )
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
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
                "channel": 6,
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
        "ssid": "ssid_profile2",
        "security": "WPA2",
        "passphrase": "12345678",
        "channel": 6,
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769980')
def test_RAM_autojoin_with_incorrect_psk_first_try_c769980(
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769980")

        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        since_time = time.perf_counter_ns()
        wifi_obj.join_to_ap()
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE ID: 0"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE ID: 0")
                    auto_join_status = True
                    break
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {1}...."
        logger().info(f"DUT AUTO-JOINED WITH PROFILE ID:  {1} SUCCESSFULLY")
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        ssid_match = re.search(r"ssid\s*:\s*(\w+)", wireless_info)
        ssid = ssid_match.group(1).strip()
        assert (
            ssid == profiles[1]["ssid"]
        ), f"\n DUT Should Connect to {profiles[1]} whereas it connected to {ssid_match}\n"
        wifi_obj.sniffer_validation(profile=profiles[1])
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA2",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile3",
                "channel": 11,
                "security": "WPA2",
                "passphrase": "123456789",
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
        "guest_networks": [
            {
                "index": "1",
                "ssid": "ssid_profile2",
                "passphrase": "12345678",
                "band": "2g",
                "security": "WPA2",
                "channel": 6,
            },
            {
                "index": "2",
                "ssid": "ssid_profile3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 11,
            },
        ],
    },
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769982')
def test_RAM_autojoin_with_two_profiles_mbssid_c769982(
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769982")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
        vap_list = wifi_obj.verify_T_and_NT_based_mbssid_in_dut_list()
        logger().info(f"\n VAP SCAN LIST: {vap_list} \n")
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        assert (
            profiles[0]["ssid"] in wireless_info
        ), f"\n {profiles[0]['ssid']} NOT PRESENT IN WIRELESS INFO \n"
        since_time = time.perf_counter_ns()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        # Add this code to stop guest network at index 1
        logger().info("Stopping guest network at index 1 (ssid_profile2)")
        try:
            # Method 1: Try to stop specific guest network (if supported)
            if hasattr(wifi_access_point.interfaces.wifi, "_stop_guest_network"):
                # Create a shell session for the AP
                with wifi_access_point.interfaces.wifi._create_shell() as shell:
                    wifi_access_point.interfaces.wifi._stop_guest_network(
                        shell=shell, band="2g", index="1"
                    )
                logger().info("Successfully stopped guest network at index 1")
            else:
                # Method 2: Fallback - stop all guest networks
                logger().info(
                    "Specific guest network stopping not supported, stopping all guest networks"
                )
                wifi_access_point.interfaces.wifi.stop_ap()
                # Restart the main AP without guest networks
                wifi_access_point.interfaces.wifi.start_ap()
                logger().info("Restarted main AP without guest networks")
        except Exception as e:
            logger().warning(f"Failed to stop specific guest network: {e}")
            logger().info("Falling back to stopping all guest networks")
            wifi_access_point.interfaces.wifi.stop_ap()
            wifi_access_point.interfaces.wifi.start_ap()
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE ID: 0"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE ID: 0")
                    auto_join_status = True
                    break
        wifi_dut.interfaces.wifi.associated = auto_join_status
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {1}...."
        logger().info(f"DUT AUTO-JOINED WITH PROFILE ID:  {1} SUCCESSFULLY")
        wifi_obj.ping()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        assert (
            profiles[1]["ssid"] in wireless_info
        ), f"\n {profiles[1]['ssid']} NOT PRESENT IN WIRELESS INFO \n"
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2",
                "passphrase": "99",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            }
        ),
    ],
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769984')
def test_RAM_autojoin_error_with_invalid_credential_c769984(
    wifi_dut, profiles, sl_collections
):

    try:
        logger().info(
            f"PROFILES ARE: {profiles} AND NUMBER OF PROFILES: {len(profiles)}"
        )
        logger().info(f"PROFILE -> {0}")
        logger().info(f"SSID : {profiles['ssid']}")
        logger().info(f"SECURITY : {profiles['security']}")
        logger().info(f"PASSPHRASE : {profiles['passphrase']}")
        wifi_dut.interfaces.wifi.sl_net_set_profile(
            ssid=profiles["ssid"],
            security=Map_security[profiles["security"]],
            credential_id=1,
            priority=1,
            profile_id=0,
            encryption=profiles["encryption_type"],
            expected_status=SLStatus.SL_STATUS_OK,
        )
        logger().info(
            f"\n Expected Staus Code: {SLStatus.SL_STATUS_INVALID_PARAMETER} for Small Credential Length \n"
        )
        wifi_dut.interfaces.wifi.sl_net_set_credential(
            credential=profiles["passphrase"],
            cred_id=1,
            expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER,
        )

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA3",
                "passphrase": "1234567890",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile3",
                "channel": 11,
                "security": "OPEN",
                "passphrase": "123456743",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C769985')
def test_RAM_autojoin_error_with_three_profiles_and_credentials_c769985(
    wifi_dut, profiles, sl_collections
):

    try:
        logger().info(
            f"PROFILES ARE: {profiles} AND NUMBER OF PROFILES: {len(profiles)}"
        )

        for _ in range(len(profiles)):
            logger().info(f"PROFILE -> {_ + 1}")
            logger().info(f"SSID : {profiles[_]['ssid']}")
            logger().info(f"SECURITY : {profiles[_]['security']}")
            logger().info(f"PASSPHRASE : {profiles[_]['passphrase']}")
            wifi_dut.interfaces.wifi.sl_net_set_profile(
                ssid=profiles[_]["ssid"],
                security=Map_security[profiles[_]["security"]],
                credential_id=_ + 1,
                priority=_ + 1,
                profile_id=_,
                encryption=profiles[_]["encryption_type"],
                expected_status=(
                    SLStatus.SL_STATUS_OK
                    if _ != 2
                    else SLStatus.SL_STATUS_INVALID_CONFIGURATION
                ),
            )
            wifi_dut.interfaces.wifi.sl_net_set_credential(
                credential=profiles[_]["passphrase"], cred_id=_ + 1
            )

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
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
@pytest.mark.test_src_map_id('C769987')
def test_NVM_autojoin_with_one_profile_and_one_credential_c769987(
    firmware_loader,
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769987")

        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="c769987" + f"capture_on_channel_{profiles[0]}"
        )
        since_time = time.perf_counter_ns()
        logger().info(f"PROFILE : {0} ")
        logger().info(f"SSID : {profiles[0]['ssid']}")
        logger().info(f"SECURITY : {profiles[0]['security']}")
        logger().info(f"PASSPHRASE : {profiles[0]['passphrase']}")
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        wifi_access_point.interfaces.wifi.start_ap(
            ssid=profiles[0]["ssid"],
            security=(profiles[0]["security"]),
            passphrase=profiles[0]["passphrase"],
            channel=profiles[0]["channel"],
        )
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE ID: 0"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE ID: 0")
                    auto_join_status = True
                    break
        wifi_dut.interfaces.wifi.associated = auto_join_status
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {0}...."
        logger().info(f"DUT AUTO-JOINED WITH PROFILE ID:  {0} SUCCESSFULLY")
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_obj.sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        for _ in range(len(profiles)):
            logger().info(f"\n Removing Profile: {profiles[_]} \n")
            wifi_dut.interfaces.wifi.delete_profile(interface=8, id=_)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client", "reset"])
@pytest.mark.config(
    "wifi_client", wifi={"interface": "wlan0", "ip_address": "192.168.0.1"}
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
                "channel": 6,
                "security": "WPA",
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
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.test_src_map_id('C769988')
def test_NVM_autojoin_with_wpa2_wpa_two_profiles_c769988(
    firmware_loader,
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769988")
        wifi_client.interfaces.wifi.start_ap(
            ssid=profiles[1]["ssid"],
            security=SecurityMode.WPA,
            passphrase=profiles[1]["passphrase"],
            channel=profiles[1]["channel"],
            standard=Standard.n,
            region=CountryCode.US,
        )
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        for _ in range(0, 3):
            try:
                wifi_dut.interfaces.wifi.sl_net_up(mode="client", profile_id=0xFF)
                wifi_dut.interfaces.wifi.associated = True
                break
            except Exception as e:
                logger().info(f"Exception while bringing up the Wi-Fi interface: {e}")
                wifi_dut.interfaces.wifi.associated = False
                time.sleep(5)
        assert wifi_dut.interfaces.wifi.associated, "DUT NOT ASSOCIATED TO AP......"
        logger().info("\n DUT Associated to AP successfully \n")

        wifi_obj.dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        wifi_obj.ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        wifi_dut.interfaces.wifi.is_external_stack_enabled = False

        ip_status, ip_config = sl_collections.configure_ip(
            wifi_dut, ip_status=False, retry_count=3, ip_version="ipv4"
        )

        assert (
            ip_status
        ), f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        wifi_obj.device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Device IP Address: {wifi_obj.device_ip}")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -I eth1 -c 10 {wifi_obj.device_ip}"
        )
        assert rc == 0, "Raspberry Pi client failed to ping DUT"
        logger().info(
            f"Ping Results:\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n"
        )
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()
        since_time = time.perf_counter_ns()
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="c769988" + f"channel_{profiles[1]['channel']}"
        )
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        logger().info(f"Profile {profiles[1]} :")
        logger().info(f"SSID : {profiles[1]['ssid']}")
        logger().info(f"Security : {profiles[1]['security']}")
        logger().info(f"Passphrase : {profiles[1]['passphrase']}")
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE {profiles[1]}"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE {profiles[1]}")
                    auto_join_status = True
                    break
        wifi_dut.interfaces.wifi.associated = auto_join_status
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE {profile}...."
        wifi_obj.set_power_save()
        wifi_obj.ap_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        wifi_obj.sniffer_validation(profile=profiles[1])
        ip_status, ip_config = sl_collections.configure_ip(
            wifi_dut, ip_status=False, retry_count=3, ip_version="ipv4"
        )

        assert (
            ip_status
        ), f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."
        wifi_obj.device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"Device IP Address: {wifi_obj.device_ip}")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -I wlan0 -c 10 {wifi_obj.device_ip}"
        )
        assert rc == 0, "Raspberry Pi client failed to ping DUT"
        logger().info(
            f"Ping Results:\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n"
        )
        wifi_dut.interfaces.wifi.sl_net_down(mode="client")
        wifi_client.interfaces.wifi.stop_ap()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        wifi_client.interfaces.wifi.stop_ap()
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "net_down"]
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
                "channel": 6,
                "security": "OPEN",
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
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.test_src_map_id('C769989')
def test_NVM_autojoin_auto_join_with_wpa2_open_two_profiles_c769989(
    firmware_loader,
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769989")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
        logger().info(
            f"\n <---------------- Set Profiles: {profiles} ---------------->\n"
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        logger().info(
            f"\n <---------------- Get Profiles: {profiles} ---------------->\n"
        )
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        logger().info(f"\n <---------------- Set Rejoin Parameters ---------------->\n")
        wifi_obj.set_rejoin_params()
        logger().info(
            f"\n <---------------- Join to Access Point with profile: {profiles[0]} ---------------->\n"
        )
        wifi_obj.join_to_ap()
        logger().info(f"\n <---------------- Enable Power Save ---------------->\n")
        wifi_obj.set_power_save()
        logger().info(
            f"\n <---------------- Sniffer Validation with Profile: {profiles[0]} ---------------->\n"
        )
        wifi_obj.sniffer_validation(
            profile=profiles[0],
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.ping()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA3",
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
        "security": "WPA3",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.test_src_map_id('C769990')
def test_NVM_autojoin_after_sl_net_deinit_with_wpa3_c769990(
    firmware_loader,
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769990")

        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
            | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.wpa3_sniffer_validation(profile=profiles[0])
        logger().info("\n ---- DEINITIALIZING DEVICE ---- \n")
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="c769990" + f"capture_on_channel_{profiles[0]}"
        )
        logger().info(f"\n ---- INITIALIZING DEVICE AGAIN ---- \n")
        since_time = time.perf_counter_ns()
        wifi_dut.interfaces.wifi.sl_net_init(mode="client")
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.join_to_ap()
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE ID: 0"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE ID: 0")
                    auto_join_status = True
                    break
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {0}...."
        logger().info(f"\n Received the CONNECTED_TO_AP ASYNC PRINT \n")
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_obj.wpa3_sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker(
    wifi_stack_len=3584,
    oper_mode=Si91xOperatingMode.EAPWiFiClient,
    ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W,
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "net_down", "clear_certs"],
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA3Enterprise",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_EAP_TLS_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA3Enterprise",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_PEAP_MSCHAPV2_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2Enterprise",
        "passphrase": "12345678",
        "channel": 1,
    },
)
@pytest.mark.test_src_map_id('C769994')
def test_NVM_autojoin_with_wpa3_enterprise_tls_peap_security_c769994(
    firmware_loader,
    wifi_dut,
    radius_server,
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
        wifi_access_point.interfaces.wifi.config["protected_management_frame"] = (
            "Required"
        )
        wifi_access_point.interfaces.wifi.start_ap()
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769994")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
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
            encryption=8,
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
        wifi_obj.set_power_save()
        wifi_obj.verify_wpa3_enterprise_sniffer_validation()
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="eap_type_tls_verification",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"], "\n Unable to find EAP frames sent from AP in sniffer \n"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file="c769994" + f"channel_{profiles[1]['channel']}"
        )
        logger().info(f"SSID : {profiles[1]['ssid']}")
        logger().info(f"Security : {profiles[1]['security']}")
        logger().info(f"Passphrase : {profiles[1]['passphrase']}")
        wifi_access_point.interfaces.wifi.config["protected_management_frame"] = (
            "Required"
        )
        wifi_access_point.interfaces.wifi.start_ap(
            ssid=profiles[1]["ssid"],
            security="WPA2Enterprise",
            passphrase=profiles[1]["passphrase"],
            channel=profiles[1]["channel"],
        )
        since_time = time.perf_counter_ns()
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE {profiles[1]}"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE {profiles[1]}")
                    auto_join_status = True
                    break
        wifi_dut.interfaces.wifi.associated = auto_join_status
        assert (
            auto_join_status
        ), f"DUT FAILED TO AUTO-JOIN WITH PROFILE {profiles[1]}...."
        wifi_obj.set_power_save()
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="eap_type_peap_verification",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"], "Unable to find EAP frames sent from AP in sniffer"

        logger().info(f"\n Validating for Power Management Bit \n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="power_mgmt_bit",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )[
            "packet_count"
        ], "Unable to find power management bit in QOS null frames in sniffer capture"
        wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_obj.ping()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker(
    wifi_stack_len=3584,
    oper_mode=Si91xOperatingMode.EAPWiFiClient,
    config_feature=Si91xConfigFeatureBitMap.TLS_V2,
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "net_down", "clear_certs"],
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2Enterprise",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_EAP_TLS_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA2Enterprise",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_EAP_TLS_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "WPA2Enterprise",
        "passphrase": "12345678",
        "channel": 1,
    },
)
@pytest.mark.test_src_map_id('C769995')
def test_NVM_autojoin_with_wpa2_enterprise_tls_ttls_security_c769995(
    firmware_loader,
    wifi_dut,
    radius_server,
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

        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c769995")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
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
        wifi_obj.set_power_save()
        sniffer_verification = SnifferValidationProcess(
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            wifi_access_point=wifi_access_point,
            dut_mac_address=wifi_obj.dut_mac_address,
            ap_mac_address=wifi_obj.ap_mac_address,
        )
        sniffer_verification.verify_sniffer_validation()
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="eap_type_tls_verification",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"], "\n Unable to find EAP frames sent from AP in sniffer \n"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=wifi_obj.ap_mac_address,
            sa_addr=wifi_obj.dut_mac_address,
            filter_name="eap_type_ttls_verification",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter
        )["packet_count"], "\n Unable to find EAP frames sent from AP in sniffer \n"
        wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_obj.ping()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SNTPClient)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
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
                "channel": 6,
                "security": "OPEN",
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
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.test_src_map_id('C770001')
def test_NVM_autojoin_while_doing_SNTP_data_transfer_c770001(
    firmware_loader,
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c770001")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
            test_type="sntp",
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_obj.sniffer_validation(
            profile=profiles[0],
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.sntp_client_start()
        wifi_obj.start()
        time.sleep(5)
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        assert (
            not wifi_obj.status
        ), f"\n SNTP Traffic Not Failed, Expected Behaviour is SNTP Data Transfer Fails during Auto-Join \n"
        logger().info(
            f"\n SNTP Transfer Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_dut.interfaces.wifi.sntp_client_start()
        time.sleep(5)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.sntp_client_stop()
        assert (
            wifi_obj.status
        ), f"\n SNTP Transfer Failed for the Profile: {profiles[1]}"
        logger().info(
            f"\n SNTP Data Transfer Successfully Done for Profile: {profiles[1]} \n"
        )
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@wifi_dut_marker(
    ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W,
    ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
    ca_cert=[
        "ca-chain.cert.pem",
        "SL_NET_SIGNING_CERTIFICATE",
        "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ],
    wifi_stack_len=4096,
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
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
                "channel": 6,
                "security": "OPEN",
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
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.test_src_map_id('C770002')
def test_NVM_autojoin_while_doing_MQTTS_data_transfer_c770002(
    firmware_loader,
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    profiles,
    mqtt_server,
    mqtt_client,
):
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c770002")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
            test_type="mqtt",
            mqtt_client=mqtt_client,
            mqtt_server=mqtt_server,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        logger().info(
            f"\n <---------------- Sniffer Validation with Profile: {profiles[0]} ---------------->\n"
        )
        wifi_obj.sniffer_validation(
            profile=profiles[0],
        )
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.iter_count = 3
        wifi_obj.mqtt_connect_to_server()
        wifi_obj.start()
        time.sleep(10)
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        assert (
            not wifi_obj.status
        ), f"\n MQTT Traffic Not Failed, Expected Behaviour is MQTT Data Transfer Fails during Auto-Join \n"
        logger().info(
            f"\n MQTT Transfer Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_obj.mqtt_connect_to_server()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert (
            wifi_obj.status
        ), f"\n MQTT Transfer Failed for the Profile: {profiles[1]}"
        logger().info(
            f"\n MQTT Data Transfer Successfully Done for Profile: {profiles[1]} \n"
        )
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
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
                "channel": 6,
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
        "ssid": "ssid_profile2",
        "security": "WPA2",
        "passphrase": "12345678",
        "channel": 6,
    },
)
@pytest.mark.test_src_map_id('C770007')
def test_NVM_autojoin_with_incorrect_psk_first_try_c770007(
    firmware_loader,
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c770007")

        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.set_rejoin_params()
        since_time = time.perf_counter_ns()
        wifi_obj.join_to_ap()
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE ID: 0"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE ID: 0")
                    auto_join_status = True
                    break
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {1}...."
        logger().info(f"DUT AUTO-JOINED WITH PROFILE ID:  {1} SUCCESSFULLY")
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        ssid_match = re.search(r"ssid\s*:\s*(\w+)", wireless_info)
        ssid = ssid_match.group(1).strip()
        assert (
            ssid == profiles[1]["ssid"]
        ), f"\n DUT Should Connect to {profiles[1]} whereas it connected to {ssid_match}\n"
        wifi_obj.sniffer_validation(profile=profiles[1])
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "net_down",
    ],
)
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA2",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile3",
                "channel": 11,
                "security": "WPA2",
                "passphrase": "123456789",
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
        "guest_networks": [
            {
                "index": "1",
                "ssid": "ssid_profile2",
                "passphrase": "12345678",
                "band": "2g",
                "security": "WPA2",
                "channel": 6,
            },
            {
                "index": "2",
                "ssid": "ssid_profile3",
                "passphrase": "123456789",
                "band": "2g",
                "security": "WPA2",
                "channel": 11,
            },
        ],
    },
)
@pytest.mark.test_src_map_id('C770009')
def test_NVM_autojoin_with_two_profiles_mbssid_c770009(
    firmware_loader,
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
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file="c770009")
        wifi_obj = WLANAutoJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
        vap_list = wifi_obj.verify_T_and_NT_based_mbssid_in_dut_list()
        logger().info(f"\n VAP SCAN LIST: {vap_list} \n")
        wifi_obj.set_profiles_and_credentials(profiles=profiles)
        wifi_obj.get_profiles_and_credentials(num_profiles=len(profiles))
        wifi_obj.set_rejoin_params()
        wifi_obj.join_to_ap()
        wifi_obj.set_power_save()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        assert (
            profiles[0]["ssid"] in wireless_info
        ), f"\n {profiles[0]['ssid']} NOT PRESENT IN WIRELESS INFO \n"
        since_time = time.perf_counter_ns()
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        # Add this code to stop guest network at index 1
        logger().info("Stopping guest network at index 1 (ssid_profile2)")
        try:
            # Method 1: Try to stop specific guest network (if supported)
            if hasattr(wifi_access_point.interfaces.wifi, "_stop_guest_network"):
                # Create a shell session for the AP
                with wifi_access_point.interfaces.wifi._create_shell() as shell:
                    wifi_access_point.interfaces.wifi._stop_guest_network(
                        shell=shell, band="2g", index="1"
                    )
                logger().info("Successfully stopped guest network at index 1")
            else:
                # Method 2: Fallback - stop all guest networks
                logger().info(
                    "Specific guest network stopping not supported, stopping all guest networks"
                )
                wifi_access_point.interfaces.wifi.stop_ap()
                # Restart the main AP without guest networks
                wifi_access_point.interfaces.wifi.start_ap()
                logger().info("Restarted main AP without guest networks")
        except Exception as e:
            logger().warning(f"Failed to stop specific guest network: {e}")
            logger().info("Falling back to stopping all guest networks")
            wifi_access_point.interfaces.wifi.stop_ap()
            wifi_access_point.interfaces.wifi.start_ap()
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        auto_join_status = False
        in_progress_status = False
        sw = Stopwatch()
        while sw.elapsed_sec < 60 and not auto_join_status:
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                event_data = event.event_data
                if "IN PROGRESS" in event_data and not in_progress_status:
                    logger().info(
                        f"AUTO JOIN PROCESS STARTED WITH EVENT: {event_data} FOR PROFILE ID: 0"
                    )
                    in_progress_status = True
                if "CONNECTED TO AP" in event_data:
                    logger().info(f"DUT CONNECTED TO PROFILE ID: 0")
                    auto_join_status = True
                    break
        wifi_dut.interfaces.wifi.associated = auto_join_status
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {1}...."
        logger().info(f"DUT AUTO-JOINED WITH PROFILE ID:  {1} SUCCESSFULLY")
        wifi_obj.ping()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        assert (
            profiles[1]["ssid"] in wireless_info
        ), f"\n {profiles[1]['ssid']} NOT PRESENT IN WIRELESS INFO \n"
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2",
                "passphrase": "99",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            }
        ),
    ],
)
@pytest.mark.test_src_map_id('C770011')
def test_NVM_autojoin_error_with_invalid_credential_c770011(
    firmware_loader, wifi_dut, profiles, sl_collections
):

    try:
        logger().info(
            f"PROFILES ARE: {profiles} AND NUMBER OF PROFILES: {len(profiles)}"
        )
        logger().info(f"PROFILE -> {0}")
        logger().info(f"SSID : {profiles['ssid']}")
        logger().info(f"SECURITY : {profiles['security']}")
        logger().info(f"PASSPHRASE : {profiles['passphrase']}")
        wifi_dut.interfaces.wifi.sl_net_set_profile(
            ssid=profiles["ssid"],
            security=Map_security[profiles["security"]],
            credential_id=1,
            priority=1,
            profile_id=0,
            encryption=profiles["encryption_type"],
            expected_status=SLStatus.SL_STATUS_OK,
        )
        logger().info(
            f"\n Expected Staus Code: {SLStatus.SL_STATUS_INVALID_PARAMETER} for Small Credential Length \n"
        )
        wifi_dut.interfaces.wifi.sl_net_set_credential(
            credential=profiles["passphrase"],
            cred_id=1,
            expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER,
        )

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_nvm3")
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.parametrize(
    "profiles",
    [
        (
            {
                "ssid": "ssid_profile1",
                "channel": 1,
                "security": "WPA2",
                "passphrase": "12345678",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA3",
                "passphrase": "1234567890",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
            {
                "ssid": "ssid_profile3",
                "channel": 11,
                "security": "OPEN",
                "passphrase": "123456743",
                "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
            },
        ),
    ],
)
@pytest.mark.test_src_map_id('C770012')
def test_NVM_autojoin_error_with_three_profiles_and_credentials_c770012(
    wifi_dut, profiles, sl_collections
):

    try:
        logger().info(
            f"PROFILES ARE: {profiles} AND NUMBER OF PROFILES: {len(profiles)}"
        )

        for _ in range(len(profiles)):
            logger().info(f"PROFILE -> {_ + 1}")
            logger().info(f"SSID : {profiles[_]['ssid']}")
            logger().info(f"SECURITY : {profiles[_]['security']}")
            logger().info(f"PASSPHRASE : {profiles[_]['passphrase']}")
            wifi_dut.interfaces.wifi.sl_net_set_profile(
                ssid=profiles[_]["ssid"],
                security=Map_security[profiles[_]["security"]],
                credential_id=_ + 1,
                priority=_ + 1,
                profile_id=_,
                encryption=profiles[_]["encryption_type"],
                expected_status=(
                    SLStatus.SL_STATUS_OK
                    if _ != 2
                    else SLStatus.SL_STATUS_INVALID_CONFIGURATION
                ),
            )
            wifi_dut.interfaces.wifi.sl_net_set_credential(
                credential=profiles[_]["passphrase"], cred_id=_ + 1
            )

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
