import time
import pytest
import string
import random
import re
from threading import Thread
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
    Si91xMqttQos,
)
from utf.interfaces.wifi import (
    Cipher,
    SecurityMode,
    Standard,
    Bandwidth,
    Rate,
    Channel,
    CountryCode,
    WirelessBand,
    WiFiScanResult,
)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import (
    AsyncEventIdentifiers,
)
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


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
        http_server=None,
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
        self.ssl_server = ssl_server
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.request = request
        self.test_type = test_type
        self.remote_socket_factory = remote_socket_factory
        self.http_addr = http_addr
        self.status = None
        self.error_data = None
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

    def verfiy_T_and_NT_based_mbssid_in_dut_list(self, scan_type=False):
        # Validation for T and NT based MBSSID in DUT scan list & sniffer capture
        packet_filter2 = "                    SSID:"
        ssid_list = self.find_ssid_list_from_dut_scan(scan_type=scan_type)
        # Check the ssid list from DUT scan list
        assert len(ssid_list) > 0, "DUT scan list is empty"
        return ssid_list
    
    def connect_socket_to_server(self):

        keepalive_time = 60
        self.remote_ip_address = self.wifi_client.interfaces.wifi.get_ip_address()
        self.port_number = random.randint(6000, 6100)
        self.socket_fd = (
            self.wifi_dut.interfaces.wifi.socket(
                domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
            )
            if self.traffic_type == "TCP"
            else self.wifi_dut.interfaces.wifi.socket(
                domain="AF_INET", stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP"
            )
        )
        self.client_socket = (
            self.remote_socket_factory.interfaces.socket.create_socket()
        )

        self.client_socket.start_server(
            port=self.port_number, socket_type=0 if self.traffic_type == "TCP" else 1
        )
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=self.socket_fd,
            device_ip=self.device_ip,
            server_port=self.port_number,
            timeout=5,
            asynch=0,
        )
        logger().info(
            f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds"
        )
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            socket_fd=self.socket_fd,
            option_name="SO_KEEPALIVE",
            option_val=keepalive_time,
        )
        for count in range(3):
            connect_status = False
            try:
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(
                    socket_fd=self.socket_fd,
                    server_ip=self.remote_ip_address,
                    server_port=self.port_number,
                )
                connect_status = True
                break
            except:
                logger().info(
                    f"Socket connection failed in DUT...retry_count:{count + 1}"
                )
                assert connect_status, "Socket connection failed in DUT"

    def transmit_data(self):
        duration = 60
        sw = Stopwatch()
        logger().info(f"\n Starting the {self.traffic_type} TX data Transfer \n")
        while sw.elapsed_sec < duration:
            sent_data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=20)
            )
            self.wifi_dut.interfaces.wifi.bsdSocketSend(
                socket_fd=self.socket_fd, data=sent_data, higher_data_len=0
            )
            if self.traffic_type == "TCP":
                self.client_socket.set_recv_timeout(socket_type=0)
            else:
                self.client_socket.set_recv_timeout(
                    socket_type=1, use_client_socket=True
                )
            received_data = (
                self.client_socket.recv_data_tcp(len(sent_data))
                if self.traffic_type == "TCP"
                else self.client_socket.recv_data_udp(len(sent_data))[0]
            )
            logger().info(
                f"\n###################### Received Data: {received_data} ######################\n"
            )
            assert (
                sent_data == received_data
            ), f"Data mismatch in sent and received data"

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

    def mqtt_connect_to_server(self):
        self.topic = "mytesttopic"
        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client",
            qos=1,
        )

        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(5)
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(5)

        logger().info("MQTT Client subscribes to the topic")
        self.mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=1)

        time.sleep(5)

    def mqtt_publish(self):
        watch = Stopwatch()
        while watch.elapsed_sec < 60:
            message = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=50)
            )
            self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()

            logger().info("\n DUT PUBLISHES MESSAGE TO THE CLIENT \n")
            self.wifi_dut.interfaces.mqtt.mqtt_client_publish(
                topic=self.topic,
                message=message,
                qos=1,
                timeout=20,
            )
            time.sleep(5)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                time.sleep(0.1)
                msgs = (
                    self.mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
                )
                if len(msgs) == 1:
                    break
            assert len(msgs) == 1, "No message is received by mqtt-client"
            assert (
                msgs[0].topic == self.topic
            ), "No message received by mqtt-client on subscribed topic"
            assert (
                msgs[0].qos == Si91xMqttQos.QOS1
            ), "DUT sent message with wrong QOS. expected is QOS1"
            assert msgs[0].payload.decode() == message, (
                "No message is received by mqtt-client on subscribed topic or "
                "message received is wrong"
            )

        self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=self.topic)
        time.sleep(5)

    def connect_to_ssl_server(self):
        port1 = self.ssl_server.interfaces.ssl.config["device_port1"]
        self.ssl_server.interfaces.ssl.start_server(port=port1)
        self.server_ip = self.ssl_server.interfaces.ssl.server_ip
        self.sock = self.wifi_dut.interfaces.wifi.socket()
        assert self.sock > -1, f"\n INVALID SOCKET ID \n"

        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(
            self.sock, option_name="TCP_ULP", option_val="tls_1_2"
        )
        local_port = random.randint(5001, 20000)
        self.wifi_dut.interfaces.wifi.bind(
            socket_fd=self.sock,
            device_ip=self.device_ip,
            server_port=local_port,
            timeout=15,
        )
        self.wifi_dut.interfaces.wifi.bsdSocketConnect(
            socket_fd=self.sock, server_ip=self.server_ip, server_port=port1
        )
        time.sleep(5)

    def run_ssl_tx_traffic(self):
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            buffer_length = 100
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
            )
            data_length = len(tx_buffer)
            self.wifi_dut.interfaces.wifi.bsdSocketSend(
                socket_fd=self.sock, data=tx_buffer
            )
            server_socket_no = self.sock + 1
            data_receive = self.ssl_server.interfaces.ssl.data_recv_content(
                server_socket_no, data_length
            )
            logger().info(f"\n DATA RECEIVED:  {data_receive} \n")
            assert (
                tx_buffer == data_receive.decode()
            ), "\n DATA SENT AND RECEIVED ARE MISMATCHING \n"

    def get_sntp_info(self):
        for _ in range(3):
            self.wifi_dut.interfaces.wifi.sntp_client_start()

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
            self.wifi_dut.interfaces.wifi.sntp_client_stop()

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
                credential_id=_ + 1,
                priority=_ + 1,
                profile_id=_,
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
        while sw.elapsed_sec < 180 and not auto_join_status:
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
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE {profile}...."
        self.set_power_save()
        self.sniffer_validation(profile=profile)

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

    def ping(self):
        logger().info("Initiating ping from Raspi to DUT to check stability")
        status = ping(self.device_ip, 30, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def firmware_upgrade_otaf(self):

        self.fw_before_upgrade = self.wifi_dut.interfaces.wifi.version()
        logger().info(f" ***** FW before upgrade: {self.fw_before_upgrade} *****")

        host_ip = self.http_server.interfaces.http.hostname_or_ip_address
        logger().info(f"SERVER IP: {host_ip}")
        start_time = time.time()
        logger().info(f"START FIRMWARE UPGRADE: {start_time}")
        logger().info("PERFORMING FIRMWARE UPGRADE....")
        self.wifi_dut.interfaces.wifi.firmware_upgrade(
            ip_address=host_ip, host_name=host_ip, timeout=200, async_timeout=300
        )
        finish_time = time.time()
        logger().info(f"FIRMWARE UPGRADED: {finish_time}")
        time_duration = finish_time - start_time
        logger().info(f"TIME TAKEN TO UPGRADE FIRMWARE: {time_duration}")

        if time_duration > 40:
            logger().warning(f"TOOK TOO LONG TIME TO DOWNLOAD FW {time_duration}")
        else:
            logger().info(f"TIME TAKEN TO UPGRADE FIRMWARE: {time_duration} seconds")

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
def test_RAM_autojoin_with_one_profile_and_one_credential_C769960(
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)

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
            capture_file=request.node.name + f"capture_on_channel_{profiles[0]}"
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
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE ID:  {0}...."
        logger().info(f"DUT AUTO-JOINED WITH PROFILE ID:  {0} SUCCESSFULLY")
        wifi_obj.set_power_save()
        wifi_obj.ping()
        wifi_obj.sniffer_validation(profile=profiles[0])
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client"]
)
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        wifi_client.interfaces.wifi.start_ap(
            ssid=profiles[1]['ssid'],
            security=SecurityMode.WPA,
            passphrase=profiles[1]['passphrase'],
            channel=profiles[1]['channel'],
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
        wifi_access_point.interfaces.wifi.disconnect_devices(
            mac_address=wifi_obj.dut_mac_address
        )
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=profiles[1]["channel"]
        )
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=request.node.name + f"channel_{profiles[1]['channel']}"
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
        assert auto_join_status, f"DUT FAILED TO AUTO-JOIN WITH PROFILE {profile}...."
        wifi_obj.set_power_save()
        wifi_obj.ap_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        wifi_obj.sniffer_validation(profile=profiles[1])
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -I eth1 -c 10 {wifi_obj.device_ip}"
        )
        assert rc == 0, "Raspberry Pi client failed to ping DUT"
        logger().info(
            f"Ping Results:\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n"
        )
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
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


@wifi_dut_marker(ext_custom_bit=Si91xExtCustomFeatureBitMap.IEEE802_11W)
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
def test_RAM_autojoin_after_sl_net_deinit_with_wpa3_C769963(
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)

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
            capture_file=request.node.name + f"capture_on_channel_{profiles[0]}"
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


@wifi_dut_marker(
    oper_mode=Si91xOperatingMode.EAPWiFiClient,
    wifi_stack_len=3584,
    eap_cert=[
        "wifi-user.pem",
        "SL_NET_CERTIFICATE",
        "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID",
    ],
)
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
                "security": "WPA2_ENTERPRISE",
                "passphrase": "12345678",
                "encryption_type": 5,
            },
            {
                "ssid": "ssid_profile2",
                "channel": 6,
                "security": "WPA2_ENTERPRISE",
                "passphrase": "12345678",
                "encryption_type": 6,
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
def test_RAM_autojoin_with_two_enterprise_profiles_tls_ttls_c769968(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    profiles,
    radius_server,
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
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            profiles=profiles,
            request=request,
        )
        logger().info(
            f"\n <---------------- Set Profiles: {profiles} ---------------->\n"
        )
        for _ in range(len(profiles)):
            wifi_dut.interfaces.wifi.sl_net_set_profile(
                ssid=profiles[_]["ssid"],
                security=Map_security[profiles[_]["security"]],
                credential_id=5,
                priority=_ + 1,
                profile_id=_,
                encryption=_ + 5,
                expected_status="SL_STATUS_OK",
            )
            wifi_dut.interfaces.wifi.sl_net_set_credential(
                credential=profiles[_]["passphrase"], cred_id=5, type=10
            )
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
    wifi_stack_len=3072, ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF
)
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
@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.end_state("wifi_dut", wifi=["sl_net_deinit_client"])
def test_RAM_autojoin_with_HTTP_OTAF_upgrade_C769969(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    profiles,
    http_server,
):
    try:
        ping_count = utf_constants.get("ping_count")
        http_addr = utf_constants.get("rps_filename")
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
            profiles=profiles,
            request=request,
            http_server=http_server,
            test_type="otaf",
            http_addr=http_addr,
        )
        wifi_obj.power_save = False
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
        wifi_obj.start()
        time.sleep(30)
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        assert (
            not wifi_obj.status
        ), f"\n HTTP OTAF Not Failed, Expected Behaviour is HTTP otaf Fails during Auto-Join \n"
        logger().info(
            f"\n HTTP OTAF Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert wifi_obj.status, f"\n HTTP OTAF Failed for the Profile: {profiles[1]}"
        logger().info(f"\n HTTP OTAF Successfully Done for Profile: {profiles[1]} \n")
        wifi_obj.check_fw_version_after_upgrade()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
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
def test_RAM_autojoin_while_doing_TCP_TX_data_transfer_c769970(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    remote_socket_factory,
    profiles,
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
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            traffic_type="TCP",
            test_type="iperf",
            profiles=profiles,
            request=request,
            remote_socket_factory=remote_socket_factory,
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
        logger().info(f"\n <---------------- Start TCP TX Traffic ---------------->\n")
        wifi_obj.connect_socket_to_server()
        wifi_obj.start()
        time.sleep(10)
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        remote_socket_factory.interfaces.socket.close_all()
        assert (
            not wifi_obj.status
        ), f"\n TCP TX Traffic Not Failed, Expected Behaviour is TCP TX Data Transfer Fails during Auto-Join \n"
        logger().info(
            f"\n TCP TX Transfer Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_obj.connect_socket_to_server()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert (
            wifi_obj.status
        ), f"\n TCP TX Transfer Failed for the Profile: {profiles[1]}"
        logger().info(
            f"\n TCP TX Data Transfer Successfully Done for Profile: {profiles[1]} \n"
        )
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
        "ssid": "ssid_profile1",
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client"]
)
def test_RAM_autojoin_while_doing_UDP_TX_data_transfer_c769971(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    profiles,
    remote_socket_factory,
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
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            traffic_type="UDP",
            test_type="iperf",
            profiles=profiles,
            request=request,
            remote_socket_factory=remote_socket_factory,
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
        logger().info(f"\n <---------------- Start UDP TX Traffic ---------------->\n")
        wifi_obj.connect_socket_to_server()
        wifi_obj.start()
        time.sleep(10)
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        remote_socket_factory.interfaces.socket.close_all()
        assert (
            not wifi_obj.status
        ), f"\n UDP TX Traffic Not Failed, Expected Behaviour is UDP TX Data Transfer Fails during Auto-Join \n"
        logger().info(
            f"\n UDP TX Transfer Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_obj.connect_socket_to_server()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert (
            wifi_obj.status
        ), f"\n UDP TX Transfer Failed for the Profile: {profiles[1]}"
        logger().info(
            f"\n UDP TX Data Transfer Successfully Done for Profile: {profiles[1]} \n"
        )
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(
    coex_mode=Si91xCoexMode.WLANOnly,
    tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
    config_feature=Si91xConfigFeatureBitMap.TLS_V2,
    wifi_stack_len=3584,
    ca_cert=[
        "ca-chain.cert.pem",
        "SL_NET_SIGNING_CERTIFICATE",
        "SL_NET_TLS_SERVER_CREDENTIAL_START",
    ],
)
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
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client"]
)
def test_RAM_autojoin_autojoin_while_doing_SSL_TX_data_transfer_c769972(
    wifi_dut,
    wifi_access_point,
    wifi_sniffer,
    sl_collections,
    sniffer_filter,
    utf_constants,
    request,
    wifi_client,
    ssl_server,
    profiles,
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
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="ssl",
            profiles=profiles,
            request=request,
            ssl_server=ssl_server,
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
        logger().info(f"\n <---------------- Start SSL TX Traffic ---------------->\n")
        wifi_obj.connect_to_ssl_server()
        wifi_obj.start()
        time.sleep(15)
        logger().info(
            f"\n <---------------- Verify Auto Join Functionality with Profile: {profiles[1]} ---------------->\n"
        )
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        assert (
            not wifi_obj.status
        ), f"\n SSL TX Traffic Not Failed, Expected Behaviour is SSL TX Data Transfer Fails during Auto-Join \n"
        logger().info(
            f"\n SSL TX Transfer Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_obj.connect_socket_to_server()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert (
            wifi_obj.status
        ), f"\n SSL TX Transfer Failed for the Profile: {profiles[1]}"
        logger().info(
            f"\n SSL TX Data Transfer Successfully Done for Profile: {profiles[1]} \n"
        )
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker(tcp_feat_bit=Si91xTCPIPFeatureBitMap.SNTPClient)
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
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client"]
)
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
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
        wifi_obj.start()
        time.sleep(8)
        wifi_obj.verify_auto_join_functionality(profile=profiles[1])
        wifi_obj.wait_for_exit()
        assert (
            not wifi_obj.status
        ), f"\n SNTP Traffic Not Failed, Expected Behaviour is SNTP Data Transfer Fails during Auto-Join \n"
        logger().info(
            f"\n SNTP Transfer Failed, Which is Expected Behaviour with error: {wifi_obj.error_data} \n"
        )
        wifi_obj.ping()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        assert (
            wifi_obj.status
        ), f"\n SNTP Transfer Failed for the Profile: {profiles[1]}"
        logger().info(
            f"\n SNTP Data Transfer Successfully Done for Profile: {profiles[1]} \n"
        )
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.mqtt_server("raspi_mosquitto")
@wifi_dut_marker(ext_tcp_feat_bit=Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature)
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
        "security": "WPA2",
        "passphrase": "1234567890",
        "channel": 1,
    },
)
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "sl_net_deinit_client"]
)
def test_RAM_autojoin_while_doing_MQTT_data_transfer_c769975(
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
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
        wifi_obj.mqtt_connect_to_server()
        wifi_obj.start()
        time.sleep(20)
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
def test_RAM_autojoin_after_sl_net_deinit_wpa2_open_two_profiles_c769977(
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
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
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
        logger().info(f"\n Destroying the NW Manager Thread \n")
        wifi_dut.interfaces.wifi.sl_net_deinit(mode="client")
        wifi_obj.verify_auto_join_functionality(profile=profiles[0])

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
def test_RAM_autojoin_with_incorrect_psk_first_try_C769977(
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
            channel=profiles[1]['channel']
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
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        ssid_match = re.search(r'ssid\s*:\s*(\w+)', wireless_info)
        ssid = ssid_match.group(1).strip()
        assert ssid == profiles[1]['ssid'], f"\n DUT Should Connect to {profiles[1]} whereas it connected to {ssid_match}\n"
        wifi_obj.sniffer_validation(profile=profiles[1])
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@wifi_dut_marker()
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
            profiles=profiles,
            request=request,
        )
        vap_list = wifi_obj.verfiy_T_and_NT_based_mbssid_in_dut_list()
        logger().info(f"\n VAP LIST: {vap_list} \n")
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

@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["sl_net_deinit_client"])
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
            }
        ),
    ],
)
def test_RAM_autojoin_error_with_three_profiles_and_credentials_C769985(
    wifi_dut,
    profiles,
):

    try:
        wifi_obj = WLANAutoJoinThread(
            wifi_dut=wifi_dut,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(
            profiles=profiles,
            expect_error=True,
            error_code=SLStatus.SL_STATUS_INVALID_PROFILE,
        )

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Fixed in WC_4.0.0")
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["sl_net_deinit_client"])
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
def test_RAM_autojoin_error_with_invalid_credential_C769984(
    wifi_dut,
    profiles,
):

    try:
        wifi_obj = WLANAutoJoinThread(
            wifi_dut=wifi_dut,
            profiles=profiles,
        )
        wifi_obj.set_profiles_and_credentials(
            profiles=profiles,
            expect_error=True,
            error_code=SLStatus.SL_STATUS_INVALID_PROFILE,
        )

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
