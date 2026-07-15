import time
import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xJoinFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.powersave.test_wlan_max_psp_functionality_sdk import FilterPacket


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9117
        1. Configuration of DUT in 2G : B/G/N/AX
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BLE
        6. Stop the sniffer  
        7. Analyizing all sniffer capture packets for wpa3 enhancements
    setup requirement:
        1. DUT(RS9117)
        2. WSDK 3.0 Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K
"""


def wpa3_sniffer_validation(wifi_sniffer, sniffer_filter, ap_mac, sec_sdk_mac):
    packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
        sa_addr=ap_mac,
        da_addr=sec_sdk_mac,
        filter_name="wpa3_confirm_commit_message_with_addr")
    logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
        'find_packet_num']
    assert int(
        snif_pkt_count) == 4, "\n ********** Expected 4 packets found in sniffer comprising of Confirm and Commit messages ********** \n"

    logger().info(f"\n Validating the Association Request-Response and 4-way Handshake \n")
    packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
        sa_addr=sec_sdk_mac,
        da_addr=ap_mac,
        filter_name="assoc_req_resp_eapol_4_way_handshake")
    logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
        'find_packet_num']
    assert int(
        snif_pkt_count) == 6, "\n ********** EAPOL 4-way handshake and Association Request-Response not found in sniffer ********** \n"


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, remote_wiseconnect3=None,
                 sniffer_filter=None,
                 data=None, ping_count=None, data_transfer=True, test_name=None, sl_collections=None, wifi_client=None,
                 traffic_type=None, dut_leave=True, protocol=None, net_perf_client=None, test_case_no=None,
                 device_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.data = data
        self.ping_count = ping_count
        self.protocol = protocol
        self.traffic_type = traffic_type
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.dut_leave = dut_leave
        self.test_name = test_name
        self.dut_mac_addr = None
        self.device_ip = device_ip

    def Traffic_Ping(self):
        # Initiate ping from third party wifi-client to DUT
        self.wifi_client.interfaces.wifi.get_ip_address(version=4)
        logger().info(f"Initiate ping from third party wifi-client to DUT")
        self.wifi_dut.interfaces.wifi.ping(server_ip='192.168.50.5', ip_version=4, ping_size=64,
                                           num_ping_attempts=45)
        time.sleep(2)

    def Secondary_SDK_Conn(self):
        self.remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ssid = "Concurent_ap"
        channel = 1
        password = "Automation@Silabs"
        if self.test_case_no == 463719:
            self.remote_wiseconnect3.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0,
                                                                                     scan_interval=6,
                                                                                     beacon_missed_count=40,
                                                                                     first_time_retry_enable=0)
            self.remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                          security="wpa3",
                                                          passphrase=password,
                                                          channel=channel, timeout=60)
        elif self.test_case_no == 468633:
            self.remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                          security="wpa3",
                                                          passphrase=password,
                                                          channel=channel, timeout=60)
        else:
            self.remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                          security="wpa3_transition",
                                                          passphrase=password,
                                                          channel=channel, timeout=60)
        self.remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                          static_subnet=static_subnet,
                                                          static_gateway=static_gateway, timeout=10)
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        if self.test_case_no == 463719 or self.test_case_no == 468633:
            logger().info("DUT will leave at end of the test case")
            time.sleep(2)
        else:
            self.remote_wiseconnect3.interfaces.sapi.leave()
            time.sleep(1)
            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(2)
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop Sniffer finally")
        time.sleep(2)

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            if self.test_case_no == 463706 or self.test_case_no == 463710 or self.test_case_no == 463711:
                ssid = "Concurent_ap"
                # security = "wpa3_transition" -->"SI91X-21328 - As WPA3_Transition mode is not supported in ap mode now and this test cases does not requires transition mode so security is changed to wpa3"
                security = "wpa3"
                password = "Automation@Silabs"
                channel = "1"
                dtim_count = "1"
                beacon_interval = "100"
                ht_caps = 1

            if self.test_case_no == 463723:
                ssid = "Concurent_ap"
                # security = "wpa3_transition" -->"SI91X-21328 - As WPA3_Transition mode is not supported in ap mode now and this test cases does not requires transition mode so security is changed to wpa3"
                security = "wpa3"
                password = "Automation@Silabs"
                channel = "1"
                dtim_count = "1"
                beacon_interval = "100"
                ht_caps = 1

            if self.test_case_no == 463719 or self.test_case_no == 468633:
                ssid = "Concurent_ap"
                security = "wpa3"
                password = "Automation@Silabs"
                channel = "1"
                dtim_count = "1"
                beacon_interval = "100"
                ht_caps = 1

            time.sleep(2)
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0",
                                                           static_gateway="192.168.100.76")
            time.sleep(2)
            if self.test_case_no == 463723 or self.test_case_no == 463710 or self.test_case_no == 463711:
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
            elif self.test_case_no == 463719:
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval,
                                                       ht_caps=ht_caps)
            else:
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval,
                                                       ht_caps=ht_caps)
            if self.test_case_no == 463710:
                logger().info(f"this wpa2 sta connectivity")
            else:
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
            self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel,
                                               ssid=self.wifi_access_point.interfaces.wifi.ssid)
            if self.test_case_no == 463710:
                self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                   security="wpa2",
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                   channel=self.wifi_access_point.interfaces.wifi.channel, timeout=60)
            elif self.test_case_no == 463711:
                self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                   security="open",
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                   channel=self.wifi_access_point.interfaces.wifi.channel, timeout=60)
            elif self.test_case_no == 463719 or self.test_case_no == 468633:
                self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                   security="wpa3",
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                   channel=self.wifi_access_point.interfaces.wifi.channel, timeout=60)
            else:
                self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=self.wifi_access_point.interfaces.wifi.ssid)
                self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                   security="wpa3_transition",
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                   channel=self.wifi_access_point.interfaces.wifi.channel, timeout=60)
            time.sleep(5)
            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
            time.sleep(2)
            self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"DUT ip: {self.device_ip}")
            time.sleep(2)
            status = ping(self.device_ip, self.ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")
            time.sleep(2)

            if self.test_case_no == 463706 or self.test_case_no == 463710 or self.test_case_no == 463711 \
                    or self.test_case_no == 463719 or self.test_case_no == 468633:
                self.Secondary_SDK_Conn()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


class WifiPingThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_client=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.test_case_no = test_case_no

    def run(self):
        ip_version = "ipv4"
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        if self.test_case_no == 463719:
            logger().info(f"Initiate ping from DUT to third party wifi-client")
            self.wifi_dut.interfaces.wifi.ping(server_ip=host_ip, ip_version=ip_version, ping_size=64,
                                               num_ping_attempts=60)
        else:
            logger().info(f"Initiate ping from third party wifi-client to DUT")
            self.wifi_client.interfaces.wifi.ping(server_ip=self.wifi_dut.interfaces.wifi.get_ip_address(),
                                                  num_ping_attempts=45)


class LongPingThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_client=None, utf_constants=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.utf_constants = utf_constants

    def run(self):
        ip_version = "ipv4"
        ping_time = self.utf_constants.get("time_period")
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.wifi_dut.interfaces.wifi.ping(server_ip=host_ip, ip_version=ip_version, ping_size=64,
                                           num_ping_attempts=ping_time)


class SecLongPing(ThreadBase):
    def __init__(self, remote_wiseconnect3=None, utf_constants=None):
        super().__init__()
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.utf_constants = utf_constants

    def run(self):
        static_gateway = "192.168.100.76"
        ping_time = self.utf_constants.get("time_period")
        self.remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=ping_time,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)


class Data_transfer(ThreadBase):
    def __init__(self, sl_collections=None, wifi_client=None, wifi_dut=None, net_perf_client=None, device_ip=None,
                 test_case_no=None):
        super().__init__()
        self.sl_collections = sl_collections
        self.wifi_client = wifi_client
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.device_ip = device_ip
        self.test_case_no = test_case_no

    def run(self):
        if self.test_case_no == 463707:
            # Initiate ping from third party wifi-client to DUT
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            protocols = ["UDP"]
            traffic_types = ["TX"]
            for protocol in protocols:
                for traffic_type in traffic_types:
                    self.sl_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=protocol,
                        device_ip=self.device_ip,
                        host_ip=host_ip,
                        timeout=35,
                        traffic_type=traffic_type,
                    )
        if self.test_case_no == 463714:
            # Initiate ping from third party wifi-client to DUT
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            protocols = ["TCP"]
            traffic_types = ["TX"]
            for protocol in protocols:
                for traffic_type in traffic_types:
                    self.sl_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=protocol,
                        device_ip=self.device_ip,
                        host_ip=host_ip,
                        timeout=35,
                        traffic_type=traffic_type,
                    )
        if self.test_case_no == 463724:
            # Initiate ping from third party wifi-client to DUT
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address('eth1')
            logger().info(f"Remote device ip :{host_ip}")
            protocols = ["TCP"]
            traffic_types = ["RX"]
            for protocol in protocols:
                for traffic_type in traffic_types:
                    self.sl_collections.run_traffic(
                        wifi_dut=self.wifi_dut,
                        net_perf_client=self.net_perf_client,
                        protocol=protocol,
                        device_ip=self.device_ip,
                        host_ip=host_ip,
                        timeout=35,
                        traffic_type=traffic_type,
                    )
        else:
            logger().info(f"Test case {self.test_case_no} is not supported for data transfer")


class Start_stop(ThreadBase):
    def __init__(self, wifi_dut=None, iter_count=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.iter_count = iter_count
        self.test_case_no = test_case_no

    def run(self):
        ssid = "Concurent_ap"
        password = "Automation@Silabs"
        channel = "1"
        dtim_count = "1"
        beacon_interval = "100"
        ht_caps = 1
        # Initiate ping from third party DUT to wifi-client
        for i in range(0, self.iter_count):
            if self.test_case_no == 463720:
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa3", channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa2", channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
            if self.test_case_no == 468633:
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa3_transition", channel=channel,
                                                       psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa3", channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
            if self.test_case_no == 468634:
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa3", channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa3_transition", channel=channel,
                                                       psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
            if self.test_case_no == 463721:
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa2", channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa3", channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
            if self.test_case_no == 463722:
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="Open", channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)
                self.wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security="wpa3", channel=channel, psk=password,
                                                       dtim_beacon_count=dtim_count,
                                                       beacon_interval=beacon_interval, encryption=None,
                                                       ht_caps=ht_caps)
                time.sleep(10)
                self.wifi_dut.interfaces.wifi.stop_soft_ap_interface()
                time.sleep(5)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "channel": 1})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
# @pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463706')
# SI91X-21328 - As WPA3_Transition mode is not supported in ap mode now and this test cases does not requires transition mode so security is changed to wpa3
def test_wifi_sdk_conn_wpa3_in_concurrent_mode_C463706(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                       request, sl_collections, remote_wiseconnect3, sniffer_filter):
    '''Verify WLAN Connectivity to STAUT with Configured 3rd Party AP and 3rd party STA's connectivity
    to APUT with WPA3 Security'''
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        primary_sdk = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_name=test_name,
                                           wifi_sniffer=wifi_sniffer, ping_count=ping_count,
                                           sl_collections=sl_collections,
                                           test_case_no=463706, remote_wiseconnect3=remote_wiseconnect3)
        primary_sdk.start()
        primary_sdk.wait_for_exit()
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_mac,
            filter_name="aput_beaconing")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find beacons with wpa3_ap_ut."
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_mac,
            filter_name="wpa3_4_way_handshake_message")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 1})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463710')
# SI91X-21328 - As WPA3_Transition mode is not supported in ap mode now and this test cases does not requires transition mode so security is changed to wpa3
def test_wifi_sdk_conn_wpa3_in_concurrent_mode_C463710(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                       request, sl_collections, remote_wiseconnect3, sniffer_filter):
    '''Check wlan connectivity of STAUT with WPA2 Security to 3rd party AP and 3rd party STA
    connectivity with WPA3 Security to APUT'''
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        primary_sdk = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_name=test_name,
                                           wifi_sniffer=wifi_sniffer, ping_count=ping_count,
                                           sl_collections=sl_collections,
                                           test_case_no=463710, remote_wiseconnect3=remote_wiseconnect3)
        primary_sdk.start()
        primary_sdk.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "channel": 1})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463711')
# SI91X-21328 - As WPA3_Transition mode is not supported in ap mode now and this test cases does not requires transition mode so security is changed to wpa3
def test_wifi_sdk_conn_wpa3_in_concurrent_mode_C463711(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                       request, sl_collections, remote_wiseconnect3, sniffer_filter):
    '''Check wlan connectivity of STAUT with OPEN securty to 3rd party AP and 3rd party STA
    connectivity with WPA3 Security'''
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        primary_sdk = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_name=test_name,
                                           wifi_sniffer=wifi_sniffer, ping_count=ping_count,
                                           sl_collections=sl_collections,
                                           test_case_no=463711, remote_wiseconnect3=remote_wiseconnect3)
        primary_sdk.start()
        primary_sdk.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 1})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.test_src_map_id('C463723')
def test_wifi_sdk_conn_wpa3_in_concurrent_mode_C463723(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                       request, sl_collections, remote_wiseconnect3, sniffer_filter):
    '''Check whether APUT is able to bringup with WPA3 Security with No encryption in
    Concurrent Mode while Statut is connected to WPA3 AP'''
    try:
        ssid = "Concurent_ap"
        # security = "wpa3_transition" -->"SI91X-21328 - As WPA3_Transition mode is not supported in ap mode now and this test cases does not requires transition mode so security is changed to wpa3"
        security = "wpa3"
        password = "Automation@Silabs"
        channel = "1"
        dtim_count = "1"
        beacon_interval = "100"
        ht_caps = 1
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            power_save=False, ping_after_power_save=False)
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count,
                                          beacon_interval=beacon_interval, encryption=None,
                                          ht_caps=ht_caps)
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "channel": 1})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    sapi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463707')
def test_wifi_sdk_wpa3_when_sta_doing_udp_tx_C463707(wifi_sniffer, wifi_access_point, wifi_dut, protocol, wifi_client,
                                                     net_perf_client, request, sl_collections, remote_wiseconnect3,
                                                     sniffer_filter):
    '''Check 3rd party STA connectivity to APUT when STAUT is doing UDP Tx to AP Backend Machine'''
    try:
        ssid = "Concurent_ap"
        # security = "wpa3_transition" -->"SI91X-21328 - As WPA3_Transition mode is not supported in ap mode now and this test cases does not requires transition mode so security is changed to wpa3"
        security = "wpa3"
        password = "Automation@Silabs"
        channel = "1"
        dtim_count = "1"
        beacon_interval = "100"
        ht_caps = 1
        test_name = request.node.name
        dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC is : {dut_mac_addr}")
        time.sleep(1)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        time.sleep(2)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=channel, psk=password,
                                          dtim_beacon_count=dtim_count,
                                          beacon_interval=beacon_interval,
                                          ht_caps=ht_caps)
        time.sleep(5)
        conc_dut_mac_addr = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"#####********>>>>>>>>Concurrent DUT_MAC is : {conc_dut_mac_addr}")
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)

        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       power_save=False, ping_after_power_save=False)
        time.sleep(2)
        trafffic_obj = Data_transfer(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                     net_perf_client=net_perf_client, device_ip=dut_addr['device_ip'])
        trafffic_obj.start()
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                 security="wpa3",
                                                 passphrase=password,
                                                 channel=channel, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        time.sleep(30)
        wifi_dut.interfaces.wifi.leave()
        time.sleep(1)
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(1)
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
# @pytest.mark.legacy_deployed - "Removed as WPA3_Transition mode is not supported in ap mode now(SI91X-21328)"
@pytest.mark.skip("Removed as WPA3_Transition mode is not supported in ap mode now(SI91X-21328)")
@pytest.mark.test_src_map_id('C468528')
def test_wifi_sdk_wpa3_in_conc_mode_with_tdi_enable_C468528(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                            request, sl_collections, remote_wiseconnect3,
                                                            sniffer_filter):
    """Enable TDI functionality in concurrent mode with WPA3 transition mode,configure third party AP with same SSID as
APUT but security in WPA2 after STA gets connected with APUT stop AP and check whether STA is able to connect to
 WPA2 enabled AP or no"""
    try:
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ssid = "Concurent_ap"
        password = "Automation@123"
        security = "wpa3_transition"
        ip_version = 'ipv4'
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(10)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=1,
                                          psk=password, dtim_beacon_count=1, tdi_flags=1,
                                          beacon_interval=100, encryption=None, ht_caps=1)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.scan(channel=0, ssid=ssid)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                 security=security,
                                                 passphrase=password,
                                                 channel=1, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=ping_count,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        time.sleep(2)
        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_mixed")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sec_sdk_mac, da_addr=ap_mac_address,
            filter_name="assoc_req_resp_eapol_4_way_handshake")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa2 packets connection flow packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_wiseconnect3.interfaces.sapi.leave()


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
# @pytest.mark.legacy_deployed - "Removed as WPA3_Transition mode is not supported in ap mode now(SI91X-21328)"
@pytest.mark.skip("Removed as WPA3_Transition mode is not supported in ap mode now(SI91X-21328)")
@pytest.mark.test_src_map_id('C468529')
def test_wifi_sdk_wpa3_in_conc_mode_with_tdi_disable_C468529(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request, sl_collections, remote_wiseconnect3,
                                                             sniffer_filter):
    """Disable TDI functionality in concurrent mode with WPA3 transition mode , configure third party AP with same SSID
     as APUT but security in WPA2 after STA gets connected with APUT stop AP and check whether STA is able to connect
     to WPA2 enabled AP or n"""
    try:
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ssid = "Concurent_ap"
        password = "Automation@123"
        security = "wpa3_transition"
        ip_version = 'ipv4'
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(10)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid=ssid, security=security, channel=1,
                                          psk=password, dtim_beacon_count=1, tdi_flags=0,
                                          beacon_interval=100, encryption=None, ht_caps=1)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.scan(channel=0, ssid=ssid)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                 security=security,
                                                 passphrase=password,
                                                 channel=1, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=ping_count,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        time.sleep(2)
        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(60)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            filter_name="aput_wpa3_mixed")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sec_sdk_mac, da_addr=ap_mac_address,
            filter_name="assoc_req_resp_eapol_4_way_handshake")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa2 packets connection flow packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_wiseconnect3.interfaces.sapi.leave()


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
# @pytest.mark.legacy_deployed - "Removed as WPA3_Transition mode is not supported in ap mode now(SI91X-21328)"
@pytest.mark.skip("Removed as WPA3_Transition mode is not supported in ap mode now(SI91X-21328)")
@pytest.mark.test_src_map_id('C468633')
def test_wifi_sdk_wpa3_conc_while_ping_dut_ap_on_off_C468633(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request, sl_collections, remote_wiseconnect3,
                                                             sniffer_filter,
                                                             wifi_client):
    """Check whether AP is able to restart in different security Mode(WPA3 Transition to WPA3) or not in concurrent Mode
    while STAUT is pinging from AP Backend machin"""
    try:
        iter_count = utf_constants.get("iter_count")
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            power_save=False, ping_after_power_save=False)
        time.sleep(2)
        ping_obj = WifiPingThread(wifi_dut, wifi_client)
        ping_obj.start()
        stst_obj = Start_stop(wifi_dut, iter_count, test_case_no=468633)
        stst_obj.start()
        ping_obj.wait_for_exit()
        stst_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
# @pytest.mark.legacy_deployed - "Removed as WPA3_Transition mode is not supported in ap mode now(SI91X-21328)"
@pytest.mark.skip("Removed as WPA3_Transition mode is not supported in ap mode now(SI91X-21328)")
@pytest.mark.test_src_map_id('C468634')
def test_wifi_sdk_wpa3_conc_while_ping_dut_ap_on_off_C468634(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request, sl_collections, remote_wiseconnect3,
                                                             sniffer_filter,
                                                             wifi_client):
    """Check whether AP is able to restart in different security Mode(WPA3 to WPA3 Transition) or not in concurrent Mode while
    STAUT is pinging from AP Backend machine"""
    try:
        iter_count = utf_constants.get("iter_count")
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            power_save=False, ping_after_power_save=False)
        time.sleep(2)
        ping_obj = WifiPingThread(wifi_dut, wifi_client)
        ping_obj.start()
        stst_obj = Start_stop(wifi_dut, iter_count, test_case_no=468634)
        stst_obj.start()
        ping_obj.wait_for_exit()
        stst_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463720')
def test_wifi_sdk_wpa3_conc_while_ping_dut_ap_on_off_C463720(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request, sl_collections, remote_wiseconnect3,
                                                             sniffer_filter,
                                                             wifi_client):
    """Check whether AP is able to restart in different security Mode(WPA3 to WPA2) or not in concurrent Mode while
    STA-UT is pinging from AP Backend machine"""
    try:
        iter_count = utf_constants.get("iter_count")
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            power_save=False, ping_after_power_save=False)
        time.sleep(2)
        ping_obj = WifiPingThread(wifi_dut, wifi_client)
        ping_obj.start()
        stst_obj = Start_stop(wifi_dut, iter_count, test_case_no=463720)
        stst_obj.start()
        ping_obj.wait_for_exit()
        stst_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463721')
def test_wifi_sdk_wpa3_conc_while_ping_dut_ap_on_off_C463721(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request, sl_collections, remote_wiseconnect3,
                                                             sniffer_filter,
                                                             wifi_client):
    """Check whether AP is able to restart in different security Mode(WPA2 to WPA3) or not in concurrent Mode while
    STA-UT is pinging from AP Backend machine"""
    try:
        iter_count = utf_constants.get("iter_count")
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            power_save=False, ping_after_power_save=False)
        time.sleep(2)
        ping_obj = WifiPingThread(wifi_dut, wifi_client)
        ping_obj.start()
        stst_obj = Start_stop(wifi_dut, iter_count, test_case_no=463720)
        stst_obj.start()
        ping_obj.wait_for_exit()
        stst_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Concurent_ap', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463722')
def test_wifi_sdk_wpa3_conc_while_ping_dut_ap_on_off_C463722(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request, sl_collections, remote_wiseconnect3,
                                                             sniffer_filter,
                                                             wifi_client):
    """"Check whether AP is able to restart in different security Mode(OPEN to WPA3) or not in concurrent Mode while
    STA-UT is pinging from AP Backend machine"""
    try:
        iter_count = utf_constants.get("iter_count")
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                            wifi_access_point=wifi_access_point,
                                            associated=wifi_dut.interfaces.wifi.associated,
                                            power_save=False, ping_after_power_save=False)
        time.sleep(2)
        ping_obj = WifiPingThread(wifi_dut, wifi_client)
        ping_obj.start()
        stst_obj = Start_stop(wifi_dut, iter_count, test_case_no=463722)
        stst_obj.start()
        ping_obj.wait_for_exit()
        stst_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Station_STA_AP',
                          "channel": 1})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "join_feature_bitmap": Si91xJoinFeatureBitMap.ListenIntervalFromJoin,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurrent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463714')
def test_wifi_sdk_wpa3_conc_listen_based_ps_enabled_C463714(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                            request, sl_collections, remote_wiseconnect3,
                                                            sniffer_filter,
                                                            wifi_client, protocol, net_perf_client):
    """"Check wlan connectivity to APUT with LI Based PS enabled 3rd party STA and TCP Tx from STAUT to AP Backend
    machine in Both interfaces with WPA3 Security Mode"""
    try:
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid='Concurrent_ap', security="wpa3", channel=1, psk='Automation@123',
                                          dtim_beacon_count=1,
                                          beacon_interval=100, encryption=None,
                                          ht_caps=1)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       power_save=False, ping_after_power_save=False)
        time.sleep(2)

        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ssid = "Concurrent_ap"
        channel = 1
        password = "Automation@123"

        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                 security="wpa3",
                                                 passphrase=password,
                                                 channel=channel, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.set_performance_profile(mode='power_save_low_latency')
        remote_wiseconnect3.interfaces.sapi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                 psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=5,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        traffic_obj = Data_transfer(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                    net_perf_client=net_perf_client, device_ip=dut_addr['device_ip'],
                                    test_case_no=463714)
        traffic_obj.start()
        traffic_obj.wait_for_exit()
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Station_STA_AP',
                          "channel": 1})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "join_feature_bitmap": Si91xJoinFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurrent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463715')
def test_wifi_sdk_wpa3_conc_dtim_based_ps_enabled_C463715(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                          request, sl_collections, remote_wiseconnect3, sniffer_filter,
                                                          wifi_client, protocol, net_perf_client):
    """"Check wlan connectivity to APUT with DTIM Based PS enabled 3rd party STA and UDP Tx from STAUT to AP Backend
    machine with WPA3 Security Mode for both APUT and STAUT interfaces"""
    try:
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid='Concurrent_ap', security="wpa3", channel=1, psk='Automation@123',
                                          dtim_beacon_count=1,
                                          beacon_interval=100, encryption=None,
                                          ht_caps=1)
        time.sleep(2)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       power_save=False, ping_after_power_save=False)
        time.sleep(2)

        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ssid = "Concurrent_ap"
        channel = 1
        password = "Automation@123"

        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                 security="wpa3",
                                                 passphrase=password,
                                                 channel=channel, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.set_performance_profile(mode='power_save_low_latency')
        remote_wiseconnect3.interfaces.sapi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                 psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=5,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        traffic_obj = Data_transfer(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                    net_perf_client=net_perf_client, device_ip=dut_addr['device_ip'],
                                    test_case_no=463707)
        traffic_obj.start()
        traffic_obj.wait_for_exit()
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("remote_wiseconnect3", wifi=["init"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'STA_Concurrent_AP',
                          "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@Silabs", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C463719')
def test_wifi_sdk_wpa3_conc_while_ping_dut_ap_restart_C463719(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                              request, sl_collections, remote_wiseconnect3,
                                                              sniffer_filter,
                                                              wifi_client):
    """Check whether AP is able to restart or not with WPA3 Security in concurrent Mode while STAUT is pinging from
    AP Backend machine"""
    try:
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        primary_sdk = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_name=test_name,
                                           wifi_sniffer=wifi_sniffer, ping_count=ping_count,
                                           sl_collections=sl_collections,
                                           test_case_no=463719, remote_wiseconnect3=remote_wiseconnect3)
        primary_sdk.start()
        primary_sdk.wait_for_exit()
        time.sleep(2)
        ping_obj = WifiPingThread(wifi_dut, wifi_client, test_case_no=463719)
        ping_obj.start()

        time.sleep(2)
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        logger().info("##########==========>>>>>>>>>>>AP is stopped")
        time.sleep(2)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid='Concurent_ap', security="wpa3", channel=1, psk='Automation@Silabs',
                                          dtim_beacon_count=1,
                                          beacon_interval=100, encryption=None,
                                          ht_caps=1)
        time.sleep(25)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=ping_count,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.leave()
        ping_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")


@pytest.mark.start_state("wifi_dut", wifi=["init", "reset"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'STA-CONC-MODE', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C468633')
def test_wifi_sdk_wpa3_conc_mode_12_hour_ping_C468633(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                      sl_collections, remote_wiseconnect3, sniffer_filter, wifi_client):
    """Longrun : Verify WLAN Connectivity to STAUT with Configured 3rd Party AP and 3rd party STA's connectivity to APUT
     with WPA3 Security do ping on both interfaces for 12 hours"""
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        primary_sdk = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_name=test_name,
                                           wifi_sniffer=wifi_sniffer, ping_count=ping_count,
                                           sl_collections=sl_collections,
                                           test_case_no=468633, remote_wiseconnect3=remote_wiseconnect3)
        primary_sdk.start()
        primary_sdk.wait_for_exit()
        time.sleep(2)
        sta_ping_obj = LongPingThread(wifi_dut=wifi_dut, utf_constants=utf_constants, wifi_client=wifi_client)
        sec_ping_obj = SecLongPing(remote_wiseconnect3=remote_wiseconnect3, utf_constants=utf_constants)
        sta_ping_obj.start()
        sec_ping_obj.start()
        sta_ping_obj.wait_for_exit()
        sec_ping_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("STA-DUT is left from Thrid Party AP")
        remote_wiseconnect3.interfaces.sapi.leave()
        logger().info("CLI-DUT is left from AP-Mode")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Station_STA_AP',
                          "channel": 1})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "join_feature_bitmap": Si91xJoinFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurrent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.end_state("remote_wiseconnect3", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C463713')
def test_wifi_sdk_wpa3_conc_LI_based_ps_enabled_11n_mode_C463713(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                 utf_constants,
                                                                 request, sl_collections, remote_wiseconnect3,
                                                                 sniffer_filter,
                                                                 wifi_client, protocol, net_perf_client):
    '''
    Test WPA3 concurrent mode with Listen Interval based power save in 11n mode.

    Verifies WPA3 security in concurrent mode (AP + STA) with 802.11n support
    while enabling Listen Interval based power save functionality. Tests PS-POLL
    timing validation and validates power save behavior through sniffer capture.
    Runs UDP traffic during power save mode to verify functionality.

    Args:
        wifi_sniffer: Sniffer device for packet capture
        wifi_access_point: Third-party AP for STA connection
        wifi_dut: Device under test in concurrent mode
        utf_constants: Test constants including ping parameters
        request: Pytest request object
        sl_collections: Utility collections for test operations
        remote_wiseconnect3: Secondary SDK device
        sniffer_filter: Filter utilities for packet analysis
        wifi_client: Third-party WiFi client
        protocol: Network protocol (UDP)
        net_perf_client: Network performance client
    '''
    try:
        listen_interval = 1000
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ssid = "Concurrent_ap"
        channel = 1
        password = "Automation@123"
        packet_filter2 = "    Type/Subtype: Association Response (0x0001)"
        ps_poll_time_delta_obj = FilterPacket()
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"\n DUT as AP MAC Address: {ap_mac} \n")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"\n DUT MAC is : {sec_sdk_mac} \n")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"\n AP_MAC_ADDRESS: {ap_mac_address} \n")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid='Concurrent_ap', security="wpa3", channel=1, psk='Automation@123',
                                          beacon_interval=100, encryption=None,
                                          ht_caps=1)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       power_save=False, ping_after_power_save=False)
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        logger().info(f"\n Enabling Listen Interval Based PS for DUT and Remote WiseConnect_3 \n")
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        remote_wiseconnect3.interfaces.sapi.set_listen_interval(listen_interval=1000)
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                 security="wpa3",
                                                 passphrase=password,
                                                 channel=channel, timeout=60)
        ip_obj = remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                              static_subnet=static_subnet,
                                                              static_gateway=static_gateway, timeout=10)
        station_ip = remote_wiseconnect3.interfaces.sapi.get_device_ip(ip_obj)
        logger().info(f"\n Station IP Address after DHCP is  : {station_ip} \n")
        remote_wiseconnect3.interfaces.sapi.set_performance_profile(mode='power_save_low_latency')
        remote_wiseconnect3.interfaces.sapi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                 psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        # status = ping(station_ip, 10, 20)
        # assert status, "\n Ping from AP backend to STA Connected to AP Unsuccessful \n"
        traffic_obj = Data_transfer(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                    net_perf_client=net_perf_client, device_ip=dut_addr['device_ip'],
                                    test_case_no=463707)
        traffic_obj.start()
        traffic_obj.wait_for_exit()
        remote_wiseconnect3.interfaces.sapi.leave()
        wifi_dut.interfaces.wifi.leave()
        logger().info("DUT is left from AP")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac, da_addr=sec_sdk_mac, filter_name="association_response")
        validation = True
        powersave_validation = True
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'No packet found for Assoc resp frame'
        packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {sec_sdk_mac}) &&' \
                         f' (wlan.da == {ap_mac}))'

        packet_filter3 = f'(wlan.da == {sec_sdk_mac} && wlan.fc.type_subtype == 0x28) || (wlan.ta == {sec_sdk_mac} && ' \
                         f'(wlan.fc.type_subtype == 0x24 || wlan.fc.type_subtype ==0x1a)) || (wlan.sa == {ap_mac} && ' \
                         f'wlan.fc.type_subtype==8) || ((wlan.sa == {ap_mac} && wlan.da == {sec_sdk_mac}) &&' \
                         f'(wlan.fc.type_subtype == 0x002c || wlan.fc.type_subtype == 0x000d || wlan.fc.type_subtype == 0x0018))'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
        assert \
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, None, powersave_validation)[
                'packet_count']

        time.sleep(1)
        association_id = ps_poll_time_delta_obj.get_association_id()
        if association_id is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')
        wifi_sniffer.interfaces.capture.stop_capture()

        ps_poll_packets_time_delta_list, case1, case2 = ps_poll_time_delta_obj.listen_interval_based_validation(
            listen_interval,
            association_id)
        case3 = ps_poll_time_delta_obj.validate_time_delta(ps_poll_packets_time_delta_list, listen_interval)
        if case1 != 0:
            logger().info(
                f'Observed {case1} times DUT is sending PS-POLL to retrieve the data even though TIM is not set')
        if case2 != 0:
            logger().info(
                f'Observed {case2} times DUT is sending the PS-POLL to retrieve the data after post listen interval beacon only even though more data bit is set')
        if case3 != 0:
            logger().info(
                f'Observed {case3} times DUT is unable to send PS-POLL at listen interval')

        if case1 or case3 > 3 or case2 != 0:
            assert False
        else:
            assert True, "DUT is sending PS-POLL to retrieve the data at Listen interval beacon only"

        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Station_STA_AP',
                          "channel": 1})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "join_feature_bitmap": Si91xJoinFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurrent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.end_state("remote_wiseconnect3", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C463724')
def test_wifi_sdk_wpa3_conc_with_11n_mode_tcp_rx_C463724(wifi_sniffer, wifi_access_point, wifi_dut,
                                                         request, sl_collections, remote_wiseconnect3, sniffer_filter,
                                                         wifi_client, protocol, net_perf_client):
    """
    Test WPA3 concurrent mode with 11n mode TCP RX traffic.

    Verifies WPA3 security in concurrent mode (AP + STA) with 802.11n support
    while running TCP receive traffic. Validates beacon frames and 4-way handshake
    messages through sniffer capture.

    Args:
        wifi_sniffer: Sniffer device for packet capture
        wifi_access_point: Third-party AP for STA connection
        wifi_dut: Device under test in concurrent mode
        request: Pytest request object
        sl_collections: Utility collections for test operations
        remote_wiseconnect3: Secondary SDK device
        sniffer_filter: Filter utilities for packet analysis
        wifi_client: Third-party WiFi client
        protocol: Network protocol (TCP)
        net_perf_client: Network performance client
    """
    try:
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        time.sleep(2)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ap(ssid='Concurrent_ap', security="wpa3", channel=1, psk='Automation@123',
                                          beacon_interval=100, encryption=None,
                                          ht_caps=1)
        time.sleep(2)
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       power_save=False, ping_after_power_save=False)
        time.sleep(2)

        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ssid = "Concurrent_ap"
        channel = 1
        password = "Automation@123"
        logger().info(f"\n Enabling Listen Interval Based PS for DUT and Remote Wiseconnect3")
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                 security="wpa3",
                                                 passphrase=password,
                                                 channel=channel, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.set_performance_profile(mode='power_save_low_latency')
        remote_wiseconnect3.interfaces.sapi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                 psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=5,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        time.sleep(2)
        traffic_obj = Data_transfer(wifi_dut=wifi_dut, sl_collections=sl_collections, wifi_client=wifi_client,
                                    net_perf_client=net_perf_client, device_ip=dut_addr['device_ip'],
                                    test_case_no=463724)
        traffic_obj.start()
        traffic_obj.wait_for_exit()
        time.sleep(2)
        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_mac,
            filter_name="aput_beaconing")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find beacons with WPA3_APUT."
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_mac,
            filter_name="wpa3_4_way_handshake_message")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'STA-CONC-MODE', "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.end_state("remote_wiseconnect3", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C537925')
def test_wifi_sdk_wpa3_conc_mode_12_hour_ping_disable_11ax_mode_C537925(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                        utf_constants, request,
                                                                        sl_collections, remote_wiseconnect3,
                                                                        wifi_client):
    """
    Test WPA3 concurrent mode with 12-hour ping and 11ax mode disabled.

    Verifies WPA3 security in concurrent mode (AP + STA) with 802.11ax support
    disabled while running extended ping tests for 12 hours. Tests concurrent
    operation with both primary and secondary SDK devices performing continuous
    ping operations.

    Args:
        wifi_sniffer: Sniffer device for packet capture
        wifi_access_point: Third-party AP for STA connection
        wifi_dut: Device under test in concurrent mode
        utf_constants: Test constants including ping parameters
        request: Pytest request object
        sl_collections: Utility collections for test operations
        remote_wiseconnect3: Secondary SDK device
        wifi_client: Third-party WiFi client
    """
    try:
        ping_count = utf_constants.get("ping_count")
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"\n DUT AS ACCESS POINT MAC ADDRESS : {ap_mac} \n")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"\n DUT MAC ADDRESS : {sec_sdk_mac} \n")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"\n AP_MAC_ADDRESS: {ap_mac_address} \n")
        primary_sdk = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           test_name=request.node.name,
                                           wifi_sniffer=wifi_sniffer, ping_count=ping_count,
                                           sl_collections=sl_collections,
                                           test_case_no=468633, remote_wiseconnect3=remote_wiseconnect3)
        primary_sdk.start()
        primary_sdk.wait_for_exit()
        sta_ping_obj = LongPingThread(wifi_dut=wifi_dut, utf_constants=utf_constants, wifi_client=wifi_client)
        sec_ping_obj = SecLongPing(remote_wiseconnect3=remote_wiseconnect3, utf_constants=utf_constants)
        sta_ping_obj.start()
        sec_ping_obj.start()
        sta_ping_obj.wait_for_exit()
        sec_ping_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("STA-DUT is left from Third Party AP")
        remote_wiseconnect3.interfaces.sapi.leave()
        logger().info("CLI-DUT is left from AP-Mode")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2WPA3MixedMode', "passphrase": "Automation@Silabs", "ssid": 'STAUT_INTERFACE',
                          "channel": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "wpa3_transition", "ssid": "APUT_INTERFACE", "passphrase": "Automation@Silabs", "channel": 1
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.end_state("remote_wiseconnect3", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C468607')
def test_wifi_sdk_wpa3_transition_conc_start_stop_ap_C468607(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                             request, sl_collections, remote_wiseconnect3,
                                                             sniffer_filter,
                                                             wifi_client):
    """
    Test WPA3 transition mode concurrent start/stop AP functionality.

    Verifies WPA3 transition security in concurrent mode (AP + STA) with
    repeated start/stop cycles of the AP interface. Tests concurrent operation
    where DUT acts as both AP (WPA3 transition) and STA (WPA3) simultaneously.
    Validates beacon frames and 4-way handshake messages through sniffer capture.

    Args:
        wifi_sniffer: Sniffer device for packet capture
        wifi_access_point: Third-party AP for STA connection
        wifi_dut: Device under test in concurrent mode
        utf_constants: Test constants including ping parameters
        request: Pytest request object
        sl_collections: Utility collections for test operations
        remote_wiseconnect3: Secondary SDK device
        sniffer_filter: Filter utilities for packet analysis
        wifi_client: Third-party WiFi client
    """
    try:
        ping_count = utf_constants.get('ping_count')
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        for _ in range(3):
            sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                      static_subnet="255.255.255.0",
                                                      static_gateway="192.168.100.76")
            wifi_dut.interfaces.wifi.start_ap(ssid='APUT_INTERFACE', security="wpa3_transition", channel=1,
                                              psk='Automation@123',
                                              beacon_interval=100, encryption=None,
                                              ht_caps=1)
            if _ == 0:
                wifi_dut.interfaces.wifi.scan(ssid='STAUT_INTERFACE', channel=wifi_access_point.interfaces.wifi.channel)
                wifi_dut.interfaces.wifi.join(channel=wifi_access_point.interfaces.wifi.channel, security='wpa3',
                                              passphrase='Automation@Silabs', ssid='STAUT_INTERFACE')
                ip_object = wifi_dut.interfaces.wifi.start_ip()
                device_ip = wifi_dut.interfaces.wifi.get_device_ip(device_ip=ip_object)
                logger().info(f"\n The Device IP is : {device_ip}\n")

            remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
            )
            static_ip = "192.168.100.77"
            static_subnet = "255.255.255.0"
            static_gateway = "192.168.100.76"
            ip_version = 'ipv4'
            ssid = "APUT_INTERFACE"
            channel = 1
            password = "Automation@123"
            logger().info(f"\n Enabling Listen Interval Based PS for DUT and Remote Wiseconnect3")
            remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                     security="wpa3",
                                                     passphrase=password,
                                                     channel=channel, timeout=60)
            remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                         static_subnet=static_subnet,
                                                         static_gateway=static_gateway, timeout=10)
            remote_wiseconnect3.interfaces.sapi.set_performance_profile(mode='power_save_low_latency')
            remote_wiseconnect3.interfaces.sapi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                     psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=ping_count,
                                                     ping_timeout=10, ip_version='ipv4', ping_size=64)
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            remote_wiseconnect3.interfaces.sapi.leave()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_mac,
            filter_name="aput_beaconing")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find beacons with WPA3_APUT."
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_mac,
            filter_name="wpa3_4_way_handshake_message")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find wpa3 packets."
    except Exception as e:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA3', "passphrase": "Automation@Silabs", "ssid": 'Station_STA_AP',
                          "channel": 1})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "channel": 1})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "Concurent_ap", "passphrase": "Automation@123", "channel": 1
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.end_state("remote_wiseconnect3", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q4
@pytest.mark.test_src_map_id('C468611')
def test_wifi_sdk_conn_wpa3_in_concurrent_mode_11n_full_sae_C468611(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                    utf_constants,
                                                                    request, sl_collections, remote_wiseconnect3,
                                                                    sniffer_filter):
    try:
        snif_pkt_count = ""
        ping_count = utf_constants.get("ping_count")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"\n DUT AS STATION MAC ADDRESS : {sec_sdk_mac} \n")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid='Concurrent_ap', security="wpa3", channel=1, psk='Automation@123',
                                          beacon_interval=100, encryption=None,
                                          ht_caps=1)
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       associated=wifi_dut.interfaces.wifi.associated,
                                                       power_save=False, ping_after_power_save=False)
        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"\n DUT AS ACCESS POINT MAC ADDRESS: {ap_mac} \n")
        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired
        )
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ssid = "Concurrent_ap"
        channel = 1
        password = "Automation@123"
        logger().info(f"\n Enabling Listen Interval Based PS for DUT and Remote Wiseconnect3")
        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid,
                                                 security="wpa3",
                                                 passphrase=password,
                                                 channel=channel, timeout=60)
        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                     static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)

        remote_wiseconnect3.interfaces.sapi.set_performance_profile(mode='power_save_low_latency')
        remote_wiseconnect3.interfaces.sapi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                 psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=5,
                                                 ping_timeout=10, ip_version='ipv4', ping_size=64)
        remote_wiseconnect3.interfaces.sapi.leave()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"\n ***********{ap_mac}**********")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac,
            da_addr=sec_sdk_mac,
            filter_name="wpa3_confirm_commit_message_with_addr")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        snif_pkt_count = int(wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'find_packet_num'])
        logger().info(f"\n ********** Confirm and Commit messages found in sniffer = {snif_pkt_count} ********** \n")
        assert int(
            snif_pkt_count) == 4, "\n ********** Expected 4 packets found in sniffer comprising of Confirm and Commit messages ********** \n"

        logger().info(f"\n Validating the Association Request-Response and 4-way Handshake \n")
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sec_sdk_mac,
            da_addr=ap_mac,
            filter_name="assoc_req_resp_eapol_4_way_handshake")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'find_packet_num']
        assert int(
            snif_pkt_count) == 6, "\n ********** EAPOL 4-way handshake and Association Request-Response not found in sniffer ********** \n"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
