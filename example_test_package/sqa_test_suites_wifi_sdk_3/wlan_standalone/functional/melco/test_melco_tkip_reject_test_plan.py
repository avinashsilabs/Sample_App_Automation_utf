from utf.utils.logger import get_logger
import pytest
import string
import time
import ipaddress
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utf_config import UtfConfig
from utf.interfaces.iperf.iperf_constants import IperfConstants


def logger():
    return get_logger(__name__)


class WLanThread(ThreadBase):
    client_info = {"mac_address": None, "ip_address": None}
    dut_info = {"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None,
                 wifi_client=None, test_id=None, test_type=None, ping_from="remote", ping_count=10, addr_type="global",
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60, wifi_clients=None,
                 wifi_sniffer=None, passphrase=None, conn_attr=None, enc=None, scan=None, capture_filename=None,
                 utf_constants=None, dtim_period=None, enable_data_rate=None, ht_caps=None,
                 ssid=None, security=None, password=None, beacon_interval=None, dut_global_ip=None,
                 dut_link_local_ip=None, beacon_stop=None,
                 channel=None, dtim_count=None, no_of_clients=None, expected_negative_status=None, sniffer_filter=None):
        super().__init__()
        self.scan = scan
        self.beacon_stop=beacon_stop
        self.capture_filename = capture_filename
        self.enc = enc
        self.dut_global_ip = dut_global_ip
        self.dut_link_local_ip = dut_link_local_ip
        self.conn_attr = conn_attr
        self.passphrase = passphrase
        self.sniffer_filter = sniffer_filter
        self.wifi_clients = wifi_clients
        self.wifi_sniffer = wifi_sniffer
        self.utf_constants = utf_constants
        self.enable_data_rate = enable_data_rate
        self.expected_negative_status = expected_negative_status
        self.dtim_period = dtim_period
        self.ht_caps = ht_caps
        self.ssid = ssid
        self.security = security
        self.password = password
        self.dtim_count = dtim_count
        self.beacon_interval = beacon_interval
        self.channel = channel
        self.no_of_clients = no_of_clients
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_from = ping_from
        self.ping_count = ping_count
        self.test_type = test_type
        self.dut_add_dict = None
        self.addr_type = addr_type
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        # self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        # logger().info(f"in harness power_save flag set to be : {self.power_save}")
        self.remote_ip = None

    def aput_start(self):
        if self.test_id in [557402]:
            security = "wpa"
        else:
            security = "wpa2"
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.wifi_dut.interfaces.wifi.start_ap(ssid="917_AP", security=security, psk="12345678", channel=11,
                                               dtim_beacon_count=3,
                                               beacon_interval=100,
                                               ht_caps=1, beacon_stop=self.beacon_stop)

    def raspi_sta_assoc_to_dut_ap(self):
        for i in range(0, self.no_of_clients):
            self.dut_add_dict = {}
            self.ping_count = 10
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join(scan_ssid=1)
            time.sleep(5)
            self.dut_add_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ip']}")
            for count in range(5):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    self.dut_add_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {self.dut_add_dict['rasp_mac_address']}")
                    self.raspi_mac = self.dut_add_dict['rasp_mac_address']
                    self.dut_add_dict['client_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip: {self.dut_add_dict['client_ip']}")
                    time.sleep(10)
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {self.ping_count} {self.dut_add_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        logger().info("Waiting 30 seconds to check connection stability")
        time.sleep(30)
        logger().info("Checking the connection stability after 30 seconds")

    def sniffer_capture_start(self, channel=11, capture_filename="sniffer_capture"):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)

        logger().info(f"channel number in which the sniffer capture is starting is {self.channel}")
        logger().info(
            f" ******* start capturing with Sniffer by giving the test case name as filename {self.capture_filename} ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)

    def third_party_ap_mac_address(self):
        ap_mac_addr = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"third_party_ap_mac_address is {ap_mac_addr}")
        return ap_mac_addr

    def aput_mac_address(self):
        if self.test_id in [557402, 557402]:
            self.ap_mac_in_ap_alone = self.wifi_dut.interfaces.wifi.get_mac_address(2)
        else:
            self.ap_mac_in_ap_alone = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"printing aput mac address {self.ap_mac_in_ap_alone}")
        return self.ap_mac_in_ap_alone

    def check_beacons_from_aput(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.aput_mac_address(),
            filter_name="beacon")
        logger().info(f"printing check_no_beacons_from_aput the vlaue of packet filter 1 {packet_filter1}")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

    def check_tkip_aes_security_from_ap_beacon(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.third_party_ap_mac_address(),
            filter_name="ap_beacon_with_tkip_aes_mixed")
        logger().info(f"Checking the beacons from 3rd party AP with TKIP+AES Securities. packet filter 1 {packet_filter1}")
        status = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        if self.test_id in [557393, 557395, 557400, 557402]:
            assert status
        else:
            assert not status
        # assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
        #     'packet_count']

    def check_tkip_aes_security_from_ap_probe_response(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.third_party_ap_mac_address(),
            filter_name="ap_probe_response_with_tkip_aes_mixed")
        logger().info(f"Checking the probe response from 3rd party AP with TKIP+AES Securities packet filter 1 {packet_filter1}")
        status = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        if self.test_id in [557393, 557395, 557400, 557402]:
            assert status
        else:
            assert not status

    def sniffer_check_for_tkip_aes_flags(self):
        self.check_tkip_aes_security_from_ap_beacon()
        self.check_tkip_aes_security_from_ap_probe_response()

    def staut_scan(self):
        scan_status, reason = self.scan(self.wifi_dut, scan_status=False, retry_count=5, channel=0)
        assert scan_status, f"....Scanning for AP failed..with reason: {reason}...."

    def staut_conn(self):
        try:
            if self.test_id in [557393, 557395, 557400, 557402]:
                expected_status = SLStatus.SL_STATUS_SI91X_REJOIN_FAILURE
            else:
                expected_status = SLStatus.SL_STATUS_OK
            self.conn_attr = self.wifi_dut.interfaces.wifi.join(ssid=self.ssid,
                                                                security=self.security,
                                                                passphrase=self.passphrase,
                                                                channel=self.channel,
                                                                pmk_enable=False,
                                                                enc=self.enc,
                                                                channel_bitmap_2_4=None,
                                                                channel_bitmap_5=None,
                                                                expected_status=expected_status,
                                                                mac=None,
                                                                timeout=60,
                                                                )

        except Exception as e:
            raise e

    def staut_ipconfig(self):
        ip_config = ""
        logger().info("....DUT configures the IP Address....")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6")
        logger().info(f"prinitng ip config {ip_config}")
        self.dut_global_ip = ip_config[1]
        self.dut_link_local_ip = ip_config[0]
        logger().info(f"DUT_Global IPv6 address is {self.dut_global_ip}")
        logger().info(f"DUT Link local IPv6 address is {self.dut_link_local_ip}")
        return ip_config

    def remote_device_ip(self):
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.addr_type)
        # remote_ip = "2401:3500:1325:1313::186d"
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        return ip_addr

    def ping_async(self):
        ip_addr = self.remote_device_ip()
        logger().info(f"remote device ip is {ip_addr}")
        self.logger.info(f"PINGING TO {ip_addr}")
        time.sleep(5)
        self.wifi_dut.interfaces.wifi.ping(server_ip=ip_addr, ip_version='ipv6', ping_size=64, num_ping_attempts=10)

    def ping_from_ap_support_machine(self):
        if self.addr_type == "link":
            status = ping(self.dut_link_local_ip, 10)
        else:
            status = ping(self.dut_global_ip, 10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def dut_sta_wifi_connection(self):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture()
        time.sleep(3)
        if self.test_id in ["557391", "557392"]:
            self.expected_negative_status = "0x48"
        else:
            self.expected_negative_status = "0x48"

        self.enc = "tkip"

        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                  wifi_access_point=self.wifi_access_point,
                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                  enc=self.enc,
                                                                  power_save=False, retry_count=3,
                                                                  ping_before_power_save=False,
                                                                  ping_after_power_save=False,
                                                                  expected_negative_status=True)
        if self.info_attr == SLStatus.SL_STATUS_COMMAND_IS_INVALID:
            assert False
        else:
            assert True
        ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                ip_version="ipv6")
        logger().info(f"printing device ip {ip_config[1]}")
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type)
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        self.ping_async(ip_addr=ip_addr)

    def dut_ap_conn(self):
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                            channel=self.channel, ssid=self.ssid,
                                                                            security=self.security,
                                                                            password=self.password,
                                                                            dtim_count=self.dtim_count,
                                                                            beacon_interval=self.beacon_interval,
                                                                            ping_count=10,
                                                                            no_of_clients=self.no_of_clients,
                                                                            leave=self.leave)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.OpenMode
                    | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
#tkip_aes
@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "aes",
                               "security": "WPA2",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_staut_connection_with_wpa2_security_with_default_sec_new_tc557391(wifi_dut, wifi_access_point,
                                                                                    wifi_sniffer,
                                                                                    sl_collections, request,
                                                                                    sniffer_filter,
                                                                                    wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557391, addr_type="global",
                              wifi_client=wifi_client, sniffer_filter=sniffer_filter, ssid="ipv6_autiomation",
                              passphrase=12345678,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557391")

        wlan_obj.sniffer_capture_start()
        wlan_obj.staut_conn()
        wlan_obj.staut_ipconfig()
        wlan_obj.ping_async()
        wlan_obj.ping_from_ap_support_machine()
        wifi_sniffer.interfaces.capture.stop_capture()
        wlan_obj.sniffer_check_for_tkip_aes_flags()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "aes",
                               "security": "WPA2",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_staut_connection_with_wpa2_security_with_ccmp_enc_new_tc557392(wifi_dut, wifi_access_point,
                                                                                 wifi_sniffer,
                                                                                 sl_collections, request,
                                                                                 sniffer_filter,
                                                                                 wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557392,
                              sniffer_filter=sniffer_filter,
                              wifi_client=wifi_client, ssid="ipv6_autiomation", passphrase=12345678,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557392")

        wlan_obj.sniffer_capture_start()
        wlan_obj.staut_conn()
        wlan_obj.staut_ipconfig()
        wlan_obj.ping_async()
        wlan_obj.ping_from_ap_support_machine()
        # wlan_obj.staut_ipconfig()
        wifi_sniffer.interfaces.capture.stop_capture()
        wlan_obj.sniffer_check_for_tkip_aes_flags()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.OpenMode
                    | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "tkip_aes",
                               "security": "WPAWPA2MixedMode",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_staut_connection_with_wpa2_tkip_ccmp_on_ap_side_new_tc557393(wifi_dut, wifi_access_point,
                                                                               wifi_sniffer,
                                                                               sl_collections, request, sniffer_filter,
                                                                               wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557393,
                              sniffer_filter=sniffer_filter,
                              wifi_client=wifi_client, ssid="ipv6_autiomation", passphrase=12345678,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557393")

        wlan_obj.sniffer_capture_start()
        wlan_obj.staut_conn()
        # wlan_obj.staut_ipconfig()
        wifi_sniffer.interfaces.capture.stop_capture()
        wlan_obj.sniffer_check_for_tkip_aes_flags()

        """
        Need to check the 3rd party AP Probe response should see the TKIP
        
        DUT should nt send the Assoc request, Sniffer code need to be added
        """

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "tkip_aes",
                               "security": "WPAWPA2MixedMode",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_staut_connection_with_wpa_wpa2_security_tkip_aes_new_security_tc557395(wifi_dut, wifi_access_point,
                                                                                         wifi_sniffer,
                                                                                         sl_collections, request,
                                                                                         sniffer_filter,
                                                                                         wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557395,
                              sniffer_filter=sniffer_filter,
                              wifi_client=wifi_client, ssid="ipv6_autiomation", passphrase=12345678,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557395")

        wlan_obj.sniffer_capture_start()
        wlan_obj.staut_conn()
        # wlan_obj.staut_ipconfig()
        wifi_sniffer.interfaces.capture.stop_capture()
        wlan_obj.sniffer_check_for_tkip_aes_flags()
        """
        Need to check the 3rd party AP Probe response should see the TKIP

        DUT should nt send the Assoc request, Sniffer code need to be added
        """

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "tkip_aes",
                               "security": "WPAWPA2MixedMode",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_staut_connection_with_wpa_wpa2_security_tkip_aes_security_tc557396(wifi_dut, wifi_access_point,
                                                                                     wifi_sniffer,
                                                                                     sl_collections, request,
                                                                                     sniffer_filter,
                                                                                     wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557396,
                              wifi_client=wifi_client, ssid="ipv6_autiomation", passphrase=12345678,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557396")

        wlan_obj.sniffer_capture_start()
        wlan_obj.staut_conn()
        # wlan_obj.staut_ipconfig()
        wifi_sniffer.interfaces.capture.stop_capture()

        """
        Need to check the 3rd party AP Probe response should see the TKIP

        DUT should nt send the Assoc request, Sniffer code need to be added
        """

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "tkip_aes",
                               "security": "WPAWPA2MixedMode",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_staut_connection_wpa2_enterpise_security_tkip_aes_tc557403(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                             sl_collections, request, sniffer_filter,
                                                                             wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557403,
                              wifi_client=wifi_client, ssid="ipv6_autiomation", passphrase=12345678,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557403")

        wlan_obj.dut_sta_wifi_connection()
        wifi_sniffer.interfaces.capture.stop_capture()

        """
        Need to check the 3rd party AP Probe response should see the TKIP

        DUT should nt send the Assoc request, Sniffer code need to be added
        """

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "tkip_aes",
                               "security": "WPAWPA2MixedMode",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_staut_connection_wpa2_enterpise_security_aes_tc557404(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                        sl_collections, request, sniffer_filter,
                                                                        wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557404,
                              wifi_client=wifi_client, ssid="ipv6_autiomation", passphrase=12345678,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557404")

        wlan_obj.dut_sta_wifi_connection()
        wifi_sniffer.interfaces.capture.stop_capture()

        """
        Need to check the 3rd party AP Probe response should see the TKIP

        DUT should nt send the Assoc request, Sniffer code need to be added
        """

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)

@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "aes",
                               "security": "WPAWPA2MixedMode",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_staut_connection_with_wpa_wpa2_security_aes_security_tc557397(wifi_dut, wifi_access_point,
                                                                                wifi_sniffer,
                                                                                sl_collections, request, sniffer_filter,
                                                                                wifi_client):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557397,sniffer_filter=sniffer_filter,
                              wifi_client=wifi_client, ssid="ipv6_autiomation", passphrase=12345678,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557397")

        wlan_obj.sniffer_capture_start()
        wlan_obj.staut_conn()
        wlan_obj.staut_ipconfig()
        wlan_obj.ping_async()
        wlan_obj.ping_from_ap_support_machine()
        wifi_sniffer.interfaces.capture.stop_capture()
        wlan_obj.sniffer_check_for_tkip_aes_flags()


    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.OpenMode
                    | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server| Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)
@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "tkip_aes",
                               "security": "WPAWPA2MixedMode",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_in_concurrent_mode_with_ap_wpawpa2_aes_ccmp_security_tc557400(wifi_dut, wifi_access_point,
                                                                                wifi_sniffer,
                                                                                sl_collections, request, sniffer_filter,
                                                                                wifi_client, wifi_clients):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557400,
                              wifi_client=wifi_client, wifi_clients=wifi_clients, ssid="ipv6_autiomation",
                              passphrase=12345678,sniffer_filter=sniffer_filter, no_of_clients=1,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557400")

        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.raspi_sta_assoc_to_dut_ap()
        wlan_obj.staut_conn()
        wifi_sniffer.interfaces.capture.stop_capture()
        wlan_obj.sniffer_check_for_tkip_aes_flags()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                    | Si91xFeatureBitMap.OpenMode
                    | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.DHCPv4Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
    }
)

@pytest.mark.config(
    "wifi_access_point", wifi={"cipher": "tkip_aes",
                               "security": "WPAWPA2MixedMode",
                               "ssid": "ipv6_autiomation",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA",
            "ssid": "917_AP",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
            "country": "US"
        }
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_wifi_sdk_in_concurrent_mode_with_ap_wpawpa2_tkip_security_tc557402(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                            sl_collections, request, sniffer_filter,
                                                                            wifi_client, wifi_clients):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=557402,
                              wifi_client=wifi_client, wifi_clients=wifi_clients, ssid="ipv6_autiomation",
                              passphrase=12345678,sniffer_filter=sniffer_filter, no_of_clients=1, beacon_stop=1,
                              security="wpa2", enc="ccmp", channel=11, capture_filename="tc_557401")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.raspi_sta_assoc_to_dut_ap()
        wlan_obj.staut_conn()
        wifi_sniffer.interfaces.capture.stop_capture()
        wlan_obj.sniffer_check_for_tkip_aes_flags()
        wlan_obj.sniffer_capture_start(capture_filename="TC557402_capture_two")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        wlan_obj.check_beacons_from_aput()


        """
        Need to check the 3rd party AP Probe response should see the TKIP

        DUT should nt send the Assoc request, Sniffer code need to be added
        """

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
