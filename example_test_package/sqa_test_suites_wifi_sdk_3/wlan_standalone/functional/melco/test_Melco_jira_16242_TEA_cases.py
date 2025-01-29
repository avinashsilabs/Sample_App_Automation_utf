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
    dut_add_dict={}
    ip_config=[]
    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None,
                 wifi_client=None, test_id=None, test_type=None, ping_from="remote", ping_count=10, addr_type="link",
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60, wifi_clients=None, wifi_sniffer = None,
                 utf_constants=None, dtim_period = None, enable_data_rate = None, ht_caps =None,
                 ssid=None, security = None, password=None, beacon_interval=None,
                 channel=None, dtim_count=None, no_of_clients=None, remote_ip=None, network_interface=None,
                 device_ip=None, ipv6_address_type=None, link_interface=None, capture_filename=None):
        super().__init__()
        self.device_ip = device_ip
        self.ipv6_address_type = ipv6_address_type
        self.capture_filename=capture_filename
        self.link_interface=link_interface
        self.wifi_clients = wifi_clients
        self.wifi_sniffer = wifi_sniffer
        self.utf_constants = utf_constants
        self.dtim_period = dtim_period
        self.network_interface = network_interface
        self.ht_caps = ht_caps
        self.ssid=ssid
        self.security=security
        self.password=password
        self.dtim_count=dtim_count
        self.beacon_interval=beacon_interval
        self.channel=channel
        self.no_of_clients=no_of_clients
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_from = ping_from
        self.ping_count = ping_count
        self.test_type = test_type
        self.addr_type = addr_type
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.remote_ip = remote_ip

    def ping_async(self):
        time.sleep(10)
        logger().info(f"Ping from DUT to remote")
        self.wifi_dut.interfaces.wifi.ping(server_ip=self.remote_ip, num_ping_attempts=self.ping_count,
                                           ping_timeout=10, ip_version='ipv6', ping_size=64)

        logger().info(f"Ping successful")

    def sniffer_capture_start(self,channel=11, capture_filename="sniffer_capture"):
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)

        logger().info(f"channel number in which the sniffer capture is starting is {self.channel}")
        logger().info(f" ******* start capturing with Sniffer by giving the test case name as filename {self.capture_filename} ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)

    def run_traffic(self, protocol="TCP", traffic_type="TX", ip_version=6, link_interface=None):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=protocol,
            device_ip=self.device_ip,
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=traffic_type,
            ip_version=ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=1,
            ipv6_address_type = "link",
            link_interface = self.network_interface
        )
    def aput_start(self):
        time.sleep(3)
        # ping_count = self.utf_constants.get("ping_count")

        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                       channel=11, ssid="917_AP",
                                                                       security="wpa2", password="12345678",
                                                                       dtim_count=3,
                                                                       beacon_interval=100,
                                                                       ht_caps=1,
                                                                       ping_count=10,
                                                                       no_of_clients=1,
                                                                       leave = False
                                                                       )

        logger().info(f"printing the value of AP dut_addr_dict {self.dut_addr_dict}")


    def dut_sta(self):
        global interface
        logger().info("********** configuring the sniffer with access point channel **********")
        if self.test_id in[638373, 638374, 638375, 638376, 638385, 638386, 638387, 638388,
                           638393, 638394, 638395, 638396]:
            self.static_ipv6 = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        if self.test_id in [638377, 638378, 638379, 638380, 638383, 638384, 638391, 638392]:
            self.static_ipv6 = "2401:2234:2234:2223::2234"
        if self.test_id in [638381, 638382, 638389, 638390]:
            self.static_ipv6 = "2401:3522:2231:1341::221"
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        #capture_file=f"{self.capture_filename}.pcap"
        self.wifi_sniffer.interfaces.capture.start_capture()
        time.sleep(3)
        # ping_count = self.utf_constants.get("ping_count")
        self.info_attr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                  wifi_access_point=self.wifi_access_point,
                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                  ip_version='ipv6',
                                                                  ip_config_disable=1,
                                                                  power_save=False, retry_count=3,
                                                                  ping_before_power_save=False,
                                                                  ping_after_power_save=False,
                                                                  )
        logger().info(f" SVN printing the testid of the present test case {self.test_id}")
        self.ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6", vid=0,
                                                           static_ipv6_address=self.static_ipv6,
                                                           ipv6_gw_address=self.static_ipv6, )

        logger().info(f"printing the type of ipconfig : {type(self.ip_config)}")
        logger().info(f"printing the device Link local address {self.ip_config[0]}")
        logger().info(f"printing the device Global unicast  address {self.ip_config[1]}")
        logger().info(f"ip_config:{self.ip_config}")
        self.dut_add_dict['device_ipv6_global'] = self.ip_config[1]
        self.dut_add_dict['device_ipv6_link'] = self.ip_config[0]
        self.device_ip = self.ip_config[0]

        logger().info(f"printing value of STA Interface info_attr {self.info_attr}")
        time.sleep(20)

        self.network_interface = self.wifi_client.interfaces.wifi.config["v6_interface"]
        logger().info(f"printing the newly added interface {self.network_interface}")
        remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.addr_type, network_interface=self.network_interface)
        logger().info(f"remote_ip: {remote_ip}")
        ip_addr = ipaddress.ip_address(remote_ip)
        self.remote_ip = ip_addr
        interface = self.wifi_client.interfaces.wifi.config["v6_interface"]
        logger().info(f"The DUT Device IP is {self.device_ip}")
        logger().info(f"The Remote Device IP is {self.remote_ip}")

        if self.test_id in [638373, 638377, 638381, 638385, 638389, 638393]:
            self.run_traffic(protocol="TCP", traffic_type="TX", ip_version=6)

        if self.test_id in [638374, 638378, 638382, 638386, 638390, 638394]:
            self.run_traffic(protocol="TCP", traffic_type="RX", ip_version=6, link_interface=self.network_interface)

        if self.test_id in [638375, 638379, 638383, 638387, 638391, 638395]:
            self.run_traffic(protocol="UDP", traffic_type="TX", ip_version=6)

        if self.test_id in [638376, 638380, 638384, 638388, 638392, 638396]:
            self.run_traffic(protocol="UDP", traffic_type="RX", ip_version=6, link_interface=self.network_interface)


@pytest.fixture(autouse=True)
def delay_between_tests():
    time.sleep(20)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": Si91xOperatingMode.ConcurrentMode,
            "coex_mode": Si91xCoexMode.WLANOnly ,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation
                        | Si91xFeatureBitMap.OpenMode
                        | Si91xFeatureBitMap.SL_SI91X_FEAT_DISABLE_11AX_SUPPORT,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                              | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                              | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.DHCPv4Server
                              | Si91xTCPIPFeatureBitMap.DHCPv4Client,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        }
    )
]


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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "disabled",
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_TCP_tx_with_STA_GUA_all_F_s_in_Concurrent_Mode_TC638373(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients,net_perf_client,protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638373,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638373_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "disabled",
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_TCP_Rx_with_STA_GUA_all_F_s_in_Concurrent_Mode_TC638374(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638374,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638374_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()

        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "disabled",
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Tx_with_STA_GUA_all_F_s_in_Concurrent_Mode_TC638375(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638375,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638375_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "disabled",
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Rx_with_STA_GUA_all_F_s_in_Concurrent_Mode_TC638376(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638376,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638376_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "disabled",
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Tx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638377(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638377,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638377_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "disabled",
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Rx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638378(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638378,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638378_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "disabled",
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Tx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638379(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638379,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638379_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": "disabled",
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Rx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638380(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638380,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638380_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel" : 11,
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Tx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638381(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638381,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638381_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Rx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638382(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638382,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638382_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

#@pytest.mark.skip
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Tx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638383(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638383,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638383_sniffer")

        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Rx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638384(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638384,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638384_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Tx_with_STA_GUA_Static_All_Fs_in_Concurrent_Mode_TC638385(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638385,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638385_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Rx_with_STA_GUA_Static_All_Fs_in_Concurrent_Mode_TC638386(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638386,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638386_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Tx_with_STA_GUA_Static_All_Fs_in_Concurrent_Mode_TC638387(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638387,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638387_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Rx__with_STA_GUA_Static_All_Fs_in_Concurrent_Mode_TC638388(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638388,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638388_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

#####


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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "1",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Tx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638389(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638389,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638389_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "1",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Rx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638390(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638390,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638390_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "1",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Tx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638391(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638391,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638391_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "1",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Rx_with_STA_GUA_all_static_ip_in_Concurrent_Mode_TC638392(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638392,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638392_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "1",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Tx_with_STA_GUA_Static_All_Fs_in_Concurrent_Mode_TC638393(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638393,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638393_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "1",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_TCP_Rx_with_STA_GUA_Static_All_Fs_in_Concurrent_Mode_TC638394(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638394,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638394_sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.skip()
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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "1",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Tx_with_STA_GUA_Static_All_Fs_in_Concurrent_Mode_TC638395(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638395,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638395_Sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


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
@pytest.mark.config(
    "wifi_access_point", wifi={"connection_type": 'STATIC_IPV6',
                               "use_ipv6_web": True,
                               "security": "WPA2",
                               "passphrase": "12345678",
                               "channel": 11,
                               "wan_ipv6_address"
                               "wan_ipv6_address": "2401:49d2:1c22:6610:bd91:8e66:bdd4:4378",
                               "wan_ipv6_gateway": "2401:49d2:1c22:6610::1",
                               "wan_prefix_length" : "64",
                               "ipv6_state": "0",
                               "lan_ipv6_address": "2401:3522:2231:1341:3213:a134:1334:1421",
                               "lan_prefix_length": "64",
                               "lan_ip_pool_start": "1000",
                               "lan_ip_pool_end": "2000",
                               "lan_lease_time": "86400",}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])

def test_UDP_Rx__with_STA_GUA_Static_All_Fs_in_Concurrent_Mode_TC638396(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                sl_collections, request, sniffer_filter,
                                                                wifi_client,wifi_clients, net_perf_client, protocol):
    test_name = request.node.name
    try:
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_name=test_name, sl_collections=sl_collections, test_id=638396,
                              wifi_client=wifi_client,wifi_clients=wifi_clients,
                              net_perf_client=net_perf_client,
                              protocol=protocol, channel=11, capture_filename="TC638396_Sniffer")
        wlan_obj.sniffer_capture_start()
        wlan_obj.aput_start()
        wlan_obj.dut_sta()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)




