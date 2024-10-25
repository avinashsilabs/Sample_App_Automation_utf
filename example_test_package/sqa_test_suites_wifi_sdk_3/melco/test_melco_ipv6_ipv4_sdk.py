from utf.utils.logger import get_logger
import pytest
import string
import time
import ipaddress
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
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.iperf.iperf_utils import ping
from threading import Thread
from utf.utf_config import UtfConfig


def logger():
    return get_logger(__name__)


"""
     Setup Requirement:
     
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)  
        
     Test Steps:
        
        1. Configure the DUT in 2G.
        2. Association of Third party AP's
        3. Configure the IPv6 addresses.
        4. Ping to the specified IPv6 address.
        5. Validate the Sniffer Checks.
    
     Authors: 
      - Swathi Chinthala 
"""
import ipaddress
import random


def random_ipv6_addr(subnet):
    network = ipaddress.ip_network(subnet)
    max_value = int(network.network_address) + network.num_addresses - 1
    random_ip = ipaddress.IPv6Address(random.randint(int(network.network_address), max_value))
    return str(random_ip)




class IperfThraed(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None,
                 traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 device_ip=None, remote_ip=None, ip_version=4):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = ip_version
        self.device_ip = device_ip
        self.remote_ip = remote_ip

    def run_traffic(self):
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=self.device_ip,
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            ip_version=self.ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=0
        )

    def run(self):
        self.run_traffic()


class WLanConThread(ThreadBase):
    """
    Thread class for WLAN operations.
    """
    client_info, dut_info = {"mac_address": None, "ip_address": None},{"mac_address": None, "ip_address": None}

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None, test_type=None, ping_count=10, remote_wiseconnect3=None,
                 ipv6_addr_type="global", switch=None,
                 set_power_save=False, traffic_type=None, protocol=None, net_perf_client=None, timeout=60):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_count = ping_count
        self.test_type = test_type
        self.ipv6_addr_type = ipv6_addr_type
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = 6
        self.ssid = "Concurent_AP"
        self.security = "WPA2"
        self.password = "Automation@123"
        self.channel = "1"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.no_of_clients = 1
        self.leave = False
        self.set_power_save = set_power_save

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

        self.remote_ipv6 = None
        self.remote_ipv4 = None
        self.dut_add_dict = None

    def run_traffic(self, device_ip=None, remote_ip=None, ip_version=4):

        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=device_ip,
            host_ip=remote_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            ip_version=ip_version,
            async_socket=0
        )

    def ping(self, ip_address=None, ping_from="remote", ping_count=10, ip_version="ipv4"):
        """
        Ping the given IP address.
        """
        if ping_from == "remote":
            status = self.sl_collections.ping(device_ip=ip_address, ping_count=ping_count, retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if ping_from == "dut":
            self.wifi_dut.interfaces.wifi.ping(server_ip=ip_address, ip_version=ip_version, ping_size=64,
                                               num_ping_attempts=10)

    def join_to_sta(self):
        self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")
        self.static_ipv6 = random_ipv6_addr("1280:2300:133c:1341::/64")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6", vid=1,
                                                           static_ipv6_address=self.static_ipv6,
                                                           ipv6_gw_address=self.static_ipv6)
        self.dut_add_dict['dut_ap_ipv6'] = self.static_ipv6

        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                               channel=self.channel,
                                               dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval)
        self.remote_wiseconnect3.interfaces.wifi.join(ssid=ssid,
                                                      security=self.security,
                                                      passphrase=self.password,
                                                      channel=self.channel, timeout=60)
        ip_config = self.remote_wiseconnect3.interfaces.wifi.start_ip(timeout=60, ip_version="ipv4")
        device_ipv4 = self.remote_wiseconnect3.interfaces.wifi.get_device_ip(ip_config)

        ip_config = self.remote_wiseconnect3.interfaces.wifi.start_ip(timeout=60, ip_version="ipv6")
        device_ipv6 = self.remote_wiseconnect3.interfaces.wifi.get_device_ip(ip_config)

        self.dut_add_dict['remote_sta_ipv6'] = device_ipv6
        self.dut_add_dict['remote_sta_ipv4'] = device_ipv4
        # if ipv6_type == 'global':
        #     device_ip = ip_config[1]
        # else:
        #     device_ip = ip_config[0]
        # self.remote_wiseconnect3.interfaces.wifi.start_ip(ip_version=ip_version, static_ip=static_ip,
        #                                                   static_subnet=static_subnet,
        #                                                   static_gateway=static_gateway, timeout=10)
        # self.static_ipv6 = random_ipv6_addr("1280:2300:133c:1341::/64")
        # ip_config = self.remote_wiseconnect3.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6",
        #                                                               static_ipv6_address=self.static_ipv6,
        #                                                               ipv6_gw_address=self.static_ipv6)
        # self.dut_add_dict['remote_sta_ipv6'] = self.static_ipv6
        # self.dut_add_dict['remote_sta_ipv4'] = self.static_ip

        self.remote_wiseconnect3.interfaces.wifi.ping(server_ip=self.dut_add_dict['dut_ap_ipv4'], num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)
        self.remote_wiseconnect3.interfaces.wifi.ping(server_ip=self.dut_add_dict['dut_ap_ipv6'], num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv6', ping_size=64)

        time.sleep(2)
        if self.power_save and self.set_power_save:
            self.enable_power_save()

    def enable_power_save(self):
        if self.power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile('power_save_low_latency')
        else:
            logger().info("skip power save mode configuration as in harness power_save flag is set to False")


    def join_to_ap(self):
        self.dut_add_dict = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     power_save=False, retry_count=3,
                                                                     ping_before_power_save=False,
                                                                     ping_after_power_save=False,
                                                                     )
        self.dut_add_dict['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid
        ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                ip_version="ipv6")
        assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
        self.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
        self.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
        logger().info(f"DUT MAC ADDRESS :  {self.dut_add_dict['dut_mac_address']}\n"
                      f"DUT IPV4 ADDRESS : {self.dut_add_dict['device_ip']}\nDUT IPV6 GLOBAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_global']}\n"
                      f"DUT IPV6 LINK LOCAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_link']}\n")

        self.dut_add_dict['remote_ap_ipv6'] = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type=self.ipv6_addr_type)
        logger().info(f"remote_ap_ipv6: {self.dut_add_dict['remote_ap_ipv6']}")
        self.dut_add_dict['remote_ap_ipv6'] = ipaddress.ip_address(self.dut_add_dict['remote_ap_ipv6'])
        self.dut_add_dict['remote_ap_ipv4'] = self.wifi_client.interfaces.wifi.get_ip_address(version=4)
        logger().info(f"remote_ap_ipv4: {self.dut_add_dict['remote_ap_ipv4'] }")



    def check_ping_from_remote_to_dut_sta(self):
        self.ping(ip_address=self.dut_add_dict['device_ip'], ping_from="remote", ping_count=self.ping_count,
                  ip_version="ipv4")
        self.ping(ip_address=self.dut_add_dict['dut_sta_ipv6_global'], ping_from="remote", ping_count=self.ping_count,
                  ip_version="ipv6")


    def check_ping_from_dut_sta_to_remote(self):
        self.ping(ip_address=self.dut_add_dict['remote_ap_ipv4'], ping_from="dut", ping_count=self.ping_count,
                  ip_version="ipv4")
        self.ping(ip_address=self.dut_add_dict['remote_ap_ipv6'], ping_from="dut", ping_count=self.ping_count,
                  ip_version="ipv6")

    def check_ping_from_remote_to_dut_sta(self):
        self.ping(ip_address=self.dut_add_dict['device_ip'], ping_from="remote", ping_count=self.ping_count,
                  ip_version="ipv4")
        self.ping(ip_address=self.dut_add_dict['dut_sta_ipv6_global'], ping_from="remote", ping_count=self.ping_count,
                  ip_version="ipv6")


    def check_ping_from_dut_ap_to_remote(self):
        self.ping(ip_address=self.dut_add_dict['remote_sta_ipv4'], ping_from="dut", ping_count=self.ping_count,
                  ip_version="ipv4")
        self.ping(ip_address=self.dut_add_dict['remote_sta_ipv6'], ping_from="dut", ping_count=self.ping_count,
                  ip_version="ipv6")

    def check_ping_from_remote_to_dut_ap(self):
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.wifi.ping(server_ip=static_gateway, num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv4', ping_size=64)
        self.remote_wiseconnect3.interfaces.wifi.ping(server_ip=static_ipv6, num_ping_attempts=self.ping_count,
                                                      ping_timeout=10, ip_version='ipv6', ping_size=64)



    def run(self):
        """
        Runs the thread.
        """
        self.join_to_ap()
        self.join_to_sta()
        self.check_ping_from_remote_to_dut_sta()


def wifi_dut_config(ext_custom_bit=0, thread_count=1):
    return {
        "thread_config": {"wifi": {"count": thread_count, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | ext_custom_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }

def remote_wiseconnect3_config():
    return {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | ext_custom_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "Concurent_AP", "passphrase": "Automation@123", "channel": 1
    }


@pytest.mark.config("wifi_dut", wifi=wifi_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config("wifi_dut", wifi=remote_wiseconnect3_config())
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_melco_sdk_ipv4_ipv6_assignment_C557352(wifi_dut, wifi_access_point, remote_wiseconnect3,
                                                     wifi_sniffer, sl_collections, request,
                                                     sniffer_filter, utf_constants,
                                                     wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client, remote_wiseconnect3=remote_wiseconnect3
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config("wifi_dut", wifi=wifi_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config("wifi_dut", wifi=remote_wiseconnect3_config())
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
def test_wifi_melco_sdk_ipv4_tcp_tx_C557353(wifi_dut, wifi_access_point, remote_wiseconnect3,
                                            wifi_sniffer, sl_collections,
                                            request,
                                            sniffer_filter, utf_constants,
                                            wifi_client, net_perf_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4. Enable wlan and bt power save mode in dut after the connection
        5. Ping from remote to DUT IPV6 address
        6. Run TCP TX on IPV4

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 remote_wiseconnect3=remote_wiseconnect3,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client, protocol="TCP",
                                 traffic_type="TX",
                                 net_perf_client=net_perf_client,
                                 )
        wlan_obj.join_to_ap()
        wlan_obj.join_to_sta()
        wlan_obj.check_ping_from_remote_to_dut_sta()
        wlan_obj.run_traffic(device_ip=wlan_obj.dut_add_dict['device_ip'], remote_ip=wlan_obj.dut_add_dict['remote_ap_ipv4'],
                             ip_version=4)

        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config("wifi_dut", wifi=wifi_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config("wifi_dut", wifi=remote_wiseconnect3_config())
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_melco_sdk_ipv4_ipv6_ping_C557354(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                               request, remote_wiseconnect3,
                                               sniffer_filter, utf_constants,
                                               wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 remote_wiseconnect3=remote_wiseconnect3,
                                 set_power_save=True
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.check_ping_from_dut()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)




@pytest.mark.config("wifi_dut", wifi=wifi_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config("wifi_dut", wifi=remote_wiseconnect3_config())
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_melco_sdk_ipv4_ipv6_ping_C557356(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                               request, remote_wiseconnect3,
                                               sniffer_filter, utf_constants,
                                               wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,remote_wiseconnect3=remote_wiseconnect3,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 set_power_save=True
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)




@pytest.mark.config("wifi_dut", wifi=wifi_dut_config())
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config("wifi_dut", wifi=remote_wiseconnect3_config())
@pytest.mark.config(
    "wifi_access_point", wifi={"ssid": "Concurent_STA", "security": "WPA2", "passphrase": "231469460", "ipv6_state": "0",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), 'channel': 11}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_melco_sdk_ipv4_ipv6_ping_STA_LI_powersave_C557357(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                               request, remote_wiseconnect3,
                                               sniffer_filter, utf_constants,
                                               wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcpv4 and dhcpv6
        4 .Create DUT as AP and connect the client to the AP
        5. Ping from remote to DUT IPV6 address

    """
    test_name = request.node.name
    try:
        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wlan_obj = WLanConThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,remote_wiseconnect3=remote_wiseconnect3,
                                 test_name=test_name, sl_collections=sl_collections, test_type="ping",
                                 ping_count=ping_count, wifi_client=wifi_client,
                                 set_power_save=True
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



