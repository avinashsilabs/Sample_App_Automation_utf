import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utf_config import UtfConfig
import ipaddress
import random
import time


def logger():
    return get_logger(__name__)


def random_ipv6_addr(subnet):
    network = ipaddress.ip_network(subnet)
    max_value = int(network.network_address) + network.num_addresses - 1
    random_ip = ipaddress.IPv6Address(random.randint(int(network.network_address), max_value))
    return str(random_ip)


"""
     Setup Requirement:

        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)  

     Test Steps:

        1. Configure the DUT in STA/AP mode and connect to the specified AP.
        2. Association of Third party AP's
        3. Configure the IPv4/IPv6 addresses.
        4. Ping to the specified IPv4/IPv6 address.
        5. Validate the Sniffer Checks.

     Author: 
      - Saurabh Sharma 
"""


class WifiThread(ThreadBase):
    dut_addr = None

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            wifi_client=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            region=None,
            switch=None,
            timeout=30,
            utf_constants=None,
            testcase=None,
            net_perf_client=None,
            protocol=None,
            traffic_type=None,
            ip_version="ipv4",
            wifi_clients=None,
            htcaps_enable=None,
            leave=True,
            enable_data_rate=False,
            version=4,
            ip_config_disable=False,
            tcp_ip_bypass=False
    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.region = region
        self.switch = switch
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.timeout = timeout
        self.utf_constants = utf_constants
        self.testcase = testcase
        self.dut_addr = None
        self.host_ip = None
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.traffic_type = traffic_type
        self.ip_version = ip_version
        self.dut_addr_dict = None
        self.wifi_clients = wifi_clients
        self.ssid = "sharma123"
        self.security = "WPA2"
        self.password = "thisistestnetwork"
        self.channel = 11
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.no_of_clients = 1
        self.htcaps_enable = 1
        self.htcaps_enable = htcaps_enable
        self.leave = leave
        self.enable_data_rate = enable_data_rate
        self.version = version
        self.dut_add_dict = {}
        self.static_ipv6 = None
        self.remote_ip = None
        self.ip_config_disable = ip_config_disable
        self.tcp_ip_bypass = tcp_ip_bypass

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run(self):
        """
        Run the test case.
        """
        if self.test_type in [557419, 557420, 557421, 563960]:
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version,
                tcp_ip_bypass=self.tcp_ip_bypass, ip_config_disable=self.ip_config_disable)

            if self.test_type == 557419:
                self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f".... Remote device ip :{self.host_ip} ....")

            if self.test_type == 557420:
                self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6)
                logger().info(f".... Remote device ip global :{self.host_ip} ....")
                ip_addr = ipaddress.ip_address(self.host_ip)

                self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
                logger().info(f".... Remote device ip link :{self.remote_ip} ....")
                ip_addr = ipaddress.ip_address(self.remote_ip)

                interface = self.wifi_client.interfaces.wifi.config["interface"]
                device_ip_link = f"{self.dut_addr['device_ip']}%{interface}"
                logger().info(f".... Device ip link :{device_ip_link} ....")

        if self.test_type in [557422, 557423]:
            ping_count = self.utf_constants.get("ping_count")
            if self.test_type == 557422:
                logger().info(".... Configuring the DUT in AP mode ....")
                self.wifi_dut.interfaces.wifi.start_ip(
                    static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
                    ip_version=self.ip_version)
                self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")

            if self.test_type == 557423:
                self.static_ipv6 = random_ipv6_addr("1280:2300:133c:1341::/64")
                ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version="ipv6",
                                                                   static_ipv6_address=self.static_ipv6,
                                                                   ipv6_gw_address=self.static_ipv6)
                self.dut_add_dict['dut_ap_ipv6'] = self.static_ipv6

            self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                                channel=self.channel, ssid=self.ssid,
                                                                                security=self.security,
                                                                                password=self.password,
                                                                                dtim_count=self.dtim_count,
                                                                                beacon_interval=self.beacon_interval,
                                                                                ht_caps=self.htcaps_enable,
                                                                                ping_count=ping_count,
                                                                                no_of_clients=self.no_of_clients,
                                                                                leave=self.leave,
                                                                                enable_data_rate=self.enable_data_rate)

        if self.test_type == 557424:
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version)

            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address(network_interface='eth1')
            logger().info(f".... Remote device ip :{self.host_ip} ....")

            ping_count = self.utf_constants.get("ping_count")
            self.wifi_dut.interfaces.wifi.start_ip(
                static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
                ip_version=self.ip_version)
            self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")

            self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                                channel=self.channel, ssid=self.ssid,
                                                                                security=self.security,
                                                                                password=self.password,
                                                                                dtim_count=self.dtim_count,
                                                                                beacon_interval=self.beacon_interval,
                                                                                ht_caps=self.htcaps_enable,
                                                                                ping_count=ping_count,
                                                                                no_of_clients=self.no_of_clients,
                                                                                leave=self.leave,
                                                                                enable_data_rate=self.enable_data_rate)
            self.wifi_dut.interfaces.wifi.sl_net_down(mode="ap")

        if self.test_type == 557425:
            ping_count = self.utf_constants.get("ping_count")
            self.wifi_dut.interfaces.wifi.start_ip(
                static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
                ip_version=self.ip_version)
            self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")

            self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                                channel=self.channel, ssid=self.ssid,
                                                                                security=self.security,
                                                                                password=self.password,
                                                                                dtim_count=self.dtim_count,
                                                                                beacon_interval=self.beacon_interval,
                                                                                ht_caps=self.htcaps_enable,
                                                                                ping_count=ping_count,
                                                                                no_of_clients=self.no_of_clients,
                                                                                leave=self.leave,
                                                                                enable_data_rate=self.enable_data_rate)
            self.wifi_dut.interfaces.wifi.sl_net_down(mode="ap")
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version)

            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address(network_interface='eth1')
            logger().info(f".... Remote device ip :{self.host_ip} ....")

    def ping(self, ping_from="remote", ping_count=10, ip_version="ipv4"):
        """
        Ping the given IP address.
        """
        if ping_from == "remote":
            status = self.sl_collections.ping(device_ip=self.dut_addr['device_ip'], ping_count=ping_count,
                                              retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if ping_from == "dut":
            self.wifi_dut.interfaces.wifi.ping(server_ip=self.host_ip, ip_version=ip_version, ping_size=64,
                                               num_ping_attempts=10)

    def traffic_run(self):
        if self.test_type == 557419:
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
                device_ip=self.dut_addr["device_ip"], host_ip=self.host_ip, timeout=self.timeout,
                ip_version=self.version)

        if self.test_type == 557420:
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
                device_ip=self.dut_addr["device_ip"], host_ip=self.remote_ip, timeout=self.timeout,
                ip_version=self.version)
        if self.test_type == 563960:
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
                device_ip=self.static_ipv6, host_ip=self.remote_ip, timeout=self.timeout,
                ip_version=self.version)

    def wlan_leave(self):
        try:
            logger().info("....Leaving the WLAN network....")
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    # def sniffer_validation(self):
    #
    #     ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
    #     packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
    #         sa_addr=self.dut_addr['dut_mac_address'], da_addr=ap_mac_address, filter_name='probe_request_HE')
    #     packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
    #         sa_addr=self.dut_addr['dut_mac_address'], da_addr=ap_mac_address, filter_name='association_request_HE')
    #
    #     logger().info("Validating Probe Req with HE information")
    #     assert not \
    #         self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2, negative_test=True)[
    #             'packet_count'], 'Unable to find Probe Req with HE capability in sniffer'
    #
    #     logger().info("Validating Assoc Req with HE information")
    #     assert not \
    #         self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3, negative_test=True)[
    #             'packet_count'], 'Unable to find Assoc Req  with HE capability in sniffer'

    def wifi_client_leave(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()

    def ap_mode_with_ipv4(self):
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_dut.interfaces.wifi.start_ip(
            static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
            ip_version='ipv4')
        self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")

        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                               channel=self.channel, dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval)

        for i in range(0, self.no_of_clients):
            connected = False
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            self.dut_add_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ip']}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    self.dut_add_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {self.dut_add_dict['rasp_mac_address']}")
                    self.dut_add_dict['client_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client_ip: {self.dut_add_dict['client_ip']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {self.dut_add_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"

        self.wifi_client_leave()

    def static_ipv6_assign(self):
        self.static_ipv6 = random_ipv6_addr("1280:2300:133c:1341::/64")
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(
            timeout=30, ip_version=self.ip_version, static_ipv6_address='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
            ipv6_gw_address='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
        self.dut_add_dict['dut_ap_ipv6'] = self.static_ipv6

        logger().info(f"********* IP **********: {ip_config}")
        logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv6']}")
        self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
        logger().info(f".... link address :{self.remote_ip} ....")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123"})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv4_assign_sta_interface_c557419(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol):
    """Verify the only IPv4 Assignment to STAUT interfaces in STAUT in concurrent Mode"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client,
                              traffic_type='TX', test_type=557419)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60)
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "ipv6_state": "1",
                          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv6_assign_sta_interface_c557420(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol):
    """Verify the only Stateful DHCPv6 IPv6 assignement to STATUT interface in concurrent Mode"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client,
                              traffic_type='TX', ip_version='ipv6', test_type=557420, version=6)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60, ip_version='ipv6')
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip(reason="Need to check the test case")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisistestnetwork", "ssid": "sharma123", "ipv6_state": "1",
                          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_static_ipv6_assign_sta_interface_c557421(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol):
    """Verify the only static IPv6 assignment to STATUT interface in STAUT Alone Mode (Disable IPv6 on 3rd party AP)"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client,
                              traffic_type='TX', ip_version='ipv6', test_type=557421)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60, ip_version='ipv6')
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv4_assign_sta_first_c557424(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify the Ping functionality of AP and STA in when Assigned with IPv4 address alone in Concurrent Mode
    (STA_First)"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=557424)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60)
        wifi_obj.wifi_client_leave()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv4_assign_apmode_first_c557425(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify the Ping functionality of AP and STA in when Assigned with IPv4 address alone in Concurrent Mode
    (STA_First)"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=557425)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60)
        wifi_obj.wifi_client_leave()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
def test_wifi_sdk_ipv4_assign_apmode_interface_c557422(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify only IPv4 Assignment to APUT interface in APUT alone Mode"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=557422)

        wifi_obj.start()
        wifi_obj.wait_for_exit()

        wifi_obj.wifi_client_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": 11,
        },
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "123456789", "ssid": "sharma1234", "ipv6_state": "0",
                          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48"), "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_ipv6_stamode_ipv4_apmode_c557427(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol, wifi_clients):
    """Verify the Ping functionality of AP in IPv4 and STAUT in Static IPv6 in concurrent Mode(STA First)"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client,
                              traffic_type='TX', ip_version='ipv6', test_type=557420, version=6,
                              wifi_clients=wifi_clients)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60, ip_version='ipv6')
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "123456789", "ssid": "sharma1234", "ipv6_state": "0",
                          "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_static_ipv6_assign_sta_interface_with_fs_c563960(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        net_perf_client, protocol):
    """Check the ICMPv6 NS Messages when the STA Static IPv6 address is configured with all f's"""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, test_type=563960,
                              ping_count=ping_count, protocol=protocol, net_perf_client=net_perf_client, version=6,
                              tcp_ip_bypass=True, ip_config_disable=False, traffic_type='TX', ip_version='ipv6')

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.static_ipv6_assign()
        wifi_obj.traffic_run()
        wifi_obj.wlan_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
