import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utf_config import UtfConfig
import time
import re


def logger():
    return get_logger(__name__)


"""
     Setup Requirement:

        1. soc
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
    dut_add_dict = {}

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
            timeout=60,
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
            tcp_ip_bypass=False,
            ipv6_addr_type="global",
            ping_type=None
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
        self.channel = 8
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.no_of_clients = 1
        self.htcaps_enable = 1
        self.htcaps_enable = htcaps_enable
        self.leave = leave
        self.enable_data_rate = enable_data_rate
        self.version = version
        self.ping_type = ping_type
        self.static_ipv6 = None
        self.remote_ip = None
        self.ip_config_disable = ip_config_disable
        self.tcp_ip_bypass = tcp_ip_bypass
        self.ipv6_addr_type = ipv6_addr_type

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run(self):
        """
        Run the test case.
        """
        if self.test_type in [690736, 690737, 700498]:
            WifiThread.dut_add_dict = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version,
                tcp_ip_bypass=self.tcp_ip_bypass, ip_config_disable=self.ip_config_disable)

            ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                    ip_version="ipv6")
            assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
            WifiThread.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
            WifiThread.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]

            logger().info(f"DUT MAC ADDRESS :  {WifiThread.dut_add_dict['dut_mac_address']}\n"
                          f"DUT IPV4 ADDRESS : {WifiThread.dut_add_dict['device_ip']}\nDUT IPV6 GLOBAL ADDRESS : {WifiThread.dut_add_dict['dut_sta_ipv6_global']}\n"
                          f"DUT IPV6 LINK LOCAL ADDRESS : {WifiThread.dut_add_dict['dut_sta_ipv6_link']}\n")

            self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="link")
            logger().info(f".... Remote device link address :{self.remote_ip} ....")

    # def check_ping_status_ipv6(self, ping_count=10):
    #     """
    #     Ping the given IP address.
    #     """
    #     interface = self.wifi_client.interfaces.wifi.config["interface"]
    #     ping_link_local_addr = f"{self.dut_add_dict['dut_sta_ipv6_link']}%{interface}"
    #     status = self.sl_collections.ping(device_ip=ping_link_local_addr, ping_count=ping_count, retry_count=3)
    #     assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
    #
    # def check_ping_status_ipv4(self, ping_count=10):
    #     self.sl_collections.ping(device_ip=self.dut_addr['device_ip'], ping_count=ping_count, retry_count=3)

    # def traffic_run(self):
    #     if self.test_type == 557419:
    #         self.sl_collections.run_traffic(
    #             wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
    #             device_ip=self.dut_addr["device_ip"], host_ip=self.host_ip, timeout=self.timeout,
    #             ip_version=self.version)
    #
    #     if self.test_type in [557420, 557421, 557427, 563960]:
    #         self.sl_collections.run_traffic(
    #             wifi_dut=self.wifi_dut, net_perf_client=self.net_perf_client, protocol=self.protocol,
    #             device_ip=self.dut_add_dict['dut_sta_ipv6_link'], host_ip=self.remote_ip, timeout=self.timeout,
    #             ip_version=self.version)

    # def check_sta_first_and_ap_second_ipv4(self):
    #     self.dut_addr = self.sl_collections.join_to_wifi_network(
    #         wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
    #         associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
    #         ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version)
    #
    #     self.ap_mode_with_ipv4()
    #
    # def check_ap_mode_first_and_sta_second_ipv4(self):
    #     self.ap_mode_with_ipv4(leave=False)
    #     self.dut_addr = self.sl_collections.join_to_wifi_network(
    #         wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
    #         associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
    #         ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version)
    #     self.wifi_client_leave()

    def ap_mode_with_ipv4(self, leave=False, scan_ssid=0):
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_dut.interfaces.wifi.start_ip(
            static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
            ip_version='ipv4')
        self.dut_add_dict['dut_ap_ipv4'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {self.dut_add_dict['dut_ap_ipv4']}")

        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                               channel=self.channel, dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval)

        self.wifi_dut.interfaces.wifi.get_channel_info(interface='ap')

        for i in range(0, self.no_of_clients):
            connected = False
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join(scan_ssid=scan_ssid)
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
        if leave:
            self.wifi_client_leave()

    def wifi_client_leave(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()

    def raspi_client_leave(self):
        self.wifi_dut.interfaces.wifi.disconnect_ap_client(
            client_mac=self.dut_add_dict['rasp_mac_address'], deauth_option="deauth_client_unspecified")

    def wlan_leave(self):
        try:
            logger().info("....Leaving the WLAN network....")
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def sniffer_validation(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")

        if self.test_type in [690734, 690736, 690737]:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_mac_address, filter_name="deauthentication")

            logger().info(f"***** Validating de-authentication packet ******")
            snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
            assert snif_pkt_count, "Unable to find de-authentication packet in sniffer"

        if self.ping_type == 'link':
            packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_mac_address,
                filter_name='No_beacon')
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
                'packet_count']

        if self.test_type == 693697:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                da_addr=dut_mac_address, filter_name="disassociation")

            logger().info(f"***** Validating disassociation packet ******")
            snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count']
            assert snif_pkt_count, "Unable to find disassociation packet in sniffer"


class ping(WifiThread):

    def __init__(
            self,
            wifi_dut=None,
            wifi_access_point=None,
            wifi_client=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            utf_constants=None,
            wifi_clients=None,
    ):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.utf_constants = utf_constants
        self.wifi_clients = wifi_clients

    def run(self):

        """ Ping the given IP address """
        if self.test_type == 690736:
            ping_global_local_addr = f"{WifiThread.dut_add_dict['dut_sta_ipv6_global']}"
            logger().info(f".... Pinging the Global Address {ping_global_local_addr} ....")
            status = self.sl_collections.ping(device_ip=ping_global_local_addr, ping_count=self.ping_count,
                                              retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_type in [690737, 700498]:
            interface = self.wifi_client.interfaces.wifi.config["interface"] = "eth1"
            ping_link_local_addr = f"{WifiThread.dut_add_dict['dut_sta_ipv6_link']}%{interface}"
            status = self.sl_collections.ping(device_ip=ping_link_local_addr, ping_count=self.ping_count, retry_count=3)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
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
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 8})
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_interface_c690734(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Disconnect the 3rd party STA From APUT in AP Alone Mode"""

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
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=690734)

        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.raspi_client_leave()
        time.sleep(5)
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.HiddenSSID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
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
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 8})
def test_wifi_sdk_check_ssid_parameter_after_disconn_from_apmode_c690735(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Check SSID Parameter in Beacons after disconnecting the 3rd party STA from APUT with Hidden SSID Parameter is
    enabled in opermode"""

    try:
        packet_filter2 = "IEEE 802.11 Wireless Management"
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False,
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=690735)

        wifi_obj.ap_mode_with_ipv4(scan_ssid=1)
        wifi_obj.wifi_client_leave()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter1 = f'(wlan.addr == {dut_mac_address} and wlan.ssid == "") && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1, packet_filter2=packet_filter2), "not found beacon from DUT "

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        hidden_ssid_check = re.findall(r"(Tag:\s*SSID\s+parameter\s+set: \s*.*)", content)
        logger().info(f"Hidden SSID Check: {hidden_ssid_check}")
        hidden_ssid = 0
        if 'Tag: SSID parameter set: Wildcard SSID' in hidden_ssid_check:
            logger().info(f"found the hidden ssid")
            hidden_ssid = 1
        assert hidden_ssid, "Hidden SSID not found in sniffer"

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
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
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
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_when_pinging_stamode_c690736(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """In Concurrent Mode, Disconnect the 3rd party STA connected to AP When STAUT is pinging from 3rd party AP
    Backend machine"""

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
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=690736)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=690736)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        ping_obj.start()
        time.sleep(10)
        wifi_obj.raspi_client_leave()
        ping_obj.wait_for_exit()
        time.sleep(5)
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.skip(reason="Need to check the test case")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.DHCPv6Server
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
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
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA2", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_when_pinging_stamode_c690737(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """In Concurrent Mode, Check beacon stop after disconnecting the 3rd party STA From APUT while pinging the STAUT
    from AP Backend machine."""

    try:
        test_name = request.node.name

        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, leave=False, ping_type='link',
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=690737)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=690737)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        ping_obj.start()
        time.sleep(10)
        # dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        # logger().info(f"*********{dut_mac_address}**********")
        # packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
        #     sa_addr=dut_mac_address, filter_name='beacon')
        # assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        #     'Unable to find  beacon in Sniffer'

        wifi_obj.raspi_client_leave()
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        ping_obj.wait_for_exit()
        time.sleep(5)
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
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
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 8})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_when_sta_with_wpa3_c700498(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify the 3rd party STA Disconnection to APUT when the STA is connected with 3rd party AP with WPA3 Security"""

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
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=700498)

        ping_obj = ping(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                        sl_collections=sl_collections, utf_constants=utf_constants, ping_count=ping_count,
                        wifi_clients=wifi_clients, test_type=700498)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        ping_obj.start()
        time.sleep(5)
        wifi_obj.raspi_client_leave()
        ping_obj.wait_for_exit()

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
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
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
            "channel": "8",
        },
    }
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 8})
def test_wifi_sdk_disconn_3rd_party_sta_from_aput_interface_c693697(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Disconnect the 3rd party STA From APUT in AP Alone Mode"""

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
                              ping_count=ping_count, wifi_clients=wifi_clients, ip_version='ipv4', test_type=693697)

        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.wifi_client_leave()
        time.sleep(10)
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()