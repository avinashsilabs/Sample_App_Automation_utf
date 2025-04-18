import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
import time


def logger():
    return get_logger(__name__)


"""
     Setup Requirement:

        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device) 

     Author: 
      - Saurabh Sharma 
"""


class WifiThread(ThreadBase):
    dut_add_dict = {}
    ip_dict = {}
    default_interface = None

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
            utf_constants=None,
            testcase=None,
            ip_version="ipv4",
            wifi_clients=None,
            leave=False,
            enable_data_rate=False,
            version=4,
            ip_config_disable=False,
            tcp_ip_bypass=False,
            ping_type=None,
            timeout=60,
            beacon_stop_ap=1

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
        self.utf_constants = utf_constants
        self.testcase = testcase
        self.ip_version = ip_version
        self.wifi_clients = wifi_clients
        self.ssid = "sharma123"
        self.security = "WPA2"
        self.password = "thisistestnetwork"
        self.channel = 8
        self.dtim_count = 3
        self.beacon_interval = 100
        self.beacon_stop = 0
        self.no_of_clients = 1
        self.htcaps_enable = 1
        self.leave = leave
        self.enable_data_rate = enable_data_rate
        self.version = version
        self.ping_type = ping_type
        self.remote_ip = None
        self.ip_config_disable = ip_config_disable
        self.tcp_ip_bypass = tcp_ip_bypass
        self.timeout = timeout
        self.beacon_stop_ap = beacon_stop_ap

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run(self):
        """
        Run the test case
        """
        if self.test_type in [557387, 557388, 557389, 557390]:
            self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, tcp_ip_bypass=self.tcp_ip_bypass,
                ip_config_disable=self.ip_config_disable)

            if self.test_type in [557387, 557388, 557389, 557390]:
                ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=1,
                                                                        ip_version=self.ip_version)
                assert ip_status, f"....Unable to assign IPv6 ADDRESS through DHCP with reason: {ip_config}...."
                self.dut_add_dict['dut_sta_ipv6_global'] = ip_config[1]
                self.dut_add_dict['dut_sta_ipv6_link'] = ip_config[0]
                logger().info(f"DUT IPV6 GLOBAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_global']}\n"
                              f"DUT IPV6 LINK LOCAL ADDRESS : {self.dut_add_dict['dut_sta_ipv6_link']}\n")

    def check_ping_status_ipv6(self, ping_count=10):
        """
        Ping the given IP address.
        """
        interface = self.wifi_client.interfaces.wifi.config["interface"]
        ping_link_local_addr = f"{self.dut_add_dict['dut_sta_ipv6_link']}%{interface}"
        status = self.sl_collections.ping(device_ip=ping_link_local_addr, ping_count=ping_count, retry_count=3)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def ap_mode_with_ipv4(self):
        self.wifi_dut.interfaces.wifi.start_ip(
            static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", vid=1,
            ip_version='ipv4')
        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security=self.security, psk=self.password,
                                               channel=self.channel, dtim_beacon_count=self.dtim_count,
                                               beacon_interval=self.beacon_interval, beacon_stop=self.beacon_stop)
    def ap_mode_conn(self, scan_ssid=0):
        ping_count = self.utf_constants.get("ping_count")
        self.wifi_dut.interfaces.wifi.get_channel_info(interface='ap')
        for i in range(0, self.no_of_clients):
            connected = False
            self.wifi_clients[i].interfaces.wifi.config['interface'] = "wlan0"
            logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is joining to DUT-AP")
            self.wifi_clients[i].interfaces.wifi.join(scan_ssid=scan_ssid)
            time.sleep(5)
            WifiThread.ip_dict['dut_ip'] = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {WifiThread.ip_dict['dut_ip']}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{self.wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{self.wifi_clients[i].name}' to DUT")
                    WifiThread.ip_dict['rasp_mac_address'] = self.wifi_clients[i].interfaces.wifi.get_mac_address()
                    logger().info(f"raspi_mac: {WifiThread.ip_dict['rasp_mac_address']}")
                    WifiThread.ip_dict[f'client{i + 1}_ip'] = self.wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {WifiThread.ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = self.wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {WifiThread.ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        return WifiThread.ip_dict

    def wifi_client_leave(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()

    def check_no_beacon(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='beacon')
        logger().info(f"***** Validating no beacon packet ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2, negative_test=True)['packet_count']
        assert not snif_pkt_count, "found beacon packet in sniffer"

    def check_beacon(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(interface=2)
        logger().info(f"*********{dut_mac_address}**********")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name='beacon')
        logger().info(f"***** Validating beacon packet ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "No beacon found in sniffer"

    def reconfigure_ap(self):
        self.wifi_dut.interfaces.wifi.sl_wifi_reconfigure_ap(interface=2, beacon_stop=self.beacon_stop_ap)

def wifi_dut_marker(accesspoint=0, concurrent=0, DHCPv6Client=0, DHCPv6Server=0, IPv6Mode=0):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": accesspoint | concurrent,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | 
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | DHCPv6Client | DHCPv6Server | IPv6Mode,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker(accesspoint=Si91xOperatingMode.AccessPoint)
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_stop_beacon_api_apmode_c557385(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants):
    """Verify STOP Beacon API Functionality in AP Mode"""

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
                              ping_count=ping_count, test_type=557385)

        wifi_obj.beacon_stop_ap = 1
        wifi_obj.beacon_stop = 0
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.check_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.reconfigure_ap()
        time.sleep(10)
        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(10)
        wifi_obj.check_no_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@wifi_dut_marker(accesspoint=Si91xOperatingMode.AccessPoint)
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_start_beacon_api_apmode_c557386(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify start Beacon API Functionality in AP Mode"""

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, wifi_clients=wifi_clients,
                              ping_count=ping_count, test_type=557386)

        wifi_obj.beacon_stop_ap = 0
        wifi_obj.beacon_stop = 1
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.check_no_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.reconfigure_ap()
        time.sleep(10)

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(10)

        wifi_obj.check_beacon()
        wifi_obj.ap_mode_conn()
        wifi_obj.wifi_client_leave()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@wifi_dut_marker(concurrent=Si91xOperatingMode.ConcurrentMode)
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
def test_wifi_sdk_stop_beacon_api_concurrent_mode_c557387(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants):
    """Verify STOP Beacon API FunctionalityÂ  for AP Mode in Concurrent Mode"""

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
                              ping_count=ping_count, test_type=557387)

        wifi_obj.beacon_stop_ap = 1
        wifi_obj.beacon_stop = 0
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.check_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.reconfigure_ap()
        time.sleep(10)

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(10)
        wifi_obj.check_no_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@wifi_dut_marker(concurrent=Si91xOperatingMode.ConcurrentMode, DHCPv6Client=Si91xTCPIPFeatureBitMap.DHCPv6Client,
                 DHCPv6Server=Si91xTCPIPFeatureBitMap.DHCPv6Server, IPv6Mode=Si91xTCPIPFeatureBitMap.IPv6Mode)
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
def test_wifi_sdk_start_beacon_api_concurrent_mode_c557388(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants):
    """Verify START Beacon API Functionality for AP Mode in Concurrent Mode"""

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, ip_version='ipv6',
                              ping_count=ping_count, test_type=557388)

        wifi_obj.beacon_stop_ap = 0
        wifi_obj.beacon_stop = 1
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.check_no_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.reconfigure_ap()
        time.sleep(10)

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(10)
        wifi_obj.check_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@wifi_dut_marker(concurrent=Si91xOperatingMode.ConcurrentMode, DHCPv6Client=Si91xTCPIPFeatureBitMap.DHCPv6Client,
                 DHCPv6Server=Si91xTCPIPFeatureBitMap.DHCPv6Server, IPv6Mode=Si91xTCPIPFeatureBitMap.IPv6Mode)
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
def test_wifi_sdk_staut_and_stop_beacon_api_concurrent_mode_c557389(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants):
    """Verify the STAUT Connectivity while Giving STOP Beacon API in concurrent Mode"""

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, ip_version='ipv6',
                              ping_count=ping_count, test_type=557389)

        wifi_obj.beacon_stop_ap = 1
        wifi_obj.beacon_stop = 0
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.check_ping_status_ipv6()
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.check_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.reconfigure_ap()
        time.sleep(10)

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(10)
        wifi_obj.check_no_beacon()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@wifi_dut_marker(concurrent=Si91xOperatingMode.ConcurrentMode, DHCPv6Client=Si91xTCPIPFeatureBitMap.DHCPv6Client,
                 DHCPv6Server=Si91xTCPIPFeatureBitMap.DHCPv6Server, IPv6Mode=Si91xTCPIPFeatureBitMap.IPv6Mode)
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
def test_wifi_sdk_staut_and_stop_beacon_api_concurrent_mode_c557390(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants):
    """Verification of STAUT connectivity to 3rd party AP after Beacon STOP API in concurrent Mode"""

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("... start capturing with Sniffer by giving the test case name as filename ...")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=test_name, wifi_client=wifi_client, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, utf_constants=utf_constants, ip_version='ipv6',
                              ping_count=ping_count, test_type=557390)

        wifi_obj.beacon_stop_ap = 1
        wifi_obj.beacon_stop = 0
        wifi_obj.ap_mode_with_ipv4()
        wifi_obj.check_beacon()
        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_obj.reconfigure_ap()
        time.sleep(10)

        logger().info("... configuring the Sniffer with the channel ...")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(10)
        wifi_obj.check_no_beacon()

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.check_ping_status_ipv6()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()