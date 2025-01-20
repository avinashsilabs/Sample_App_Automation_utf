import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xJoinFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
import time
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in concurrent mode
        2. create DUT as access point and join DUT to 3rd party access point
        3. Initiate ping from the dut and vice versa
        4. Disconnect dut from the 3rd party access point

    setup requirement:
        1. DUT(SiWG917 _ACX (BRD4343A)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC

    Author: Saurabh Sharma

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
            ip_version="ipv4",
            wifi_clients=None,
            htcaps_enable=None,
            leave=True,
            enable_data_rate=False,
            version=4
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
        self.ip_version = ip_version
        self.dut_addr_dict = None
        self.wifi_clients = wifi_clients
        self.ssid = "sharma123"
        self.security = "WPA2"
        self.password = "thisistestnetwork"
        self.channel = 6
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

        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def run(self):
        """
        Run the test case.
        """
        if self.test_type in [661457, 661458, 661460]:
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point, power_save=False,
                associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, ping_before_power_save=False,
                ping_after_power_save=False, ping_count=self.ping_count, ip_version=self.ip_version)

        if self.test_type == 661459:
            self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point,
                                                  expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
            logger().info("connection will fail and getting error code 0x10003 which is expected")

    def ap_mode_connection(self):
        logger().info(".... Configuring the DUT in AP mode ....")

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
        if self.test_type in [661457, 661459]:
            self.wifi_client_leave()

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

    def wlan_leave(self):
        try:
            logger().info("....Leaving the WLAN network....")
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def wifi_client_leave(self):
        for i in range(0, self.no_of_clients):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            self.wifi_clients[i].interfaces.wifi.leave()


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
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": 6,
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 6})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_first_sta_conn_and_apmode_later_c661457(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify connection behavior when STAUT is configured first and APUT is configured later"""

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
                              ping_count=ping_count, wifi_clients=wifi_clients, test_type=661457)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60)
        wifi_obj.ap_mode_connection()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": 6,
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 6})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_first_ap_conn_and_stamode_later_c661458(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify connection behavior when APUT is configured first and STAUT is configured later"""

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
                              ping_count=ping_count, test_type=661458)

        wifi_obj.ap_mode_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60)
        wifi_obj.wifi_client_leave()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
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
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234", "channel": 11})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_sta_conn_with_bg_scan_c661460(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify STAUT connection when BG scan is enabled"""

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
                              ping_count=ping_count, test_type=661460)

        logger().info(f"**** enabling the BG scan params ****")

        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
            adv_active_channel_time=15, adv_passive_channel_time=20)

        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_obj.ping(ping_from="remote", ping_count=60)
        logger().info("\n *** Enable BGscan *** \n")
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
        wifi_obj.wlan_leave()

        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="probe_request")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
            'packet_count']
        assert snif_pkt_count, "Unable to find probe request frames in sniffer"

        wifi_obj.ap_mode_connection()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@pytest.mark.skip("need to check the test case for ignore region channel 13")
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
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "sharma123",
            "passphrase": "thisistestnetwork",
            "channel": 6,
        },
    }
)
@pytest.mark.config("wifi_access_point",
                    wifi={"security": "WPA3", "passphrase": "thisisatestnetwork", "ssid": "sharma1234",
                          "region": 'China', "channel": 13})
def test_wifi_sdk_aput_conn_when_staut_connected_ch13_c661459(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, wifi_client, utf_constants,
        wifi_clients):
    """Verify APUT connection behavior when STAUT is connected in channel 13"""

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
                              ping_count=ping_count, test_type=661459)

        wifi_obj.ap_mode_connection()
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        logger().info(".... stop the sniffer ....")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
