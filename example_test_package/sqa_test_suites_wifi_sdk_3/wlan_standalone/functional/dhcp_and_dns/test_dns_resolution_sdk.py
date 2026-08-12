import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xModuleType, Si91xCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(Si917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
              
    Test Steps:
        1. Configuration of DUT in 2G/5G 
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BT
        6. Issue DNS query
        7. Stop the sniffer  
        8. Analyizing all sniffer capture packets and find the dns packets in sniffer file.
        
    Author: Shaik Abdul Azeez
"""


class WifiJoinThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 sl_collections=None, sniffer_filter=None, capture_filename=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.ping_count = ping_count
        self.test_case = test_case
        self.sl_collections = sl_collections
        self.capture_filename = capture_filename
        self.test_case_no = test_case_no
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None

    def run(self):
        try:
            ap_addr = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP MAC: {ap_addr}")
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=3,
                                                                     ping_count=self.ping_count)
            time.sleep(2)

            if self.test_case_no == 19300:
                logger().info("==DNS address command is given when both primary and secondary DNS server ip addresses are given statically ==")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="NULL", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4", timeout=50)

            if self.test_case_no == 19302:
                logger().info("==DNS address command is given when both primary and secondary DNS server ip addresses are given statically ==")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",secondary_dns_server_address="10.207.210.13", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4", timeout=50)

            if self.test_case_no == 19303:
                logger().info("=======DNS address command is given when only primary DNS server ip address is given statically ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",secondary_dns_server_address="NULL", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000, ip_version="ipv4", timeout=50)

            if self.test_case_no == 19304:
                logger().info("=======DNS address command is given when only secondary DNS server ip address is given statically ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="NULL",secondary_dns_server_address="10.207.210.13", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4", timeout=50)

            if self.test_case_no == 19310:
                logger().info("==DNS address command is given 'twice' with the different DNS server IP addresses ==")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",secondary_dns_server_address="10.207.210.13", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4", timeout=50)

                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",secondary_dns_server_address="10.207.210.13", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4", timeout=50)

            if self.test_case_no == 19311:
                logger().info("==DNS address command is given when both primary and secondary DNS server ip addresses are given statically ==")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="NULL",secondary_dns_server_address="NULL", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4", timeout=50)

            if self.test_case_no == 551125:
                logger().info(f"\n==========>>>>>> Verifying DNS functionality for 30 minutes <<<<<<===========\n")
                start_time = time.time()
                logger().info(
                    "==DNS address command is given when both primary and secondary DNS server ip addresses are given statically ==")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="10.207.210.13", timeout=50)
                while (time.time() - start_time) < 1800:
                    self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4", timeout=50)

            if self.test_case_no == 553434:
                logger().info(f"\n==========>>>>>> Verifying DNS functionality for 24 hours <<<<<<===========\n")
                start_time = time.time()
                logger().info(
                    "==DNS address command is given when both primary and secondary DNS server ip addresses are given statically ==")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="10.207.210.13", timeout=50)
                while (time.time() - start_time) < 86400:
                    self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4", timeout=50)

            if self.test_case_no == 19302 or self.test_case_no == 19303 or self.test_case_no == 19304 or self.test_case_no == 19310\
                    or self.test_case_no == 551125 or self.test_case_no == 553434 or self.test_case_no == 19311:

                device_address = {'sa_addr': self.dut_addr['dut_mac_address'], 'da_addr': ap_addr}
                filters_name = {1: 'dns_id', 2: 'association_request', 3: 'power_mgmt_bit', 4: 'ps_poll'}

                self.sl_collections.sniffer_validation_for_packet_filters(self.wifi_sniffer, self.sniffer_filter,device_address, filter_name=filters_name)

            if self.test_case_no == 19305 or self.test_case_no == 19306 or self.test_case_no == 19308 or self.test_case_no == 19309:
                self.negative_test_cases()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def negative_test_cases(self):
        try:
            if self.test_case_no == 19305:
                logger().info("=======DNS address command is given both primary and secondary DNS server addresses are set to '0' statically ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="0.0.0.0",secondary_dns_server_address="0.0.0.0")
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,ip_version="ipv4",
                                                      expected_status=SLStatus.SL_STATUS_SI91X_SMTP_OVER_SIZE_MAIL_DATA)
                logger().info(f"\n\n Observed the expected error code: 0x1BBA1 (SMTP_OVER_SIZE_MAIL_DATA) \n\n")

            if self.test_case_no == 19306:
                logger().info("=======DNS get command with Primary & Secondary DNS server IP's which are wrong ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.210.91",secondary_dns_server_address="10.81.44.13")
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=240000, ip_version="ipv4",timeout=240,
                                                      expected_status=SLStatus.SL_STATUS_SI91X_SMTP_DNS_QUERY_FAILED)
                logger().info(f"\n\n Observed the expected error code: 0x1BBA3 (SMTP_DNS_QUERY_FAILED) \n\n")

            if self.test_case_no == 19308:
                logger().info("=======DNS address command is given with the same IP address ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="10.207.110.11",
                                                              expected_status=SLStatus.SL_STATUS_SI91X_DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE)
                logger().info(f"\n\n Observed the expected error code: 0x100AF (DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE) \n\n")

            if self.test_case_no == 19309:
                logger().info("=======DNS address command is given 'twice' with the same DNS server IP addresses ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",secondary_dns_server_address="10.207.110.11",
                                                              expected_status=SLStatus.SL_STATUS_SI91X_DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE)
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",secondary_dns_server_address="10.207.110.11",
                                                              expected_status=SLStatus.SL_STATUS_SI91X_DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE)
                logger().info(f"\n\n Observed the expected error code: 0x100AF (DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE) \n\n")

            logger().info("DUT going leave the AP")
            self.wifi_dut.interfaces.wifi.leave()

            logger().info("Stop the sniffer")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(2)

        except Exception as e:
            raise e


class DnsFunctionalityThread(ThreadBase):
    """Thread to verify DNS functionality."""

    def __init__(self, wifi_dut, wifi_access_point, test_case_no):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.test_case_no = test_case_no

    def run(self):
        try:
            if self.test_case_no == 553435:
                logger().info("Starting DNS functionality verification...")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11", secondary_dns_server_address="10.207.210.13", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000, ip_version="ipv4", timeout=50)

            if self.test_case_no == 551127:

                logger().info("Starting DNS functionality verification...")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11", secondary_dns_server_address="10.207.210.13", timeout=50)
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000, ip_version="ipv4", timeout=50)

                logger().info(f"\n\n *** Unplugging internet cable from AP *** \n\n")
                self.wifi_access_point.interfaces.wifi.enable_block_all_devices_internet_access()
                time.sleep(120)

                sw = Stopwatch()
                end_time = 1800
                while sw.elapsed_sec <= end_time:
                    # Negative test for DNS address setting
                    result_set_dns_address = self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                                                           secondary_dns_server_address="10.207.210.13", timeout=50)
                    # Negative test for DNS query
                    result_dns_get = self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,
                                                                           ip_version="ipv4", negative_flag=True, timeout=50)
                    # Corrected condition for result validation
                    logger().info(f"result_set_dns_address = {result_set_dns_address}, Result_dns_get={result_dns_get}")
                    time.sleep(5)

                # Unblocking internet access
                self.wifi_access_point.interfaces.wifi.disable_block_all_devices_internet_access()
                logger().info(f"\n\n Sleeping for 121 seconds before re-test \n\n")
                time.sleep(120)

                # Restore DNS settings
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="10.207.210.13", timeout=50)
                # Re-test DNS query
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,
                                                      ip_version="ipv4", timeout=50)
        except Exception as ex:
            logger().exception("Error in DNS functionality thread.")
            raise


class WLANDisconnectionThread(ThreadBase):
    """Thread to disconnect WLAN."""

    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        try:
            time.sleep(10)  # Delay before disconnection
            logger().info("Disconnecting WLAN...")
            self.wifi_dut.interfaces.wifi.leave()
        except Exception as ex:
            logger().exception("Error in WLAN disconnection thread.")
            raise


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19302')
def test_wifi_sdk_when_both_pri_sec_ips_are_statically_c19302(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):
    """Obtain the IP address of the specific domain name when both
       primary and secondary DNS server ip addresses are given statically."""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19302)
        for i in range(3):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19303')
def test_wifi_sdk_when_only_primary_ip_statically_c19303(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                         request, utf_constants, sniffer_filter):
    """Obtain the IP address of the specific domain name
       when only primary DNS server ip address is given statically."""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19303)
        for i in range(3):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19304')
def test_wifi_sdk_when_only_secondary_ip_statically_c19304(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                           request, utf_constants, sniffer_filter):
    """Obtain the IP address of the specific domain name
       when only secondary DNS server ip address is given statically"""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19304)
        for i in range(3):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19305')
def test_wifi_sdk_when_both_pri_sec_set_to_0_statically_c19305(wifi_sniffer, wifi_access_point, wifi_dut,
                                                               sl_collections, request, utf_constants, sniffer_filter):
    """Obtain the IP address of the specific domain name
       when both primary and secondary DNS server addresses are set to 0 statically."""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19305)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19306')
def test_wifi_sdk_when_both_pri_sec_ip_with_wrong_dns_server_ips_c19306(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):

    """Obtain the IP address of the specific domain name when both
       primary and secondary wrong DNS server ip addresses are configured statically.  """
    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19306)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19307')
def test_wifi_sdk_when_both_pri_sec_dut_static_ip_with_wrong_gateway_c19307(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):
    """Obtain the IP address of the specific domain name when both
       primary and secondary DNS server ip addresses are given statically
       using dns server command, DUT IP is static and selected wrong gateway address in the ip config command. """
    try:
        capture_filename = request.node.name
        mode = "power_save_low_latency"

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        static_ip = UtfConfig.instance().defaults["wifi"].get("static_ip", None)
        logger().info(f"in harness static_ip flag set to be : {static_ip}")

        static_subnet = UtfConfig.instance().defaults["wifi"].get("static_subnet", None)
        logger().info(f"in harness static_subnet flag set to be : {static_subnet}")

        static_gateway = '192.168.50.55'
        logger().info(f"in harness static_gateway flag set to be : {static_gateway}")

        ip_version = 'ipv4'

        logger().info(f"=======>>>>>Verifying Static IP<<<<<<<======")
        sl_collections.scan(wifi_dut=wifi_dut)
        sl_collections.connect(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point)

        logger().info(f"***** Assigning static IP for DUT with wrong gateway ******")
        wifi_dut.interfaces.wifi.start_ip(ip_version=ip_version, static_ip=static_ip, static_subnet=static_subnet,
                                          static_gateway=static_gateway, timeout=10)

        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info("=======Get DNS response when DUT get static IP and with wrong gateway ========")
        wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11", secondary_dns_server_address="10.207.210.13")
        wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=240000,ip_version="ipv4", timeout=240,
                                         expected_status=SLStatus.SL_STATUS_SI91X_SMTP_DNS_QUERY_FAILED)
        logger().info(f"\n Observed the expected error code: 0x1BBA3 (SMTP_DNS_QUERY_FAILED) \n")

        logger().info("DUT going leave the AP")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19308')
def test_wifi_sdk_when_pri_sec_with_same_dns_server_ips_c19308(wifi_sniffer, wifi_access_point, wifi_dut,
                                                               sl_collections, request, utf_constants, sniffer_filter):
    """Obtain the IP address of the specific domain name when both
       primary and secondary DNS server ip addresses are given statically
       and both primary and secondary DNS addresses are given with same ip address """

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19308)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19309')
def test_wifi_sdk_when_pri_sec_set_twice_with_same_dns_server_ips_c19309(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                         sl_collections, request, utf_constants,
                                                                         sniffer_filter):
    """Obtain the IP address of the specific domain name when
       both primary and secondary DNS server ip addresses are
       configured statically twice with same DNS server ip addresses """

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19309)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19310')
def test_wifi_sdk_when_both_pri_sec_twice_diff_dns_server_ips_c19310(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):
    """Obtain the IP address of the specific domain name when
       both primary and secondary DNS server ip addresses are
       configured statically twice, but with different ip addresses"""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19310)
        for i in range(3):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN', "dhcp_dns_1":'8.8.8.8'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19300')
def test_wifi_sdk_when_only_pri_dns_server_ip_assign_through_dhcp_c19300(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):
    """Obtain the IP address of the specific domain name
       when only primary DNS server ip address is received by dhcp server"""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19300)
        for i in range(3):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN', "dhcp_dns_1":'8.8.8.8', "dhcp_dns_2":'8.8.4.4'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19311')
def test_wifi_sdk_when_two_dns_server_ips_assign_through_dhcp_c19301_c19311(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):
    """DNS client functionality when 2 DNS server Ips are got through DHCP"""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=19311)
        for i in range(3):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(5)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C551125')
def test_wifi_sdk_dns_functionality_for_30_minutes_c551125(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):
    """Verify DNS functionality for 30 minutes"""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=551125)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        time.sleep(5)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C553434')
def test_wifi_sdk_dns_functionality_for_24_hours_c553434(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):
    """Verify DNS functionality for 24 hours"""

    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")

    try:
        wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                  test_case=capture_filename,
                                  ping_count=ping_count, test_case_no=553434)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()
        time.sleep(5)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C553435')
def test_wifi_sdk_verify_dns_and_wlan_disconnection_c553435(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                              request, utf_constants, sniffer_filter):
    """Verify DNS functionality in one thread and WLAN disconnection in another."""

    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        sl_collections.join_to_wifi_network(wifi_dut,wifi_access_point=wifi_access_point, power_save=True,
                                            mode=mode,ping_after_power_save=True, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated, ping_count=ping_count)

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        dns_thread = DnsFunctionalityThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=553435)
        disconnection_thread = WLANDisconnectionThread(wifi_dut=wifi_dut)

        # Start both threads
        dns_thread.start()
        disconnection_thread.start()

        # Wait for both threads to complete
        dns_thread.wait_for_exit()
        disconnection_thread.wait_for_exit()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, filter_name='dns_id')
        filter_2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,filter_name='association_request')
        filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,filter_name='power_mgmt_bit')
        filter_4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,filter_name='ps_poll')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find dns id sniffer packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_2)['packet_count'], \
            'Unable to find the association request sniffer packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3)['packet_count'], \
            'Unable to find the power management save sniffer packets'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_4)['packet_count'], \
            'Unable to find the ps poll sniffer packets'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C551127')
def test_wifi_sdk_ap_no_internet_for_30mins_recon_check_behavior_c551127(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                          sl_collections,
                                                                          request, utf_constants, sniffer_filter):
    """Verify DNS functionality when AP doesn't have internet for 30 minutes,
       After 30 minutes connect internet cable and check behavior."""

    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point, power_save=True,
                                            mode=mode, ping_after_power_save=True, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated, ping_count=ping_count)

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        dns_thread = DnsFunctionalityThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case_no=551127)

        # Start thread
        dns_thread.start()

        # Wait for thread to complete
        dns_thread.wait_for_exit()

        logger().info("Disconnecting WLAN...")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_access_point.interfaces.wifi.disable_block_all_devices_internet_access()
        logger().info(f"\n\n Sleeping for 120 seconds before re-test \n\n")
        time.sleep(120)