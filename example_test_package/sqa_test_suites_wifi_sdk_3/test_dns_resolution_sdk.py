import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xModuleType, Si91xCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus


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
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=3,
                                                                     ping_count=self.ping_count)
            time.sleep(2)

            if self.test_case_no == 19302:
                logger().info(
                    "==DNS address command is given when both primary and secondary DNS server ip addresses are given statically ==")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="10.8.4.10")
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,
                                                      ip_version="ipv4")

            if self.test_case_no == 19303:
                logger().info(
                    "=======DNS address command is given when only primary DNS server ip address is given statically ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="NULL")
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,
                                                      ip_version="ipv4")

            if self.test_case_no == 19304:
                logger().info(
                    "=======DNS address command is given when only secondary DNS server ip address is given statically ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="NULL",
                                                              secondary_dns_server_address="10.8.4.10")
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,
                                                      ip_version="ipv4")

            if self.test_case_no == 19302 or self.test_case_no == 19303 or self.test_case_no == 19304:
                device_address = {'sa_addr': self.dut_addr['dut_mac_address'], 'da_addr': ap_addr}
                filters_name = {1: 'dns_id', 2: 'association_request', 3: 'power_mgmt_bit', 4: 'ps_poll'}
                # filters_name = {1: 'dns_id'}
                self.sl_collections.sniffer_validation_for_packet_filters(self.wifi_sniffer, self.sniffer_filter,
                                                                          device_address,
                                                                          filter_name=filters_name)

            if self.test_case_no == 19305 or self.test_case_no == 19308 or self.test_case_no == 19309:
                self.negative_test_cases()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def negative_test_cases(self):
        try:
            if self.test_case_no == 19305:
                logger().info(
                    "=======DNS address command is given both primary and secondary DNS server addresses are set to '0' statically ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="0.0.0.0",
                                                              secondary_dns_server_address="0.0.0.0")
                self.wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", query_timeout=20000,
                                                      ip_version="ipv4",
                                                      expected_status=SLStatus.SL_STATUS_SI91X_SMTP_OVER_SIZE_MAIL_DATA)
                logger().info(f"\n Observed the expected error code: 0x1BBA1 (SMTP_OVER_SIZE_MAIL_DATA) \n")

            if self.test_case_no == 19308:
                logger().info("=======DNS address command is given with the same IP address ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="10.207.110.11",
                                                              expected_status=SLStatus.SL_STATUS_SI91X_DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE)
                logger().info(
                    f"\n Observed the expected error code: 0x100AF (DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE) \n")

            if self.test_case_no == 19309:
                logger().info(
                    "=======DNS address command is given 'twice' with the same DNS server IP addresses ========")
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="10.207.110.11",
                                                              expected_status=SLStatus.SL_STATUS_SI91X_DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE)
                self.wifi_dut.interfaces.wifi.set_dns_address(primary_dns_server_address="10.207.110.11",
                                                              secondary_dns_server_address="10.207.110.11",
                                                              expected_status=SLStatus.SL_STATUS_SI91X_DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE)
                logger().info(
                    f"\n Observed the expected error code: 0x100AF (DUPLICATE_ENTRY_EXISTS_IN_DNS_SERVER_TABLE) \n")

            logger().info("DUT going leave the AP")
            self.wifi_dut.interfaces.wifi.leave()

            logger().info("Stop the sniffer")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(2)

        except Exception as e:
            raise e


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
            "bt_features": 0,
            "ble_features": 0,
            "ble_custom_ext_features": 0,
        }
    )
]


@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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


@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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


@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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


@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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


@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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


@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
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
