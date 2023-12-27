import time
import pytest
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode
from utf_wiseconnect_3.tests.devices.si91x import (Si91xTCPIPFeatureBitMap, Si91xFeatureBitMap, \
                                                   Si91xConfigFeatureBitMap)
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""
    Test Steps:
        1. Configuration of DUT in 2G/5G 
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BT
        6. Issue DNS query
        7. Stop the sniffer  
        8. Analyzing all sniffer capture packets and find the dns packets in sniffer file.

    Setup requirement:
        1. SoC board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer (NUC device)
"""


class WlanThread(ThreadBase):
    """This class is responsible for the AP connectivity."""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None,
                 sl_collections=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.sl_collections = sl_collections
        self.dut_addr = None

    def run(self):
        try:
            logger().info(" ====== configuring the Sniffer with access point channel ====== ")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)

            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case_no)

            logger().info(" ====== Trying to connect to the Access Point ====== ")
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     power_save=True,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)
            logger().info(" ====== DUT successfully connected with AP ====== ")

        except Exception as Ex:
            logger().info(f"\n\n **** Got exception in test case thread: {str(Ex)} ****\n\n")
            raise Ex


@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
def test_wifi_sdk_dns_server_obtaining_ip_through_dhcp_handshake_c19297(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                        request, sniffer_filter,
                                                                        sl_collections):
    """
        Test steps:
            1. Configuration of DUT in 2G/5G
            2. Start the sniffer before connection
            3. Association of Third party AP's
            4. Enable the power save mode in DUT & BT
            5. Issue DNS query
            6. Get the valid IP address through DHCP handshake process
            7. Stop the sniffer
            8. Analyzing all sniffer capture packets and find the dns packets in sniffer file.
    """
    try:
        test_name = request.node.name
        wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_case_no=test_name, sl_collections=sl_collections)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(" ====== Initiating DNS get command when DNS IP address is obtained through dhcp handshake "
                      "process ====== ")
        status = wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", timeout=30, query_timeout=1.2)
        logger().info(f'\n *** DNS address = {status} *** \n')
        time.sleep(2)

        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

        logger().info(" ====== Initiating the disconnect with AP ====== ")
        wifi_dut.interfaces.wifi.leave()

        logger().info("\n\n ====== Validating the sniffer ====== \n\n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='dns_id')

        result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)
        logger().info(f"DNS address = {result}")

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DHCP decryption is in progress {decryption_key}")

        logger().info(f"\n\n *** Validation for DHCP 4 way handshake is about to start *** \n\n")
        wifi_sniffer.interfaces.capture.get_dhcp_list(wlan_obj.dut_addr['dut_mac_address'], decryption_key, ["dhcp"])

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='ps_poll')

        result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count']
        logger().info(f"DNS address = {result}")

        assert result, "Can not find power management packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
def test_wifi_sdk_dns_server_dns_feature_disable_c19299(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                                        sl_collections):
    """
        Test steps:
            1. Configuration of DUT in 2G/5G
            2. Start the sniffer before connection
            3. Association of Third party AP's
            4. Enable the power save mode in DUT & BT
            5. Issue DNS query when DNS feature is not enabled in oper_mode
            5. Check for the feature not enabled error code
    """
    try:
        test_name = request.node.name
        wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_case_no=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(" ====== DNS SERVER WITHOUT ENABLING DNS FEATURE ====== ")
        result = wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com", timeout=30,
                                                  expected_status=SLStatus.SL_STATUS_SI91X_FEATURE_NOT_ENABLED)
        logger().info(result)
        logger().info("\n\n ****** Observed error code 0x1FF74 which is expected ****** \n\n")
        time.sleep(2)
        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip('Not supported on WSDK 3.0')
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
def test_wifi_sdk_dns_server_c19298(wifi_sniffer, wifi_access_point, wifi_dut, request, sniffer_filter, sl_collections):
    """
        Test steps:
            1. Start the sniffer.
            2. Connect to the AP.
            3. Issue DNS query.
            4. Stop the sniffer.
            5. Analyzing all sniffer capture packets and find the dns packets in sniffer file.
        Query DNS server IP address when DNS server IP addresses are set statically
    """
    try:
        test_name = request.node.name
        wlan_obj = WlanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              test_case_no=test_name, sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("=======Initiating DNS get command with Primary and Secondary Static IPs for DNS server========")
        status = wifi_dut.interfaces.wifi.dns_get(domain_name="www.google.com")
        logger().info(f'\n *** DNS address = {status} *** \n')
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        wifi_dut.interfaces.wifi.leave()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name='dns_id')
        result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                    sniffer_validation=False)
        assert result['packet_count'], "DNS packets are not found in sniffer file"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
