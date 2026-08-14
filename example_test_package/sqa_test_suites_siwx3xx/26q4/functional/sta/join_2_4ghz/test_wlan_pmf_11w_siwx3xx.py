import time
import pytest as pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wiseconnect_3.wifi.siwx3xx.tests.devices.siwx3xx import (
    Siwx3xxOperatingMode,
    Siwx3xxCoexMode,
    Siwx3xxFeatureBitMap,
    Siwx3xxTCPIPFeatureBitMap,
    Siwx3xxCustomFeatureBitMap,
    Siwx3xxExtCustomFeatureBitMap,
    Siwx3xxBTFeatureBitMap,
    Siwx3xxExtTCPIPFeatureBitMap,
    Siwx3xxBLEFeatureBitMap,
    Siwx3xxBLECustomFeatureBitMap,
    Siwx3xxConfigFeatureBitMap,
    Siwx3xxJoinFeatureBitMap,
    Siwx3xxBSDSocketParams,
    IEEE802_11W
)
from utf_wiseconnect_3.wifi.siwx3xx.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""Author : Vinod"""

"""This function runs below test steps for DUT-Siwx3xx to verify 802.11w functionality 
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's(ASUS RT AX3000)
        3. Get the valid IP address
        4. Enable Background scan
        4. Create a new TCP/IP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Validate PMF capable/Required bit in Association Req RSN information, Protected flag:Data is protected in 
           Data/Control frame via sniffer.

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's-ASUS with PMF capability)
        4. Sniffer(NUC device)
"""


def wifi_dut_marker(region=None, region_code=None):
    """
    Common method to generate wifi_dut marker for pytest.mark.config decorator.
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Siwx3xxOperatingMode.WiFiClient,
        "coex_mode": Siwx3xxCoexMode.WLANOnly,
        "features": Siwx3xxFeatureBitMap.Default,
        "custom_features": Siwx3xxCustomFeatureBitMap.Default,
        "config_features": Siwx3xxConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Siwx3xxConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Siwx3xxTCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": Siwx3xxExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Siwx3xxExtCustomFeatureBitMap.Default | Siwx3xxExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
    if region:
        config["region"] = region
    if region_code:
        config["region_code"] = region_code

    return pytest.mark.config("wifi_dut", wifi=config)


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None,
                 test_name=None, siwx3xx_collections=None, data_transfer=False, net_perf_client=None,
                 wifi_client=None, protocol=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = 30
        self.data = 'Thisisfromclient'
        self.wifi_sniffer = wifi_sniffer
        self.dut_addr = None
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.siwx3xx_collections = siwx3xx_collections
        self.test_name = test_name
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.host_ip = None

    def run(self):
        try:
            """ Enabling Rejoin """
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)

            logger().info("\n *** Start sniffer configuration *** \n")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            time.sleep(2)

            if self.test_case_no == 19658 or self.test_case_no == 19671:
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=IEEE802_11W.Protection_capable)
                self.dut_addr = self.siwx3xx_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                              wifi_access_point=self.wifi_access_point,
                                                                              associated=False,
                                                                              ping_after_power_save=False)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)

            if self.test_case_no == 19659:
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=IEEE802_11W.Protection_Required)
                self.dut_addr = self.siwx3xx_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                              wifi_access_point=self.wifi_access_point,
                                                                              associated=False,
                                                                              ping_after_power_save=False)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)

            if self.test_case_no == 19670:
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      IEEE802_11W.Protection_capable |
                                                                      IEEE802_11W.Protection_Required)
                self.dut_addr = self.siwx3xx_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                              wifi_access_point=self.wifi_access_point,
                                                                              associated=False,
                                                                              ping_after_power_save=False)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)

            if self.data_transfer:
                self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"***** Host IP Address is {self.host_ip} ******")

                self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol)
                logger().info(
                    f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol} ")
                logger().info(f"***** starting iperf ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** send traffic ******")
                self.wifi_dut.interfaces.wifi.iperf(family=Siwx3xxBSDSocketParams.AF_INET,
                                                    transfer_type=Siwx3xxBSDSocketParams.SOCK_STREAM,
                                                    protocol=Siwx3xxBSDSocketParams.IPPROTO_TCP,
                                                    local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    size=1460, ttl=30, throughput_type=1)

            time.sleep(2)

            if self.test_case_no == 19671:
                logger().info(f"***** Start get IP address ******")
                self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()

                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol)
                logger().info(
                    f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol} ")
                logger().info(f"***** start iperf  ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** Start listening ******")
                self.wifi_dut.interfaces.wifi.iperf(family=Siwx3xxBSDSocketParams.AF_INET,
                                                    transfer_type=Siwx3xxBSDSocketParams.SOCK_STREAM,
                                                    protocol=Siwx3xxBSDSocketParams.IPPROTO_TCP,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1460, ttl=30, throughput_type=3)
                logger().info("data transfer is successful")
                time.sleep(5)

            self.wifi_dut.interfaces.wifi.leave()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19658')
def test_wifi_sdk_siwx3xx_pmf_cap_c19658(wifi_sniffer, wifi_access_point, wifi_dut, siwx3xx_collections, request,
                                         sniffer_filter, wifi_client, net_perf_client, protocol):
    test_name = request.node.name

    '''Check whether the device is advertising MFP Capable under RSN Information in the association request'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19658, siwx3xx_collections=siwx3xx_collections,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_with_assoc_req")

        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packets for Association req, with mgmt frame with protection capable'

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19659')
def test_wifi_sdk_siwx3xx_pmf_req_c19659(wifi_sniffer, wifi_access_point, wifi_dut, siwx3xx_collections, request,
                                         sniffer_filter, wifi_client, net_perf_client, protocol):
    test_name = request.node.name

    '''Check whether the device is advertising MFP Required under RSN Information in the association request'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19659, siwx3xx_collections=siwx3xx_collections,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_required_with_assoc_req")

        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packets ' \
                             'filter for Association req, with mgmt frame with protection capable'

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19661')
def test_wifi_sdk_siwx3xx_pmf_req_ap_pmf_cap_dut_c19661(wifi_sniffer, wifi_access_point, wifi_dut, siwx3xx_collections,
                                                        request, sniffer_filter, wifi_client, net_perf_client,
                                                        protocol):
    test_name = request.node.name

    """ Verify the Connection between AP(PMF required) and DUT(PMF capable)
    Check whether the device is connecting to PMF Required AP when the device is configured with PMF Capable"""
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19658, siwx3xx_collections=siwx3xx_collections,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_with_assoc_req")

        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find packets filter for Association req, with mgmt frame with protection capable'

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19670')
def test_wifi_sdk_siwx3xx_pmf_req_ap_pmf_req_and_cap_dut_c19670(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                siwx3xx_collections,
                                                                request, sniffer_filter, wifi_client, net_perf_client,
                                                                protocol):
    test_name = request.node.name

    """ Verify the Connection between AP(PMF required) and DUT(PMF capable+required)
    Check whether the device is connecting to PMF Capable AP when the device is configured with PMF Required and 
       Capable"""
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, siwx3xx_collections=siwx3xx_collections,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable+required
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_required_with_assoc_req")

        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], \
            'Unable to find packet filter for Association req, with mgmt frame with protection capable+required'

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19663')
def test_wifi_sdk_siwx3xx_pmf_cap_ap_pmf_req_and_cap_dut_c19663(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                siwx3xx_collections,
                                                                request, sniffer_filter, wifi_client, net_perf_client,
                                                                protocol):
    test_name = request.node.name

    '''Check whether the device is connecting to PMF Capable AP when the device is configured with PMF Required 
       and Capable'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, siwx3xx_collections=siwx3xx_collections,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable+required
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_required_with_assoc_req")

        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packet filter for Association req, with mgmt frame with protection ' \
                             'capable+required'

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19665')
def test_wifi_sdk_siwx3xx_unicast_frame_protection_bit_c19665(wifi_sniffer, wifi_access_point, wifi_dut,
                                                              siwx3xx_collections,
                                                              request, sniffer_filter, wifi_client, net_perf_client,
                                                              protocol):
    test_name = request.node.name

    '''Verify that after association only unicast mgmt packet transmission with protection bit enable '''
    '''Check whether the device is sending the Unicast Management frames(Action Frames) with Protection bit set after 
        association'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, siwx3xx_collections=siwx3xx_collections,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable+required
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_required_with_assoc_req")

        # Packet filter for mgmt action frame with protection bit enable and packet should only be unicast
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="mgmt_action_frame_protection_bit_enable_unicast")

        wifi_sniffer.interfaces.capture.stop_capture()

        result1 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        result2 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        if result1 is False or result2 is False:
            logger().info(
                f"Expected packet validation failed, Assoc req with RSN cap = {result1}, Action frame with Protection bit = {result2}")
            assert False
        else:
            logger().info(
                f"Assoc req with RSN cap = {result1}, Action frame with Protection bit = {result2}")
            logger().info("Sniffer validation Passed")
            assert True
    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19667')
def test_wifi_sdk_siwx3xx_action_frame_with_protection_bit_encrypted_c19667(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                            siwx3xx_collections, request,
                                                                            sniffer_filter, wifi_client,
                                                                            net_perf_client, protocol):
    test_name = request.node.name

    '''Validate encrypted mgmt action frame after association with protection bit enable'''
    ''' Check whether the device is sending the Unicast Management frames(Action Frames) with Payload Encrypted'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, siwx3xx_collections=siwx3xx_collections,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable+required
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_required_with_assoc_req")

        # Packet filter to verify encrypted mgmt action packet after association to check protection bit on
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="mgmt_action_frame_protection_bit_enable")

        wifi_sniffer.interfaces.capture.stop_capture()

        result1 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        result2 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        if result1 is False or result2 is False:
            logger().info(
                f"Expected packet validation failed, Assoc req with RSN cap = {result1}, Protection bit in Action frame = {result2}")
            assert False
        else:
            logger().info(
                f"Assoc req with RSN cap = {result1}, Protection bit in Action frame = {result2}")
            logger().info("Sniffer validation Passed")
            assert True

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19672')
def test_wifi_sdk_siwx3xx_disconnection_with_pmf_c19672(wifi_sniffer, wifi_access_point, wifi_dut, siwx3xx_collections,
                                                        request, sniffer_filter, wifi_client, net_perf_client,
                                                        protocol):
    test_name = request.node.name

    """Validate disassoc mgmt frame after association with protection bit enable"""
    '''Check the Disconnection Functionality when the PMF is enabled'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, siwx3xx_collections=siwx3xx_collections,
                          net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable+required
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_required_with_assoc_req")

        # Packet filter to verify encrypted mgmt action packet after association to check protection bit on
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="pmf_enabled_with_disassociation")

        time.sleep(30)
        wifi_sniffer.interfaces.capture.stop_capture()

        result1 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        result2 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        if result1 is False or result2 is False:
            logger().info(
                f"Expected packet validation failed, Assoc req with RSN cap = {result1}, Protection bit in Deauth frame = {result2}")
            assert False
        else:
            logger().info(
                f"Assoc req with RSN cap = {result1}, Protection bit in Deauth frame = {result2}")
            logger().info("Sniffer validation Passed")
            assert True

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C19671')
def test_wifi_sdk_siwx3xx_mgmt_pmf_enable_receive_data_c19671(wifi_dut, wifi_access_point, wifi_sniffer,
                                                              siwx3xx_collections, request, sniffer_filter,
                                                              wifi_client, net_perf_client, protocol):
    """Check whether the data transfer(receiver) is happening with PMF enable mode"""
    test_name = request.node.name
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19671, siwx3xx_collections=siwx3xx_collections,
                          data_transfer=False, net_perf_client=net_perf_client, wifi_client=wifi_client,
                          protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable+required
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_with_assoc_req")

        # Stop sniffer and validate pmf bit in assoc request
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

    except Exception as e:
        siwx3xx_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="net_init_client")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C19664')
def test_wifi_sdk_siwx3xx_mgmt_pmf_req_connection_fail_c19664(wifi_access_point, wifi_dut, wifi_sniffer, request):
    """ Verify the Connection between AP(PMF required) and DUT(PMF disable)"""
    '''	Check whether the device is not connecting to PMF Required AP when the device is not configured with PMF'''
    test_name = request.node.name
    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                             beacon_missed_count=40,
                                                             first_time_retry_enable=0)
    time.sleep(2)
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(5)

    logger().info("\n *** Start sniffer configuration *** \n")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    time.sleep(2)

    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, expected_status=SLStatus.SL_STATUS_SI91X_REJOIN_FAILURE)
    logger().info(f"Dut Tried to connect to ap between AP(PMF required) and DUT(PMF disable), observed error code "
                  f"0x10019 which is expected")

    wifi_sniffer.interfaces.capture.stop_capture()
