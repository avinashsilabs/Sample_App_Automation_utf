import re
import time
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf import UtfDatabaseProperties
from utf.utils.iperf.iperf_utils import ping
from test_wlan_data_rates_sdk import SocketDataTransfer
import threading
from threading import Thread, Event
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.shell.ssh_shell import SSHShell
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xJoinFeatureBitMap,
    IEEE802_11W
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""Author : Vivek"""

"""This function runs below test steps for DUT-Si91x to verify 802.11w functionality 
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


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None,
                 test_name=None, sl_collections=None, data_transfer=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = 30
        self.data = 'Thisisfromclient'
        self.wifi_sniffer = wifi_sniffer
        self.dut_addr = None
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                             time_period=self.time_period, data=self.data)

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

            if self.test_case_no == 19658:
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=IEEE802_11W.Protection_capable)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         mode='power_save',
                                                                         associated=False,
                                                                         ping_after_power_save=False)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)

            if self.test_case_no == 19659:
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=IEEE802_11W.Protection_Required)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         mode='power_save',
                                                                         associated=False,
                                                                         ping_after_power_save=False)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)

            if self.test_case_no == 19670:
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                      IEEE802_11W.Protection_capable |
                                                                      IEEE802_11W.Protection_Required)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         mode='power_save',
                                                                         associated=False,
                                                                         ping_after_power_save=False)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)

            if self.data_transfer:
                self.socket_obj.socket_data_transfer()
            time.sleep(2)

            if not self.test_name == "test_wifi_sdk_mgmt_pmf_enable_receive_data_c19671":
                self.wifi_dut.interfaces.wifi.leave()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_pmf_cap_c19658(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, request,
                                 sniffer_filter):
    test_name = request.node.name

    '''Check whether the device is advertising MFP Capable under RSN Information in the association request'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19658, sl_collections=sl_collections)
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_pmf_req_c19659(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, request,
                                 sniffer_filter):
    test_name = request.node.name

    '''Check whether the device is advertising MFP Required under RSN Information in the association request'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19659, sl_collections=sl_collections)

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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_pmf_req_ap_pmf_cap_dut_c19661(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                request, sniffer_filter):
    test_name = request.node.name

    """ Verify the Connection between AP(PMF required) and DUT(PMF capable)
    Check whether the device is connecting to PMF Required AP when the device is configured with PMF Capable"""
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19658, sl_collections=sl_collections)
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_pmf_req_ap_pmf_req_and_cap_dut_c19670(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                        request, sniffer_filter):
    test_name = request.node.name

    """ Verify the Connection between AP(PMF required) and DUT(PMF capable+required)
    Check whether the device is connecting to PMF Capable AP when the device is configured with PMF Required and 
       Capable"""
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, sl_collections=sl_collections)
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_pmf_cap_ap_pmf_req_and_cap_dut_c19663(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                        request, sniffer_filter):
    test_name = request.node.name

    '''Check whether the device is connecting to PMF Capable AP when the device is configured with PMF Required 
       and Capable'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, sl_collections=sl_collections)
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_unicast_frame_protection_bit_c19665(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                      request, sniffer_filter):
    test_name = request.node.name

    '''Verify that after association only unicast mgmt packet transmission with protection bit enable '''
    '''Check whether the device is sending the Unicast Management frames(Action Frames) with Protection bit set after 
        association'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, sl_collections=sl_collections)
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_action_frame_with_protection_bit_encrypted_c19667(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                    sl_collections, request, sniffer_filter):
    test_name = request.node.name

    '''Validate encrypted mgmt action frame after association with protection bit enable'''
    ''' Check whether the device is sending the Unicast Management frames(Action Frames) with Payload Encrypted'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, sl_collections=sl_collections)
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_disconnection_with_pmf_c19672(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections,
                                                request, sniffer_filter):
    test_name = request.node.name

    """Validate disassoc mgmt frame after association with protection bit enable"""
    '''Check the Disconnection Functionality when the PMF is enabled'''
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19670, sl_collections=sl_collections)
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mgmt_pmf_enable_receive_data_c19671(wifi_dut, wifi_access_point, wifi_sniffer,
                                                      sl_collections, request, sniffer_filter, remote_socket):
    # Check whether the data transfer(receiver) is happening with PMF enable mode
    test_name = request.node.name
    tcp_ip_port = 7007
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
    wifi_access_point.interfaces.wifi.start_ap()

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19658, sl_collections=sl_collections, data_transfer=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Packet filter for Association req, with mgmt frame with protection capable+required
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'], radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name="protection_capable_with_assoc_req")

        # Open TCP socket remotely
        remote_ip = remote_socket.interfaces.socket.server_ip
        logger().info(f"Remote_IP = {remote_ip}")
        remote_socket.interfaces.socket.start_server(server_ip=remote_ip, port=tcp_ip_port)

        # Open TCP socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(timeout=20)

        assert sock == 0, "socket id received is not matched. Expected is 0"

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wlan_obj.dut_addr['device_ip'], server_port=tcp_ip_port)
        wifi_dut.interfaces.wifi.bsdSocketConnect(sock, remote_ip, 4, server_port=tcp_ip_port, timeout=30)

        tx_buffer = "12345678901234567890123456789012345678901234567890"

        remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)

        data_received = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
        actual_data = (data_received.decode().split(':')[2].splitlines()[0])
        logger().info(f"Data Received : {actual_data}")
        assert tx_buffer != data_received, "buffer length sent and received is not matched"
        logger().info(f"\n **** Transmit data matched ****\n")

        # Stop sniffer and validate pmf bit in assoc request
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init", device="reset")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.PSKSecurity,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mgmt_pmf_req_connection_fail_c19664(wifi_access_point, wifi_dut):
    """ Verify the Connection between AP(PMF required) and DUT(PMF disable)"""
    '''	Check whether the device is not connecting to PMF Required AP when the device is not configured with PMF'''
    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                             beacon_missed_count=40,
                                                             first_time_retry_enable=0)
    time.sleep(2)
    wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(5)

    wifi_dut.interfaces.wifi.scan(ssid=None)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, expected_status=SLStatus.SL_STATUS_SI91X_REJOIN_FAILURE)
    logger().info(f"Dut Tried to connect to ap between AP(PMF required) and DUT(PMF disable), observed error code "
                  f"0x10019 which is expected")


