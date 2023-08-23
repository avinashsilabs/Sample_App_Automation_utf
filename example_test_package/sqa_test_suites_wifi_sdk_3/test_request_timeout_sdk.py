import re
import time
from retry import retry
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf import UtfDatabaseProperties
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116DataRate, RS9116RejoinParams, RS9116ExtCustomFeatureBitMap, \
    RS9116BTFeatureBitMap
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect.utils.sl_collections import SLCollections


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Set the keep alive timer in various time intervals(10sec & 30sec) 
        4. Association of Third party AP's
        5. Get the valid IP address
        6. Enable the power save mode in DUT & BT
        7. Stop the sniffer  
        8. Analyizing all sniffer capture packets and find the arp announcement packet 
        9. Validate the arp announcement packets with time delta as per keep alive timer
    setup requirement:
        1. DUT(RS9117)
        2. WSDK 3.0 Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K
"""


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, time_period=None,
                 data=None, ping_count=None, data_transfer=True, test_name=None, sl_collections=None, dut_leave=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.data = data
        self.ping_count = ping_count
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.dut_leave = dut_leave
        self.test_name = test_name


    def run(self):
        try:
            if self.test_case_no == 19746:
                """ set timeout of keep-alive for 10 seconds """
                self.wifi_dut.interfaces.wifi.set_timeout(feature=4, timeout=10,
                                                                expected_status=SLStatus.SL_STATUS_OK, thread=True)
            if self.test_case_no == 19750:
                """ set timeout of keep-alive for 30 seconds """
                self.wifi_dut.interfaces.wifi.set_timeout(feature=4, timeout=30,
                                                                expected_status=SLStatus.SL_STATUS_OK, thread=True)

            if self.test_case_no == 19748:
                """ set timeout of scan timeout for 100 Mi-sc """
                self.wifi_dut.interfaces.wifi.set_timeout(feature=2, timeout=100,
                                                                expected_status=SLStatus.SL_STATUS_OK, thread=True)
                with TimeMeasurer() as t:
                    logger().info(f"Initiating Scan")
                    scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
                logger().info(scan_results)
                assert len(scan_results) > 0
                logger().info(f"Scan in {t.duration} seconds")
                assert (1.2 < t.duration < 1.5)
                time.sleep(2)

            if self.test_case_no == 19751:
                """ set timeout of scan timeout for 500 Mi-sc """
                self.wifi_dut.interfaces.wifi.set_timeout(feature=2, timeout=500,
                                                                expected_status=SLStatus.SL_STATUS_OK, thread=True)
                with TimeMeasurer() as t:
                    logger().info(f"Initiating scan")
                    scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
                logger().info(scan_results)
                assert len(scan_results) > 0
                logger().info(f"Scan in {t.duration} seconds")
                assert (1.2 < t.duration < 5.8)
                time.sleep(2)

            if self.test_case_no == 19637:
                """ set timeout of keep-alive for 10 seconds with traffic """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=150,
                                                                              scan_interval=4,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                         adv_passive_channel_time=20)
                self.wifi_dut.interfaces.wifi.set_timeout(feature=4, timeout=10)

            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)
            logger().info("DUT successfully connected with AP")

            time.sleep(2)
            if self.dut_leave:
                self.wifi_dut.interfaces.wifi.leave(thread=True)
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e

    def delta_between_arp_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff_list.append(float(time_delta_from_previous_packet))

        filter_file.close()
        return time_diff_list


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.parametrize("channel", [4])
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_wifi_sdk_request_timeout_keep_alive_10sec_c19746(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name
    time_delta = 10
    '''Verifying ARP announcement packets with configured interval of 10 Milli-Seconds'''

    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                 test_case_no="19746")
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                        radio_ch={wifi_access_point.interfaces.wifi.channel}, filter_name="arp_power_mgmt_bit")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find ARP Announcement packets & Unable to find ARP Announcement packets with-in assigned time'
        """=============================Validation of time delta between keep-alive packets=========================="""
        arp_packets_time_delta_list = wlan_obj.delta_between_arp_packet()
        arp_packets_time_delta_list.pop(0)
        arp_packets_time_delta_list.pop(0)
        logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
        for time_diff in arp_packets_time_delta_list:
            logger().info(int(time_diff))
            is_between = int(time_diff) in range(0, time_delta + 2)
            if is_between is False:
                logger().info(is_between)
                status = is_between
                break
            else:
                logger().info(is_between)
                status = is_between
        assert status
        time.sleep(1)
    except Exception as e:
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.parametrize("channel", [4])
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_wifi_sdk_request_timeout_keep_alive_30sec_c19750(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        time_delta = 30
        '''Verifying ARP announcement packets with configured interval of 30 Milli-Seconds'''

        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        test_case_no="19750")
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                        radio_ch={wifi_access_point.interfaces.wifi.channel}, filter_name="arp_power_mgmt_bit")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(
            'Address Resolution Protocol (ARP Announcement)')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find ARP Announcement packets & able to find ARP Announcement packets with-in assigned time'
        """=============================Validation of time delta between keep-alive packets=========================="""
        arp_packets_time_delta_list = wlan_obj.delta_between_arp_packet()
        arp_packets_time_delta_list.pop(0)
        arp_packets_time_delta_list.pop(0)
        logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
        for time_diff in arp_packets_time_delta_list:
            logger().info(int(time_diff))
            is_between = int(time_diff) in range(0, time_delta + 2)
            if is_between is False:
                logger().info(is_between)
                status = is_between
                break
            else:
                logger().info(is_between)
                status = is_between
        assert status
        time.sleep(1)
    except Exception as e:
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_request_timeout_scan_100misec_c19748(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        '''Verifying the scan results with-in the configure time interval of 100 Milli-Seconds '''
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        test_case_no="19748")
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.interfaces.wifi.channel, filter_name='probe_request')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Probe Request packets'
    except Exception as e:
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_request_timeout_scan_500misec_c19751(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        '''Verifying the scan results with-in the configure time interval of 500 Milli-Seconds '''
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        test_case_no="19751")
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.interfaces.wifi.channel, filter_name='probe_request')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Probe Request packets'
    except Exception as e:
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.parametrize("channel", [4])
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_wifi_sdk_keep_alive_10sec_with_traffic_c19637(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        time_delta = 10
        '''Verifying ARP announcement packets with configured interval of 10 Milli-Seconds with idle of 50 seconds'''
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        test_case_no="19637", dut_leave=False)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(50)
        wifi_dut.interfaces.wifi.leave(thread=True)
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                        radio_ch={wifi_access_point.interfaces.wifi.channel}, filter_name="arp_power_mgmt_bit")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find ARP Announcement packets & Unable to find ARP Announcement packets with-in assigned time'
        """=============================Validation of time delta between keep-alive packets=========================="""
        arp_packets_time_delta_list = wlan_obj.delta_between_arp_packet()
        logger().info(f'APR packet time delta list before removing 0 = {arp_packets_time_delta_list}')
        arp_packets_time_delta_list.pop(0)
        arp_packets_time_delta_list.pop(0)
        logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
        for time_diff in arp_packets_time_delta_list:
            logger().info(int(time_diff))
            is_between = int(time_diff) in range(0, time_delta + 2)
            if is_between is False:
                logger().info(is_between)
                status = is_between
                break
            else:
                logger().info(is_between)
                status = is_between
        assert status, "packets are not received in expected time"
        time.sleep(1)
    except Exception as e:
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"