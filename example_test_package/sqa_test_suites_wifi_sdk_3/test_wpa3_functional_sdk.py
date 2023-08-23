import re
import time
from retry import retry
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf import UtfDatabaseProperties
from utf.utils.logger import get_logger
from utf_wiseconnect3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xAsyncEventType, \
    Si91xCustomFeatureBitMap, Si91xPowerSaveModes, Si91xDataRate, Si91xRejoinParams, Si91xExtCustomFeatureBitMap, \
    Si91xBTFeatureBitMap
from utf_wiseconnect3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, Si91xCustomFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect.utils.sl_collections import SLCollections


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9117
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BT
        6. Stop the sniffer  
        7. Analyizing all sniffer capture packets for wpa3 functionality
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
        self.device_ip = None
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.dut_leave = dut_leave
        self.test_name = test_name


    def run(self):
        try:
            if self.test_case_no == 34503:
                """ scanning for wpa3 configured Access Point """
                scan_dict = [{"ssid": None, "channel": 0},
                             {"ssid": None, "channel": self.wifi_access_point.interfaces.wifi.channel},
                             {"ssid": self.wifi_access_point.interfaces.wifi.ssid,
                              "channel": self.wifi_access_point.interfaces.wifi.channel}]

                for i in range(len(scan_dict)):
                    assert self.wifi_dut.interfaces.wifi.scan(ssid=scan_dict[i]['ssid'], channel=scan_dict[i]['channel'])
                    time.sleep(3)
            if self.test_case_no == 34509:
                """ Enabling the rejion feature """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)
            if self.test_case_no == 34511:
                """ Enabling the BG-Scan feature """
                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                              adv_passive_channel_time=20)
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.scan(bgscan=False, bg_scan_periodicity=10)

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

    @retry(Exception, delay=15, tries=3)
    def ping_to_dut(device_ip, ping_count=10):
        status = ping(device_ip, ping_count)
        assert status, "Failed to ping to DUT"
        return status


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.ULPGPIOHandshake,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_wifi_sdk_scan_wpa3_c34503_04_05_07(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        '''Verifying scan for wpa3 configured access point'''

        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                     test_case_no="34503")

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="wpa3_confirm_commit_message")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="wpa3_4_way_handshake_message")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter3=packet_filter3)['packet_count'], \
            'Unable to find the commit & confirm packets.'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.ULPGPIOHandshake,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_wifi_sdk_conn_deconn_reconn_wpa3_C34508(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_name = request.node.name
        '''Verifying connection, disconnection and reconnection with WPA3 configured Access Point'''

        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections)
        for i in range(0, iter_count):
            wlan_obj.start()
            wlan_obj.wait_for_exit()

            packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                                                                                filter_name="wpa3_confirm_commit_message")
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

            packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                                                                                filter_name="wpa3_4_way_handshake_message")
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")

            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop Sniffer finally")
            time.sleep(2)
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter3=packet_filter3)['packet_count'], \
                'Unable to find the commit & confirm packets.'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.ULPGPIOHandshake,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_wifi_sdk_bgscan_specific_chal_wpa3_C34511(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
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
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.ULPGPIOHandshake,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.IEEE802_11W,

    }
)
def test_wifi_sdk_rejoin_with_wpa3_security_c34509(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                         sniffer_filter, switch, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        ''' Verify Rejoin Functionality in WPA3 Security'''
        state = switch.interfaces.pdu_switch.get_state()
        logger().info("pdu switch state : " + str(state))
        if state == 'true':
            logger().info('PDU is ready for use')
        else:
            logger().info(f'\n\n Please check the AP & PDU current state')
            assert False
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
        # device_ip = wifi_dut.interfaces.wifi.get_device_ip(wlan_obj.)
        time.sleep(2)
        if state == 'true':
            logger().info('#### Turn off the Access Point')
            switch.interfaces.pdu_switch.turn_off()
        time.sleep(30)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info('##### Turn on Access point #####')
        state = switch.interfaces.pdu_switch.get_state()
        logger().info(f"checking status: {state}")
        if state == 'false':
            switch.interfaces.pdu_switch.turn_on()
            logger().info(
                f"PDU was off, trying to turn on using PDU, Please wait for 60 seconds to check DUT is rejoined to that AP or not ........")
            time.sleep(60)
        if wifi_dut.interfaces.wifi.associated is True:
            logger().info(f"Initiating ping to DUT ip {wlan_obj.device_ip['device_ip']} after successful rejoin")
        status = wlan_obj.ping_to_dut(wlan_obj.device_ip['device_ip'], ping_count)
        assert status, "DUT not responding for ping request......"
        if status == 1:
            logger().info('#### Ping successful ####')
        else:
            logger().info('#### Ping unsuccessful ####')
        logger().info("ping to DUT is successful....")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Probe Request packets'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"
    finally:
        if state == 'false':
            switch.interfaces.pdu_switch.turn_on()
            logger().info(
                f"PDU was off, trying to turn on using PDU, Please wait for 60 seconds ........")
            time.sleep(60)
