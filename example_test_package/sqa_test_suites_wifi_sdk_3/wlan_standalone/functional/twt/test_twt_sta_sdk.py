import pytest
import time
import re

from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xTWTRescheduleParams
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers

"""
    Setup requirement:
        1. Soc board
        2. Raspberry PI4
        3. Access Point with TWT Support(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Validate TWT configurations

    Author: Ayush Agarwal

"""


# Define logger
def logger():
    return get_logger(__name__)


class WLanTwTThread(ThreadBase):
    def __init__(self, twt_enable=1, twt_flow_id=1, wake_duration=0x60, wake_duration_unit=0, wake_duration_tol=0x60,
                 wake_int_exp=13, wake_int_exp_tol=13, wake_int_mantissa=0x1D4C, wake_int_mantissa_tol=0x1D4C,
                 implicit_twt=1, un_announced_twt=1, triggered_twt=0, twt_channel=0, twt_protection=0,
                 restrict_tx_outside_tsp=1, twt_retry_limit=6, twt_retry_interval=10, req_type=1, negotiation_type=0,
                 wifi_dut=None, sl_collections=None, wifi_sniffer=None, wifi_access_point=None, switch=None,
                 test_case=None, sniffer_filter=None, power_save=False, before_join=False, utf_constants=None,
                 sniffer_capture=None, wifi_client=None, net_perf_client=None):
        super().__init__()
        # Define all the parameters
        self.twt_enable = twt_enable
        self.twt_flow_id = twt_flow_id
        self.wake_duration = wake_duration
        self.wake_duration_unit = wake_duration_unit
        self.wake_duration_tol = wake_duration_tol
        self.wake_int_exp = wake_int_exp
        self.wake_int_exp_tol = wake_int_exp_tol
        self.wake_int_mantissa = wake_int_mantissa
        self.wake_int_mantissa_tol = wake_int_mantissa_tol
        self.implicit_twt = implicit_twt
        self.un_announced_twt = un_announced_twt
        self.triggered_twt = triggered_twt
        self.twt_channel = twt_channel
        self.twt_protection = twt_protection
        self.restrict_tx_outside_tsp = restrict_tx_outside_tsp
        self.twt_retry_limit = twt_retry_limit
        self.twt_retry_interval = twt_retry_interval
        self.req_type = req_type
        self.negotiation_type = negotiation_type
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.wake_duration_time = 0
        self.power_save = power_save
        self.mantissa_req = None
        self.wake_interval_exponent_req = None
        self.minimum_wake_duration_req = None

        self.wake_interval_req = None
        self.wake_period_req = None
        self.target_wake_time = None

        self.mantissa_resp = None
        self.wake_interval_exponent_resp = None
        self.minimum_wake_duration_resp = None

        self.wake_interval_resp = None
        self.wake_period_resp = None

        self.sniffer_filter = sniffer_filter
        self.sniffer_capture = sniffer_capture
        self.switch = switch
        self.dut_addr = None
        self.ap_mac_address = None
        self.before_join = before_join
        self.utf_constants = utf_constants
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.time_duration = utf_constants.get("time_duration")
        self.wait_for_response_time = 60
        self.indicate_twt_success_response = False

        # Create packet filters variables
        self.packet_filter1 = None
        self.packet_filter2 = None
        self.packet_filter3 = None
        self.packet_filter4 = None
        self.power_save_filter = None
        self.second_level_filter = '        Tag: Target Wake Time'

    def run(self):
        try:
            # Check test case 113733 or 113735 and set advanced client configuration
            if self.test_case == '113733' or self.test_case == '113735' or self.test_case == '113754':
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                              beacon_missed_count=1000,
                                                                              first_time_retry_enable=0)
            if self.test_case == '113760' or self.test_case == '113761':
                self.time_duration = self.utf_constants.get("long_duration")
            # Configure the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.configure_interface(self.wifi_access_point.interfaces.wifi.channel)
            # Start the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.start_capture(self.sniffer_capture)
            # Get the mac address of the wifi_access_point
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid

            time_obj = Stopwatch()
            # Check Test Case 113764 and enable BG scan
            if self.test_case == '113764':
                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                              adv_passive_channel_time=20)

            if self.before_join:
                # Call set_twt API
                self.wifi_dut.interfaces.wifi.set_twt(twt_enable=self.twt_enable,
                                                      twt_flow_id=self.twt_flow_id,
                                                      wake_duration=self.wake_duration,
                                                      wake_duration_unit=self.wake_duration_unit,
                                                      wake_duration_tol=self.wake_duration_tol,
                                                      wake_int_exp=self.wake_int_exp,
                                                      wake_int_exp_tol=self.wake_int_exp_tol,
                                                      wake_int_mantissa=self.wake_int_mantissa,
                                                      wake_int_mantissa_tol=self.wake_int_mantissa_tol,
                                                      implicit_twt=self.implicit_twt,
                                                      un_announced_twt=self.un_announced_twt,
                                                      triggered_twt=self.triggered_twt,
                                                      twt_channel=self.twt_channel,
                                                      twt_protection=self.twt_protection,
                                                      restrict_tx_outside_tsp=self.restrict_tx_outside_tsp,
                                                      twt_retry_limit=self.twt_retry_limit,
                                                      twt_retry_interval=self.twt_retry_interval,
                                                      req_type=self.req_type,
                                                      negotiation_type=self.negotiation_type)

            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     power_save=self.power_save,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)

            if self.test_case == '586161':
                self.wifi_dut.interfaces.wifi.set_twt(twt_enable=self.twt_enable,
                                                      twt_flow_id=self.twt_flow_id,
                                                      wake_duration=self.wake_duration,
                                                      wake_duration_unit=self.wake_duration_unit,
                                                      wake_duration_tol=self.wake_duration_tol,
                                                      wake_int_exp=self.wake_int_exp,
                                                      wake_int_exp_tol=self.wake_int_exp_tol,
                                                      wake_int_mantissa=self.wake_int_mantissa,
                                                      wake_int_mantissa_tol=self.wake_int_mantissa_tol,
                                                      implicit_twt=self.implicit_twt,
                                                      un_announced_twt=self.un_announced_twt,
                                                      triggered_twt=self.triggered_twt,
                                                      twt_channel=self.twt_channel,
                                                      twt_protection=self.twt_protection,
                                                      restrict_tx_outside_tsp=self.restrict_tx_outside_tsp,
                                                      twt_retry_limit=self.twt_retry_limit,
                                                      twt_retry_interval=self.twt_retry_interval,
                                                      req_type=self.req_type,
                                                      negotiation_type=self.negotiation_type)
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                twt_setup_success_event = [event for event in events if
                                           event.event_type == AsyncEventIdentifiers.WIFI_TWT_RESPONSE_EVENT]
                if len(twt_setup_success_event):
                    self.indicate_twt_success_response = True

                assert self.indicate_twt_success_response, f"\n....TWT Not initialized on device under {self.wait_for_response_time} seconds Duration....\n"

                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                return

            if self.before_join:
                while time_obj.elapsed_sec < self.wait_for_response_time:
                    events = self.wifi_dut.interfaces.wifi.get_async_events()
                    twt_setup_success_event = [event for event in events if
                                               event.event_type == AsyncEventIdentifiers.WIFI_TWT_RESPONSE_EVENT]
                    if len(twt_setup_success_event):
                        self.indicate_twt_success_response = True
                        break
                    self.wifi_dut.interfaces.wifi.set_twt(twt_enable=self.twt_enable,
                                                          twt_flow_id=self.twt_flow_id,
                                                          wake_duration=self.wake_duration,
                                                          wake_duration_unit=self.wake_duration_unit,
                                                          wake_duration_tol=self.wake_duration_tol,
                                                          wake_int_exp=self.wake_int_exp,
                                                          wake_int_exp_tol=self.wake_int_exp_tol,
                                                          wake_int_mantissa=self.wake_int_mantissa,
                                                          wake_int_mantissa_tol=self.wake_int_mantissa_tol,
                                                          implicit_twt=self.implicit_twt,
                                                          un_announced_twt=self.un_announced_twt,
                                                          triggered_twt=self.triggered_twt,
                                                          twt_channel=self.twt_channel,
                                                          twt_protection=self.twt_protection,
                                                          restrict_tx_outside_tsp=self.restrict_tx_outside_tsp,
                                                          twt_retry_limit=self.twt_retry_limit,
                                                          twt_retry_interval=self.twt_retry_interval,
                                                          req_type=self.req_type,
                                                          negotiation_type=self.negotiation_type)
                assert self.indicate_twt_success_response, f"\n....TWT Not initialized on device under {self.wait_for_response_time} seconds Duration....\n"

            if self.test_case == '113739':
                try:
                    self.wifi_dut.interfaces.wifi.set_twt(twt_enable=self.twt_enable,
                                                          twt_flow_id=self.twt_flow_id,
                                                          wake_duration=0x50,
                                                          wake_duration_unit=self.wake_duration_unit,
                                                          wake_duration_tol=0x60,
                                                          wake_int_exp=13,
                                                          wake_int_exp_tol=13,
                                                          wake_int_mantissa=0x1D4C,
                                                          wake_int_mantissa_tol=0x1D4C,
                                                          implicit_twt=1,
                                                          un_announced_twt=1,
                                                          triggered_twt=0,
                                                          twt_channel=0,
                                                          twt_protection=0,
                                                          restrict_tx_outside_tsp=1,
                                                          twt_retry_limit=10,
                                                          twt_retry_interval=10,
                                                          req_type=2,
                                                          negotiation_type=0)
                    logger().info("***** TWT is failed for first time trying for second time *****")

                except Exception as e:
                    while time_obj.elapsed_sec < self.wait_for_response_time:
                        self.wifi_dut.interfaces.wifi.set_twt(twt_enable=self.twt_enable,
                                                              twt_flow_id=self.twt_flow_id,
                                                              wake_duration=0x80,
                                                              wake_duration_unit=self.wake_duration_unit,
                                                              wake_duration_tol=0x80,
                                                              wake_int_exp=self.wake_int_exp,
                                                              wake_int_exp_tol=self.wake_int_exp_tol,
                                                              wake_int_mantissa=0x3D4C,
                                                              wake_int_mantissa_tol=0x3D4C,
                                                              implicit_twt=1,
                                                              un_announced_twt=1,
                                                              triggered_twt=0,
                                                              twt_channel=0,
                                                              twt_protection=0,
                                                              restrict_tx_outside_tsp=1,
                                                              twt_retry_limit=10,
                                                              twt_retry_interval=10,
                                                              req_type=0,
                                                              negotiation_type=0)
                        events = self.wifi_dut.interfaces.wifi.get_async_events()
                        twt_setup_success_event = [event for event in events if
                                                   event.event_type == AsyncEventIdentifiers.WIFI_TWT_RESPONSE_EVENT]
                        if len(twt_setup_success_event):
                            logger().info("***** TWT is set successfully for second time *****")
                            self.indicate_twt_success_response = True
                            break
                    assert self.indicate_twt_success_response, f"\n....TWT Not initialized on device under {self.wait_for_response_time} seconds Duration....\n"

            # Check test case 113733 and turn off the switch
            if self.test_case == '113733' or self.test_case == '113735' or self.test_case == '113754':
                self.switch.interfaces.pdu_switch.turn_off()
                if self.test_case != '113754':
                    self.wifi_dut.interfaces.wifi.set_twt(twt_enable=self.twt_enable,
                                                          twt_flow_id=self.twt_flow_id,
                                                          wake_duration=self.wake_duration,
                                                          wake_duration_unit=self.wake_duration_unit,
                                                          wake_duration_tol=self.wake_duration_tol,
                                                          wake_int_exp=self.wake_int_exp,
                                                          wake_int_exp_tol=self.wake_int_exp_tol,
                                                          wake_int_mantissa=self.wake_int_mantissa,
                                                          wake_int_mantissa_tol=self.wake_int_mantissa_tol,
                                                          implicit_twt=self.implicit_twt,
                                                          un_announced_twt=self.un_announced_twt,
                                                          triggered_twt=self.triggered_twt,
                                                          twt_channel=self.twt_channel,
                                                          twt_protection=self.twt_protection,
                                                          restrict_tx_outside_tsp=self.restrict_tx_outside_tsp,
                                                          twt_retry_limit=self.twt_retry_limit,
                                                          twt_retry_interval=self.twt_retry_interval,
                                                          req_type=self.req_type,
                                                          negotiation_type=self.negotiation_type)
                time.sleep(110)
                retry_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                    filter_name="twt_request_packets")
                logger().info(f'***** twt_request_packets = {retry_filter}')
                if self.test_case == '113733':
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    assert int(self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=retry_filter)[
                                   'find_packet_num']) == self.twt_retry_limit, "Unable to find TWT request packets"
                    logger().info('\n\n**** Retry packets verified successfully ****\n\n')
                    return
                if self.test_case == '113735':
                    self.switch.interfaces.pdu_switch.turn_on(delay=60)
                    self.wifi_sniffer.interfaces.capture.stop_capture()
                    self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=retry_filter,
                                                                            packet_filter2=self.second_level_filter)
                    self.validate_retry_interval()
                    logger().info('\n\n**** Retry interval verified successfully ****\n\n')
                    return
                if self.test_case == '113754':
                    self.switch.interfaces.pdu_switch.turn_on(delay=60)

            # Check the test 540489 and call the disable TWT API
            if self.test_case == '540489':
                self.wifi_dut.interfaces.wifi.disable_twt(expected_status=SLStatus.SL_STATUS_SI91X_EAPOL_TIMEOUT)
                logger().info("***** Getting 0x10073 Error, which is expected *****")
                return

            if self.test_case == '540488':
                self.wifi_dut.interfaces.wifi.set_twt(twt_enable=self.twt_enable,
                                                      twt_flow_id=self.twt_flow_id,
                                                      wake_duration=self.wake_duration,
                                                      wake_duration_unit=self.wake_duration_unit,
                                                      wake_duration_tol=self.wake_duration_tol,
                                                      wake_int_exp=self.wake_int_exp,
                                                      wake_int_exp_tol=self.wake_int_exp_tol,
                                                      wake_int_mantissa=self.wake_int_mantissa,
                                                      wake_int_mantissa_tol=self.wake_int_mantissa_tol,
                                                      implicit_twt=self.implicit_twt,
                                                      un_announced_twt=self.un_announced_twt,
                                                      triggered_twt=self.triggered_twt,
                                                      twt_channel=self.twt_channel,
                                                      twt_protection=self.twt_protection,
                                                      restrict_tx_outside_tsp=self.restrict_tx_outside_tsp,
                                                      twt_retry_limit=self.twt_retry_limit,
                                                      twt_retry_interval=self.twt_retry_interval,
                                                      req_type=self.req_type,
                                                      negotiation_type=self.negotiation_type)
                self.wifi_dut.interfaces.wifi.disable_twt(twt_flow_id=0,
                                                          expected_status=SLStatus.SL_STATUS_TWT_TEARDOWN_ERR_FLOWID_NOT_MATCHED)
                logger().info('***** Getting expected error code which is 0x10072 *****')
                return

            if not self.before_join and self.test_case != '113739':
                # Call set_twt API
                while time_obj.elapsed_sec < self.wait_for_response_time:
                    self.wifi_dut.interfaces.wifi.set_twt(twt_enable=self.twt_enable,
                                                          twt_flow_id=self.twt_flow_id,
                                                          wake_duration=self.wake_duration,
                                                          wake_duration_unit=self.wake_duration_unit,
                                                          wake_duration_tol=self.wake_duration_tol,
                                                          wake_int_exp=self.wake_int_exp,
                                                          wake_int_exp_tol=self.wake_int_exp_tol,
                                                          wake_int_mantissa=self.wake_int_mantissa,
                                                          wake_int_mantissa_tol=self.wake_int_mantissa_tol,
                                                          implicit_twt=self.implicit_twt,
                                                          un_announced_twt=self.un_announced_twt,
                                                          triggered_twt=self.triggered_twt,
                                                          twt_channel=self.twt_channel,
                                                          twt_protection=self.twt_protection,
                                                          restrict_tx_outside_tsp=self.restrict_tx_outside_tsp,
                                                          twt_retry_limit=self.twt_retry_limit,
                                                          twt_retry_interval=self.twt_retry_interval,
                                                          req_type=self.req_type,
                                                          negotiation_type=self.negotiation_type)
                    events = self.wifi_dut.interfaces.wifi.get_async_events()
                    twt_setup_success_event = [event for event in events if
                                               event.event_type == AsyncEventIdentifiers.WIFI_TWT_RESPONSE_EVENT]
                    if len(twt_setup_success_event):
                        self.indicate_twt_success_response = True
                        break
                assert self.indicate_twt_success_response, f"\n....TWT Not initialized on device under {self.wait_for_response_time} seconds Duration....\n"

            # Call set_twt API by checking test case
            if self.test_case == '113738':
                self.wifi_dut.interfaces.wifi.set_twt(
                    expected_status=SLStatus.SL_STATUS_TWT_SETUP_ERR_SESSION_ACTIVE)
                logger().info("***** TWT session is active, so unable to set TWT again")
                logger().info("**** Getting 0x10071 error code which is expected ****")
                return

            # Set wake_duration_time
            if self.wake_duration_unit == 0:
                self.wake_duration_time = 256
            if self.wake_duration_unit == 1:
                self.wake_duration_time = 1024

            # Get sniffer filter for twt request frame
            self.packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                filter_name="twt_requesting_sta_1")
            # Get sniffer filter for twt response frame
            self.packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                da_addr=self.dut_addr['dut_mac_address'], sa_addr=self.ap_mac_address,
                filter_name="twt_responding_sta_0")

            # Log the packet filters
            logger().info(f'***** twt_requesting_sta_1 = {self.packet_filter1}')
            logger().info(f'***** twt_responding_sta_0 = {self.packet_filter2}')

            # Get sniffer filter for twt assoc request frame
            self.packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                filter_name="twt_assoc_request_frame")

            # Log the packet filter
            logger().info(f'***** twt_assoc_request_frame = {self.packet_filter3}')

            # Do sniffer validation for packet_filter1 with second_level_filter
            self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter1,
                                                                    packet_filter2=self.second_level_filter)

            # Call get_twt_params API for request frames
            self.get_twt_params(filter=1)

            # Call wake_interval_and_wake_period for response frames
            self.wake_interval_and_wake_period(filter=1)

            # Do sniffer validation for packet_filter2 with second_level_filter
            self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter2,
                                                                    packet_filter2=self.second_level_filter)

            # Call get_twt_params API for response frames
            self.get_twt_params(filter=0)

            # Call wake_interval_and_wake_period for request frames
            self.wake_interval_and_wake_period(filter=0)

            if self.test_case != '113760' and self.test_case != '113761':
                # Sleep for 10 minutes
                logger().info(f'**** Pinging for {self.time_duration} seconds ****')

                start_time = time.time()
                while (time.time() - start_time) < self.time_duration:
                    self.sl_collections.ping_with_custom_interval(device_ip=self.dut_addr['device_ip'],
                                                                  interval=int(self.wake_interval_resp) // 10000000)
            if self.test_case == '113760':
                self.tcp_single_socket_dut_client()
            if self.test_case == '113761':
                logger().info(f'Setting DUT IDLE for {self.time_duration / 3600} hours')
                time.sleep(self.time_duration)

            # Stop the sniffer
            self.wifi_sniffer.interfaces.capture.stop_capture()

            # Do power save validation after checking power_save variable
            if self.power_save:
                self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.power_save_filter)[
                           'packet_count'], "Unable to find NULL-Data frame packets with power save bit = 1"

            # assert some packets are captured
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter3)[
                'packet_count'], f"DUT is not able to send TWT association request frame to AP"

            # Check test case 113725 and return
            if self.test_case == '113725':
                return

            self.wifi_sniffer.interfaces.capture.collecting_frame_number(
                packet_filter1=f'wlan.fixed.timestamp >= {int(self.target_wake_time)}')

            filter_file = open(f'./reports/filter2_file.txt', 'r')
            first_line = filter_file.readline().replace('\n', '')

            logger().info(f"\n\n***** Packets before TWT hits = {first_line}\n\n")

            self.packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                frame_number=first_line, dut_addr=self.dut_addr['dut_mac_address'],
                filter_name='twt_data_transfer_packets')
            self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter4,
                                                                    packet_filter2='        Timestamp:')
            self.verify_twt_wake_interval()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def get_twt_params(self, filter):
        # Read the filter file
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        content = filter_file.read()
        if filter == 1:
            self.mantissa_req = int(re.findall(r'((?<=Mantissa:\s)\d+)', content)[0])
            self.minimum_wake_duration_req = int(re.findall(r'((?<=Minimum TWT Wake duration:\s)\d+)', content)[0])
            self.wake_interval_exponent_req = int(re.findall(r'((?<=Wake Interval Exponent:\s)\d+)', content)[0])
            logger().info(f'***** Mantissa Req = {self.mantissa_req}')
            logger().info(f'***** Wake Interval Exponent Req = {self.wake_interval_exponent_req}')
            logger().info(f'***** Minimum Wake Duration Req = {self.minimum_wake_duration_req}')
            target_wake_time = int(re.findall(r'((?<=Target Wake Time:\s)\d+)', content)[0])
            logger().info(f"***** Target Wake Time Req = {target_wake_time}")
        if filter == 0:
            self.mantissa_resp = int(re.findall(r'((?<=Mantissa:\s)\d+)', content)[0])
            self.minimum_wake_duration_resp = int(re.findall(r'((?<=Minimum TWT Wake duration:\s)\d+)', content)[0])
            self.wake_interval_exponent_resp = int(re.findall(r'((?<=Wake Interval Exponent:\s)\d+)', content)[0])
            logger().info(f'***** Mantissa Resp = {self.mantissa_resp}')
            logger().info(f'***** Wake Interval Exponent Resp = {self.wake_interval_exponent_resp}')
            logger().info(f'***** Minimum Wake Duration Resp = {self.minimum_wake_duration_resp}')
            self.target_wake_time = int(re.findall(r'((?<=Target Wake Time:\s)\d+)', content)[0])
            logger().info(f"***** Target Wake Time Resp = {self.target_wake_time}")

    def wake_interval_and_wake_period(self, filter):
        # Wake interval : TWT Wake Interval Mantissa *2^Wake Interval Exponent
        # Wake Period : Minimum TWT Wake Duration * Wake Duration Time
        if filter == 1:
            self.wake_interval_req = self.mantissa_req * (2 ** int(self.wake_interval_exponent_req))
            self.wake_period_req = self.minimum_wake_duration_req * self.wake_duration_time
            logger().info(f'***** Wake Interval Req= {self.wake_interval_req}')
            logger().info(f'***** Wake Period Req = {self.wake_period_req}')

        if filter == 0:
            self.wake_interval_resp = self.mantissa_resp * (2 ** int(self.wake_interval_exponent_resp))
            self.wake_period_resp = self.minimum_wake_duration_resp * self.wake_duration_time
            logger().info(f'***** Wake Interval Resp= {self.wake_interval_resp}')
            logger().info(f'***** Wake Period Resp = {self.wake_period_resp}')

    def validate_retry_interval(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        lines = filter_file.read()
        time_delta = re.findall(r'((?<=Time delta from previous captured frame:\s)\d+)', lines)
        logger().info(f"Time delta between retry packets = {time_delta}")
        for i in range(self.twt_retry_limit):
            if i == 0 or i == 1:
                continue
            assert abs(int(time_delta[i]) - int(time_delta[i - 1])) in range(0, 2), "Retry interval is not 10 seconds"

    def verify_twt_wake_interval(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        lines = filter_file.read()
        time_delta = re.findall(r'((?<=Epoch Time:\s)\d+\.\d+)', lines)
        if not time_delta:
            time_delta = re.findall(r'((?<=Epoch Arrival Time:\s)\d+\.\d+)', lines)
        time_ref = float(time_delta[0])
        actual_validation = True
        lower_threshold = 9 * self.wake_interval_resp / 10000000
        upper_threshold = 11 * self.wake_interval_resp / 10000000

        for i in range(1, len(time_delta)):
            time_delta[i] = float(time_delta[i])
            if actual_validation and time_delta[i] - time_ref < 0.005:
                continue
            if lower_threshold < float(time_delta[i]) - float(time_ref) < upper_threshold:
                time_ref = time_delta[i]
                actual_validation = False
                continue
            if lower_threshold > float(time_delta[i]) - float(
                    time_ref) > 1.01 * self.wake_period_resp:
                assert False, f"Expected Wake Interval = {self.wake_interval_resp}, but got beyond the threshold of 10%"

            assert time_delta[i] - time_ref < 1.01 * self.wake_period_resp, \
                f"Expected Wake Period = {self.wake_period_resp}, but got beyond the threshold of 1%"

        logger().info(f"***** Wake Interval and wake Period is verified successfully *****")

    def tcp_single_socket_dut_client(self):

        # protocol = 6
        traffic = '0x00'
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=self.dut_addr['device_ip'],
                                                             protocol=IperfConstants.TCP, tos_value=traffic)
        # logger().info(f"Host IP: {host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {protocol}, "
        #               f"tos_value: {traffic}")
        logger().info(f"***** starting iperf ******")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port, size=1460,
                                            ttl=self.time_duration, throughput_type=1, qos=0, timeout=self.time_duration+100)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "bt_features": 0,
            "ble_features": 0,
            "ble_custom_ext_features": 0,
        }
    ),
    pytest.mark.firmware_app("test_twt_sta")
]


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113725')
def test_wifi_sdk_verify_twt_in_assoc_req_c113725(firmware_loader, wifi_dut, wifi_access_point, sl_collections, wifi_sniffer,
                                                  sniffer_filter, utf_constants):
    """Verify whether DUT is able to send TWT requester capability in Assoc req packet when TWT support is enabled"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113725',
                                 before_join=True, utf_constants=utf_constants, sniffer_capture='113725')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip('Not Applicable')
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113726')
def test_wifi_sdk_verify_twt_functionality_when_enabled_through_join_c113726(firmware_loader, wifi_dut, wifi_access_point,
                                                                             sl_collections, wifi_sniffer,
                                                                             sniffer_filter, utf_constants):
    """Verify whether DUT is able to send Association request with TWT element when TWT support is enabled"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113726',
                                 before_join=True, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113727')
def test_wifi_sdk_verify_twt_request_when_enabled_before_join_c113727(firmware_loader, wifi_dut, wifi_access_point, sl_collections,
                                                                      wifi_sniffer, sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with request support after association(key exchange) when we call
    TWT config api before join and also verify the DUT behavior whether it is able to wakeup and receive data based on
    the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113727', req_type=0, before_join=True, utf_constants=utf_constants,
                                 sniffer_capture='113727')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113728')
def test_wifi_sdk_verify_twt_suggest_when_enabled_before_join_c113728(firmware_loader, wifi_dut, wifi_access_point, sl_collections,
                                                                      wifi_sniffer, sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with suggest support after association(key exchange) when we call
     TWT config api before join and also verify the DUT behavior whether it is able to wakeup and receive data based on
     the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113728', req_type=1, before_join=True, utf_constants=utf_constants,
                                 sniffer_capture='113728')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113729')
def test_wifi_sdk_verify_twt_demand_when_enabled_before_join_c113729(firmware_loader, wifi_dut, wifi_access_point,
                                                                     sl_collections, wifi_sniffer,
                                                                     sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with demand support after association(key exchange) when we call
    TWT config api before join and also verify the DUT behavior whether it is able to wakeup and receive data based on
    the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113729', before_join=True, wake_int_mantissa=0x0E4C,
                                 wake_int_mantissa_tol=0x0E4C, un_announced_twt=0, req_type=2,
                                 utf_constants=utf_constants, sniffer_capture='113729')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", 'disable_twt'])
@pytest.mark.test_src_map_id('C113730')
def test_wifi_sdk_verify_twt_request_when_enabled_after_join_c113730(firmware_loader, wifi_dut, wifi_access_point,
                                                                     sl_collections, wifi_sniffer,
                                                                     sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with request support when we call  TWT config api after join and
    also verify the DUT behavior whether it is able to wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113730',
                                 power_save=True, test_case='113730', wake_duration=0x80, wake_duration_tol=0x80,
                                 wake_int_exp=13, wake_int_exp_tol=13, wake_int_mantissa=0x1E4C,
                                 wake_int_mantissa_tol=0x1E4C, un_announced_twt=0, req_type=0,
                                 utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", 'disable_twt'])
@pytest.mark.test_src_map_id('C113731')
def test_wifi_sdk_verify_twt_suggest_when_enabled_after_join_c113731(firmware_loader, wifi_dut, wifi_access_point,
                                                                     sl_collections, wifi_sniffer,
                                                                     sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with suggest support when we call TWT config api after join and
    also verify the DUT behavior whether it is able to wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113731',
                                 power_save=True, test_case='113731', wake_duration=0x20, wake_duration_tol=0x20,
                                 wake_int_exp=10, wake_int_exp_tol=15, wake_int_mantissa=0x104C,
                                 wake_int_mantissa_tol=0x104C, un_announced_twt=0, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113732')
def test_wifi_sdk_verify_twt_demand_when_enabled_after_join_c113732(firmware_loader, wifi_dut, wifi_access_point,
                                                                    sl_collections, wifi_sniffer,
                                                                    sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with demand support  when we call TWT config api after join and
    also verify the DUT behavior whether it is able to wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, req_type=2,
                                 power_save=True, test_case='113732', utf_constants=utf_constants,
                                 sniffer_capture='113732')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113733')
def test_wifi_sdk_verify_default_retry_attempts_for_twt_c113733(firmware_loader, wifi_dut, wifi_access_point, sl_collections,
                                                                wifi_sniffer, sniffer_filter, switch, utf_constants):
    """Verify DUT is able to retry the TWT req frame for default number of TWT setup retry limit if AP doesn't give TWT
    response"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sniffer_capture='113733',
                                 sl_collections=sl_collections, test_case='113733', wifi_sniffer=wifi_sniffer,
                                 sniffer_filter=sniffer_filter, switch=switch, power_save=True,
                                 utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113734')
def test_wifi_sdk_verify_configured_retry_attempts_for_twt_c113734(firmware_loader, wifi_dut, wifi_access_point, sl_collections,
                                                                   wifi_sniffer, sniffer_filter, switch, utf_constants):
    """Verify DUT is able to retry the TWT req frame for configured number of TWT setup retry limit if AP doesn't give
    TWT response"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 sl_collections=sl_collections, test_case='113733', sniffer_capture='113734',
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, switch=switch,
                                 power_save=True, twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113735')
def test_wifi_sdk_verify_default_retry_interval_for_twt_c113735(firmware_loader, wifi_dut, wifi_access_point, sl_collections,
                                                                wifi_sniffer, sniffer_filter, switch, utf_constants):
    """Verify the delay between each retry TWT request frame when we configured the Retry Periodicity"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 sl_collections=sl_collections, test_case='113735', sniffer_capture='113735',
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, switch=switch,
                                 power_save=True, twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113736')
def test_wifi_sdk_verify_whether_dut_accepts_rejects_alternate_twt_setup_c113736(firmware_loader, wifi_dut, wifi_access_point,
                                                                                 sl_collections, wifi_sniffer,
                                                                                 sniffer_filter, utf_constants):
    """Verify whether DUT is able to accept or reject the alternate TWT setup request when TWT session is active"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113736', wake_duration=0x50, wake_duration_tol=0x50,
                                 utf_constants=utf_constants, sniffer_capture='113736')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113738')
def test_wifi_sdk_verify_whether_dut_able_to_teardown_with_second_twt_enablement_c113738(firmware_loader, wifi_dut, wifi_access_point,
                                                                                         sl_collections, wifi_sniffer,
                                                                                         sniffer_filter, utf_constants):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113738',
                                 power_save=True, test_case='113738', utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113739')
def test_wifi_sdk_verify_whether_dut_able_to_setup_second_time_when_first_twt_fails_c113739(firmware_loader, wifi_dut, wifi_access_point,
                                                                                            sl_collections,
                                                                                            wifi_sniffer,
                                                                                            sniffer_filter,
                                                                                            utf_constants):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113739',
                                 power_save=True, test_case='113739', wake_duration=0x50, wake_duration_tol=0x60,
                                 twt_retry_limit=10, req_type=2, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113742')
def test_wifi_sdk_verify_whether_dut_able_to_setup_implicit_twt_c113742(firmware_loader, wifi_dut, wifi_access_point,
                                                                        sl_collections, wifi_sniffer,
                                                                        sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with implicit TWT and check the DUT behavior whether it is able to
    wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113742',
                                 power_save=True, test_case='113742', implicit_twt=1, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113743')
def test_wifi_sdk_verify_whether_dut_able_to_send_implicit_twt_after_sending_explicit_twt_c113743(firmware_loader, wifi_dut,
                                                                                                  wifi_access_point,
                                                                                                  sl_collections,
                                                                                                  wifi_sniffer,
                                                                                                  sniffer_filter,
                                                                                                  utf_constants):
    """Verify whether DUT is  sending TWT req with implicit mode only even if we configure explicit TWT from
    parameters"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113743',
                                 power_save=True, test_case='113743', implicit_twt=0, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113744')
def test_wifi_sdk_verify_whether_dut_able_to_setup_unannounced_twt_c113744(firmware_loader, wifi_dut, wifi_access_point,
                                                                           sl_collections, wifi_sniffer,
                                                                           sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with announced TWT and check the DUT behavior whether it is able
    to wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113744',
                                 power_save=True, test_case='113744', twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113745')
def test_wifi_sdk_verify_whether_dut_able_to_setup_announced_twt_c113745(firmware_loader, wifi_dut, wifi_access_point,
                                                                         sl_collections, wifi_sniffer,
                                                                         sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with unannounced TWT and check the DUT behavior whether it is able
    to wakeup and receive data based on the TWT agreement """
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113745',
                                 power_save=True, test_case='113736', twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113746')
def test_wifi_sdk_verify_whether_dut_able_to_setup_announced_and_triggered_twt_c113746(firmware_loader, wifi_dut, wifi_access_point,
                                                                                       sl_collections, wifi_sniffer,
                                                                                       sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with announced & Trigger based TWT and check the DUT behavior
    whether it is able to wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113746',
                                 power_save=True, test_case='113736', twt_retry_limit=10, un_announced_twt=0,
                                 utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113747')
def test_wifi_sdk_verify_whether_dut_able_to_setup_unannounced_and_triggered_twt_c113747(firmware_loader, wifi_dut, wifi_access_point,
                                                                                         sl_collections, utf_constants,
                                                                                         wifi_sniffer, sniffer_filter):
    """Verify whether DUT is able to create TWT setup with unannounced & Trigger based TWT and check the DUT behavior
    whether it is able to wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113747',
                                 power_save=True, test_case='113736', twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113748')
def test_wifi_sdk_verify_whether_dut_able_to_create_twt_within_wake_duration_c113748(firmware_loader, wifi_dut, wifi_access_point,
                                                                                     sl_collections, utf_constants,
                                                                                     wifi_sniffer, sniffer_filter):
    """Verify whether DUT is able to create TWT setup within the  Wake duration (Nominal Minimum wake time)"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113748',
                                 power_save=True, test_case='113736', twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113749')
def test_wifi_sdk_verify_whether_dut_able_to_create_twt_within_wake_duration_tolerance_c113749(firmware_loader, wifi_dut,
                                                                                               wifi_access_point,
                                                                                               sl_collections,
                                                                                               wifi_sniffer,
                                                                                               sniffer_filter,
                                                                                               utf_constants):
    """Verify whether DUT is able to create TWT setup within the  Wake duration Tolerance"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 power_save=True, test_case='113736', wake_duration=0xF0, wake_duration_tol=0xFF,
                                 sniffer_capture='113749')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113750')
def test_wifi_sdk_verify_whether_dut_able_to_create_twt_within_wake_interval_exponent_c113750(firmware_loader, wifi_dut,
                                                                                              wifi_access_point,
                                                                                              sl_collections,
                                                                                              wifi_sniffer,
                                                                                              sniffer_filter,
                                                                                              utf_constants):
    """Verify whether DUT is able to create TWT setup within the  Wake Interval Exponent"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113750',
                                 power_save=True, test_case='113736', wake_duration=0x80, wake_duration_tol=0x80,
                                 twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113751')
def test_wifi_sdk_verify_whether_dut_able_to_create_twt_within_wake_interval_exponent_tolerance_c113751(firmware_loader, wifi_dut,
                                                                                                        wifi_access_point,
                                                                                                        sl_collections,
                                                                                                        wifi_sniffer,
                                                                                                        sniffer_filter,
                                                                                                        utf_constants):
    """Verify whether DUT is able to create TWT setup within the  Wake Interval Exponent Tolerance"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113751',
                                 power_save=True, test_case='113736', utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113752')
def test_wifi_sdk_verify_whether_dut_able_to_create_twt_within_wake_interval_mantissa_c113752(firmware_loader, wifi_dut,
                                                                                              wifi_access_point,
                                                                                              sl_collections,
                                                                                              wifi_sniffer,
                                                                                              sniffer_filter,
                                                                                              utf_constants):
    """Verify whether DUT is able to create TWT setup within the  Wake Interval Mantissa"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113730',
                                 wake_duration=0x90, wake_duration_tol=0x90, wake_int_mantissa=0x7530,
                                 utf_constants=utf_constants, sniffer_capture='113752')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113753')
def test_wifi_sdk_verify_whether_dut_able_to_create_twt_within_wake_interval_mantissa_tolerance_c113753(firmware_loader, wifi_dut,
                                                                                                        wifi_access_point,
                                                                                                        sl_collections,
                                                                                                        wifi_sniffer,
                                                                                                        sniffer_filter,
                                                                                                        utf_constants):
    """Verify whether DUT is able to create TWT setup within the  Wake Interval Mantissa Tolerance"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113730',
                                 wake_duration=0x90, wake_duration_tol=0x90, wake_int_mantissa=0x4E20,
                                 wake_int_mantissa_tol=0x2710, utf_constants=utf_constants, sniffer_capture='113753')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_whether_dut_able_to_setup_twt_after_rejoin_c113754(firmware_loader, wifi_dut, wifi_access_point, sl_collections,
                                                                            wifi_sniffer, sniffer_filter, switch,
                                                                            utf_constants):
    """Verify whether DUT is able to create TWT setup after rejoined to the AP"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 sl_collections=sl_collections, test_case='113754', sniffer_capture='113754',
                                 wake_duration=0x90, wake_duration_tol=0x90, before_join=True,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, switch=switch,
                                 power_save=True, twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_when_device_idle_for_long_hours_c113761(firmware_loader, wifi_dut, wifi_access_point,
                                                                     sl_collections, wifi_sniffer,
                                                                     sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with demand support after association(key exchange) when we call
    TWT config api before join and also verify the DUT behavior whether it is able to wakeup and receive data based on
    the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113761', wake_duration=0xF0,
                                 wake_duration_tol=0x90, wake_int_mantissa=0x37D0, wake_int_mantissa_tol=0x37D0,
                                 utf_constants=utf_constants, sniffer_capture='113761')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_tcp_data_transfer_for_long_hours_c113760(firmware_loader, wifi_dut, wifi_access_point, sl_collections,
                                                                      net_perf_client, wifi_sniffer, wifi_client,
                                                                      sniffer_filter, utf_constants):
    """Verify the DUT behavior when enable TWT setup and run continuous TCP traffic for long hours - 10 hours"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113760', wake_duration=0xF0, wake_duration_tol=0x90,
                                 wake_int_mantissa=0x37D0, wake_int_mantissa_tol=0x37D0, utf_constants=utf_constants,
                                 sniffer_capture='113760', net_perf_client=net_perf_client, wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113762')
def test_wifi_sdk_verify_whether_dut_able_to_setup_unannounced_and_triggered_twt_before_join_c113762(firmware_loader, wifi_dut,
                                                                                                     wifi_access_point,
                                                                                                     sl_collections,
                                                                                                     wifi_sniffer,
                                                                                                     sniffer_filter,
                                                                                                     utf_constants):
    """Verify whether DUT is able to create TWT setup with request support after association when we call TWT config api
    before join and also verify the DUT behavior whether it is able to wakeup and receive data based on the TWT
    agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113762', un_announced_twt=1, triggered_twt=1, before_join=True,
                                 utf_constants=utf_constants, sniffer_capture='113762')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113763')
def test_wifi_sdk_verify_whether_dut_able_to_setup_unannounced_and_triggered_twt_after_join_c113763(firmware_loader, wifi_dut,
                                                                                                    wifi_access_point,
                                                                                                    sl_collections,
                                                                                                    wifi_sniffer,
                                                                                                    sniffer_filter,
                                                                                                    utf_constants):
    """Verify whether DUT is able to create TWT setup with request support when we call  TWT config api after join and
    also verify the DUT behavior whether it is able to wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113763',
                                 power_save=True, test_case='113730', utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C113764')
def test_wifi_sdk_verify_whether_dut_able_to_setup_twt_with_bg_scan_after_join_c113764(firmware_loader, wifi_dut, wifi_access_point,
                                                                                       sl_collections, wifi_sniffer,
                                                                                       sniffer_filter, utf_constants):
    """Verify whether DUT is able to create TWT setup with BG Scan when we call  TWT config api after join and
    also verify the DUT behavior whether it is able to wakeup and receive data based on the TWT agreement"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable power-save mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113764',
                                 power_save=True, test_case='113764', utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.test_src_map_id('C540487')
def test_wifi_sdk_verify_whether_dut_able_to_teardown_when_first_session_is_active_c540487(firmware_loader, wifi_dut, wifi_access_point,
                                                                                           sl_collections, wifi_sniffer,
                                                                                           sniffer_filter,
                                                                                           utf_constants):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='540487',
                                 power_save=True, test_case='113738', utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_verify_whether_dut_able_to_send_error_when_different_flow_id_is_provided_c540488(firmware_loader, wifi_dut,
                                                                                                   wifi_access_point,
                                                                                                   sl_collections,
                                                                                                   wifi_sniffer,
                                                                                                   sniffer_filter,
                                                                                                   utf_constants):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='540488',
                                 power_save=True, test_case='540488', utf_constants=utf_constants, wake_duration=0x60,
                                 wake_duration_unit=0, wake_duration_tol=0x60, wake_int_exp=13, wake_int_exp_tol=13, wake_int_mantissa=0x1D4C,
                                 wake_int_mantissa_tol=0x1D4C, req_type=1, twt_flow_id=1, twt_enable=1)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.disable_twt()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C540489')
def test_wifi_sdk_verify_whether_dut_able_to_send_error_when_disable_twt_without_enable_twt_c540489(firmware_loader, wifi_dut,
                                                                                                    wifi_access_point,
                                                                                                    sl_collections,
                                                                                                    wifi_sniffer,
                                                                                                    sniffer_filter,
                                                                                                    utf_constants):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='540489',
                                 power_save=True, test_case='540489', utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN', "standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_verify_tcp_keep_alive_functionality_twt_enabled_with_LI_900ms_c586161(firmware_loader, wifi_dut, wifi_access_point,
                                                                                                 sl_collections, wifi_sniffer,
                                                                                                 sniffer_filter, utf_constants,
                                                                                                  remote_socket):
    """
        Test Steps:
            1. Set Listen Interval
            2. Configure the Wi-Fi DUT with the specified features and TCP/IP configurations.
            3. TWT setup configurations
            4. Enable power-save mode
            5. verify the keep-alive functionality for each interval.
            6. Capture and validate the network traffic to ensure the keep-alive functionality is working as expected.
    """
    try:
        keepalive_time = 30
        wifi_dut.interfaces.wifi.wifi_set_listen_interval(listen_interval=900)
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='586161',
                                 power_save=True, test_case='586161', utf_constants=utf_constants,
                                 wake_duration=0xF0,
                                 wake_duration_tol=0x90, wake_int_mantissa=0x07D0, wake_int_mantissa_tol=0x07D0,
                                 )
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        # Open remote server socket
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port
        remote_socket.interfaces.socket.time_limit = 305
        logger().info(f"\n Starting the Remote Socket Server \n")
        remote_socket.interfaces.socket.start_server()

        sockID = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {sockID}")
        wifi_dut.interfaces.wifi.bind(socket_fd=sockID, device_ip=wlan_obj.dut_addr['device_ip'],
                                      server_port=server_port,
                                      timeout=15)
        logger().info(f"Setting the socket option SO_KEEPALIVE with {keepalive_time} seconds")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sockID, option_name="SO_KEEPALIVE",
                                                 option_val=keepalive_time)

        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sockID, server_ip=server_ip, server_port=server_port)
        logger().info("*********** Socket connection is successful ************")

        logger().info("*********** wait for 300 sec ************")
        time.sleep(300)
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_mac = wifi_access_point.interfaces.wifi.bssid

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sockID)
        logger().info(f"Stopping the Remote Socket Server")
        remote_socket.interfaces.socket.stop()

        wifi_dut.interfaces.wifi.disable_twt()
        wifi_dut.interfaces.wifi.leave()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                               wlan_obj.dut_addr['dut_mac_address'],
                                               ap_mac, sniffer_filter)
        logger().info(f"Starting the Keep Alive Validation with duration {keepalive_time} seconds")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(ta_addr=wlan_obj.dut_addr['dut_mac_address'],
            ra_addr=ap_mac, filter_name="keep_alive")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], f"Keep alive packets not found in sniffer packets"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
