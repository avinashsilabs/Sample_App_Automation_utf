import pytest
import time
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xBLECustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
import string
import random
from utf.interfaces.bluetooth import BLEDeviceState

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
        6. Validate BLE Functionality

    Author: Saurabh Sharma

"""


# Define logger
def logger():
    return get_logger(__name__)


class WLanTwTThread(ThreadBase):
    def __init__(self, twt_enable=1, twt_flow_id=1, wake_duration=0x40, wake_duration_unit=0, wake_duration_tol=0,
                 wake_int_exp=13, wake_int_exp_tol=0, wake_int_mantissa=0x2B3, wake_int_mantissa_tol=0,
                 implicit_twt=1, un_announced_twt=1, triggered_twt=0, twt_channel=0, twt_protection=0,
                 restrict_tx_outside_tsp=1, twt_retry_limit=6, twt_retry_interval=10, req_type=1, negotiation_type=0,
                 wifi_dut=None, sl_collections=None, wifi_sniffer=None, wifi_access_point=None,
                 test_case=None, sniffer_filter=None, open_tcp_socket=False, power_save=False, disable_twt=False,
                 utf_constants=None, switch=None):
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
        self.disable_twt = disable_twt

        self.wake_interval_req = None
        self.wake_period_req = None
        self.target_wake_time = None

        self.mantissa_resp = None
        self.wake_interval_exponent_resp = None
        self.minimum_wake_duration_resp = None

        self.wake_interval_resp = None
        self.wake_period_resp = None

        self.sniffer_filter = sniffer_filter
        self.switch = switch
        self.dut_addr = None
        self.ap_mac_address = None
        # Create packet filters variables
        self.packet_filter1 = None
        self.packet_filter2 = None
        self.packet_filter3 = None
        self.packet_filter4 = None
        self.power_save_filter = None
        self.open_tcp_socket = open_tcp_socket
        self.second_level_filter = '        Tag: Target Wake Time'
        self.socket_id = None
        self.utf_constants = utf_constants
        self.time_duration = utf_constants.get("time_duration")

    def run(self):
        try:
            # Check test case 198628 set advanced client configuration
            if self.test_case == '198628':
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                              beacon_missed_count=1000,
                                                                              first_time_retry_enable=0)

            # Configure the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.configure_interface(self.wifi_access_point.interfaces.wifi.channel)
            # Start the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.start_capture(self.test_case)
            # Get the mac address of the wifi_access_point
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid

            # Set wake_duration_time
            if self.wake_duration_unit == 0:
                self.wake_duration_time = 256
            if self.wake_duration_unit == 1:
                self.wake_duration_time = 1024

            self.dut_addr = self.sl_collections.join_to_wifi_network(
                self.wifi_dut, self.wifi_access_point, power_save=self.power_save,
                associated=self.wifi_dut.interfaces.wifi.associated)

            if self.test_case == '198624' or self.test_case == '198625' or self.test_case == '198626' or self.test_case == '198627' or self.test_case == '198630' or self.test_case == '198631':
                return

            if self.test_case == '198620' or self.test_case == '198619' or self.test_case == '198623' or self.test_case == '198632':
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

                logger().info(f"....Applying performance profile mode")
                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            if self.test_case == '198629':
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
                                                      negotiation_type=self.negotiation_type,
                                                      expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)

                logger().info(f"....Applying performance profile mode")
                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                return

            # Check test case 198628 and turn off the switch
            if self.test_case == '198628':
                self.switch.interfaces.pdu_switch.turn_off()
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
                time.sleep(120)
                retry_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                    filter_name="twt_request_packets")
                logger().info(f'***** twt_request_packets = {retry_filter}')

                self.switch.interfaces.pdu_switch.turn_on(delay=60)
                self.wifi_sniffer.interfaces.capture.stop_capture()

                assert int(self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=retry_filter)[
                               'find_packet_num']) == self.twt_retry_limit + 1, "Unable to find TWT request packets"
                logger().info('\n\n**** Retry packets verified successfully ****\n\n')

                self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=retry_filter,
                                                                        packet_filter2=self.second_level_filter)
                self.validate_retry_interval()
                logger().info('\n\n**** Retry interval verified successfully ****\n\n')
                return

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

            # assert some packets are captured
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter3)[
                'packet_count'], f"DUT is not able to send TWT association request frame to AP"

            if self.test_case == '198623' or self.test_case == '198632':
                # Sleep for 10 minutes
                logger().info(f'**** Pinging for {self.time_duration} seconds ****')

                start_time = time.time()
                while (time.time() - start_time) < self.time_duration:
                    self.sl_collections.ping_with_custom_interval(device_ip=self.dut_addr['device_ip'],
                                                                  interval=int(self.wake_interval_resp) // 10000000)

            # Stop the capture
            self.wifi_sniffer.interfaces.capture.stop_capture()

            # Do power save validation after checking power_save variable
            # if self.power_save:
            self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.power_save_filter)[
                       'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

            if self.test_case == '198623' or self.test_case == '198632':
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
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

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
            self.wake_interval_req = self.mantissa_req * (2 ** self.wake_interval_exponent_req)
            self.wake_period_req = self.minimum_wake_duration_req * self.wake_duration_time
            logger().info(f'***** Wake Interval Req= {self.wake_interval_req}')
            logger().info(f'***** Wake Period Req = {self.wake_period_req}')

        if filter == 0:
            self.wake_interval_resp = self.mantissa_resp * (2 ** int(self.wake_interval_exponent_resp))
            self.wake_period_resp = self.minimum_wake_duration_resp * self.wake_duration_time
            logger().info(f'***** Wake Interval Resp= {self.wake_interval_resp}')
            logger().info(f'***** Wake Period Resp = {self.wake_period_resp}')

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

    def validate_retry_interval(self):
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        lines = filter_file.read()
        time_delta = re.findall(r'((?<=Time delta from previous captured frame:\s)\d+)', lines)
        time_delta = time_delta[0:len(time_delta) - 1]
        logger().info(f"Time delta between retry packets = {time_delta}")
        for i in range(len(time_delta)):
            if i == 0 or i == 1:
                continue
            assert abs(int(time_delta[i]) - int(time_delta[i - 1])) in range(0, 2), "Retry interval is not 10 seconds"

    def set_twt_operation(self):
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

        logger().info(f"....Applying performance profile mode")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

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

        # assert some packets are captured
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter3)[
            'packet_count'], f"DUT is not able to send TWT association request frame to AP"

        # call sleep
        logger().info(f'**** Pinging for {self.time_duration} seconds ****')

        start_time = time.time()
        while (time.time() - start_time) < self.time_duration:
            self.sl_collections.ping_with_custom_interval(device_ip=self.dut_addr['device_ip'],
                                                          interval=int(self.wake_interval_resp) // 10000000)

        # Stop the capture
        self.wifi_sniffer.interfaces.capture.stop_capture()

        # Do power save validation
        self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.power_save_filter)[
                   'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

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

    def twt_teardown_and_recreate_session(self):
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

        logger().info(f"....Applying performance profile mode")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

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

        # assert some packets are captured
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter3)[
            'packet_count'], f"DUT is not able to send TWT association request frame to AP"

        # call sleep
        logger().info(f'**** Pinging for {self.time_duration} seconds ****')

        start_time = time.time()
        while (time.time() - start_time) < self.time_duration:
            self.sl_collections.ping_with_custom_interval(device_ip=self.dut_addr['device_ip'],
                                                          interval=int(self.wake_interval_resp) // 10000000)

        # Stop the capture
        self.wifi_sniffer.interfaces.capture.stop_capture()

        # Do power save validation
        self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.power_save_filter)[
                   'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

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

        if self.disable_twt:
            self.wifi_dut.interfaces.wifi.disable_twt()
        if self.test_case == '198631':
            self.req_type = 0

        # Configure the sniffer on wifi_access_point channel
        self.wifi_sniffer.interfaces.capture.configure_interface(self.wifi_access_point.interfaces.wifi.channel)
        # Start the sniffer on wifi_access_point channel
        self.wifi_sniffer.interfaces.capture.start_capture(self.test_case)

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

        logger().info(f"....Applying performance profile mode")
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        # call sleep
        logger().info(f'**** Pinging for {self.time_duration} seconds ****')

        start_time = time.time()
        while (time.time() - start_time) < self.time_duration:
            self.sl_collections.ping_with_custom_interval(device_ip=self.dut_addr['device_ip'],
                                                          interval=int(self.wake_interval_resp) // 10000000)

        # Stop the capture
        self.wifi_sniffer.interfaces.capture.stop_capture()

        # Do power save validation
        self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.power_save_filter)[
                   'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

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


class ble_device_state:
    connected_adv = 9  # 8 for connection + 1 for advertising
    connected_scanning = 10  # 10 for connection and scanning


class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, test_case=None,
                 ble_dut=None, ble_pairing=0, utf_constants=None, ble_dut_address=None, ble_client_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.ble_client_address = ble_client_address
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.ble_pairing = ble_pairing
        self.utf_constants = utf_constants

        """ **************** Set up DUT for BLE advertising **************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.ble_pairing)
        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

    def run(self):
        try:

            if self.test_case == '198619':
                self.sl_collections.check_ble_advertise_functionality(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                    timeout=20)
                self.ble_client.interfaces.bluetooth.close()
                time.sleep(3)
                self.sl_collections.check_ble_scan_functionality(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_address=self.ble_dut_address, timeout=20)
                self.wifi_dut.interfaces.wifi.ble_stop_scanning()
                time.sleep(2)

            if self.test_case == '198621':
                self.sl_collections.check_ble_advertise_functionality(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                    timeout=20)
                self.ble_client.interfaces.bluetooth.close()
                time.sleep(3)
                self.ble_client_address = self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address, retries=1,
                    timeout=20, dev_state=9, mode='master')

                logger().info("..... checking for ble connection stability ......")
                time.sleep(60)

            if self.test_case == '198622':
                self.sl_collections.check_ble_scan_functionality(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_address=self.ble_dut_address, timeout=20)
                time.sleep(2)
                self.ble_client.interfaces.bluetooth.close()

                logger().info("..... Advertising the DUT .....")
                self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

                self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                    ble_pairing=self.ble_pairing, dev_state=10)

                logger().info("..... checking for ble connection stability ......")
                time.sleep(60)

        except Exception as e:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=e)

    def ble_master_slave_data_transfer(self):
        try:
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            if self.test_case == '198625' or self.test_case == '198626' or self.test_case == '198632':
                self.sl_collections.check_ble_advertise_functionality(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                    timeout=20)
                self.ble_client.interfaces.bluetooth.close()
                time.sleep(3)
                logger().info("******************** initializing ble in remote device ********************")
                self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=self.ble_dut_address)
                assert self.ble_client_address, "failed to initialize ble in remote device"

                logger().info("******************** start scanning in dut ********************")
                self.ble_dut.interfaces.bluetooth.ble_start_scanning(
                    ble_client_address=self.ble_client_address, timeout=100)
                time.sleep(5)
                self.ble_dut.interfaces.bluetooth.ble_stop_scanning()

                logger().info("..... initiating BLE connection ......")
                self.ble_dut.interfaces.bluetooth.ble_connect(
                    ble_remote_dev_address=self.ble_client_address, expected="RSI_BLE_SECURITY_KEYS_EVENT")

            if self.test_case == '198627':
                self.sl_collections.check_ble_scan_functionality(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_address=self.ble_dut_address, timeout=20)
                time.sleep(2)
                self.ble_client.interfaces.bluetooth.close()

                self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
                    wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                    timeout=20)

                logger().info("...... connect to ble dut ......")
                self.ble_client.interfaces.bluetooth.connect(self.ble_dut_address)
                time.sleep(10)

            logger().info(f"..... checking for ble connection stability ......")
            time.sleep(60)

            if self.test_case == '198625' or self.test_case == '198626' or self.test_case == '198632':
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == ble_device_state.connected_adv, "DUT BLE device is not in connected state"

            if self.test_case == '198627':
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == ble_device_state.connected_scanning, "DUT BLE device is not in connected state"

            servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"

            char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=service_uid, char_uid=char_uid)
            assert char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

            logger().info(f' *********************** subscribe to notifications ***********************')
            self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=char_path, char_uid=char_uid)

            self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                ble_remote_dev_address=self.ble_client_address, buffer_mode=0, buffer_count=2)

            sw = Stopwatch()
            count = 0
            while sw.elapsed_sec < 60:
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                self.wifi_dut.interfaces.wifi.ble_notify_custom_value(data=data, ble_remote_dev_address=self.ble_client_address)
                time.sleep(3)
                logger().info("******************** Validate Data ********************")
                notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(
                    f' *********************** Notification is {notifications} ***********************')
                assert len(notifications) > 0, "received data is empty"
                assert notifications[count] == data, "Data Mismatched"
                count += 1

            logger().info(f' *********************** unsubscribe to notifications ***********************')
            self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
            time.sleep(1)

            logger().info("******************** ble_remove_service ***********************")
            self.wifi_dut.interfaces.wifi.ble_remove_service()

            if self.test_case == '198632':
                self.sl_collections.cleanup_ble(
                    ble_dut=self.wifi_dut, ble_client=self.ble_client, ble_client_address=self.ble_client_address)

        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

    def ble_disconnect(self, disconnect_from="remote"):
        self.sl_collections.ble_disconnect(
            wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
            disconnect_from=disconnect_from, ble_client_address=self.ble_client_address)

    def ble_cleanup(self):
        self.sl_collections.cleanup_ble(
            ble_dut=self.wifi_dut, ble_client=self.ble_client, ble_client_address=self.ble_client_address)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                              "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        }
    )
]


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv",
                             "disable_twt"])
def test_wifi_sdk_verify_ble_scan_adv_after_twt_c198619(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client,
        utf_constants):
    """Verify whether DUT is able to perform BLE Scan and advertising after setting the TWT Interval before WLAN join"""

    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 test_case='198619')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198619')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv",
                             "disable_twt"])
def test_wifi_sdk_verify_ble_scan_adv_before_twt_c198620(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client, utf_constants):
    """Verify whether DUT is able to perform BLE Scan and advertising if we set the TWT Interval after WLAN Join"""

    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 test_case='198620')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198619')

        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_ble_master_before_twt_c198621(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client, utf_constants):
    """Verify whether DUT is able setup the Suggested TWT with AP after the BLE Master connection."""
    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 test_case='198619')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198621')
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_ble_slave_before_twt_c198622(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client, utf_constants):
    """Verify whether DUT is able to set up the Requested TWT with AP Before WLAN Join command with BLE As slave"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, req_type=0,
                                 utf_constants=utf_constants, test_case='198619')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198622')
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_and_dut_wake_interval_before_ble_master_c198623(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client,
        utf_constants):
    """Verify whether DUT is able to set up the Suggested TWT with  BLE Master connection and able to wake up and
    receive the Data at regular TWT Intervals"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 test_case='198623')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198621')

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_and_dut_wake_interval_after_ble_slave_c198624(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client,
        utf_constants):
    """Verify whether DUT is able to wake up and receive the DATA at regular TWT Intervals when TWT Command is given
    after connection with BLE Slave connection """

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 test_case='198624')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198622')

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.set_twt_operation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_with_ble_master_tx_data_transfer_c198625(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client,
        utf_constants):
    """Check whether DUT is able to wake up at regular TWT intervals and receive data or not in suggested
    when DUT is doing BLE Data transfer in master connection"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 test_case='198625')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198625')

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.ble_master_slave_data_transfer()
        wlan_obj.set_twt_operation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.skip("Not Deployed Yet")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_announced_trigger_with_ble_master_tx_data_transfer_c198626(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client,
        utf_constants):
    """Check whether DUT is able to wake up at regular TWT intervals and receive data or not in unannounced + trigger
    based TWT type when DUT is connected as BLE Master connection with data transfer from DUT to Remote device"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 un_announced_twt=0, triggered_twt=1, test_case='198626')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198626')

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.ble_master_slave_data_transfer()
        wlan_obj.set_twt_operation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.skip("Not Deployed Yet")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_unannounced_trigger_with_ble_slave_tx_data_transfer_c198627(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client,
        utf_constants):
    """Check whether DUT is able to wake up at regular TWT intervals and receive data or not in unannounced + trigger
    based TWT type when DUT is connected as BLE Slave connection with data transfer between DUT to Remote device"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 triggered_twt=1, test_case='198627')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198627')

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.ble_master_slave_data_transfer()
        wlan_obj.set_twt_operation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_retry_frames_with_ble_master_c198628(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client,
        utf_constants, switch):
    """Check whether DUT is able to send the TWT Retry frames or not for Failed TWT Setup when DUT as BLE Master role"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 power_save=True, switch=switch, twt_retry_limit=10, test_case='198628')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198621')

        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_twt_conn_with_invalid_parameter_ble_master_c198629(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client, utf_constants):
    """Check DUT is able to create the TWT Connection to AP with invalid TWT Parameters when DUT is connected as
    master"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='198629',
                                 wake_int_exp=32, utf_constants=utf_constants)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198621')
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(" ********* TWT Invalid Parameter Error 0x0021 which is expected behaviour ********* ")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.skip("Not Deployed Yet")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_teardown_recreate_session_with_ble_master_c198630(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client, utf_constants):
    """Check whether DUT is able to teardown and recreate the TWT Session when DUT BLE as Master"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 disable_twt=True, test_case='198630')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198621')
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.twt_teardown_and_recreate_session()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="twt_teardown_check")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find teardown packet"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.skip("Not Deployed Yet")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_teardown_recreate_session_with_another_type_and_ble_slave_c198631(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client, utf_constants):
    """Check whether DUT is able to teardown and recreate the TWT Session with another TWT type When DUT BLE as slave"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='198631',
                                 utf_constants=utf_constants, disable_twt=True)
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198622')
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.twt_teardown_and_recreate_session()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="twt_teardown_check")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find teardown packet"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()


@pytest.mark.skip("Not Deployed Yet")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', 'twt': 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_with_ble_master_conn_reconn_c198632(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client, utf_constants):
    """DUT is able to wake up at regular TWT Intervals when The DUT BLE is connecting, Sending the Data and
    disconnecting continuously"""

    ble_obj = None
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, utf_constants=utf_constants,
                                 test_case='198632')

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=1,
                                         ble_dut=ble_dut, ble_client=ble_client, utf_constants=utf_constants,
                                         test_case='198632')
        wlan_obj.start()
        time.sleep(25)
        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            ble_obj.ble_master_slave_data_transfer()
            wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_obj.ble_cleanup()
