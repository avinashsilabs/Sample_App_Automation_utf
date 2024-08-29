import pytest
import time
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xTWTRescheduleParams
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus

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


def logger():
    return get_logger(__name__)


class RescheduleTwTThread(ThreadBase):
    def __init__(self, twt_enable=1, twt_flow_id=1, wake_duration=0x60, wake_duration_unit=0, wake_duration_tol=0x60,
                 wake_int_exp=13, wake_int_exp_tol=13, wake_int_mantissa=0x1D4C, wake_int_mantissa_tol=0x1D4C,
                 implicit_twt=1, un_announced_twt=1, triggered_twt=0, twt_channel=0, twt_protection=0,
                 restrict_tx_outside_tsp=1, twt_retry_limit=6, twt_retry_interval=10, req_type=1, negotiation_type=0,
                 wifi_dut=None, sl_collections=None, wifi_sniffer=None, wifi_access_point=None, switch=None,
                 test_case=None, sniffer_filter=None, power_save=False, utf_constants=None, sniffer_capture=None):
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
        self.utf_constants = utf_constants
        self.time_duration = utf_constants.get("time_duration")

        # Create packet filters variables
        self.packet_filter1 = None
        self.packet_filter2 = None
        self.packet_filter3 = None
        self.packet_filter4 = None
        self.power_save_filter = None
        self.second_level_filter = '        Tag: Target Wake Time'

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(self.sniffer_capture)
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     power_save=self.power_save,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)

            if self.test_case == '540486':
                self.wifi_dut.interfaces.wifi.twt_reschedule(flow_id=1, suspend_duration=0,
                                                             twt_reschedule_action=Si91xTWTRescheduleParams.SL_WIFI_RESUME_IMMEDIATELY,
                                                             expected_status=SLStatus.SL_STATUS_SI91X_RESCHEDULE_TWT_ERR_NOACTIVE_SESS)
                logger().info('***** Getting error code 0x10076, which is expected *****')
                return

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

            if self.wake_duration_unit == 0:
                self.wake_duration_time = 256
            if self.wake_duration_unit == 1:
                self.wake_duration_time = 1024

            self.packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                filter_name="twt_requesting_sta_1")
            # Get sniffer filter for twt response frame
            self.packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                da_addr=self.dut_addr['dut_mac_address'], sa_addr=self.ap_mac_address,
                filter_name="twt_responding_sta_0")

            logger().info(f'***** twt_requesting_sta_1 = {self.packet_filter1}')
            logger().info(f'***** twt_responding_sta_0 = {self.packet_filter2}')

            self.packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                filter_name="twt_assoc_request_frame")

            logger().info(f'***** twt_assoc_request_frame = {self.packet_filter3}')
            self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter1,
                                                                    packet_filter2=self.second_level_filter)

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

            logger().info(f'**** Pinging for {self.time_duration} seconds ****')

            start_time = time.time()
            while (time.time() - start_time) < 300:
                self.sl_collections.ping_with_custom_interval(device_ip=self.dut_addr['device_ip'],
                                                              interval=10)

            self.wifi_sniffer.interfaces.capture.stop_capture()

            self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")
            packet_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.power_save_filter)[
                       'find_packet_num']

            assert int(packet_count), 'Unable to find ps-poll packets'
            logger().info(f'***** Power Save packets before rescheduling TWT = {packet_count} *****')

            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter3)[
                'packet_count'], f"DUT is not able to send TWT association request frame to AP"

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

            if self.test_case == '540478':
                self.wifi_dut.interfaces.wifi.twt_reschedule(flow_id=1, suspend_duration=0)

                time.sleep(60)

                packet_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=self.power_save_filter)[
                    'find_packet_num']

                assert int(packet_count), 'Unable to find ps-poll packets'
                logger().info(f'***** Power Save packets after rescheduling TWT = {packet_count} *****')
                return

            if self.test_case == '540479' or self.test_case == '540485':
                self.wifi_dut.interfaces.wifi.twt_reschedule(flow_id=1, twt_reschedule_action=Si91xTWTRescheduleParams.SL_WIFI_SUSPEND_FOR_DURATION)

                if self.test_case == '540485':
                    self.wifi_dut.interfaces.wifi.twt_reschedule(flow_id=1,
                                                                 twt_reschedule_action=Si91xTWTRescheduleParams.SL_WIFI_SUSPEND_FOR_DURATION)

                time.sleep(60)

                packet_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=self.power_save_filter)[
                    'find_packet_num']

                assert int(packet_count), 'Unable to find ps-poll packets'
                logger().info(f'***** Power Save packets after rescheduling TWT = {packet_count} *****')

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
        for i in range(len(time_delta)):
            if i == 0 or i == 1:
                continue
            assert abs(int(time_delta[i]) - int(time_delta[i - 1])) in range(0,
                                                                             2), "Retry interval is not 10 seconds"

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
    )
]


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_reschedule_twt_indefinite_time_c540478(wifi_dut, wifi_access_point, sl_collections,
                                                         wifi_sniffer, sniffer_filter, utf_constants):
    try:
        wlan_obj = RescheduleTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                       sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                       sniffer_filter=sniffer_filter, power_save=True, test_case='540478',
                                       utf_constants=utf_constants, sniffer_capture='540478')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_reschedule_twt_for_duration_c540479(wifi_dut, wifi_access_point, sl_collections,
                                                      wifi_sniffer, sniffer_filter, utf_constants):
    try:
        wlan_obj = RescheduleTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                       sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                       sniffer_filter=sniffer_filter, power_save=True, test_case='540479',
                                       utf_constants=utf_constants, sniffer_capture='540479')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", 'disable_twt'])
def test_wifi_sdk_reschedule_twt_twice_c540485(wifi_dut, wifi_access_point, sl_collections, wifi_sniffer,
                                               sniffer_filter, utf_constants):
    try:
        wlan_obj = RescheduleTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                       sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                       sniffer_filter=sniffer_filter, power_save=True, test_case='540485',
                                       utf_constants=utf_constants, sniffer_capture='540485')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_reschedule_twt_without_set_twt_c540486(wifi_dut, wifi_access_point, sl_collections,
                                                         wifi_sniffer, sniffer_filter, utf_constants):
    try:
        wlan_obj = RescheduleTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                       sl_collections=sl_collections, wifi_sniffer=wifi_sniffer,
                                       sniffer_filter=sniffer_filter, power_save=True, test_case='540486',
                                       utf_constants=utf_constants, sniffer_capture='540486')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



