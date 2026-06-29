import pytest
import time
import re
import random
import string
from datetime import datetime

from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf_wifi_zephyr.utils.sl_status import SLStatus
from utf_wifi_zephyr.devices.si91x import WiFiTwtSetupCmd, WiFiTwtNegotiationType, Si91xBSDSocketParams

"""
    Setup requirement:
        1. SoC board
        2. Raspberry PI4
        3. Access Point with TWT support (third-party AP)
        4. Sniffer (NUC device)

    Test Steps:
        1. Configure the DUT in WLAN alone mode for 2.4 GHz operation
        2. Join the access point and enable DHCP
        3. Enable WLAN power save mode on the DUT after connection
        4. Initiate ping or traffic based on the test scenario
        5. Validate TWT configuration and DUT behavior

    Author: Vinod.G

"""


# Define logger
def logger():
    return get_logger(__name__)


TWT_SETUP_KWARGS = dict(
    setup_cmd=WiFiTwtSetupCmd.Request,
    dialog_token=0,
    flow_id=1,
    negotiation_type=WiFiTwtNegotiationType.Individual,
    responder=0,
    implicit=1,
    trigger=0,
    announce=0,
    wake_interval=32768,
    info_disable=1,
    exponent=13,
    mantissa=7500,
    wake_ahead=0,
)

TWT_WAIT_SECONDS = 3 * 60
TWT_TCP_LOOP_DURATION_SECONDS = 30 * 60
TWT_TCP_PACKET_COUNT = 100
TWT_TCP_DATA_LENGTH = 100
TWT_TCP_PORT = 5001


def configure_twt_setup(wifi_dut):
    status, data = wifi_dut.interfaces.wifi.set_twt(**TWT_SETUP_KWARGS)
    logger().info(f"TWT setup status and response -------> {status}         {data}")
    if "TWT alternate" in data:
        status, data = wifi_dut.interfaces.wifi.set_twt()
        logger().info(f"TWT setup (alternate) status and response -------> {status}         {data}")


def configure_twt_teardown(wifi_dut):
    wifi_dut.interfaces.wifi.wifi_twt_teardown(flow_id=TWT_SETUP_KWARGS['flow_id'])
    logger().info("TWT teardown completed")


def tcp_open_send_close_100_packets(wifi_dut, remote_socket, device_ip, server_ip,
                                    port=TWT_TCP_PORT, data_length=TWT_TCP_DATA_LENGTH,
                                    packet_count=TWT_TCP_PACKET_COUNT):
    """TCP client open, send packet_count packets, and close — based on c19347."""
    logger().info("Starting the Remote Socket Server")
    remote_socket.interfaces.socket.start_server(port=port)
    socket_id = wifi_dut.interfaces.wifi.socket(domain=Si91xBSDSocketParams.AF_INET,
                                                stream_type=Si91xBSDSocketParams.SOCK_STREAM,
                                                protocol=Si91xBSDSocketParams.IPPROTO_TCP)
    logger().info(f"Socket open successfully : {socket_id}")
    wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=device_ip, port=port, timeout=5)

    connect_status = False
    for count in range(3):
        try:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_id, server_ip, port)
            connect_status = True
            break
        except Exception:
            logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
    assert connect_status, "Socket connection failed in DUT"
    logger().info("*********** Socket connection is successful ************")

    sent_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=data_length))
    for packet_num in range(1, packet_count + 1):
        status, _ = wifi_dut.interfaces.wifi.send(socket_fd=socket_id, data=sent_data)
        assert status == 0, f"TCP send failed at packet {packet_num}/{packet_count}"
        received_data = remote_socket.interfaces.socket.recv_data_tcp(len(sent_data))
        assert sent_data == received_data, f"Data mismatch at packet {packet_num}/{packet_count}"

    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
    logger().info("Stopping the Remote Socket Server")
    remote_socket.interfaces.socket.stop()
    logger().info(f"Successfully sent and verified {packet_count} TCP packets")


def assign_static_ipv4_to_dut(wifi_dut, wifi_client):
    """Assign static IPv4 to DUT — based on c49347."""
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    ip_parts = host_ip.split('.')
    ip_parts[-1] = str(int(ip_parts[-1]) + 1)
    dut_ip_static = '.'.join(ip_parts)
    gateway_parts = dut_ip_static.split('.')
    gateway_parts[-1] = "1"
    static_gateway = '.'.join(gateway_parts)
    dut_ip = wifi_dut.interfaces.wifi.start_ip(static_ip=dut_ip_static, static_subnet="255.255.255.0",
                                               static_gateway=static_gateway)
    device_ip = dut_ip.ip.decode()
    logger().info(f"DUT static IP assigned: {device_ip}")
    return device_ip


def get_twt_wake_interval_from_setup_kwargs():
    return TWT_SETUP_KWARGS['mantissa'] * (2 ** TWT_SETUP_KWARGS['exponent'])


class WLanTwTThread(ThreadBase):
    def __init__(self, setup_cmd=WiFiTwtSetupCmd.Request, dialog_token=0, flow_id=1,
                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1, trigger=0,
                 announce=0, wake_interval=32768, info_disable=1,
                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0,
                 wifi_dut=None, zephyr_wifi_collections=None, wifi_sniffer=None, wifi_access_point=None, switch=None,
                 test_case=None, sniffer_filter=None, power_save=False, before_join=False, utf_constants=None,
                 sniffer_capture=None, wifi_client=None, net_perf_client=None):
        super().__init__()
        # Define all the parameters
        self.setup_cmd = setup_cmd
        self.dialog_token = dialog_token
        self.flow_id = flow_id
        self.negotiation_type = negotiation_type
        self.responder = responder
        self.implicit = implicit
        self.trigger = trigger
        self.announce = announce
        self.wake_interval = wake_interval
        self.info_disable = info_disable
        self.exponent = exponent
        self.mantissa = mantissa
        self.wake_ahead = wake_ahead
        self.timeout_ms = timeout_ms

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.zephyr_wifi_collections = zephyr_wifi_collections
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
            if self.test_case == '113760' or self.test_case == '113761':
                self.time_duration = self.utf_constants.get("long_duration")
            # Configure the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.configure_interface(self.wifi_access_point.interfaces.wifi.channel)
            # Start the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.start_capture(self.sniffer_capture)
            # Get the mac address of the wifi_access_point
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid

            time_obj = Stopwatch()
            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut,
                                                                              wifi_access_point=self.wifi_access_point,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated)
            if self.test_case == '113743':
                logger().info("113743 return from here")
                return
            # power_save=self.power_save)

            # if self.test_case == '113725':
            if self.test_case != '540489':
                status, data = self.wifi_dut.interfaces.wifi.set_twt(setup_cmd=self.setup_cmd,
                                                                     dialog_token=self.dialog_token,
                                                                     flow_id=self.flow_id,
                                                                     negotiation_type=self.negotiation_type,
                                                                     responder=self.responder,
                                                                     implicit=self.implicit,
                                                                     trigger=self.trigger,
                                                                     announce=self.announce,
                                                                     wake_interval=self.wake_interval,
                                                                     info_disable=self.info_disable,
                                                                     exponent=self.exponent,
                                                                     mantissa=self.mantissa,
                                                                     wake_ahead=self.wake_ahead)
                logger().info(f"status and twt response -------> {status}         {data}")
                if "TWT alternate" in data:
                    status, data = self.wifi_dut.interfaces.wifi.set_twt()
                    logger().info(f"status and twt response -------> {status}         {data}")

            if self.power_save:
                self.wifi_dut.interfaces.wifi.wifi_ps(enabled=1)
                time.sleep(2)

            if self.test_case == '1912308':
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("***** Validating first TWT agreement before STA disconnect *****")
                self._validate_twt_request_response_packets()
                logger().info("***** STA-initiated disconnect from AP *****")
                self.wifi_dut.interfaces.wifi.leave()
                time.sleep(5)
                reconnect_capture_name = (
                    f"{self.test_case}_after_reconnect_"
                    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                )
                logger().info(
                    f"***** Starting sniffer capture for reconnect phase: {reconnect_capture_name} *****")
                self.wifi_sniffer.interfaces.capture.start_capture(reconnect_capture_name)
                logger().info("***** Reconnecting DUT to AP *****")
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                    self.wifi_dut,
                    wifi_access_point=self.wifi_access_point,
                    associated=self.wifi_dut.interfaces.wifi.associated)
                status, data = self.wifi_dut.interfaces.wifi.set_twt(setup_cmd=self.setup_cmd,
                                                                     dialog_token=self.dialog_token,
                                                                     flow_id=self.flow_id,
                                                                     negotiation_type=self.negotiation_type,
                                                                     responder=self.responder,
                                                                     implicit=self.implicit,
                                                                     trigger=self.trigger,
                                                                     announce=self.announce,
                                                                     wake_interval=self.wake_interval,
                                                                     info_disable=self.info_disable,
                                                                     exponent=self.exponent,
                                                                     mantissa=self.mantissa,
                                                                     wake_ahead=self.wake_ahead)
                logger().info(f"status and twt response after reconnect -------> {status}         {data}")
                if "TWT alternate" in data:
                    status, data = self.wifi_dut.interfaces.wifi.set_twt()
                    logger().info(f"status and twt response after reconnect -------> {status}         {data}")
                if self.power_save:
                    self.wifi_dut.interfaces.wifi.wifi_ps(enabled=1)
                    time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("***** Validating TWT agreement after reconnect *****")
                self._validate_twt_request_response_packets()
                return

            # Check Test Case 113764 and enable BG scan
            if self.test_case == '113764':
                self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)

            if self.test_case == '113738':
                self.wifi_dut.interfaces.wifi.set_twt(setup_cmd=self.setup_cmd,
                                                      dialog_token=self.dialog_token,
                                                      flow_id=self.flow_id,
                                                      negotiation_type=self.negotiation_type,
                                                      responder=self.responder,
                                                      implicit=self.implicit,
                                                      trigger=self.trigger,
                                                      announce=self.announce,
                                                      wake_interval=self.wake_interval,
                                                      info_disable=self.info_disable,
                                                      exponent=self.exponent,
                                                      mantissa=self.mantissa,
                                                      wake_ahead=self.wake_ahead,
                                                      expected_status=SLStatus.SL_STATUS_FAIL)
                return

            # Check the test 540489 and call the disable TWT API
            if self.test_case == '540489':
                self.wifi_dut.interfaces.wifi.wifi_twt_teardown(expected_status=SLStatus.SL_STATUS_FAIL)
                logger().info("***** Getting Error, which is expected *****")
                return
            if self.test_case == '540488':
                self.wifi_dut.interfaces.wifi.wifi_twt_teardown(flow_id=2, expected_status=SLStatus.SL_STATUS_FAIL)
                logger().info("***** Getting Error, which is expected *****")
                return

            if self.test_case == '586161':
                self.wifi_dut.interfaces.wifi.set_twt(
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
                # twt_setup_success_event = [event for event in events if
                #                            event.event_type == AsyncEventIdentifiers.WIFI_TWT_RESPONSE_EVENT]
                # if len(twt_setup_success_event):
                #     self.indicate_twt_success_response = True

                assert self.indicate_twt_success_response, f"\n....TWT Not initialized on device under {self.wait_for_response_time} seconds Duration....\n"

                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                return

            if self.test_case == '113739':
                try:
                    self.wifi_dut.interfaces.wifi.set_twt(
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
                        negotiation_type=WiFiTwtNegotiationType.Individual)
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
                                                              negotiation_type=WiFiTwtNegotiationType.Individual)
                        events = self.wifi_dut.interfaces.wifi.get_async_events()
                        # twt_setup_success_event = [event for event in events if
                        #                            event.event_type == AsyncEventIdentifiers.WIFI_TWT_RESPONSE_EVENT]
                    #     if len(twt_setup_success_event):
                    #         logger().info("***** TWT is set successfully for second time *****")
                    #         self.indicate_twt_success_response = True
                    #         break
                    # assert self.indicate_twt_success_response, f"\n....TWT Not initialized on device under {self.wait_for_response_time} seconds Duration....\n"

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

            # Set wake_duration_time

            self.wake_duration_time = 256

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
            #
            # # Call get_twt_params API for response frames
            self.get_twt_params(filter=0)

            # Call wake_interval_and_wake_period for request frames
            self.wake_interval_and_wake_period(filter=0)

            if self.test_case != '113760' and self.test_case != '113761':
                # Sleep for 10 minutes
                logger().info(f'**** Pinging for {self.time_duration} seconds ****')

                start_time = time.time()
                while (time.time() - start_time) < self.time_duration:
                    self.zephyr_wifi_collections.ping_with_custom_interval(device_ip=self.dut_addr['device_ip'],
                                                                           interval=int(
                                                                               self.wake_interval_resp) // 10000000)
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
                packet_filter1=f'wlan.fixed.timestamp >= {int(self.target_wake_time)} && (wlan.ta == {self.ap_mac_address})')

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

    def _validate_twt_request_response_packets(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
            filter_name="twt_requesting_sta_1")
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=self.dut_addr['dut_mac_address'], sa_addr=self.ap_mac_address,
            filter_name="twt_responding_sta_0")
        logger().info(f'***** twt_requesting_sta_1 = {packet_filter1}')
        logger().info(f'***** twt_responding_sta_0 = {packet_filter2}')
        self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                packet_filter2=self.second_level_filter)
        self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2,
                                                                packet_filter2=self.second_level_filter)

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
                                            ttl=self.time_duration, throughput_type=1, qos=0,
                                            timeout=self.time_duration + 100)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_twt_in_assoc_req_c113725(wifi_dut, wifi_access_point, zephyr_wifi_collections,
                                                     wifi_sniffer,
                                                     sniffer_filter, utf_constants):
    """Verify whether DUT is able to send TWT requester capability in Assoc req packet when TWT support is enabled"""
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113725',
                                 before_join=True, utf_constants=utf_constants, sniffer_capture='113725',
                                 setup_cmd=WiFiTwtSetupCmd.Request, dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", 'disable_twt'])
def test_wifi_zephyr_verify_twt_request_c113730(wifi_dut, wifi_access_point,
                                                zephyr_wifi_collections, wifi_sniffer,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113730',
                                 power_save=True,
                                 utf_constants=utf_constants, setup_cmd=WiFiTwtSetupCmd.Request, dialog_token=0,
                                 flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", 'disable_twt'])
def test_wifi_zephyr_verify_twt_setup_after_sta_disconnect_reconnect_c1912308(wifi_dut, wifi_access_point,
                                                                              zephyr_wifi_collections, wifi_sniffer,
                                                                              sniffer_filter, utf_constants):
    """Verify that the DUT can establish a TWT agreement again after an intentional STA-initiated disconnect from the
    AP, followed by a reconnect"""
    """
    Test Steps:
        1. Join the AP and establish initial TWT agreement with request parameters
        2. Enable power-save mode and validate first TWT request/response frames
        3. Intentionally disconnect the DUT from the AP using leave()
        4. Reconnect the DUT to the AP
        5. Establish TWT agreement again with the same parameters
        6. Validate TWT request/response frames and DUT wake behavior after reconnect
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='1912308',
                                 power_save=True, test_case='1912308', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Request, dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", 'disable_twt'])
def test_wifi_zephyr_verify_twt_suggest_c113731(wifi_dut, wifi_access_point,
                                                zephyr_wifi_collections, wifi_sniffer,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113731',
                                 power_save=True, test_case='113731', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Suggest,
                                 dialog_token=0, flow_id=1, negotiation_type=WiFiTwtNegotiationType.Individual,
                                 responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_twt_demand_c113732(wifi_dut, wifi_access_point,
                                               zephyr_wifi_collections, wifi_sniffer,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                 power_save=True, test_case='113732', utf_constants=utf_constants,
                                 sniffer_capture='113732', setup_cmd=WiFiTwtSetupCmd.Demand,
                                 dialog_token=0, flow_id=1, negotiation_type=WiFiTwtNegotiationType.Individual,
                                 responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=25000, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=69, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_alternate_twt_setup_c113736(wifi_dut,
                                                        wifi_access_point,
                                                        zephyr_wifi_collections,
                                                        wifi_sniffer,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                 power_save=True, test_case='113736', utf_constants=utf_constants,
                                 sniffer_capture='113736', setup_cmd=WiFiTwtSetupCmd.Suggest,
                                 dialog_token=5, flow_id=1, negotiation_type=WiFiTwtNegotiationType.Individual,
                                 responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=25000, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_whether_dut_able_to_teardown_with_second_twt_enablement_c113738(wifi_dut,
                                                                                            wifi_access_point,
                                                                                            zephyr_wifi_collections,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113738',
                                 power_save=True, test_case='113738', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_whether_dut_able_to_send_implicit_twt_after_sending_explicit_twt_c113743(wifi_dut,
                                                                                                     wifi_access_point,
                                                                                                     zephyr_wifi_collections,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113743',
                                 power_save=True, test_case='113743', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.set_twt(setup_cmd=WiFiTwtSetupCmd.Request,
                                         dialog_token=0,
                                         flow_id=1,
                                         negotiation_type=WiFiTwtNegotiationType.Individual,
                                         responder=0,
                                         implicit=0,
                                         trigger=0,
                                         announce=0,
                                         wake_interval=32768,
                                         info_disable=1,
                                         exponent=13,
                                         mantissa=7500,
                                         wake_ahead=0,
                                         expected_status=SLStatus.SL_STATUS_FAIL)
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_whether_dut_able_to_setup_announced_twt_c113744(wifi_dut, wifi_access_point,
                                                                            zephyr_wifi_collections, wifi_sniffer,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113744',
                                 power_save=True, test_case='113744', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0,
                                 announce=1, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_whether_dut_able_to_setup_unannounced_twt_c113745(wifi_dut, wifi_access_point,
                                                                              zephyr_wifi_collections, wifi_sniffer,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113745',
                                 power_save=True, test_case='113745', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0,
                                 announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_whether_dut_able_to_setup_announced_and_triggered_twt_c113746(wifi_dut,
                                                                                          wifi_access_point,
                                                                                          zephyr_wifi_collections,
                                                                                          wifi_sniffer,
                                                                                          sniffer_filter,
                                                                                          utf_constants):
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113746',
                                 power_save=True, test_case='113736', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=1,
                                 announce=1, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_whether_dut_able_to_setup_unannounced_and_triggered_twt_c113747(wifi_dut,
                                                                                            wifi_access_point,
                                                                                            zephyr_wifi_collections,
                                                                                            utf_constants,
                                                                                            wifi_sniffer,
                                                                                            sniffer_filter):
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113747',
                                 power_save=True, test_case='113747', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=1,
                                 announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_whether_dut_able_to_create_twt_within_wake_interval_exponent_c113750(wifi_dut,
                                                                                                 wifi_access_point,
                                                                                                 zephyr_wifi_collections,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113750',
                                 utf_constants=utf_constants, sniffer_capture='113750',
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0, announce=0, wake_interval=32768, info_disable=1,
                                 exponent=10, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_whether_dut_able_to_create_twt_within_wake_interval_mantissa_c113752(wifi_dut,
                                                                                                 wifi_access_point,
                                                                                                 zephyr_wifi_collections,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113752',
                                 utf_constants=utf_constants, sniffer_capture='113752',
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0, announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=8000, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.skip()
def test_wifi_zephyr_verify_whether_dut_able_to_setup_twt_after_rejoin_c113754(wifi_dut,
                                                                               wifi_access_point,
                                                                               zephyr_wifi_collections,
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
                                 zephyr_wifi_collections=zephyr_wifi_collections, test_case='113754',
                                 sniffer_capture='113754',
                                 wake_duration=0x90, wake_duration_tol=0x90, before_join=True,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, switch=switch,
                                 power_save=True, twt_retry_limit=10, utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.skip()
def test_wifi_zephyr_verify_twt_when_device_idle_for_long_hours_c113761(wifi_dut, wifi_access_point,
                                                                        zephyr_wifi_collections, wifi_sniffer,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113761', wake_duration=0xF0,
                                 wake_duration_tol=0x90, wake_int_mantissa=0x37D0, wake_int_mantissa_tol=0x37D0,
                                 utf_constants=utf_constants, sniffer_capture='113761')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.skip()
def test_wifi_zephyr_verify_twt_tcp_data_transfer_for_long_hours_c113760(wifi_dut, wifi_access_point,
                                                                         zephyr_wifi_collections,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113760', wake_duration=0xF0, wake_duration_tol=0x90,
                                 wake_int_mantissa=0x37D0, wake_int_mantissa_tol=0x37D0, utf_constants=utf_constants,
                                 sniffer_capture='113760', net_perf_client=net_perf_client, wifi_client=wifi_client)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
@pytest.mark.skip()
def test_wifi_zephyr_verify_whether_dut_able_to_setup_twt_with_bg_scan_after_join_c113764(wifi_dut,
                                                                                          wifi_access_point,
                                                                                          zephyr_wifi_collections,
                                                                                          wifi_sniffer,
                                                                                          sniffer_filter,
                                                                                          utf_constants):
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='113764',
                                 power_save=True, test_case='113764', utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_verify_whether_dut_able_to_send_error_when_different_flow_id_is_provided_c540488(wifi_dut,
                                                                                                      wifi_access_point,
                                                                                                      zephyr_wifi_collections,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='540488',
                                 power_save=True, test_case='540488', utf_constants=utf_constants,
                                 setup_cmd=WiFiTwtSetupCmd.Request,
                                 dialog_token=0, flow_id=1,
                                 negotiation_type=WiFiTwtNegotiationType.Individual, responder=0, implicit=1,
                                 trigger=0, announce=0, wake_interval=32768, info_disable=1,
                                 exponent=13, mantissa=7500, wake_ahead=0, timeout_ms=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_verify_whether_dut_able_to_send_error_when_disable_twt_without_enable_twt_c540489(wifi_dut,
                                                                                                       wifi_access_point,
                                                                                                       zephyr_wifi_collections,
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
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, sniffer_capture='540489',
                                 power_save=True, test_case='540489', utf_constants=utf_constants)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN', "standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.skip()
def test_wifi_zephyr_verify_tcp_keep_alive_functionality_twt_enabled_with_LI_900ms_c586161(wifi_dut,
                                                                                           wifi_access_point,
                                                                                           zephyr_wifi_collections,
                                                                                           wifi_sniffer,
                                                                                           sniffer_filter,
                                                                                           utf_constants,
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
                                 zephyr_wifi_collections=zephyr_wifi_collections,
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

        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'],
                                                        ap_mac, sniffer_filter)
        logger().info(f"Starting the Keep Alive Validation with duration {keepalive_time} seconds")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wlan_obj.dut_addr['dut_mac_address'],
            ra_addr=ap_mac, filter_name="keep_alive")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], f"Keep alive packets not found in sniffer packets"

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_twt_setup_teardown_tcp_loop_c1912309(wifi_dut, wifi_access_point,
                                                          zephyr_wifi_collections, wifi_sniffer,
                                                          sniffer_filter, remote_socket,
                                                          wifi_client):
    """Verify TWT setup, 3-minute wait, teardown, and TCP data transfer in a loop for 30 minutes"""
    """
    Test Steps:
        1. Configure and start sniffer capture
        2. Join the AP
        3. For 30 minutes, repeat:
           a. Establish TWT agreement (request parameters per c113730)
           b. Wait 3 minutes with TWT active
           c. Tear down TWT session
           d. Create TCP socket and send 100 packets (per c19347)
        4. Stop sniffer capture and validate power-save frames
    """
    sniffer_started = False
    try:
        port = TWT_TCP_PORT
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='1912309')
        sniffer_started = True

        dut_addr = zephyr_wifi_collections.join_to_wifi_network(
            wifi_dut,
            wifi_access_point=wifi_access_point,
            associated=wifi_dut.interfaces.wifi.associated)
        wifi_dut.interfaces.wifi.wifi_ps(enabled=1)
        time.sleep(2)

        sw = Stopwatch()
        iteration = 0
        while sw.elapsed_sec <= TWT_TCP_LOOP_DURATION_SECONDS:
            iteration += 1
            remaining_min = int((TWT_TCP_LOOP_DURATION_SECONDS - sw.elapsed_sec) / 60)
            logger().info(
                f"*************** Iteration {iteration}: remaining test time ~{remaining_min} minutes ***************")

            logger().info("***** TWT setup *****")
            configure_twt_setup(wifi_dut)

            logger().info(f"***** Waiting {TWT_WAIT_SECONDS // 60} minutes with TWT active *****")
            time.sleep(TWT_WAIT_SECONDS)

            logger().info("***** TWT teardown *****")
            configure_twt_teardown(wifi_dut)

            logger().info(f"***** TCP open/send/close — {TWT_TCP_PACKET_COUNT} packets *****")
            tcp_open_send_close_100_packets(wifi_dut, remote_socket, dut_addr['device_ip'], server_ip, port=port)

        logger().info(f"Completed {iteration} TWT setup/teardown/TCP iterations in 30 minutes")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_started = False
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_addr['dut_mac_address'], da_addr=ap_mac_address, filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
            'Sniffer: Unable to find power management bit 1 in sniffer'

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if sniffer_started:
            logger().info("Stop the sniffer (cleanup)")
            wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 0})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_verify_twt_setup_fails_when_ap_twt_disabled_c1912310(wifi_dut, wifi_access_point,
                                                                          zephyr_wifi_collections, wifi_sniffer,
                                                                          sniffer_filter):
    """[Neg] Ensure TWT setup returns a failure when TWT is disabled on the access point"""
    """
    Test Steps:
        1. Configure the access point with TWT disabled
        2. Configure and start sniffer capture
        3. Join the DUT to the access point
        4. Attempt TWT setup with request parameters (per c113730)
        5. Verify TWT setup returns SL_STATUS_FAIL
        6. Stop sniffer capture
    """
    sniffer_started = False
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='1912310')
        sniffer_started = True

        zephyr_wifi_collections.join_to_wifi_network(
            wifi_dut,
            wifi_access_point=wifi_access_point,
            associated=wifi_dut.interfaces.wifi.associated)
        wifi_dut.interfaces.wifi.set_twt(**TWT_SETUP_KWARGS,
                                         expected_status=SLStatus.SL_STATUS_FAIL)
        logger().info("***** TWT setup failed as expected when AP TWT is disabled *****")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_started = False

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if sniffer_started:
            logger().info("Stop the sniffer (cleanup)")
            wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_zephyr_verify_twt_setup_before_ipconfig_c1912312(wifi_dut, wifi_access_point,
                                                               zephyr_wifi_collections, wifi_sniffer,
                                                               sniffer_filter, wifi_client):
    """Verify whether DUT is able to create TWT setup when it is given before IPCONFIG"""
    """
    Test Steps:
        1. Configure and start sniffer capture
        2. Join the AP without DHCP (ip_config_disable)
        3. Wait 10 seconds after association
        4. Establish TWT setup before IP configuration
        5. Assign static IPv4 address to DUT (per c49347)
        6. Ping DUT for 3 iterations using TWT wake interval (per lines 474-480)
    """
    sniffer_started = False
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='1912312')
        sniffer_started = True

        dut_addr = zephyr_wifi_collections.join_to_wifi_network(
            wifi_dut,
            wifi_access_point=wifi_access_point,
            associated=wifi_dut.interfaces.wifi.associated,
            ip_config_disable=1)
        logger().info(f"DUT associated, MAC: {dut_addr['dut_mac_address']}")

        logger().info("***** Waiting 10 seconds after association *****")
        time.sleep(10)

        logger().info("***** TWT setup before IP configuration *****")
        configure_twt_setup(wifi_dut)
        wifi_dut.interfaces.wifi.wifi_ps(enabled=1)
        time.sleep(2)

        device_ip = assign_static_ipv4_to_dut(wifi_dut, wifi_client)

        wake_interval_resp = get_twt_wake_interval_from_setup_kwargs()
        ping_interval = int(wake_interval_resp) // 10000000
        logger().info(f'**** Pinging DUT for 3 iterations with interval {ping_interval} seconds ****')
        for iteration in range(1, 4):
            logger().info(f'**** Ping iteration {iteration}/3 with interval {ping_interval} seconds ****')
            zephyr_wifi_collections.ping_with_custom_interval(device_ip=device_ip,
                                                              interval=ping_interval)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_started = False

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        dhcp_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_addr['dut_mac_address'], da_addr=ap_mac_address, filter_name='dhcp_discover')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=dhcp_filter)['packet_count'] == 0, \
            'Able to find the dhcp discover packets in the sniffer capture which is not expected'

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if sniffer_started:
            logger().info("Stop the sniffer (cleanup)")
            wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "twt": 1})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_verify_twt_setup_fails_before_connection_c1912313(wifi_dut, wifi_access_point,
                                                                       zephyr_wifi_collections, wifi_sniffer,
                                                                       sniffer_filter):
    """[Neg] Verify TWT setup fails when NET_REQUEST_WIFI_TWT is executed before connection"""
    """
    Test Steps:
        1. Configure and start sniffer capture
        2. Ensure DUT is initialized but not connected to the AP
        3. Attempt TWT setup before connection with request parameters (per c113730)
        4. Verify TWT setup returns SL_STATUS_FAIL
        5. Stop sniffer capture
    """
    sniffer_started = False
    try:
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='1912313')
        sniffer_started = True

        assert not wifi_dut.interfaces.wifi.associated, "DUT must not be connected before TWT setup attempt"
        wifi_dut.interfaces.wifi.set_twt(**TWT_SETUP_KWARGS,
                                         expected_status=SLStatus.SL_STATUS_FAIL)
        logger().info("***** TWT setup failed as expected when executed before connection *****")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_started = False

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if sniffer_started:
            logger().info("Stop the sniffer (cleanup)")
            wifi_sniffer.interfaces.capture.stop_capture()
