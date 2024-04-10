import pytest
import time
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap
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


# Define logger
def logger():
    return get_logger(__name__)


class WLanTwTThread(ThreadBase):
    def __init__(self, twt_enable=1, twt_flow_id=1, wake_duration=0x60, wake_duration_unit=0, wake_duration_tol=0x60,
                 wake_int_exp=13, wake_int_exp_tol=13, wake_int_mantissa=0x1D4C, wake_int_mantissa_tol=0x1D4C,
                 implicit_twt=1, un_announced_twt=1, triggered_twt=0, twt_channel=0, twt_protection=0, 
                 restrict_tx_outside_tsp=1, twt_retry_limit=6, twt_retry_interval=10, req_type=1, negotiation_type=0, 
                 wifi_dut=None, sl_collections=None, wifi_sniffer=None, wifi_access_point=None, 
                 test_case=None, sniffer_filter=None, open_tcp_socket=False, power_save=False):
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

        self.mantissa_resp = None
        self.wake_interval_exponent_resp = None
        self.minimum_wake_duration_resp = None

        self.wake_interval_resp = None
        self.wake_period_resp = None

        self.sniffer_filter = sniffer_filter
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

    def run(self):
        try:
            # Configure the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.configure_interface(self.wifi_access_point.interfaces.wifi.channel)
            # Start the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.start_capture(self.test_case)
            # Get the mac address of the wifi_access_point
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid

            if self.test_case == '113725':
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
            
            if self.test_case != '113725':

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
            
            # Sleep for 6 minutes
            time.sleep(300)

            # Stop the capture
            self.wifi_sniffer.interfaces.capture.stop_capture()

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
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="twt_assoc_request_frame")
            
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

            # Do power save validation after checking power_save variable
            if self.power_save:
                self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="power_mgmt_bit")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.power_save_filter)[
                    'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"
                
            # assert some packets are captured        
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=self.packet_filter3)[
                'packet_count'], f"DUT is not able to send TWT association request frame to AP"
            
            # Call set_twt API by checking test case
            if self.test_case == '113738':
                self.wifi_dut.interfaces.wifi.set_twt(expected_status=SLStatus.SL_STATUS_TWT_SETUP_ERR_SESSION_ACTIVE)
                logger().info("***** TWT session is active, so unable to set TWT again")
                logger().info("**** Getting 0x10071 error code which is expected ****")
                return
            
            # Check whether we need to open the tcp socket
            if self.open_tcp_socket:
                self.socket_id = self.wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")
                logger().info(f"Socket open successfully : {self.socket_id}")
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
            target_wake_time = int(re.findall(r'((?<=Target Wake Time:\s)\d+)', content)[0])
            logger().info(f"***** Target Wake Time Resp = {target_wake_time}")

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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_verify_twt_in_assoc_req_c113725(wifi_dut, wifi_access_point, sl_collections, wifi_sniffer,
                                                  sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113725')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_verify_twt_functionality_when_enabled_through_join_c113726(wifi_dut, wifi_access_point,
                                                                             sl_collections, wifi_sniffer,
                                                                             sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='113725')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_verify_twt_request_when_enabled_before_join_c113727(wifi_dut, wifi_access_point, sl_collections, wifi_sniffer,
                                                                      sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Run the thread
        3. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113725', req_type=0, open_tcp_socket=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_verify_twt_suggest_when_enabled_before_join_c113728(wifi_dut, wifi_access_point, sl_collections, wifi_sniffer,
                                                                      sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113725', req_type=1, open_tcp_socket=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_demand_when_enabled_before_join_c113729(wifi_dut, wifi_access_point,
                                                                     sl_collections, wifi_sniffer,
                                                                     sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, power_save=True,
                                 test_case='113725', req_type=2, open_tcp_socket=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", 'disable_twt'])
def test_wifi_sdk_verify_twt_request_when_enabled_after_join_c113730(wifi_dut, wifi_access_point,
                                                                     sl_collections, wifi_sniffer,
                                                                     sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                 power_save=True, test_case='113730', req_type=0, open_tcp_socket=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", 'disable_twt'])
def test_wifi_sdk_verify_twt_suggest_when_enabled_after_join_c113731(wifi_dut, wifi_access_point,
                                                                      sl_collections, wifi_sniffer,
                                                                      sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                 power_save=True, test_case='113731', req_type=1, open_tcp_socket=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_twt_demand_when_enabled_after_join_c113732(wifi_dut, wifi_access_point,
                                                                    sl_collections, wifi_sniffer,
                                                                    sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, req_type=2,
                                 power_save=True, test_case='113732', open_tcp_socket=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_whether_dut_able_to_teardown_with_second_twt_enablement_c113738(wifi_dut, wifi_access_point,
                                                                                         sl_collections, wifi_sniffer,
                                                                                         sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                 power_save=True, test_case='113738')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")
        

@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_whether_dut_able_to_setup_implicit_twt_c113742(wifi_dut, wifi_access_point,
                                                                        sl_collections, wifi_sniffer,
                                                                        sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                 power_save=True, test_case='113742', implicit_twt=1, open_tcp_socket=True)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")
        

@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_whether_dut_able_to_setup_unannounced_twt_c113744(wifi_dut, wifi_access_point,
                                                                           sl_collections, wifi_sniffer,
                                                                           sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, open_tcp_socket=True,
                                 power_save=True, test_case='113744', un_announced_twt=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_whether_dut_able_to_setup_announced_twt_c113745(wifi_dut, wifi_access_point,
                                                                         sl_collections, wifi_sniffer,
                                                                         sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, open_tcp_socket=True,
                                 power_save=True, test_case='113736', un_announced_twt=1)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")
        
        
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "disable_twt"])
def test_wifi_sdk_verify_whether_dut_able_to_setup_announced_and_triggered_twt_c113746(wifi_dut, wifi_access_point,
                                                                                       sl_collections, wifi_sniffer,
                                                                                       sniffer_filter):
    """
    Test Steps:
        1. Create thread for twt functionality
        2. Enable powersave mode
        3. Run the thread
        4. Exit the thread
    """
    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, open_tcp_socket=True,
                                 power_save=True, test_case='113736', un_announced_twt=0, triggered_twt=1)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wlan_obj.wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=wlan_obj.socket_id)
    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")

