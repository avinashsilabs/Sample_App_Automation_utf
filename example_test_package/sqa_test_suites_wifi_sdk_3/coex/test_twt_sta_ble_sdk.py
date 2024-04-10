import pytest
import time
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, Si91xBLECustomFeatureBitMap
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
        6. Validate BLE Functioanlity

    Author: Saurabh Sharma

"""


# Define logger
def logger():
    return get_logger(__name__)


class WLanTwTThread(ThreadBase):
    def __init__(self, twt_enable=1, twt_flow_id=1, wake_duration=0x40, wake_duration_unit=0, wake_duration_tol=0x40,
                 wake_int_exp=13, wake_int_exp_tol=13, wake_int_mantissa=0x2B3, wake_int_mantissa_tol=0x2B3,
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

            if self.test_case == '198619':
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

            if self.test_case != '198619':
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
                self.socket_id = self.wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                           protocol="IPPROTO_TCP")
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


class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, test_case=None,
                 ble_dut=None, ble_pairing=0, switch=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.ble_pairing = ble_pairing
        self.switch = switch

    def run(self):
        """ *************************** Set up DUT for BLE advertising ***************************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

        if self.test_case == '198619':
            self.sl_collections.check_ble_advertise_functionality(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address, timeout=20)
            self.ble_client.interfaces.bluetooth.close()
            time.sleep(3)
            self.sl_collections.check_ble_scan_functionality(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_address=self.ble_dut_address, timeout=20)
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            time.sleep(2)

        if self.test_case == '198621':
            self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address, timeout=20,
                mode='master')
        if self.test_case == '198622':
            logger().info(f"Advertising the DUT")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)
            self.sl_collections.scan_and_connect_from_remote(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                ble_pairing=self.ble_pairing)

    def ble_disconnect(self, disconnect_from="remote"):
        self.sl_collections.ble_disconnect(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                           ble_dut_address=self.ble_dut_address,
                                           disconnect_from=disconnect_from, ble_client_address=self.ble_client_address)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
            "oper_mode": Si91xOperatingMode.WiFiClient,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        }
    )
]


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "ble_stop_adv"])
def test_wifi_sdk_verify_twt_ble_scan_adv_c198619(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client):

    """Verify whether DUT is able to perform BLE Scan and advertising after setting the TWT Interval before WLAN join"""

    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='198619')
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, test_case='198619')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "ble_stop_adv"])
def test_wifi_sdk_verify_twt_ble_scan_adv_c198620(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client):

    """Verify whether DUT is able to perform BLE Scan and advertising if we set the TWT Interval after WLAN Join"""

    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='198620')
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, test_case='198619')
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.start()
        ble_obj.wait_for_exit()

    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_verify_twt_after_ble_master_c198621(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client):

    """Verify whether DUT is able setup the Suggested TWT with AP after the BLE Master connection."""

    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='198619')
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, test_case='198621')
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.ble_disconnect()

    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")


@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "ble_stop_adv"])
def test_wifi_sdk_verify_twt_after_ble_slave_c198622(
        wifi_dut, wifi_access_point, sl_collections, wifi_sniffer, sniffer_filter, ble_dut, ble_client):

    """Verify whether DUT is able to setup the Requested TWT with AP Before WLAN Join command with BLE As slave"""

    try:
        wlan_obj = WLanTwTThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, sl_collections=sl_collections,
                                 wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, req_type=0,
                                 test_case='198619')
        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, sl_collections=sl_collections, ble_pairing=0,
                                         ble_dut=ble_dut, ble_client=ble_client, test_case='198622')
        ble_obj.start()
        ble_obj.wait_for_exit()
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="remote")

    except Exception as Ex:
        logger().info(f"Exception occurred: {Ex}")
