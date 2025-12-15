import binascii
import hashlib
import pytest
import time
import re
from datetime import datetime, date
from utf.interfaces.wifi.fixtures import wifi_client
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xPowerSaveModes, Si91xJoinFeatureBitMap, \
    Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. Soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        3. Enable the WPS push button mode on the access point and on DUT as well
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    Author: Sakshi Agrawal

"""


class WPSThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, ping_count=None, test_case=None, sniffer_filter=None,
                 sl_collections=None, power_save=None, auto_connect=True, wifi_sniffer=None,
                 wifi_client=None, switch=None, leave=True, stop_capture=True, run_time=30):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None
        self.ap_addr = None
        self.power_save = power_save
        self.auto_connect = auto_connect
        self.wifi_client = wifi_client
        self.switch = switch
        self.leave = leave
        self.stop_capture = stop_capture
        self.run_time = run_time
        self.device_ip = None

    def delta_between_dhcp_req_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff

    def generate_psk(self):
        ssid = self.wifi_access_point.interfaces.wifi.ssid
        passphrase = self.wifi_access_point.interfaces.wifi.passphrase

        ssid_bytes = ssid.encode('utf-8')
        passphrase_bytes = passphrase.encode('utf-8')

        iterations = 4096
        key_length = 32

        psk_bytes = hashlib.pbkdf2_hmac('sha1', passphrase_bytes, ssid_bytes, iterations, key_length)
        psk_hex = binascii.hexlify(psk_bytes).decode('ascii').upper()
        logger().info(f"\n Generated PSK (hex) using AP ssid and passphrase: {psk_hex} \n")
        return psk_hex

    def verify_response_structure(self, data):
        """This function is responsible for verifying the WPS response structure and validating against AP configuration"""

        required_fields = ['status', 'ssid', 'ssid_length', 'security_type', 'key', 'ap_mac_address', 'reserved']

        for field in required_fields:
            assert field in data, f"{field} field is missing in WPS response structure"
        logger().info(f"\n **** WPS response structure verification completed ****\n")

        ap_ssid = self.wifi_access_point.interfaces.wifi.ssid
        ap_passphrase = self.wifi_access_point.interfaces.wifi.passphrase
        ap_security = self.wifi_access_point.interfaces.wifi.security.name.lower()
        ap_mac = self.wifi_access_point.interfaces.wifi.bssid
        ap_psk = self.generate_psk()

        if self.test_case == "922293":
            ap_security = "wpa2"

        logger().info(f"\n AP Configuration - SSID: {ap_ssid}, Security: {ap_security}, MAC: {ap_mac} \n ")
        security_mapping = {
            'open': '0x00',
            'wpa': '0x01',
            'wpa2': '0x02',
        }
        assert data['ssid'] == ap_ssid, f"SSID mismatch: WPS response '{data['ssid']}' != AP SSID '{ap_ssid}'"
        logger().info(f"SSID validation successful: '{data['ssid']}' matches AP SSID '{ap_ssid}'")

        if ap_security != 'open':
            assert data[
                       'key'].upper() == ap_psk, f"Passphrase mismatch: WPS response key '{data['key']}' != AP PSK '{ap_psk}'"
            logger().info(f"Passphrase validation successful: '{data['key']}' matches AP passphrase")

        assert data['security_type'] == security_mapping.get(
            ap_security), f"Security type mismatch: WPS response '{data['security_type']}' != Expected corresponding AP security '{ap_security}'"
        logger().info(
            f"Security type validation successful: WPS response '{data['security_type']}' matches AP security '{ap_security}'")

        assert data['ap_mac_address'].replace(':', '').upper() == ap_mac.replace(':',
                                                                                 '').upper(), f"MAC address mismatch: WPS response '{data['ap_mac_address']}' != AP MAC '{ap_mac}'"
        logger().info(
            f"AP MAC address validation successful: WPS response '{data['ap_mac_address']}' matches AP MAC '{ap_mac}'")

        assert data['status'] == '0x00000000', f"WPS operation failed with status: {data['status']}"

        logger().info(f"\n **** WPS response validation against AP configuration completed successfully ****\n")

    def negative_sniffer_validation(self, beacon=True, probe_req=True, assoc_req=True, assoc_resp=True):
        logger().info(f"\n ============== WPS Sniffer validation started ============= \n")

        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.ap_addr,
                                                                                             filter_name='ap_wps_pbc_beacon')
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.dut_addr,
                                                                                             filter_name='dut_wps_pbc_probe_req')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.dut_addr,
                                                                                             filter_name='dut_wps_assoc_req')
        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.ap_addr,
                                                                                             filter_name='ap_wps_assoc_resp')
        if beacon:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], \
                'Sniffer:Found beacon frame with WPS PBC enabled from AP, but expected not to find'
            logger().info("\n ****************** Beacon frame with WPS PBC not found as expected ****************** \n")

        if probe_req:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
                'packet_count'], \
                'Sniffer:Found probe request frame with WPS PBC enabled from DUT, but expected not to find'
            logger().info(
                "\n ****************** Probe request frame with WPS PBC not found as expected ****************** \n")

        if assoc_req:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
                'packet_count'], \
                'Sniffer:Found WPS association request frame from DUT, but expected not to find'
            logger().info(
                "\n ****************** WPS association request frame not found as expected ****************** \n")

        if assoc_resp:
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
                'packet_count'], \
                'Sniffer:Found WPS association response frame from AP, but expected not to find'
            logger().info(
                "\n ****************** WPS association response frame not found as expected ****************** \n")

    def wps_pbc_sniffer_validation(self, beacon=True, probe_req=True, assoc_req=True, assoc_resp=True,
                                   power_mgmt_bit=True):
        logger().info(f"\n ============== WPS Sniffer validation started ============= \n")

        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.ap_addr,
                                                                                             filter_name='ap_wps_pbc_beacon')
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.dut_addr,
                                                                                             filter_name='dut_wps_pbc_probe_req')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.dut_addr,
                                                                                             filter_name='dut_wps_assoc_req')
        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr=self.ap_addr,
                                                                                             filter_name='ap_wps_assoc_resp')
        packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_addr,
                                                                                             da_addr=self.ap_addr,
                                                                                             filter_name='power_mgmt_bit')
        if beacon:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], \
                'Sniffer: Unable to find beacon frame with WPS PBC enabled from AP'
        if probe_req:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
                'packet_count'], \
                'Sniffer: Unable to find probe request frame with WPS PBC enabled from DUT'
        if assoc_req:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
                'packet_count'], \
                'Sniffer: Unable to find WPS association request frame from DUT'
        if assoc_resp:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
                'packet_count'], \
                'Sniffer: Unable to find WPS association response frame from AP'
        if power_mgmt_bit:
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
                'packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '

    def run(self):
        try:
            logger().info(" ====== configuring the Sniffer with access point channel ====== ")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)

            self.dut_addr = self.wifi_dut.interfaces.wifi.get_mac_address()
            self.ap_addr = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"\n **** DUT MAC ADDRESS ={self.dut_addr} ****\n")
            logger().info(f"\n **** AP MAC ADDRESS ={self.ap_addr} ****\n")

            if self.test_case == "893054":
                logger().info(" ====== Disable WPS on Access Point ====== ")
                self.wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=False)
            if self.test_case == "893047":
                logger().info(" ====== Do not start WPS PBC on Access Point ====== ")
                logger().info(" ====== Start WPS PBC on DUT ====== ")
                self.wifi_dut.interfaces.wifi.start_client_wps(auto_connect=self.auto_connect,
                                                               expected_status=SLStatus.SL_STATUS_SI91X_ASSOCIATION_TIMEOUT_IN_P2P_WPS_MODE)

            elif self.test_case == "893052" or self.test_case == "893055":
                logger().info(
                    " ====== Start WPS PBC on DUT with WPS role is incorrectly set to SL_WIFI_WPS_ROLE_REGISTRAR====== ")
                data = self.wifi_dut.interfaces.wifi.start_client_wps(wps_role=1, auto_connect=self.auto_connect,
                                                                      expected_status=SLStatus.SL_STATUS_NOT_SUPPORTED)
            elif self.test_case == "893056":
                logger().info(" ====== Start WPS PBC on DUT and DUT is in concurrent mode ====== ")
                data = self.wifi_dut.interfaces.wifi.start_client_wps(auto_connect=self.auto_connect,
                                                                      expected_status=SLStatus.SL_STATUS_SI91X_WPS_NOT_SUPPORTED)

            elif self.test_case == "893059":
                logger().info(" ====== Start WPS PBC on Access Point ====== ")
                self.wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
                logger().info(" ====== Start WPS PBC on DUT ====== ")
                data = self.wifi_dut.interfaces.wifi.start_client_wps(auto_connect=self.auto_connect,
                                                                      expected_status=SLStatus.SL_STATUS_SI91X_FEATURE_NOT_AVAILABLE)

            elif self.test_case == "893054":
                logger().info(" ====== Start WPS PBC pin method on Access Point ====== ")
                self.wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, pin_value="12345678")
                logger().info(
                    " ====== Start WPS PBC on DUT with WPS Pin method====== ")
                data = self.wifi_dut.interfaces.wifi.start_client_wps(wps_mode=1, auto_connect=self.auto_connect,
                                                                      wps_pin="12345678",
                                                                      expected_status=SLStatus.SL_STATUS_NOT_SUPPORTED)

            elif self.test_case == "922347" or self.test_case == "922348":
                logger().info(
                    " ====== Start WPS PBC on DUT with WPS Pin method====== ")
                data = self.wifi_dut.interfaces.wifi.start_client_wps(null_response=True,
                                                                      auto_connect=self.auto_connect,
                                                                      expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
            elif self.test_case == "893046":
                logger().info(" ====== Start WPS PBC on DUT in one thread ====== ")
                data = self.wifi_dut.interfaces.wifi.start_client_wps(auto_connect=self.auto_connect,
                                                                      expected_status=SLStatus.SL_STATUS_SI91X_ASSOCIATION_TIMEOUT_IN_P2P_WPS_MODE)

            elif self.test_case == "893090":
                logger().info(" ====== Start WPS PBC on Access Point ====== ")
                self.wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)

                logger().info(" ====== Start WPS PBC on DUT ====== ")
                data = self.wifi_dut.interfaces.wifi.start_client_wps(auto_connect=self.auto_connect)
                self.verify_response_structure(data)

            else:
                logger().info(" ====== Start WPS PBC on Access Point ====== ")
                self.wifi_access_point.interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
                if self.test_case == "893051":
                    self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                       passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                       security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                       timeout=60)
                else:
                    logger().info(" ====== Start WPS PBC on DUT ====== ")
                    data = self.wifi_dut.interfaces.wifi.start_client_wps(auto_connect=self.auto_connect)
                    self.verify_response_structure(data)

                if self.auto_connect == False:
                    self.wifi_dut.interfaces.wifi.join(ssid=data['ssid'],
                                                       passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                       security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                       timeout=60)

                ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut, ip_status=False, retry_count=3)
                assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

                self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)

                logger().info(f"\n **** Device IP Address: {self.device_ip} ****\n")
                logger().info(f"\n =========== pinging DUT before power save ===============\n")
                status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                logger().info(f"\n =========== Initiate the ping from DUT to Station ===============\n")
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                self.wifi_dut.interfaces.wifi.ping(server_ip=host_ip, num_ping_attempts=5, )

                if self.power_save:
                    self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                    self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                       psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                    if self.test_case == "893058":
                        logger().info(f"=========== pinging DUT for {self.run_time} seconds  ===============")
                        start_time = time.time()
                        while time.time() - start_time < self.run_time:
                            status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
                            if not status:
                                logger().info("Ping failed")
                                break
                            time.sleep(1)

                    logger().info("=========== pinging DUT after power save ===============")
                    status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
                    assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

                    time.sleep(30)
                    logger().info("=========== Verifying connection status after 30 second delay ========")
                    status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
                    assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

                logger().info(" ====== WPS process completed, verified the connection status ====== ")

                if self.test_case == "893048":
                    time.sleep(5)
                    logger().info("Turning off the AP")
                    self.switch.interfaces.pdu_switch.turn_off(delay=20)
                    logger().info("Again turning on the AP")
                    self.switch.interfaces.pdu_switch.turn_on(delay=100)
                    logger().info("Successfully powered on AP")
                    logger().info("Pinging to DUT to check rejoin process is completed or not")
                    status = self.sl_collections.ping(self.device_ip, 30, 5)
                    assert status, "Pinging to DUT is failed, and STA remains disconnected after reboot AP"

                time.sleep(2)
                if self.leave:
                    logger().info("disconnecting to ap.....")
                    self.wifi_dut.interfaces.wifi.leave()

                time.sleep(2)
                if self.stop_capture:
                    logger().info("Stop Sniffer finally")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


class SecondWPSThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        logger().info(" ====== Start WPS PBC on DUT ====== ")
        data = self.wifi_dut.interfaces.wifi.start_client_wps(expected_status=SLStatus.SL_STATUS_TIMEOUT)


def wifi_dut_marker(ca_cert=None, client_cert=None, thread_count=1):
    config = {
        "thread_config": {"wifi": {"count": thread_count, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNS | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            10),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_pbc_conn_c893042(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                           sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC connection via Software API """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893042",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_pbc_conn_loop_c893043(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC connection via Software API in loop """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893043",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        for i in range(5):
            logger().info(f"\n ===================**** Iteration {i + 1} ****=========================== \n")
            wps_obj.start()
            wps_obj.wait_for_exit()
            wps_obj.wps_pbc_sniffer_validation()
            wifi_access_point.interfaces.wifi.set_configure_wps_web()
            time.sleep(10)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_no_AP_in_PBC_mode_c893047(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the SL_STATUS_SI91X_ASSOCIATION_TIMEOUT_IN_P2P_WPS_MODE error when no AP in PBC mode """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893047",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation(beacon=False, probe_req=True, assoc_req=False, assoc_resp=False,
                                           power_mgmt_bit=False)
        wps_obj.negative_sniffer_validation(beacon=True, probe_req=False, assoc_req=True, assoc_resp=True)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_AP_reboot_c893048(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                            sl_collections, sniffer_filter, request, wifi_client, switch):
    """This test case verifies the STA WPS PBC connection via Software API with AP reboot during WPS process"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893048",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client, switch=switch)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
    finally:
        wifi_access_point.interfaces.wifi.set_configure_wps_web()
        switch.interfaces.pdu_switch.turn_on(delay=60)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_ragistrar_role_c893052(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                             sl_collections, sniffer_filter, request, wifi_client):
    """ This test case verifies when the WPS role is incorrectly set to SL_WIFI_WPS_ROLE_REGISTRAR """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893052",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_auto_conn_false_c893053(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                              sl_collections, sniffer_filter, request, wifi_client):
    """ This test case verifies the STA WPS PBC connection via Software API with auto_connect parameter set to false """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893053",
                            auto_connect=False,
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@pytest.mark.skip("Not Applicable")
@pytest.mark.config("wifi_dut",
                    wifi=
                    {
                        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
                        "oper_mode": Si91xOperatingMode.AccessPoint,
                        "coex_mode": Si91xCoexMode.WLANOnly,
                        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation,
                        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNS | Si91xTCPIPFeatureBitMap.SSL
                                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
                        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
                        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
                        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
                            10),
                        "config_features": 0,
                        "bt_features": 0,
                        "ble_features": 0,
                        "ble_custom_ext_features": 0,
                    })
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_ap_mode_ragistrar_role_c893055(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                     sl_collections, sniffer_filter, request, wifi_client):
    """ This test case verify WPS feature in AP mode and the WPS role is set to SL_WIFI_WPS_ROLE_REGISTRAR """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893055",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.skip("Not Applicable")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNS | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            10),
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "config_features": 0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11
    },
)
@pytest.mark.config("wifi_client",
                    wifi={"security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 11,
                          "interface": "wlan0"})
@pytest.mark.config('wifi_access_point',
                    wifi={'ssid': 'Concurent_ap', 'security': 'WPA2', 'passphrase': 'test1234', 'channel': 11})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_pbc_concurrent_mode_c893056(wifi_access_point, wifi_dut, wifi_client, wifi_sniffer,
                                                  sniffer_filter, utf_constants, sl_collections):
    """ To Verify Dut Behaviour in  STA and AP connection by enabling concurrent mode"""
    try:
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893056",
                            power_save=True, wifi_client=wifi_client, leave=False, stop_capture=True)

        wps_obj.start()
        wps_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_tcp_tx_c893057(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                     protocol, net_perf_client, sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC connection via Software API and TCP TX data Transfer"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893057",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client, leave=False,
                            stop_capture=False)
        wps_obj.start()
        wps_obj.wait_for_exit()

        logger().info(" ====== Starting TCP TX Traffic ====== ")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client,
                                   protocol=protocol, device_ip=wps_obj.device_ip,
                                   host_ip=host_ip, timeout=30, traffic_type="TX")

        logger().info("disconnecting to ap.....")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wps_obj.wps_pbc_sniffer_validation()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_ping_long_run_c893058(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                            sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC connection via Software API and ping long run"""
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        long_run_time = 60
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893058",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client,
                            run_time=long_run_time)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_api_disabled_c893051(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                               sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC when WPS API is disabled """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893051",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation(beacon=True, probe_req=False, assoc_req=False, assoc_resp=True,
                                           power_mgmt_bit=True)
        wps_obj.negative_sniffer_validation(beacon=False, probe_req=True, assoc_req=True, assoc_resp=False)

        logger().info(
            "\n ====== Validate Association Request/Response frames without WPS feature in Sniffer Capture ====== \n")
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wps_obj.dut_addr,
                                                                                       da_addr=wps_obj.ap_addr,
                                                                                       filter_name='assoc_req_resp_eapol_4_way_handshake')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
            'Sniffer: Unable to find the Association Request/Response frames in the capture file'


    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNS | Si91xTCPIPFeatureBitMap.SSL
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            10),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_bit_disabled_c893059(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                               sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC when WPS bit is disabled """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893059",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation(beacon=True, probe_req=False, assoc_req=False, assoc_resp=False,
                                           power_mgmt_bit=False)
        wps_obj.negative_sniffer_validation(beacon=False, probe_req=True, assoc_req=True, assoc_resp=True)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_pin_method_c893054(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                             sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PIN method connection"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893054",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.negative_sniffer_validation(beacon=True, probe_req=True, assoc_req=True, assoc_resp=True)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_pbc_conn_open_security_c893092(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                         sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC connection with OPEN security via Software API """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893092",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_pbc_conn_response_struct_null_c922347(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                utf_constants,
                                                                sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC with response structure as NULL """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="922347",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_sta_wps_response_struct_null_autoconnect_false_c922348(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                         utf_constants,
                                                                         sl_collections, sniffer_filter, request,
                                                                         wifi_client):
    """This test case verifies the STA WPS PBC with response structure as NULL and auto_connect as False"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="922348",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client, auto_connect=False)

        wps_obj.start()
        wps_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(thread_count=2)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_session_lockout_c893046(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                              sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies WPS session lockout mechanism by initiating WPS PBC from DUT while another WPS session is ongoing and NO AP in PBC mode"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893046",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        sec_obj = SecondWPSThread(wifi_dut=wifi_dut)

        wps_obj.start()
        time.sleep(30)
        logger().info("\n =================Starting WPS second thread on DUT====================\n")
        sec_obj.start()
        sec_obj.wait_for_exit()
        wps_obj.wait_for_exit()
        wps_obj.wps_pbc_sniffer_validation(beacon=False, probe_req=True, assoc_req=False, assoc_resp=False,
                                           power_mgmt_bit=False)
        wps_obj.negative_sniffer_validation(beacon=True, probe_req=False, assoc_req=True, assoc_resp=True)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("dhcp_lease", [120])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120", "security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_dhcp_renewal_after_wps_conn_c893091(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                      utf_constants, request, sl_collections, dhcp_lease,
                                                      sniffer_filter):
    """This test case verifies the DHCP renewal process after WPS PBC connection via Software API"""
    time_delta = 60
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    status = None
    wps_obj = WPSThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                        wifi_client=wifi_client, sl_collections=sl_collections, power_save=True, sniffer_filter=sniffer_filter,
                        ping_count=ping_count, test_case="893091", leave=False, stop_capture=False)
    try:
        logger().info(f"Enabling DHCP lease time")
        wifi_access_point.interfaces.wifi.enable_dhcp_ap()
        logger().info(f"\n ========= After setting value of dhcp lease, waiting for 60 sec======== \n")
        time.sleep(60)

        wps_obj.start()
        wps_obj.wait_for_exit()

        logger().info(f"\n ========= Waiting for 300 sec to capture DHCP renewal packets======== \n")
        time.sleep(300)

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        wps_obj.wps_pbc_sniffer_validation()

        device_address = {'sa_addr': wps_obj.dut_addr, 'da_addr': wps_obj.ap_addr,
                          'wlan_addr': wps_obj.dut_addr}
        filters_name = {1: 'power_mgmt_bit', 2: 'dhcp'}
        output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'
        filters_name_1 = {1: 'dhcp_renewal'}
        output_2 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name_1,
                                                                        packet_filter2=packet_filter2)
        logger().info(f'\n OUTPUT 1 = {output_2}\n')
        assert all(output_2.values()), 'Unable to find expected filter'
        dhcp_request_packets_time_delta_list = wps_obj.delta_between_dhcp_req_packet()
        logger().info(f'Probe packet time delta list= {dhcp_request_packets_time_delta_list}')
        dhcp_request_packets_time_delta_list.pop(0)
        logger().info(f'DHCP Req packet time delta list after removing 0 = {dhcp_request_packets_time_delta_list}')

        for time_diff in dhcp_request_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(50, time_delta + 5)
            if is_between is False:
                logger().info(f"{is_between}")
                status = is_between
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
        assert status, 'value is out of range so test case is failed'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.parametrize("dhcp_lease", [60])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_dhcp_discover_failure_after_wps_conn_c893090(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                               sl_collections, sniffer_filter, request, wifi_client,
                                                               dhcp_lease):
    """This test case verifies the DHCP discover failure after WPS PBC connection via Software API"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="893090",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client, stop_capture=False,
                            leave=False)

        wps_obj.start()
        wps_obj.wait_for_exit()

        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.212", dhcp_end="192.168.50.213")
        logger().info(f"\n ========= After setting value of dhcp start and end, waiting for 60 sec======== \n")
        time.sleep(60)

        wifi_dut.interfaces.wifi.start_ip(expected_status=SLStatus.SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE)
        logger().info(f"\n\n Observed the expected error code: 0x1FF9C (SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE) \n\n")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("\n Disconnect DUT ................\n")
        wifi_dut.interfaces.wifi.leave()

        wps_obj.wps_pbc_sniffer_validation(power_mgmt_bit=False)
        logger().info("\n ============== Validating DHCP Discover packets in sniffer capture ============\n")
        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wps_obj.dut_addr,
                                                                                  da_addr=wps_obj.ap_addr,
                                                                                  filter_name='dhcp_discover')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp discover sniffer packets'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2WPA3MixedMode', 'protected_management_frame': 'Capable'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wps_pbc_wpa2_wpa3_PMF_capable_c922293(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                        sl_collections, sniffer_filter, request, wifi_client):
    """This test case verifies the STA WPS PBC connection when AP is configured with wpa2/wpa3 mixed and PMF Capable"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wps_obj = WPSThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case="922293",
                            ping_count=ping_count, power_save=True, wifi_client=wifi_client)

        wps_obj.start()
        wps_obj.wait_for_exit()
        logger().info("\n ====== Validate Beacon frame with PMF capable in Sniffer Capture ====== \n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wps_obj.ap_addr,
                                                                                        filter_name="beacon_pmf")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find beacon frame with PMF capable'

        wps_obj.wps_pbc_sniffer_validation()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
    finally:
        logger().info(" ====== Stop WPS PBC on Access Point ====== ")
        wifi_access_point.interfaces.wifi.set_configure_wps_web()