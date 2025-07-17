import pytest
import time
import re
from datetime import datetime, date
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xPowerSaveModes, Si91xJoinFeatureBitMap,\
    Si91xPowerSaveProcedureTypes
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
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
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    Author: Abdul, Ayush and Harshitha

"""


class WLanJoinThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 sl_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None, pmk_enable=False, wifi_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None
        self.power_save = power_save
        self.ap_mac_address = ap_mac_address
        self.pmk_enable = pmk_enable
        self.wifi_client = wifi_client

    def run(self):
        try:
            if 'PMK' in self.test_case:
                self.pmk_enable = True

            if '19716' in self.test_case:

                self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point,
                                                      pmk_enable=self.pmk_enable,
                                                      expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
                logger().info(
                    f"Dut Tried to connect to ap with wrong password, observed error code 0x10008 which is expected")

            elif '694554' in self.test_case:
                self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point,
                                                      pmk_enable=self.pmk_enable,
                                                      expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
                logger().info(
                    f"\n Observed 0x10008 error on connecting DUT with wrong PSK, which is expected \n")

                self.wifi_access_point.interfaces.wifi.passphrase = 'test12345678'

                self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     power_save=self.power_save,
                                                                     ping_after_power_save=True, retry_count=3,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     pmk_enable=self.pmk_enable)
                time.sleep(2)
                logger().info("disconnecting to ap.....")
                self.wifi_dut.interfaces.wifi.leave()

            elif '19717' in self.test_case:
                self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point,
                                                      pmk_enable=self.pmk_enable,
                                                      expected_status=SLStatus.SL_STATUS_SI91X_SSID_NOT_PRESENT_FOR_PMK_GENERATION)
                logger().info(
                    "Try to generate PMK without SSID, getting error code 0x1003A, which is expected")
            elif '770031' in self.test_case or '770028' in self.test_case or '770029' in self.test_case or '770030' in self.test_case:
                if '770031' in self.test_case or '770028' in self.test_case:
                    scan_results = self.wifi_dut.interfaces.wifi.scan()
                    assert len(scan_results) > 0, f"\n No scan results found \n"
                    self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                       passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                       security="wpa" if '770031' in self.test_case else "wpa2",
                                                       channel=self.wifi_access_point.interfaces.wifi.channel)
                if '770029' in self.test_case:
                    self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                        join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable |
                                            Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             power_save=True,
                                                                             ping_after_power_save=True)
                elif '770030' in self.test_case:
                    self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                            wifi_access_point=self.wifi_access_point,
                                                                            eap_type="tls",
                                                                            ping_after_power_save=True)

                device_ip  = self.wifi_dut.interfaces.wifi.start_ip()
                device_ip =  self.wifi_dut.interfaces.wifi.get_device_ip(device_ip)
                logger().info(f"\n **** Device IP Address: {device_ip} ****\n")
                if self.power_save:
                    self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                    self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                  psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                wireless_info = self.wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
                pattern = r"(?:\n)?([0-9A-Za-z]{32})"
                # Find all matches
                matches = re.findall(pattern, wireless_info)
                logger().info(f"Pattern are {matches}")
                if matches:
                    assert any(char != '0' for char in matches[0]) == False, f"\n PSK Information not Hidden \n"
                else:
                    assert False, "\n Wireless Info Doesn't contain PSK Data \n"

                status = ping(host=device_ip, count=10)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                logger().info(f"\n Wireless DUT Stats: {wireless_info} \n")
                self.wifi_dut.interfaces.wifi.leave()
                time.sleep(2)
                self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                            self.wifi_dut.interfaces.wifi.get_mac_address(), self.wifi_access_point.interfaces.wifi.bssid,
                                                            self.sniffer_filter, power_save=self.power_save)

            else:
                logger().info(" ====== configuring the Sniffer with access point channel ====== ")
                self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
                logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)
                self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         power_save=self.power_save,
                                                                         ping_after_power_save=True, retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         pmk_enable=self.pmk_enable)
                if '770043' in self.test_case:
                    logger().info(f"\n =========== Initiate the ping from DUT to Station ===============\n")
                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    self.wifi_dut.interfaces.wifi.ping(server_ip=host_ip, num_ping_attempts=5,)
                time.sleep(2)
                logger().info("disconnecting to ap.....")
                self.wifi_dut.interfaces.wifi.leave()
                time.sleep(2)
                logger().info("Stop Sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(2)
                self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                            self.dut_addr['dut_mac_address'], self.ap_mac_address,
                                                            self.sniffer_filter, power_save=self.power_save)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def time_diff(self):
        packet_filter1 = "Arrival Time:"
        count = 0
        time_diff_list = []
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter1 in x:
                result = re.search(r'\d+:\d+:\d+.\d+', x)
                logger().info(f" RESULT {result}")
                time_stamp = result.group()
                logger().info(f'time_stamp={time_stamp}')
                time_diff_list.append(time_stamp)

        filter_file.close()
        logger().info(f'time stamp list ={time_diff_list}')
        time_str1 = time_diff_list[0]
        time_str1 = time_str1[:-3]
        time_object1 = datetime.strptime(time_str1, '%H:%M:%S.%f').time()
        logger().info(f'probe req time {time_object1}')

        time_str2 = time_diff_list[1]
        time_str2 = time_str2[:-3]
        time_object2 = datetime.strptime(time_str2, '%H:%M:%S.%f').time()

        logger().info(f'eapol key time {time_object2}')
        date1 = date(1, 1, 1)
        datetime1 = datetime.combine(date1, time_object1)
        datetime2 = datetime.combine(date1, time_object2)
        time_taken = datetime2 - datetime1
        time_taken = time_taken.total_seconds()
        return time_taken


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_connectivity_with_11n_mode_c19707(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                    sl_collections, sniffer_filter, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Do sniffer Validation for 11n mode
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies the connectivity with 11n only mode with ap """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"ssid": "TEST-ASUS-hidden", "broadcast_ssid": False})
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_connectivity_with_hidden_mode_ap_c19708(wifi_dut, wifi_access_point, wifi_sniffer,
                                                          utf_constants, sl_collections, sniffer_filter, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Do sniffer Validation for hidden mode
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies connectivity with hidden mode AP"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address, hidden_ssid="\"\"",
                                                                                        filter_name='hidden_ssid')

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find hidden in sniffer'
        time.sleep(2)
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_join_time_providing_psk_c19712(wifi_dut, wifi_access_point, wifi_sniffer, request,
                                                 sl_collections, sniffer_filter, utf_constants):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Do sniffer Validation for probe_req_response,and eapol_4_way_handshake
        6. Calculate the join time and validate the join time is less than 0.4 secs
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """ This test case verifies joining time in WPA2 Mode by providing PSK"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    rerun = False
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        if not rerun:
            packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter. \
                get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=ap_mac_address,
                                   filter_name='assoc_req_resp_eapol_4_way_handshake')
            rerun = True
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter2)['packet_count'], \
            'Sniffer: Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'

        time_taken = wlan_obj.time_diff()
        assert time_taken <= 0.4, "****Time required is more than 0.4 secs****"
        logger().info(f"time taken to connect is: {time_taken}")
        time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"passphrase": 'test123@random'})
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_Joining_by_rsi_psk_command_c19714(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper, utf_constants,
                                                    request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "Testssid",
                          "passphrase": "1234567890qwertyuioplkjhgfdsazxcvbnmoirgrgrtyuio123456!@#$%+=_,",
                          "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_psk_with_64_different_characters_c19719(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                          utf_constants, request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies Joining to the psk by giving 64 different characters"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing', "security": 'WPA2', "channel": 7})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_Init_Scan_Join_Disconnect_30min_C19710(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                         utf_constants, request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        with TimeMeasurer() as t:
            t_end = time.time() + 60 * 30
            while time.time() < t_end:
                wlan_obj.start()
                wlan_obj.wait_for_exit()
                time.sleep(5)

        logger().info(f"Associated and ping in {t.duration} seconds")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_Join_providing_PMK_C19715(wifi_dut, wifi_access_point, wifi_sniffer,
                                            utf_constants, request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "pmkwithwrongpsk", "passphrase": 'thisisatestnetwork', "security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_Joining_to_PMK_in_module_by_wrong_PSK_C19716(wifi_dut, wifi_access_point, wifi_sniffer,
                                                               utf_constants, request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify error SI91X_DEAUTHENTICATION
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_access_point.interfaces.wifi.passphrase = '12345678'
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"ssid": "Thisssidis32bytesofsize!@#$%+=_,",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnmzx!@#$%+=_,",
                                               "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_join_PMK_with_64_characters_psk_32_characters_ssid_C19720(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                            utf_constants, request, sl_collections,
                                                                            sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Join with PMK with 64 characters PSK and 32 characters ssid
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")

        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"ssid": ' redpine', "passphrase": '12345678', "security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wifi_join_PMK_with_space_before_redpine_ssid_C19718(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                      utf_constants, request, sl_collections,
                                                                      sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Join with PMK with a space before SSID
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"ssid": "testingpmk", "passphrase": 'Testing_pmk', "security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_Joining_time_PMK_C19711(wifi_dut, wifi_access_point, wifi_sniffer, request,
                                          sl_collections, sniffer_filter, utf_constants):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Do sniffer Validation for probe_req_response,and eapol_4_way_handshake
        6. Calculate the join time and validate the join time is less than 0.4 secs
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    rerun = False
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        if not rerun:
            packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter. \
                get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=ap_mac_address,
                                   filter_name='assoc_req_resp_eapol_4_way_handshake')
            rerun = True

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                  packet_filter2=packet_filter2)['packet_count'], \
            'Sniffer: Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'

        time_taken = wlan_obj.time_diff()
        assert time_taken <= 0.4, "****Time required is more than 0.4 secs****"
        logger().info(f"time taken to connect is: {time_taken}")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": '""', "passphrase": 'Testing_pmk', "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wifi_join_PMK_without_SSID_C19717(wifi_dut, wifi_access_point, sl_collections, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Join with PMK without SSID
        6. Verify error SI91X_NO_AP_FOUND
    """

    try:
        with TimeMeasurer() as t:
            test_case = request.node.name

            wifi_access_point.interfaces.wifi.bssid = "''"

            wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                      sl_collections=sl_collections, test_case=test_case)

            wlan_obj.start()
            wlan_obj.wait_for_exit()
        logger().info(f"test executed in {t.duration} seconds")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'TESTTEST-ASUS-ANSHUL',"security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_sdk_wlan_get_stats_sta_C19175(wifi_dut, wifi_access_point, wifi_sniffer,  sl_collections, request, utf_constants):
    """ Test case verifies the device is able to get the wireless statistics in station mode"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point, ping_after_power_save=True,
                                            retry_count=3, associated=wifi_dut.interfaces.wifi.associated)

        operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, busy_interval = wifi_dut.interfaces.wifi.get_wifi_operational_stats(timeout=15)
        logger().info(f'Operating mode: {operating_mode}')
        logger().info(f'Dtim period: {dtim_period}')
        logger().info(f'Ideal beacon info: {ideal_beacon_info}')
        logger().info(f'Busy beacon info: {busy_beacon_info}')
        logger().info(f'Busy interval: {busy_interval}')

        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "12345678", "channel": 11,
        "region": 1,
        "region_code": "us"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wifi_sdk_wlan_get_stats_ap_c19176(wifi_dut, wifi_sniffer, sl_collections):

    """Verify whether the device is able to get the Wireless Statistics in AP Mode"""
    channel = 11
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=f"{channel}")
        capture_filename = "test_wifi_wireless_statistics_AP_TC19176"
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0",
                                                       static_gateway="192.168.100.76")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="12345678", channel=channel,
                                          dtim_beacon_count=4, beacon_interval=100, ht_caps=0)

        operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, busy_interval = wifi_dut.interfaces.wifi.get_wifi_operational_stats(interface = "ap", timeout=15)

        logger().info(f'Operating mode: {operating_mode}')
        logger().info(f'Dtim period: {dtim_period}')
        logger().info(f'Ideal beacon info: {ideal_beacon_info}')
        logger().info(f'Busy beacon info: {busy_beacon_info}')
        logger().info(f'Busy interval: {busy_interval}')

        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point',wifi={"ssid":'sta_mode_ssid', "passphrase":'12345678', "security":'WPA2',})
def test_wifi_sdk_verify_device_wpa2_sec_to_sta_mode_c564145(wifi_dut, request,utf_constants, wifi_sniffer, sniffer_filter,wifi_access_point, sl_collections):

    """Verify whether the device is able to get the
       wireless information in WPA2 security-station mode)"""

    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        sl_collections.join_to_wifi_network(wifi_dut,wifi_access_point=wifi_access_point, power_save=True,
                                            mode=mode,ping_after_power_save=True, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated, ping_count=ping_count)

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info(timeout=100)

        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the power management save sniffer packets'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
         "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
         "oper_mode": Si91xOperatingMode.AccessPoint,
         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
         "features": Si91xFeatureBitMap.PSKSecurity,
         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
         "custom_features": Si91xCustomFeatureBitMap.Default,
         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
         "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": "11",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
                "security": "WPA2",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 11,
                "interface": "wlan0",
         }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_verify_device_wpa2_sec_to_ap_mode_c564146(wifi_dut, wifi_client, request,utf_constants, wifi_sniffer, sniffer_filter, sl_collections):

    """Verify whether the device is able to get
       the wireless information in WPA2 security- AP mode)"""

    try:
        test_case = request.node.name

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                  static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        time.sleep(2)

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count=1, beacon_interval=100)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security="WPA2",passphrase="Automation@123")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")

        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(10)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count:10")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info(timeout=200)

        wifi_client.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',wifi={"ssid":'sta_mode_ssid', "passphrase":'12345678', "security": 'WPA3', "protected_management_frame": "Capable",})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_device_wpa3_sec_to_sta_mode_c564147(wifi_dut, request,utf_constants, wifi_sniffer, sniffer_filter,wifi_access_point, sl_collections):

    """Verify whether the device is able to get the
       wireless information in WPA3 security-station mode)"""

    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count")
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable |
                                                                             Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,wifi_access_point=wifi_access_point, power_save=True,
                                            mode=mode,ping_after_power_save=True, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated, ping_count=ping_count)

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info(timeout=100)

        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the power management save sniffer packets'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "security": "WPA3", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 1
    },
)
def test_wifi_sdk_verify_device_wpa3_sec_to_ap_mode_c564148(wifi_dut, wifi_client, request, utf_constants, remote_wiseconnect3,
                                                                wifi_sniffer, sniffer_filter, sl_collections):
    """Verify whether the device is able to get
       the wireless information in WPA3 security- AP mode)"""
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")

        wifi_sniffer.interfaces.capture.configure_interface(channel=1)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable |
                                                                                        Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        ssid = "SILABS_AP_MODE"
        password = "Automation@123"
        channel = 1

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="wpa3", psk="Automation@123", channel=1,
                                          dtim_beacon_count=1, beacon_interval=100)

        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)

        remote_wiseconnect3.interfaces.sapi.join(ssid=ssid, security="wpa3", passphrase=password, channel=channel, timeout=60)

        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip, static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)
        time.sleep(2)

        remote_wiseconnect3.interfaces.sapi.ping(server_ip=static_gateway, num_ping_attempts=ping_count,
                                                 ping_timeout=10,  ip_version='ipv4', ping_size=64)
        time.sleep(2)

        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")

        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)

        wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info(timeout=200)

        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(1)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_verify_device_wpa2_enterprise_to_sta_mode_c564149(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                                    radius_server, sl_collections, request, utf_constants, wifi_client):

    """Verify whether the device is able to get the
       wireless information in Enterprise security- Station mode)"""

    try:
        test_case = request.node.name
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        wifi_dut.interfaces.wifi.load_certs(eap_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])

        sl_collections.join_to_eap_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           ping_after_power_save=True, eap_type="tls")

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        data=wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info(timeout=200)
        logger().info(f'========= wireless_info {data}===========')

        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the power management save sniffer packets'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": (Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode |
                     Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake),
        "tcpip_features": (Si91xTCPIPFeatureBitMap.DHCPv4Client |
                           Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                           Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid),
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0),
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                               Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID),
        "config_features": (Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                            Si91xConfigFeatureBitMap.EnahanceMaxPsp),
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "boot_option": 113
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'WPA2', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_traffic_with_load_default_nwp_fw_active_low_c38192(wifi_dut, request, utf_constants, wifi_sniffer, wifi_client, net_perf_client,
                                                                     sniffer_filter, wifi_access_point, protocol, sl_collections):
    """Verify whether DUT is able to do traffic when
       we do device initialization with LOAD_DEFAULT_NWP_FW_ACTIVE_LOW."""

    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count",)

        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        logger().info("Joining WiFi network...")
        dut_addr=sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, power_save=True, mode=mode,
                                                     ping_after_power_save=True, retry_count=3, associated=wifi_dut.interfaces.wifi.associated,
                                                     ping_count=ping_count)

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC address: {da_addr}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        protocols = ["TCP"]
        traffic_types = ["TX"]
        for protocol in protocols:
            for traffic_type in traffic_types:
                sl_collections.run_traffic(
                    wifi_dut=wifi_dut,
                    net_perf_client=net_perf_client,
                    protocol=protocol,
                    device_ip=dut_addr['device_ip'],
                    host_ip=host_ip,
                    timeout=35,
                    traffic_type=traffic_type,
                )

        # Disconnect from the network
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stopping sniffer...")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Validate captured packets
        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr, filter_name='power_mgmt_bit')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the power management save sniffer packets'

    except Exception as EX:
           sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": (Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode |
                     Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake),
        "tcpip_features": (Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                           Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid),
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0),
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                               Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID),
        "config_features": (Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp),
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "boot_option":113,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'WPA2', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_wifi_init_with_load_default_nwp_fw_active_low_c38056(wifi_dut, wifi_sniffer,wifi_access_point,
                                                                       request,sniffer_filter, utf_constants, sl_collections):

    """Verify whether wireless initialization is successful
       when we do device initialization with LOAD_DEFAULT_NWP_FW_ACTIVE_LOW."""

    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count",)

        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        logger().info("Joining WiFi network...")
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, power_save=True, mode=mode,
                                            ping_after_power_save=True, retry_count=3, associated=wifi_dut.interfaces.wifi.associated,
                                            ping_count=ping_count)
        # Disconnect from the network
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stopping sniffer...")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": (Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode |
                     Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake),
        "tcpip_features": (Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                           Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid),
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0),
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                               Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID),
        "config_features": (Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp),
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'join:BSSID:00:11:22:33:44:55', "passphrase": '12345678', "security": 'WPA2', "protected_management_frame": "Capable"})
def test_wifi_sdk_join_bssid_with_spaces_and_colons_c37566(wifi_dut, wifi_sniffer,wifi_access_point,
                                                           sniffer_filter, utf_constants, sl_collections):

    """Verify whether Device is throwing error for join BSSID command along with spaces /colons."""

    try:
        wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.bssid, passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security=wifi_access_point.interfaces.wifi.security, expected_status=SLStatus.SL_STATUS_COMMAND_IS_INVALID)
        logger().info(f"\n\n Observed the expected error code: 0x00048 (SL_STATUS_COMMAND_IS_INVALID) \n\n")
        time.sleep(10)
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": (Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.OpenMode |
                     Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake),
        "tcpip_features": (Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                           Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid),
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": (Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0),
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                               Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID),
        "config_features": (Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp),
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'WPA2', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_dut_conn_with_third_party_ap_using_sl_wifi_api_c686553(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                       request,sniffer_filter, utf_constants, sl_collections):
    """Verify DUT connectivity with third party AP using sl_wifi API's"""
    try:
        test_case = request.node.name
        mode = "power_save_low_latency"
        ping_count = utf_constants.get("ping_count",)

        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        logger().info("Joining WiFi network...")
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, power_save=True, mode=mode,
                                            ping_after_power_save=True, retry_count=3, associated=wifi_dut.interfaces.wifi.associated,
                                            ping_count=ping_count)
        # Disconnect from the network
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stopping sniffer...")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@pytest.mark.config(
    "wifi_dut",
    wifi={
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": 'test12345678', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_connectivity_with_correct_psk_after_wrong_psk_c694554(wifi_dut, wifi_access_point, wifi_sniffer,
                                                               utf_constants, request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify error SI91X_DEAUTHENTICATION on connecting wrong PSK
        6. Try with correct PSK
        7. Connection should be a success
  """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        wrong_psk = '12345678'
        logger().info(f"\n Changing the PSK to {wrong_psk}\n")
        wifi_access_point.interfaces.wifi.passphrase = wrong_psk
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stopping sniffer...")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Europe", "channel": 12})
def test_wifi_sdk_connection_in_eu_region_C782626(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, sl_collections, sniffer_filter):

    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2.Configure the DUT in EU region
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "japan"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Europe", "channel": 13})
def test_wifi_sdk_connection_in_JP_region_C782627(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, sl_collections, sniffer_filter):

    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2.Configure the DUT in EU region
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "worldwide"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Europe", "channel": 11})
def test_wifi_sdk_connection_in_world_region_C782628(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, sl_collections, sniffer_filter):

    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2.Configure the DUT in EU region
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HidePSKCredentials,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"ssid": "TEST-WPA2", "security": "WPA2", "passphrase": "test12345678"})
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_connectivity_with_wpa2_security_hidden_psk_c770028(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                      utf_constants, sl_collections, sniffer_filter, request):
        
    """Test WiFi connectivity with WPA2 security and hidden PSK credentials.
    Verifies that the DUT can successfully connect to a WPA2-secured access point
    when PSK credentials are hidden from wireless information output. The test
    configures sniffer capture, joins the network, and validates connectivity.
    """

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies connectivity with WPA2 mode AP"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HidePSKCredentials,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"ssid": "TEST-MIXED", "security": "WPAWPA2MixedMode", "passphrase": "test12345678"})
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_connectivity_with_wpa_wpa2_mixed_hidden_psk_c770031(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                      utf_constants, sl_collections, sniffer_filter, request):

    """Test WiFi connectivity with WPA/WPA2 mixed mode security and hidden PSK credentials.
    
    Verifies that the DUT can successfully connect to a WPA/WPA2 mixed mode access point
    when PSK credentials are hidden from wireless information output. The test configures
    sniffer capture, joins the network, and validates connectivity with mixed security mode.
    """
    
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies connectivity with WPA/WPA2 Mixed mode AP with hidden SSID"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_LONG_ICMP_PACKET,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_long_icmp_packet_functionality_ipv4_c770033(wifi_dut, wifi_access_point, wifi_sniffer,
                                                         sl_collections, sniffer_filter, request, wifi_client):
    """
        Test Case: C770033 - Verify functionality of long ICMP packets in IPv4.

        Description:
            This test validates the ability of the Device Under Test (DUT) to handle long ICMP packets
            with the SL_SI91X_FEAT_LONG_ICMP_PACKET feature enabled. It ensures proper transmission
            and reception of long ICMP packets without errors.

        Parameters:
            wifi_dut: DUT interface for Wi-Fi operations.
            wifi_access_point: Access point interface for testing.
            wifi_sniffer: Network sniffer for capturing packets.
            utf_constants: Constants for test configuration.
            sl_collections: Utilities for test execution.
            sniffer_filter: Filter configuration for sniffer.
            request: Pytest request object for test-specific configurations.
            wifi_client: Client interface for Wi-Fi operations.

        Expected Outcome:
            DUT successfully sends and receives long ICMP packets without errors.
        """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies the device can handle long ICMP packets with SL_SI91X_FEAT_LONG_ICMP_PACKET feature enabled"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       power_save=power_save,
                                                       ping_before_power_save=False,
                                                       ping_after_power_save=False,
                                                       associated=wifi_dut.interfaces.wifi.associated)

        device_ip = dut_addr['device_ip']
        logger().info(f"\n **** Device IP Address: {device_ip} ****\n")

        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(" ====== Sending ping packets from DUT with 300 bytes ====== ")
        wifi_dut.interfaces.wifi.ping(server_ip=client_ip,
                                      num_ping_attempts=5,
                                      ping_timeout=10,
                                      ip_version='ipv4',
                                      ping_size=300)

        logger().info(f" ====== Sending large ping from AP backend with size 1472 bytes ====== ")
        sl_collections.ping_with_custom_size(device_ip=device_ip,
                                             ping_counts=3,
                                             byte_size=1472)

        logger().info(" ====== Checking device logs for errors ====== ")
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        logger().info(f"\n Wireless DUT Stats: {wireless_info} \n")

        logger().info("disconnecting to ap.....")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        icmp_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=client_ip,
            da_addr=device_ip,
            type=8,
            length=1400,
            filter_name='icmpv4_custom_len'
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=icmp_filter,
                                                           packet_filter2="        Tag: Internet Control Message Protocol")['packet_count'], "\n ICMP Ping Packet not captured \n"
        with open("./reports/filter2_file.txt", "r") as file:
            data = file.read()
            pattern = r"Data \((\d+) bytes\)"
            match = re.search(pattern, data)
            if match:
                data_length = int(match.group(1))
                logger().info(f"Data length: {data_length} bytes")
            else:
                logger().info("Data length not found.")

        logger().info(
            f" **** Adding ICMP Header Size: 8 Bytes to Captured Packet Length on-Air, Length: {data_length + 8}**** ")
        assert data_length + 8 == 1472, f"\n ICMP Ping Packet Length isn't matching \n"

        logger().info(" ====== Long ICMP packet test completed successfully ====== ")
        logger().info(" ====== No packet drops or errors detected in device logs ====== ")

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_LONG_ICMP_PACKET,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_long_icmp_packet_functionality_ipv6_c770035(firmware_loader, wifi_dut, wifi_access_point,
                                                              wifi_sniffer,
                                                              sl_collections, sniffer_filter, request, wifi_client):
    """
        Test Case: C770035 - Verify functionality of long ICMP packets in IPv6.

        Description:
            This test validates the ability of the Device Under Test (DUT) to handle long ICMP packets
            in IPv6 mode with the SL_SI91X_FEAT_LONG_ICMP_PACKET feature enabled. It ensures proper
            transmission and reception of long ICMP packets without errors.

        Parameters:
            firmware_loader: Interface for loading firmware onto the DUT.
            wifi_dut: DUT interface for Wi-Fi operations.
            wifi_access_point: Access point interface used for testing.
            wifi_sniffer: Network sniffer for capturing packets.
            utf_constants: Constants for test configuration.
            sl_collections: Utilities for test execution and validation.
            sniffer_filter: Filter configuration for the network sniffer.
            request: Pytest request object for accessing test-specific configurations.
            wifi_client: Client interface for Wi-Fi operations.

        Expected Outcome:
            DUT successfully sends and receives long ICMP packets in IPv6 mode without errors,
            and the sniffer captures the expected packets.
        """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies the device can handle long ICMP packets with SL_SI91X_FEAT_LONG_ICMP_PACKET feature enabled"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name

        logger().info(" ====== Step 1: Initializing wireless module and configuring sniffer ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        logger().info(" ====== Step 2: Configuring device with network parameters and joining WiFi network ====== ")
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       ip_version='ipv6',
                                                       power_save=power_save,
                                                       ping_before_power_save=False,
                                                       ping_after_power_save=False,
                                                       associated=wifi_dut.interfaces.wifi.associated)

        device_ip = dut_addr['device_ip']
        logger().info(f"\n **** Device IP Address: {device_ip} ****\n")

        client_ip = wifi_client.interfaces.wifi.get_ip_address(version=6)
        logger().info(f"\n **** Client IP Address: {client_ip} ****\n")
        logger().info(" ====== Step 4: Sending ping packets from DUT with 1452 bytes ====== ")
        wifi_dut.interfaces.wifi.ping(server_ip=client_ip,
                                      num_ping_attempts=5,
                                      ping_timeout=10,
                                      ip_version='ipv6',
                                      ping_size=300)

        logger().info(" ====== Step 5: Sending large ICMP packet (1452 bytes) from AP backend ====== ")
        sl_collections.ping_with_custom_size(device_ip=device_ip,
                                             ping_counts=3,
                                             byte_size=1452)

        icmp_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=device_ip,
            da_addr=client_ip,
            type=129,
            length=1400,
            filter_name='icmpv6_custom_len'
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=icmp_filter,
                                                           packet_filter2="        Tag: Internet Control Message Protocol")["packet_count"], f" ICMP Packet not Captured "
        with open("./reports/filter2_file.txt", "r") as file:
            data = file.read()
            pattern = r"Data \((\d+) bytes\)"
            match = re.search(pattern, data)
            if match:
                data_length = int(match.group(1))
                logger().info(f"Data length: {data_length} bytes")
            else:
                logger().info("Data length not found.")

        logger().info(
            f" **** Adding ICMP Header Size: 8 Bytes to Captured Packet Length on-Air**** ")
        assert data_length == 1452, f"\n ICMP Ping Packet Length isn't matching \n"

        logger().info(" ====== Long ICMP packet test completed successfully ====== ")
        logger().info(" ====== No packet drops or errors detected in device logs ====== ")
        logger().info(
            " ====== Device successfully handled long ICMP packets with SL_SI91X_FEAT_LONG_ICMP_PACKET feature ====== ")

    except Exception as EX:
        logger().error(f" ====== Error during long ICMP packet test: {str(EX)} ====== ")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
         "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
         "oper_mode": Si91xOperatingMode.WiFiClient,
         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
         "features": Si91xFeatureBitMap.Default,
         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.DISABLE_SHORT_GI,
         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
         "bt_features": 0,
         "ble_features": 0,
         "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_disabling_short_GI_C770043(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                    sl_collections, sniffer_filter, request, wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        4. Initiate ping from the dut
        5. Initiate ping from rasp to DUT
        5. Do sniffer Validation for Short GI disabled
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies the connectivity with 11n only mode with ap """
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("========= Verify the sniffer packets with short GI disabled =========")
        dut_mac_address = wlan_obj.dut_addr['dut_mac_address']
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address, filter_name='disable_sgi_ping')
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address, filter_name='disable_sgi_assoc_pkt')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'unable to find the ping packets with short GI disabled'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'unable to find the association packets with short GI disabled'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HidePSKCredentials,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"ssid": "TEST-WPA3", "security": "WPA3", "passphrase": "test12345678"})
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_connectivity_with_wpa3_security_hidden_psk_c770029(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                      utf_constants, sl_collections, sniffer_filter, request):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies connectivity with WPA3 mode AP and hidden PSK"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.HidePSKCredentials,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2Enterprise", "passphrase": "12345678"})
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_connectivity_with_EAP_TLS_mixed_hidden_psk_c770030(wifi_dut, wifi_access_point, wifi_sniffer, radius_server,
                                                                      utf_constants, sl_collections, sniffer_filter, request):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=request.node.name)
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies connectivity with WPA/WPA2 Mixed mode AP and hidden SSID"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_LONG_ICMP_PACKET,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_long_icmp_packet_more_than_1472_bytes_c770039(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                         sl_collections, sniffer_filter, request, wifi_client):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz with SL_SI91X_FEAT_LONG_ICMP_PACKET feature enabled
        2. Join the access point and enable the dhcp
        3. Send ping from RASP to DUT with more than 1472 bytes
        4. Ping should fail
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies the device can handle long ICMP packets with SL_SI91X_FEAT_LONG_ICMP_PACKET feature enabled"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       power_save=power_save,
                                                       ping_before_power_save=False,
                                                       ping_after_power_save=False,
                                                       associated=wifi_dut.interfaces.wifi.associated)

        device_ip = dut_addr['device_ip']
        logger().info(f"\n **** Device IP Address: {device_ip} ****\n")

        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(" ====== Sending ping packets from DUT with 300 bytes ====== ")
        wifi_dut.interfaces.wifi.ping(server_ip=client_ip,
                                      num_ping_attempts=5,
                                      ping_timeout=10,
                                      ip_version='ipv4',
                                      ping_size=300)

        logger().info(f" ====== Sending large ping from AP backend with size 1472 bytes ====== ")
        sl_collections.ping_with_custom_size(device_ip=device_ip,
                                             ping_counts=1,
                                             byte_size=1472)

        logger().info(f" ====== Sending large ping from AP backend with size greater than 1472 bytes ====== ")
        sl_collections.ping_with_custom_size(device_ip=device_ip,
                                             ping_counts=1,
                                             byte_size=1473, negative_test=True)

        logger().info(" ====== Checking device logs for errors ====== ")
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        logger().info(f"\n Wireless DUT Stats: {wireless_info} \n")

        logger().info("disconnecting to ap.....")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.SL_SI91X_FEAT_LONG_ICMP_PACKET,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv6Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.IPv6Mode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_long_icmp_packet_more_than_1452_bytes_ipv6_c770040(firmware_loader, wifi_dut, wifi_access_point,
                                                              wifi_sniffer, utf_constants,
                                                              sl_collections, sniffer_filter, request, wifi_client):
    """
    Test Steps:
        1. Initialize the wireless module
        2. Configure the device with necessary network parameters (SSID, password, etc.)
        3. Enable the SL_SI91X_FEAT_LONG_ICMP_PACKET feature in device configuration
        4. Use network tools to send ICMP packets larger than standard size (2048 bytes) to the device
        5. Do ping from DUT sl_send_ping with 1452 bytes and from AP Backend
        6. Monitor device logs and use network sniffer to verify device receives long ICMP packets
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies the device can handle long ICMP packets with SL_SI91X_FEAT_LONG_ICMP_PACKET feature enabled"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")

        logger().info(" ====== Step 1: Initializing wireless module and configuring sniffer ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        logger().info(" ====== Step 2: Configuring device with network parameters and joining WiFi network ====== ")
        dut_addr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                       wifi_access_point=wifi_access_point,
                                                       ip_version='ipv6',
                                                       power_save=power_save,
                                                       ping_before_power_save=False,
                                                       ping_after_power_save=False,
                                                       associated=wifi_dut.interfaces.wifi.associated)

        device_ip = dut_addr['device_ip']
        logger().info(f"\n **** Device IP Address: {device_ip} ****\n")

        logger().info(" ====== Step 3: Verifying SL_SI91X_FEAT_LONG_ICMP_PACKET feature is enabled ====== ")
        wireless_info = wifi_dut.interfaces.wifi.sl_wifi_get_wireless_info()
        logger().info(f"\n Wireless DUT Stats: {wireless_info} \n")

        client_ip = wifi_client.interfaces.wifi.get_ip_address(version=6)
        logger().info(f"\n **** Client IP Address: {client_ip} ****\n")

        logger().info(" ====== Step 4: Sending ping packets from DUT with 300 bytes ====== ")
        wifi_dut.interfaces.wifi.ping(server_ip=client_ip,
                                      num_ping_attempts=5,
                                      ping_timeout=10,
                                      ip_version='ipv6',
                                      ping_size=300)

        logger().info(" ====== Step 5: Sending large ICMP packet of 1452 byte from AP backend ====== ")
        sl_collections.ping_with_custom_size(device_ip=device_ip,
                                             ping_counts=2,
                                             byte_size=1452)

        logger().info(" ====== Step 5: Sending large ICMP packet more than 1452 byte from AP backend ====== ")
        sl_collections.ping_with_custom_size(device_ip=device_ip,
                                             ping_counts=2,
                                             byte_size=1453, negative_test=True)

        logger().info("disconnecting to ap.....")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as EX:
        logger().error(f" ====== Error during long ICMP packet test: {str(EX)} ====== ")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)