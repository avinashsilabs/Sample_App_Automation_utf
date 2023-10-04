import pytest
import time
import re
from datetime import datetime, date
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap
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

    Author: Ayush and Harshitha

"""


class WLanJoinThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 sl_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None, pmk_enable=False):
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

    def run(self):
        try:
            if 'PMK' in self.test_case:
                self.pmk_enable = True

            if '19716' in self.test_case:

                logger().info(" ====== configuring the Sniffer with access point channel ====== ")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)

                logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)

                self.wifi_access_point.interfaces.wifi.passphrase = '12345678'

                self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                         wifi_access_point=self.wifi_access_point,
                                                         power_save=self.power_save,
                                                         ping_after_power_save=True, retry_count=3,
                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                         pmk_enable=self.pmk_enable,
                                                         expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
                logger().info(
                    f"Dut Tried to connect to ap with wrong password, observed error code 0x10008 which is expected")

                logger().info("disconnecting to ap.....")
                self.wifi_dut.interfaces.wifi.leave()

                logger().info("Stop Sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()

                self.sl_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                            self.dut_addr['dut_mac_address'], self.ap_mac_address,
                                                            self.sniffer_filter, power_save=self.power_save)

            elif '19717' in self.test_case:
                self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                         wifi_access_point=self.wifi_access_point,
                                                         power_save=self.power_save,
                                                         ping_after_power_save=True, retry_count=3,
                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                         pmk_enable=self.pmk_enable,
                                                         expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
                logger().info(
                    f"Dut Tried to connect to ap with wrong password, observed error code 0x10008 which is expected")

            else:
                logger().info(" ====== configuring the Sniffer with access point channel ====== ")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)

                logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)

                self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         power_save=self.power_save,
                                                                         ping_after_power_save=True, retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         pmk_enable=self.pmk_enable)
                logger().info("disconnecting to ap.....")
                self.wifi_dut.interfaces.wifi.leave()

                logger().info("Stop Sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()

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

        logger().info("\n **** 11n packet validation for probe_request_HT**** \n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=ap_mac_address, filter_name="probe_request_HT")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find 11n packet'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


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
        6. Repeat the steps 2-5 for number of iterations
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies connectivity with hidden mode AP"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = 3
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        hidden_ssid='""',
                                                                                        filter_name='hidden_ssid')

        for count in range(0, iteration):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find hidden in sniffer'
            time.sleep(2)
    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


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
        7. Repeat the steps 2-6 for number of iterations
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
        iteration = 3
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        for count in range(0, iteration):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            if not rerun:
                packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                    da_addr=ap_mac_address,
                    filter_name='probe_req_response')
                packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter. \
                    get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=ap_mac_address,
                                       filter_name='assoc_req_resp_eapol_4_way_handshake')
                rerun = True
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Sniffer: Unable to find probe_req_response packet in sniffer'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                      packet_filter2=packet_filter2)['packet_count'], \
                'Sniffer: Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'

            time_taken = wlan_obj.time_diff()
            assert time_taken <= 0.4
            logger().info(f"time taken to connect is: {time_taken}")
            time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
        5. Repeat the steps 2-4 for number of iterations
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies Joining to the security enable ap by giving psk"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = 3
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)
        for count in range(0, iteration):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "Testssid",
                          "passphrase": "1234567890qwertyuioplkjhgfdsazxcvbnm[]oirgrgrtyuio1234567890os1",
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
        5. Repeat the steps 2-4 for number of iterations
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies Joining to the psk by giving 64 different characters"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = 3
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)
        for count in range(0, iteration):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            time.sleep(2)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
        5. Repeat the steps 2-4 for 1800 secs
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
        5. Verify error code by validating PMK
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


@pytest.mark.config('wifi_access_point', wifi={"ssid": "thisssidisthirteeetwobytesofsize",
                                               "passphrase": "123456789qwertyuio123456789qwertyuio123456789zxcvbnm123456789zx",
                                               "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_join_pmk_with_64_characters_psk_32_characters_ssid_C19720(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                            utf_constants, request, sl_collections,
                                                                            sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Join with PMK with 64 characters PSK and 32 characters ssid
        6. Repeat the steps 2-5 for number of iterations
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    iteration = 3
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")

        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)
        for count in range(0, iteration):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
@pytest.mark.config('wifi_access_point', wifi={"ssid": " redpine", "passphrase": 'Testing_pmk', "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wifi_join_pmk_with_space_before_redpine_ssid_C19718(wifi_dut, wifi_access_point, wifi_sniffer,
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
        7. Repeat the steps 2-6 for number of iterations
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    """This test case verifies Joining to the psk by giving 64 different characters"""
    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    rerun = False
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        iteration = 3
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)
        for count in range(0, iteration):
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            if not rerun:
                packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                    da_addr=ap_mac_address,
                    filter_name='probe_req_response')
                packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter. \
                    get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=ap_mac_address,
                                       filter_name='assoc_req_resp_eapol_4_way_handshake')
                rerun = True
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Sniffer: Unable to find probe_req_response packet in sniffer'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3,
                                                                      packet_filter2=packet_filter2)['packet_count'], \
                'Sniffer: Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'

            time_taken = wlan_obj.time_diff()
            assert time_taken <= 0.4
            logger().info(f"time taken to connect is: {time_taken}")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "testwithnossid", "passphrase": 'Testing_pmk', "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_wifi_join_PMK_without_SSID_C19717(wifi_dut, wifi_access_point, sl_collections, request):

    try:
        with TimeMeasurer() as t:
            test_case = request.node.name
            wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, test_case=test_case,
                                      sl_collections=sl_collections)

            wlan_obj.start()
            wlan_obj.wait_for_exit()
        logger().info(f"test executed in {t.duration} seconds")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
