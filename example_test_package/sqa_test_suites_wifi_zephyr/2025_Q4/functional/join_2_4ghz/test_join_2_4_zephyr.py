import pytest
import time
import re
from datetime import datetime, date
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf_wifi_zephyr.utils.sl_status import SLStatus
from utf_wifi_zephyr.devices.si91x import (
    ZephyrWifiMfpOptions
)


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. Soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Configuration of DUT in 2G : bgnax
        2. Join the access point and enable the dhcp
        3. Initiate Ping from remote peer

    Author: Vinod.G

"""


class WLanJoinThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 zephyr_wifi_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None,
                 pmk_enable=False,
                 wifi_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None
        self.power_save = power_save
        self.ap_mac_address = ap_mac_address
        self.pmk_enable = pmk_enable
        self.wifi_client = wifi_client

    def run(self):
        try:
            if '694554' in self.test_case:
                self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point,
                                                      pmk_enable=self.pmk_enable,
                                                      expected_status=SLStatus.SL_STATUS_FAIL)
                logger().info(
                    f"\n Observed error on connecting DUT with wrong PSK, which is expected \n")

                self.wifi_access_point.interfaces.wifi.passphrase = 'test12345678'

                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  power_save=self.power_save,
                                                                                  ping_after_power_save=True,
                                                                                  retry_count=3,
                                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                                  pmk_enable=self.pmk_enable)
                time.sleep(2)
                logger().info("disconnecting to ap.....")
                self.wifi_dut.interfaces.wifi.leave()


            else:
                logger().info(" ====== configuring the Sniffer with access point channel ====== ")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  power_save=self.power_save,
                                                                                  ping_after_power_save=True,
                                                                                  retry_count=3,
                                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                                  pmk_enable=self.pmk_enable)

                time.sleep(1)
                logger().info("disconnecting to ap.....")
                self.wifi_dut.interfaces.wifi.leave()
                time.sleep(1)
                logger().info("Stop Sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(1)
                self.zephyr_wifi_collections.join_sniffer_validation(self.wifi_access_point, self.wifi_sniffer,
                                                                     self.dut_addr['dut_mac_address'],
                                                                     self.ap_mac_address,
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
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C19707')
def test_wifi_zephyr_connectivity_with_11n_mode_c19707(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                       zephyr_wifi_collections, sniffer_filter, request):
    """
    Test Steps:
        1. Configure the DUT in Wlan mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Initiate ping from remote peer to DUT
        4. Do sniffer Validation for 11n mode
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
                                  zephyr_wifi_collections=zephyr_wifi_collections, sniffer_filter=sniffer_filter,
                                  test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={"ssid": "TEST-ASUS-hidden", "broadcast_ssid": False})
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C19708')
def test_wifi_zephyr_connectivity_with_hidden_mode_ap_c19708(wifi_dut, wifi_access_point, wifi_sniffer,
                                                             utf_constants, zephyr_wifi_collections, sniffer_filter,
                                                             request):
    """
    Test Steps:
        1. Configure the DUT in Wlan mode for 2.4Ghz
        2. Keep SSID to hidden mode in AP
        2. Join the access point and enable the dhcp
        3. Initiate ping from remote peer to DUT
        4. Do sniffer Validation for hidden mode
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
                                  zephyr_wifi_collections=zephyr_wifi_collections, sniffer_filter=sniffer_filter,
                                  test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        hidden_ssid="\"\"",
                                                                                        filter_name='hidden_ssid')

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find hidden in sniffer'
        time.sleep(2)
    except Exception as EX:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "Testssid",
                          "passphrase": "1234567890qwertyuioplkjhgfdsazxcvbnmoirgrgrtyuio123456!@#$%+=_,",
                          "security": "WPA2"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C19719')
def test_wifi_zephyr_psk_with_64_different_characters_c19719(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                             utf_constants, request, zephyr_wifi_collections,
                                                             sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Initiate ping from remote peer to DUT

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
                                  zephyr_wifi_collections=zephyr_wifi_collections, sniffer_filter=sniffer_filter,
                                  test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing', "security": 'WPA2', "channel": 7})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C19710')
def test_wifi_zephyr_Init_Scan_Join_Disconnect_30min_C19710(wifi_dut, wifi_access_point, wifi_sniffer, rs_helper,
                                                            utf_constants, request, zephyr_wifi_collections,
                                                            sniffer_filter):
    """
    Verify connect and disconnect functionality to the AP for multiple times for 15 minutes
    """
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        test_case = request.node.name
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  zephyr_wifi_collections=zephyr_wifi_collections, sniffer_filter=sniffer_filter,
                                  test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        with TimeMeasurer() as t:
            t_end = time.time() + 60 * 5
            while time.time() < t_end:
                wlan_obj.start()
                wlan_obj.wait_for_exit()
                time.sleep(5)

        logger().info(f"Associated and ping in {t.duration} seconds")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sta_mode_ssid', "passphrase": 'test12345678', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C694554')
def test_wifi_zephyr_verify_connectivity_with_correct_psk_after_wrong_psk_c694554(wifi_dut, wifi_access_point,
                                                                                  wifi_sniffer,
                                                                                  utf_constants, request,
                                                                                  zephyr_wifi_collections,
                                                                                  sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Verify error on connecting wrong PSK
        4. Try with correct PSK
        5. Connection should be success
        6. Initiate ping from the dut
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
                                  zephyr_wifi_collections=zephyr_wifi_collections, sniffer_filter=sniffer_filter,
                                  test_case=test_case,
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stopping sniffer...")
        wifi_sniffer.interfaces.capture.stop_capture()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wlan_obj.dut_addr['dut_mac_address'],
                                                        ap_mac_address,
                                                        sniffer_filter, power_save=power_save)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'sta_mode_ssid', "passphrase": 'test12345678', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C79234')
def test_wifi_zephyr_connectivity_neg_psk_7_bytes_or_64_bytes_c79234(wifi_dut, wifi_access_point,
                                                                     wifi_sniffer,
                                                                     utf_constants, request, zephyr_wifi_collections,
                                                                     sniffer_filter):
    """
    Connection to the AP should fail as psk length is not in the permittable range
    """

    try:
        test_case = request.node.name

        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                      passphrase="1234567",
                                      channel=wifi_access_point.interfaces.wifi.channel,
                                      timeout=60,
                                      expected_status=SLStatus.SL_STATUS_FAIL
                                      )

        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security=wifi_access_point.interfaces.wifi.security.name.lower(),
                                      passphrase="1234567890123456789012345678901234567890123456789012345678901234",
                                      channel=wifi_access_point.interfaces.wifi.channel,
                                      timeout=60,
                                      expected_status=SLStatus.SL_STATUS_FAIL
                                      )

        logger().info("Stopping sniffer...")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'TESTTEST-WPA2', "security": 'WPA2', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C19175')
def test_wifi_zephyr_wlan_get_stats_sta_wpa2_C19175(wifi_dut, wifi_access_point, wifi_sniffer, zephyr_wifi_collections,
                                                    request,
                                                    utf_constants, sniffer_filter):
    """ Test case verifies the device is able to get the wireless statistics in station mode"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        dut_addr = zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point,
                                                                ping_after_power_save=True,
                                                                retry_count=3,
                                                                associated=wifi_dut.interfaces.wifi.associated,
                                                                power_save=power_save)

        state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
            timeout=15)

        assert int(state) == 9, "DUT is not in connected state"
        assert ssid == wifi_access_point.interfaces.wifi.ssid, "SSID details retrieved using WIFI_IFACE_STATUS API are wrong"
        assert int(
            channel) == wifi_access_point.interfaces.wifi.channel, "Channel info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(security) == 1, "Security info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert bssid.upper() == wifi_access_point.interfaces.wifi.bssid, "BSSID info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(
            dtim_period) == wifi_access_point.interfaces.wifi.dtim, "DTIM period set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(
            beacon_interval) == wifi_access_point.interfaces.wifi.beacon_interval, "Beacon interval set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        # assert int(twt_capable) == wifi_access_point.interfaces.wifi.twt, "TWT info set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"

        wifi_sniffer.interfaces.capture.stop_capture()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        dut_addr['dut_mac_address'],
                                                        ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'TESTTEST-ASUS-OPEN', "security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C29175')
def test_wifi_zephyr_wlan_get_stats_sta_open_security_C29175(wifi_dut, wifi_access_point, wifi_sniffer,
                                                             zephyr_wifi_collections,
                                                             request,
                                                             utf_constants, sniffer_filter):
    """ Test case verifies the device is able to get the wireless statistics in station mode"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        dut_addr = zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point,
                                                                ping_after_power_save=True,
                                                                retry_count=3,
                                                                associated=wifi_dut.interfaces.wifi.associated,
                                                                power_save=power_save)

        state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
            timeout=15)

        assert int(state) == 9, "DUT is not in connected state"
        assert ssid == wifi_access_point.interfaces.wifi.ssid, "SSID details retrieved using WIFI_IFACE_STATUS API are wrong"
        assert int(
            channel) == wifi_access_point.interfaces.wifi.channel, "Channel info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(security) == 0, "Security info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert bssid.upper() == wifi_access_point.interfaces.wifi.bssid, "BSSID info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(
            dtim_period) == wifi_access_point.interfaces.wifi.dtim, "DTIM period set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(
            beacon_interval) == wifi_access_point.interfaces.wifi.beacon_interval, "Beacon interval set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        # assert int(twt_capable) == wifi_access_point.interfaces.wifi.twt, "TWT info set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"

        wifi_sniffer.interfaces.capture.stop_capture()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        dut_addr['dut_mac_address'],
                                                        ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C39175')
def test_wifi_sdk_wlan_get_stats_sta_security_wpa3_C39175(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                          request,
                                                          sniffer_filter, zephyr_wifi_collections):
    """ Test case verifies the device is able to get the wireless statistics in station mode in WPA3 security mode"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        test_case = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        dut_addr = zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point,
                                                                ping_after_power_save=True,
                                                                retry_count=3,
                                                                associated=wifi_dut.interfaces.wifi.associated,
                                                                power_save=power_save, mfp=ZephyrWifiMfpOptions.WIFI_MFP_REQUIRED)

        state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
            timeout=15)

        assert int(state) == 9, "DUT is not in connected state"
        assert ssid == wifi_access_point.interfaces.wifi.ssid, "SSID details retrieved using WIFI_IFACE_STATUS API are wrong"
        assert int(
            channel) == wifi_access_point.interfaces.wifi.channel, "Channel info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(security) == 3, "Security info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert bssid.upper() == wifi_access_point.interfaces.wifi.bssid, "BSSID info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(
            dtim_period) == wifi_access_point.interfaces.wifi.dtim, "DTIM period set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(
            beacon_interval) == wifi_access_point.interfaces.wifi.beacon_interval, "Beacon interval set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        # assert int(twt_capable) == wifi_access_point.interfaces.wifi.twt, "TWT info set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"

        wifi_sniffer.interfaces.capture.stop_capture()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        dut_addr['dut_mac_address'],
                                                        ap_mac_address,
                                                        sniffer_filter, power_save=power_save)
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
