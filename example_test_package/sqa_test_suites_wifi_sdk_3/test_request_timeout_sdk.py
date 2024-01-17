from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Set the keep alive timer in various time intervals
        4. Association of Third party AP's
        5. Get the valid IP address
        6. Enable the power save mode
        7. Stop the sniffer  
        8. Analyzing all sniffer capture packets and find the arp announcement packet 
        9. Validate the arp announcement packets with time delta as per keep alive timer
    setup requirement:
        1. Soc
        2. Nuc
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Saurabh Sharma
"""


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, wifi_client=None, channel=None,
                 capture_filename=None, sl_collections=None, test_case_no=None, sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.wifi_client = wifi_client
        self.channel = channel
        self.capture_filename = capture_filename
        self.sl_collections = sl_collections
        self.test_case_no = test_case_no
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None

    def run(self):
        try:
            ping_count = 10
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.capture_filename)

            if self.test_case_no == 19748 or self.test_case_no == 19751:

                with TimeMeasurer() as t:
                    logger().info(f"Initiating Scan")
                    scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=0, sleep_time=0.00001)
                logger().info(scan_results)
                assert len(scan_results) > 0
                logger().info(f"Scan in {t.duration} seconds")

                if self.test_case_no == 19748:
                    assert (1.1 < t.duration < 1.7)
                    time.sleep(2)

                if self.test_case_no == 19751:
                    assert (5.3 < t.duration < 5.9)
                    time.sleep(2)

                dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
                logger().info(f'dut_mac_address is {dut_mac_address}')

                join_status, reason = self.sl_collections.connect(wifi_dut=self.wifi_dut,
                                                                  wifi_access_point=self.wifi_access_point)
                assert join_status, f"....Connection to the AP failed with reason: {reason}...."
                logger().info("....Successfully connected to the AP....")

                ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
                assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

                device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                logger().info(f"DUT IP is {device_ip}")

                logger().info(f"DUT MAC ADDRESS :  {dut_mac_address} DUT IP ADDRESS : {device_ip}")

                logger().info(f"....Pinging to DUT before Power Save")
                status = self.sl_collections.ping(device_ip=device_ip, ping_count=10)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                self.wifi_dut.interfaces.wifi.set_performance_profile()
                self.wifi_dut.interfaces.wifi.enable_bt_power_save()

                logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
                status = ping(device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")

                logger().info(" *** wait for 20 seconds *** ")
                time.sleep(20)

                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("Stop Sniffer finally")
                time.sleep(1)
                packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=dut_mac_address, filter_name="probe_request")

                snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                    'packet_count']
                assert snif_pkt_count, "Unable to find probe request frames in sniffer"

                return

            if self.test_case_no == 19637:
                logger().info(f"**** enabling the BG scan params ****")

                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                              adv_passive_channel_time=20)
                logger().info(f"**** enabling the rejoin params ****")
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)

            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)
        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

    ''' This function is responsible to create a list for ARP announcement packet time delta '''

    def delta_between_arp_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        count1 = 0
        for x in line:
            count = count + 1
            if packet_filter in x:
                count1 += 1
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')

                if round(float(time_delta_from_previous_packet)) == 0:
                    count1 -= 1
                    continue
                else:
                    time_diff_list.append(float(time_delta_from_previous_packet))

        logger().info("Calculating the threshold value for keep alive interval")

        if self.test_case_no == 19746 or self.test_case_no == 19637:
            average = sum(time_diff_list) // 10
            threshold_value = ((len(time_diff_list) + 1) / (average + 1)) * 100
            assert threshold_value > 60, "More than 40 % Packets are missing within configured keep alive time interval"
            logger().info(f'*** No. of packets = {count1} Threshold = {threshold_value} ***')

        if self.test_case_no == 19750:
            average = sum(time_diff_list) // 30
            threshold_value = ((len(time_diff_list) + 1) / (average + 1)) * 100
            assert threshold_value > 60, "More than 40 % Packets are missing within configured keep alive time interval"
            logger().info(f'*** No. of packets = {count1} Threshold = {threshold_value} ***')

        filter_file.close()
        return time_diff_list


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "set_default_timeout_config"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "keep_alive_timeout_value": 30
    },
)
@pytest.mark.parametrize("channel", [4])
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_wifi_sdk_request_timeout_keep_alive_30s_c19750(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, channel):
    """ Verify the keep alive functionality with configured value 30s """

    try:
        capture_filename = request.node.name
        time_delta = 30
        ping_count = 10
        packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'

        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, channel=channel, capture_filename=capture_filename,
                                        sl_collections=sl_collections, test_case_no=19750)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
        status = ping(wlan_obj.dut_addr['device_ip'], ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info(" *** wait for 240 seconds *** ")
        time.sleep(240)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="arp_packet")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                            packet_filter2=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, ("Unable to find ARP Announcement packets & Unable to find ARP Announcement packets "
                                "with-in assigned time")

        logger().info("""******** Validation of time delta between keep-alive packets ********""")
        arp_packets_time_delta_list = wlan_obj.delta_between_arp_packet()
        logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
        for time_diff in arp_packets_time_delta_list:
            logger().info(int(time_diff))
            is_between = int(time_diff) in range(0, time_delta + 5)
            logger().info(is_between)
        time.sleep(1)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "set_default_timeout_config"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "keep_alive_timeout_value": 10

    },
)
@pytest.mark.parametrize("channel", [4])
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_wifi_sdk_request_timeout_keep_alive_10s_c19746(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, channel):
    """Verify the STA keep alive functionality with 10s keep alive time"""

    capture_filename = request.node.name
    time_delta = 10
    ping_count = 10
    packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'

    try:
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, channel=channel, capture_filename=capture_filename,
                                        sl_collections=sl_collections, test_case_no=19746)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"*****Initiate ping from third party wifi-client to DUT******")
        status = ping(wlan_obj.dut_addr['device_ip'], ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info(" *** wait for 90 seconds *** ")
        time.sleep(90)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="arp_packet")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                            packet_filter2=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, ("Unable to find ARP Announcement packets & Unable to find ARP Announcement packets "
                                "with-in assigned time")

        logger().info(""" ******** Validation of time delta between keep-alive packets ******** """)
        arp_packets_time_delta_list = wlan_obj.delta_between_arp_packet()
        logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
        for time_diff in arp_packets_time_delta_list:
            logger().info(int(time_diff))
            is_between = int(time_diff) in range(0, time_delta + 5)
            logger().info(is_between)
        time.sleep(1)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "set_default_timeout_config"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "active_chan_scan_timeout_value": 100
    },
)
def test_wifi_sdk_request_timeout_scan_100ms_c19748(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """ Verify the functionality by enabling each channel active scan time with default value(100ms) """

    try:
        capture_filename = request.node.name
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, capture_filename=capture_filename,
                                        sl_collections=sl_collections, test_case_no=19748,
                                        sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "set_default_timeout_config"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "active_chan_scan_timeout_value": 500
    },
)
def test_wifi_sdk_request_timeout_scan_500ms_C19751(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter):
    """ Verify time for each channel active scan in request timeout command with configured value 500ms """

    try:
        capture_filename = request.node.name
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, capture_filename=capture_filename,
                                        sl_collections=sl_collections, test_case_no=19751,
                                        sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "unassociated", "set_default_timeout_config"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "enable_timeout_config": True,
        "keep_alive_timeout_value": 10

    },
)
@pytest.mark.parametrize("channel", [4])
@pytest.mark.config("wifi_access_point", wifi={"channel": 4, "security": 'OPEN'})
def test_wifi_sdk_sta_keep_alive_10s_with_bg_scan_C19637(
        wifi_sniffer, wifi_access_point, wifi_dut, request, sl_collections, sniffer_filter, channel):
    """ STA keep alive functionality with BG scan """

    try:
        capture_filename = request.node.name
        time_delta = 10
        packet_filter2 = 'Address Resolution Protocol (ARP Announcement)'

        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer, channel=channel, capture_filename=capture_filename,
                                        sl_collections=sl_collections, test_case_no=19637)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(" *** wait for 90 seconds *** ")
        time.sleep(90)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(1)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="arp_packet")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                            packet_filter2=packet_filter2)['packet_count']
        assert snif_pkt_count, ("Unable to find ARP Announcement packets & Unable to find ARP Announcement packets "
                                "with-in assigned time")

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            mac_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="association_request_ht_supported_rates")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count']
        assert snif_pkt_count, "Unable to find association frames request with supported rates"

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("\n *** Enable BGscan *** \n")
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
        logger().info(" *** wait for 20 seconds *** ")
        time.sleep(30)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="probe_request")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find probe request frames in sniffer"

        logger().info("""********* Validation of time delta between keep-alive packets *********""")
        arp_packets_time_delta_list = wlan_obj.delta_between_arp_packet()
        logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
        for time_diff in arp_packets_time_delta_list:
            logger().info(int(time_diff))
            is_between = int(time_diff) in range(0, time_delta + 5)
            logger().info(is_between)
        time.sleep(1)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "enable_timeout_config": True,
        "auth_assoc_timeout_value": 100
    },
)
def test_wifi_sdk_auth_timeout_with_100ms_c19749(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                 sniffer_filter):
    """Verify negative functionality by setting request timeout for association and authentication request for 100ms"""

    try:
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(5)

        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')

        wifi_access_point.interfaces.wifi.enable_mac_filter_ap(client_mac=dut_mac_address)

        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase, security="wpa2",
                                      expected_status=SLStatus.SL_STATUS_SI91X_AUTHENTICATION_TIMEOUT)
        logger().info(f"Authentication timeout error code 0x10048 which is expected")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name="authentication")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find authentication"

    finally:
        wifi_access_point.interfaces.wifi.disable_mac_filter_ap()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "enable_timeout_config": True,
        "auth_assoc_timeout_value": 300
    },
)
def test_wifi_sdk_auth_timeout_with_300ms_c19747(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                 sniffer_filter):
    """Verify negative functionality by setting request timeout for association and authentication request for 300ms"""

    try:
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(5)

        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')

        wifi_access_point.interfaces.wifi.enable_mac_filter_ap(client_mac=dut_mac_address)

        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase, security="wpa2",
                                      expected_status=SLStatus.SL_STATUS_SI91X_AUTHENTICATION_TIMEOUT)
        logger().info(f"Authentication timeout error code 0x10048 which is expected")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address, filter_name="authentication")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find authentication"

    finally:
        wifi_access_point.interfaces.wifi.disable_mac_filter_ap()
