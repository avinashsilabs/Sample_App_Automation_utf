# Description: This script is used to test the passive scan functionality by enabling passive scan bit in scan request.
"""
    setup requirement:
        1. DUT(Si917_ZEPHYR)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan mode
        2. Verify passive scan duration taken by DUT is within the expected threshold value.
        2. Join the access point and enable the dhcp.
        3. Initiate ping from the dut.
        4. Check for unicast probe request, power management bit and association request with HE information

    Author: Vinod.G
"""

import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wifi_zephyr.utils.sl_status import SLStatus
from utf.utf_config import UtfConfig


def logger():
    return get_logger(__name__)


class PassiveScanFunctionality:
    def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, zephyr_wifi_collections, request,
                 dwell_time, scan_type, lp_mode=0, measure_scan_time=1, ap_bssid=None, power_save=None):
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.dwell_time = dwell_time
        self.lp_mode = lp_mode
        self.scan_type = scan_type
        self.measure_scan_time = measure_scan_time
        self.test_name = request.node.name
        self.ap_bssid = ap_bssid if ap_bssid else self.wifi_access_point.interfaces.wifi.bssid
        self.dut_mac = None
        self.power_save = power_save

    def scan(self, all_ch_scan=True, test_id=''):
        self.dut_mac = self.wifi_dut.interfaces.wifi.get_mac_address()
        channel = 0 if all_ch_scan else self.wifi_access_point.interfaces.wifi.channel
        if self.scan_type == 1:
            scan_time_threshold = (11 * self.dwell_time + 100) / 1000 if all_ch_scan else (self.dwell_time + 100) / 1000
            logger().info(f"Configuring the sniffer with channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"unicast_probe_check_{test_id}")
            time.sleep(5)
            scan_time = 0
            logger().info(f"*********** Starting passive scan by enabling passive scan bit in scan request ***********")
            if self.dwell_time == 0:
                scan_time_threshold = (11 * 400 + 100) / 1000 if all_ch_scan else (400 + 100) / 1000
            for count in range(3):
                try:
                    scan_time = self.wifi_dut.interfaces.wifi.scan(measure_scan_time=self.measure_scan_time,
                                                                   scan_type=self.scan_type,
                                                                   channel=channel, dwell_time_passive=self.dwell_time)[
                        -1]
                    scan_time = float(scan_time.split(':')[-1])
                    break
                except Exception as err:
                    logger().info("..........Scan_Retry..........")
                    if count == 2: raise err
            assert scan_time <= scan_time_threshold, (f"Observed passive scan time is more than expected value:"
                                                      f"{scan_time_threshold} Seconds")
            logger().info(f"\n\n******** Time taken for passive scan is --> '{scan_time}' seconds, which is within the "
                          f"expected threshold value '{scan_time_threshold}' seconds ********")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("******** Checking for unicast probe request packet in sniffer capture ********")
            packet_filter1 = f"(wlan.fc.type_subtype == 4) && (wlan.sa == {self.dut_mac}) && (wlan.da == {self.ap_bssid})"
            assert not self.wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
                "Found unicast probe request packet in sniffer capture, which is not expected"
        else:
            logger().info(f"************ Starting active scan from DUT ************")
            self.wifi_dut.interfaces.wifi.scan(scan_type=self.scan_type, channel=channel,
                                               measure_scan_time=self.measure_scan_time)

    def join_to_ap(self, ping_count=10, ps_enable=False):
        logger().info(f"\n\nConfiguring the sniffer with channel {self.wifi_access_point.interfaces.wifi.channel}")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
        time.sleep(3)
        self.zephyr_wifi_collections.connect(self.wifi_dut, self.wifi_access_point, retry_count=3)
        ip_config = self.zephyr_wifi_collections.configure_ip(self.wifi_dut, retry_count=3, timeout=120)[-1]
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        time.sleep(5)
        logger().info("Pinging to DUT")
        status = self.zephyr_wifi_collections.ping(device_ip=device_ip, ping_count=ping_count, retry_count=3)
        assert status, "Failed to ping to DUT before power save"
        if ps_enable:
            self.wifi_dut.interfaces.wifi.wifi_ps(enabled=1)
            status = self.zephyr_wifi_collections.ping(device_ip=device_ip, ping_count=ping_count, retry_count=3)
            assert status, "Failed to ping to DUT after power save"

    def sniffer_validation(self):
        logger().info("Stop sniffer capture finally")
        self.wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac,
                                                                                             da_addr=self.ap_bssid,
                                                                                             filter_name='power_mgmt_bit')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac,
                                                                                             da_addr=self.ap_bssid,
                                                                                             filter_name='association_request')
        logger().info("******** Checking for power management bit in sniffer capture ********")
        status = self.wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter2)['packet_count']
        if not status: logger().info("Unable to find power management bit 1 in sniffer")
        logger().info("******** Validating Assoc Req with HE information ********")
        status = self.wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter3)['packet_count']
        if not status: logger().info('Unable to find Assoc Req  with HE capability in sniffer')
        if self.power_save:
            packet_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=self.dut_mac,
                                                                                                da_addr=self.ap_bssid,
                                                                                                filter_name='power_mgmt_bit')

            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
                'packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C551131')
def test_wifi_zephyr_passive_scan_with_dwell_time_110ms_c551131(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                                sniffer_filter, zephyr_wifi_collections):
    """
    Verify Passive scan functionality by enabling dwell time to minimum value of 110ms.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                            zephyr_wifi_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551131')

    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.parametrize("dwell_time", [200, 400, 600, 800])
@pytest.mark.test_src_map_id('C551133')
def test_wifi_zephyr_passive_scan_for_diff_dwell_time_c551133(wifi_access_point, wifi_sniffer,
                                                              wifi_dut,
                                                              request, sniffer_filter, zephyr_wifi_collections,
                                                              dwell_time):
    """
    Verify Passive scan functionality by enabling dwell time to different values like 200ms,400ms,600ms,800ms and
    LP chain enabled.
    """
    try:
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                            zephyr_wifi_collections,
                                            request, dwell_time=dwell_time, scan_type=1, lp_mode=1)
        wlan_obj.scan(test_id='c551133')

    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.parametrize("dwell_time", [300, 500, 700])
@pytest.mark.test_src_map_id('C551134')
def test_wifi_zephyr_passive_scan_for_diff_dwell_time_c551134(wifi_access_point, wifi_sniffer, wifi_dut,
                                                              request, sniffer_filter, zephyr_wifi_collections,
                                                              dwell_time):
    """
    Verify Passive scan functionality by enabling dwell time to different values like 300ms,500ms,700ms and LP chain
    disabled.
    """
    try:

        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                            zephyr_wifi_collections,
                                            request, dwell_time=dwell_time, scan_type=1, lp_mode=0)
        wlan_obj.scan(test_id='c551134')

    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C551132')
def test_wifi_zephyr_passive_scan_max_dwell_time_1000ms_c551132(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                                sniffer_filter, zephyr_wifi_collections):
    """
    Verify Passive scan functionality by enabling dwell time to maximum value of 1000ms(1s)
    """
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                            zephyr_wifi_collections,
                                            request, dwell_time=1000, scan_type=1, lp_mode=0, power_save=power_save)
        wlan_obj.scan(test_id='c551132')
        wlan_obj.join_to_ap(ps_enable=power_save)
        wlan_obj.sniffer_validation()
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C551135')
def test_wifi_zephyr_passive_scan_func_probe_response_check_c551135(wifi_access_point, wifi_sniffer, wifi_dut, request,
                                                                    sniffer_filter, zephyr_wifi_collections):
    """
    Negative Case : Verify Passive scan functionality if DUT did not receives any probe response whether DUT is
    switching to Active scan or not.
    """
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                            zephyr_wifi_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=0, power_save=power_save)
        wlan_obj.scan(test_id='c551135')
        logger().info("******** Checking for probe response packet in sniffer capture ********")
        packet_filter1 = f"wlan.fc.type_subtype == 5 && wlan.sa == {wlan_obj.ap_bssid} && wlan.da == {wlan_obj.dut_mac}"
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
            "Found probe response packet in sniffer capture, which is not expected"
        logger().info("****************** DUT did not switch to active scan ************************")
        wlan_obj.join_to_ap(ps_enable=power_save)
        wlan_obj.sniffer_validation()
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('C551136')
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_passive_scan_with_dwell_time_1001ms_c551136(wifi_dut, zephyr_wifi_collections):
    """
    Negative Case : Verify Passive scan functionality by enabling Dwell time to 1001msec.
    """
    try:
        wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=1, dwell_time_passive=1001,
                                      expected_status=SLStatus.SL_STATUS_FAIL)
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C996247')
def test_wifi_zephyr_passive_scan_connect_disconnect_30min_c996247(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                   request, sniffer_filter, zephyr_wifi_collections):
    """
    Verify Passive scan functionality with LP chain disabled, Passive scan disconnect and connect back with passive
    scan only do it in loop for 30 minutes.
    """
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        sw = Stopwatch()
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                            zephyr_wifi_collections,
                                            request, dwell_time=110, scan_type=1, lp_mode=0, power_save=power_save)
        t_end = (30 * 60)
        while sw.elapsed_sec <= t_end:
            time_left = int((t_end - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            wlan_obj.scan(test_id='996247')
            wlan_obj.join_to_ap(ps_enable=power_save)
            wlan_obj.sniffer_validation()
            wifi_dut.interfaces.wifi.leave()
            logger().info("\n\n")
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C996248')
def test_wifi_zephyr_passive_scan_and_active_scan_30min_c996248(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                request, sniffer_filter, zephyr_wifi_collections):
    """
    Verify Passive scan functionality with LP chain enabled, Passive scan and active scan in loop for 30 minutes.
    """
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        sw = Stopwatch()
        t_end = (30 * 60)
        while sw.elapsed_sec <= t_end:
            time_left = int((t_end - sw.elapsed_sec) / 60)
            logger().info(f"*************** Remaining time to complete test is: '{time_left}' minutes ***************")
            for scan_type in [0, 1]:
                logger().info(f"******** Initiating test for scan type ---> {scan_type} ********")
                wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                    zephyr_wifi_collections, request, dwell_time=110,
                                                    scan_type=scan_type,
                                                    lp_mode=1,
                                                    power_save=power_save)
                wlan_obj.scan(test_id='996248')
                wlan_obj.join_to_ap(ps_enable=power_save)
                wlan_obj.sniffer_validation()
                wifi_dut.interfaces.wifi.leave()
                logger().info("\n\n")
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C996249')
def test_wifi_zephyr_passive_scan_default_dwell_time_in_all_channels_c996249(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                             request,
                                                                             sniffer_filter, zephyr_wifi_collections):
    """
    Verify Passive scan functionality by enabling dwell time to maximum value of 1000ms(1s)
    """
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                            zephyr_wifi_collections,
                                            request, dwell_time=0, scan_type=1, lp_mode=0, power_save=power_save)
        wlan_obj.scan(test_id='996249')
        wlan_obj.join_to_ap(ps_enable=power_save)
        wlan_obj.sniffer_validation()
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.test_src_map_id('C996250')
def test_wifi_zephyr_passive_scan_default_dwell_time_in_single_channel_c996250(wifi_access_point, wifi_sniffer,
                                                                               wifi_dut,
                                                                               request,
                                                                               sniffer_filter, zephyr_wifi_collections):
    """
    Verify Passive scan functionality by enabling dwell time to maximum value of 1000ms(1s)
    """
    try:
        power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
        wlan_obj = PassiveScanFunctionality(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                            zephyr_wifi_collections,
                                            request, dwell_time=0, scan_type=1, lp_mode=0, power_save=power_save)
        wlan_obj.scan(test_id='996250', all_ch_scan=False)
        wlan_obj.join_to_ap(ps_enable=power_save)
        wlan_obj.sniffer_validation()
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_passive_scan_neg_band_5ghz_c996254(wifi_dut, zephyr_wifi_collections):
    """
    Negative Case : Verify Passive scan functionality by enabling Dwell time to 1001msec.
    """
    try:
        wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=1, bands=2,
                                      expected_status=SLStatus.SL_STATUS_FAIL)
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
# Verifies the scan functionality with the channel 1,6,11
@pytest.mark.test_src_map_id('C996255')
def test_wifi_zephyr_passive_scan_selective_channel_c996255(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                            sniffer_filter,
                                                            zephyr_wifi_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        channel_list = [1, 6, 11]
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 110

            scan_time_threshold = scan_expected_time + 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(1)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results, scan_time = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                                    scan_bitmap_2_4=channel_bitmap_2_4,
                                                                    scan_type=1, dwell_time_passive=110,
                                                                    measure_scan_time=1)
            scan_time = float(scan_time.split(':')[-1])

            assert scan_time <= scan_time_threshold, (f"Observed passive scan time is more than expected value:"
                                                      f"{scan_time_threshold} Seconds")
            time.sleep(2)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "Scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("******** Checking for probe response packet in sniffer capture ********")
            packet_filter1 = f"wlan.fc.type_subtype == 5 && wlan.sa == {wifi_access_point.interfaces.wifi.bssid} && wlan.da == {sa_addr}"
            assert not wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter1)['packet_count'], \
                "Found probe response packet in sniffer capture, which is not expected"
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('C996256')
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_passive_scan_neg_dwell_time_less_than_10sec_c996256(wifi_dut, zephyr_wifi_collections):
    """
    Negative Case : Verify Passive scan functionality by enabling Dwell time to 9 sec.
    """
    try:
        wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=1, dwell_time_passive=9,
                                      expected_status=SLStatus.SL_STATUS_FAIL)
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
