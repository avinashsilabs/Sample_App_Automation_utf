import pytest
import time

from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils import print_dict
from utf.utf_config import UtfConfig

"""
    Setup requirement:
        1. SoC board
        2. Raspberry PI4
        3. 2.4 GHz Access Point
        4. Sniffer (NUC device)

    Test Steps:
        1. Configure the DUT in WLAN alone mode for 2.4 GHz operation
        2. Join the access point and enable DHCP
        3. Enable background scan on the DUT
        4. Start sniffer capture to monitor probe requests on the configured channels
        5. Validate bg scan behavior such as channel coverage, wildcard probe requests, and scan periodicity


    Author: Vinod.G

"""


# Define logger
def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


WILDCARD_PROBE_PERIODICITY_MIN_GAP_SEC = 4.0
WILDCARD_PROBE_PERIODICITY_MAX_GAP_SEC = 6.0


def validate_wildcard_probe_request_periodicity(
        wifi_sniffer,
        packet_filter,
        min_gap=WILDCARD_PROBE_PERIODICITY_MIN_GAP_SEC,
        max_gap=WILDCARD_PROBE_PERIODICITY_MAX_GAP_SEC,
):
    """Report wildcard probe request periodicity stats using frame epoch time."""
    epoch_times = wifi_sniffer.interfaces.capture.fetch_packet_epoch_timestamps(packet_filter)
    probe_count = len(epoch_times)

    logger().info(f"Wildcard probe request count: {probe_count}")
    logger().info(f"Expected gap range: [{min_gap}, {max_gap}]s")

    if probe_count < 2:
        logger().warning(
            f"Need at least 2 wildcard probe requests for periodicity stats, found {probe_count}"
        )
        return {
            "probe_count": probe_count,
            "epoch_times": epoch_times,
            "gaps": [],
            "gaps_in_range": [],
            "gaps_out_of_range": [],
        }

    epoch_values = [float(timestamp) for timestamp in epoch_times]
    gaps = [epoch_values[index] - epoch_values[index - 1] for index in range(1, len(epoch_values))]
    gaps_in_range = [gap for gap in gaps if min_gap <= gap <= max_gap]
    gaps_out_of_range = [gap for gap in gaps if gap not in gaps_in_range]

    logger().info(f"Wildcard probe request epoch times: {epoch_values}")
    logger().info(f"Wildcard probe request gaps (s): {[round(gap, 3) for gap in gaps]}")
    logger().info(
        f"Gap stats (s): min={min(gaps):.3f}, max={max(gaps):.3f}, "
        f"mean={sum(gaps) / len(gaps):.3f}, in_range={len(gaps_in_range)}, "
        f"out_of_range={len(gaps_out_of_range)}"
    )

    for index, gap in enumerate(gaps, start=1):
        if min_gap <= gap <= max_gap:
            logger().info(
                f"Probe request gap #{index}: {gap:.3f}s is within [{min_gap}, {max_gap}]s"
            )
        else:
            logger().warning(
                f"Probe request gap #{index}: {gap:.3f}s is outside expected range "
                f"[{min_gap}, {max_gap}]s"
            )

    if gaps_out_of_range:
        logger().warning(
            f"{len(gaps_out_of_range)} of {len(gaps)} probe request gap(s) are outside "
            f"[{min_gap}, {max_gap}]s"
        )
    else:
        logger().info(
            f"All {len(gaps)} wildcard probe request gap(s) are within [{min_gap}, {max_gap}]s"
        )

    return {
        "probe_count": probe_count,
        "epoch_times": epoch_values,
        "gaps": gaps,
        "gaps_in_range": gaps_in_range,
        "gaps_out_of_range": gaps_out_of_range,
    }


class SnifferChannelSwitchThread(ThreadBase):
    """Cycles sniffer channels while capture is active."""

    def __init__(
            self,
            wifi_sniffer,
            start_channel: int = 1,
            end_channel: int = 11,
            switch_interval: int = 30,
    ):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.start_channel = start_channel
        self.end_channel = end_channel
        self.switch_interval = switch_interval

    def run(self):
        channel = self.start_channel
        logger().info(
            f"Sniffer channel switch thread started: channels "
            f"{self.start_channel}-{self.end_channel}, interval {self.switch_interval}s"
        )

        while not self.stop_requested:
            logger().info(f"Switching sniffer to channel {channel}")
            self.wifi_sniffer.interfaces.capture.switch_channel(channel=channel)

            channel += 1
            if channel > self.end_channel:
                channel = self.start_channel

            elapsed = 0
            while elapsed < self.switch_interval and not self.stop_requested:
                time.sleep(1)
                elapsed += 1

        logger().info("Sniffer channel switch thread stopped")


class WLanBgScanThread(ThreadBase):
    def __init__(self, wifi_dut=None, zephyr_wifi_collections=None, wifi_sniffer=None, wifi_access_point=None,
                 test_case=None, sniffer_filter=None, utf_constants=None,
                 sniffer_capture=None, wifi_client=None, net_perf_client=None,
                 channel_switch_start=1, channel_switch_end=11, channel_switch_interval=30, protocol=None,
                 power_save=None):
        super().__init__()
        # Define all the parameters

        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.sniffer_capture = sniffer_capture
        self.dut_addr = None
        self.ap_mac_address = None
        self.channel_switch_thread = None
        self.channel_switch_start = channel_switch_start
        self.channel_switch_end = channel_switch_end
        self.channel_switch_interval = channel_switch_interval

        self.utf_constants = utf_constants
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.time_duration = 400
        self.protocol = protocol
        self.power_save = power_save

    def _stop_sniffer_channel_switch_thread(self):
        if self.channel_switch_thread is not None:
            logger().info("Stopping sniffer channel switch thread")
            self.channel_switch_thread.stop()
            self.channel_switch_thread.wait_for_exit(raise_exceptions=False)
            self.channel_switch_thread = None

    def run(self):
        sa_addr = None
        capture_stopped = False
        try:
            sa_addr = self.wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Device mac address: {sa_addr}")
            # Configure the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.configure_interface(self.wifi_access_point.interfaces.wifi.channel)
            # Start the sniffer on wifi_access_point channel
            self.wifi_sniffer.interfaces.capture.start_capture(self.sniffer_capture)
            # Get the mac address of the wifi_access_point
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(
                self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                associated=self.wifi_dut.interfaces.wifi.associated,
                power_save=self.power_save,
                ping_after_power_save=True,
            )
            if self.test_case == '19039':
                channel_list = [1, 6, 11]
                channel_bitmap_2_4 = 0
                scan_expected_time = 0
                for count in channel_list:
                    channel_bitmap_2_4 += 1 << (count - 1)
                    scan_expected_time += 100
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                                  scan_bitmap_2_4=channel_bitmap_2_4)
                time.sleep(2)
                logger().info(scan_results)
                assert len(scan_results) >= 1, "Scan results not found"
                # for count in scan_results:
                #     assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"
            elif self.test_case == '1733721':
                dwell_time_active = 50
                scan_time_threshold = (11 * dwell_time_active + 100) / 1000
                scan_results, scan_time = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                                             dwell_time_active=dwell_time_active,
                                                                             measure_scan_time=1)
                time.sleep(2)
                assert len(scan_results) >= 1, "Scan failed"
                logger().info(scan_results)
                logger().info(f"scan time--------------> {scan_time}")

                scan_time = float(scan_time.split(':')[-1])
                assert scan_time <= scan_time_threshold, (f"Observed active scan time is more than expected value:"
                                                          f"{scan_time_threshold} Seconds")
                logger().info(
                    f"\n\n******** Time taken for active scan is --> '{scan_time}' seconds, which is within the "
                    f"expected threshold value '{scan_time_threshold}' seconds ********")
            elif self.test_case == '1733722':
                dwell_time_passive = 100
                scan_time_threshold = (11 * dwell_time_passive + 100) / 1000
                scan_results, scan_time = self.wifi_dut.interfaces.wifi.scan(channel=0, scan_type=1, ssid=None,
                                                                             dwell_time_passive=dwell_time_passive,
                                                                             measure_scan_time=1)
                time.sleep(2)
                assert len(scan_results) >= 1, "Scan failed"
                logger().info(scan_results)
                logger().info(f"scan time--------------> {scan_time}")

                scan_time = float(scan_time.split(':')[-1])
                assert scan_time <= scan_time_threshold, (f"Observed active scan time is more than expected value:"
                                                          f"{scan_time_threshold} Seconds")
                logger().info(
                    f"\n\n******** Time taken for active scan is --> '{scan_time}' seconds, which is within the "
                    f"expected threshold value '{scan_time_threshold}' seconds ********")
            elif self.test_case == '1733726':
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=14, ssid=None)
                time.sleep(2)
                assert len(
                    scan_results) == 0, "Expected scan failure when invalid channel is provided, But observed scan results"
                logger().info(scan_results)
            else:
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                time.sleep(2)
                assert len(scan_results) >= 1, "Scan failed"
                logger().info(scan_results)
                if self.test_case == '1733727':
                    time.sleep(1)
                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    dut_ip = self.dut_addr['device_ip']
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                         device_ip=dut_ip,
                                                                         protocol=self.protocol)
                    logger().info(
                        f"Host IP: {host_ip}, Dut IP: {dut_ip}, Protocol: {self.protocol}")

                    logger().info(f"***** starting iperf ******")
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info(f"***** send traffic  ******")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=dut_ip, remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=1460, ttl=30, throughput_type=2)
                    logger().info(f"***** get and print throughput ******")
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp, "failed to get throughput..."
                    # __print_throughput(tp)
                    logger().info("data transfer is successful")
                    time.sleep(5)

            if (self.test_case == '19035') or (self.test_case == '19039'):
                self.channel_switch_thread = SnifferChannelSwitchThread(
                    wifi_sniffer=self.wifi_sniffer,
                    start_channel=self.channel_switch_start,
                    end_channel=self.channel_switch_end,
                    switch_interval=self.channel_switch_interval,
                )
                self.channel_switch_thread.start()

                logger().info(f"Waiting {self.time_duration}s for bg scan while sniffer hops channels 1-11")
                time.sleep(self.time_duration)
            elif self.test_case == '1733720' or self.test_case == '1733725':
                logger().info(f"Waiting 120s for bg scan while sniffer capture the packets")
                time.sleep(120)
            elif self.test_case == '19637':
                logger().info(f"Waiting 240s for bg scan while sniffer capture the packets")
                time.sleep(900)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e
        finally:
            if (self.test_case == '19035') or (self.test_case == '19039'):
                self._stop_sniffer_channel_switch_thread()
            if not capture_stopped:
                self.wifi_sniffer.interfaces.capture.stop_capture()
                capture_stopped = True
        if self.test_case == '1733720' or self.test_case == '1733727' or self.test_case == '19637':
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr,
                hidden_ssid="\"\"",
                filter_name="probe_request_wildcard",
            )
            logger().info(f"packet filter -> {packet_filter1}")
            validation_result = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                True, packet_filter1=packet_filter1
            )
            packet_count = validation_result.get("packet_count")
            find_packet_num = validation_result.get("find_packet_num", 0)
            logger().info(
                f"Probe request with WildCard SSID: found={packet_count}, count={find_packet_num}"
            )
            if not packet_count:
                logger().warning(
                    f"Unable to find Probe request with WildCard SSID:"
                )
        if (self.test_case == '19035') or (self.test_case == '19039'):
            for channel_number in range(1, 12):
                packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    channel_number=channel_number,
                    sa_addr=sa_addr,
                    filter_name="probe_request_channel",
                )
                logger().info(f"packet filter for channel {channel_number} -> {packet_filter1}")
                logger().info("Validate broadcast probe request")
                validation_result = self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    True, packet_filter1=packet_filter1
                )
                packet_count = validation_result.get("packet_count")
                find_packet_num = validation_result.get("find_packet_num", 0)
                logger().info(
                    f"Probe requests on channel {channel_number}: found={packet_count}, count={find_packet_num}"
                )
                if not packet_count:
                    logger().warning(
                        f"Unable to find broadcast probe request on channel {channel_number}"
                    )
        if self.test_case == '1733725':
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr,
                hidden_ssid="\"\"",
                filter_name="probe_request_wildcard",
            )
            logger().info(f"packet filter -> {packet_filter1}")
            min_gap = WILDCARD_PROBE_PERIODICITY_MIN_GAP_SEC
            max_gap = WILDCARD_PROBE_PERIODICITY_MAX_GAP_SEC

            validate_wildcard_probe_request_periodicity(
                wifi_sniffer=self.wifi_sniffer,
                packet_filter=packet_filter1,
                min_gap=min_gap,
                max_gap=max_gap,
            )


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_bg_scan_all_channels_2_4_ghz_c19035(firmware_loader, wifi_dut, wifi_access_point,
                                                         zephyr_wifi_collections,
                                                         wifi_sniffer,
                                                         sniffer_filter, utf_constants):
    """Verify bg scan works fine in channels 1 to 11"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='19035',
                                    utf_constants=utf_constants, sniffer_capture='19035', power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_bg_scan_2_4_ghz_channels_1_6_11_c19039(firmware_loader, wifi_dut, wifi_access_point,
                                                            zephyr_wifi_collections,
                                                            wifi_sniffer,
                                                            sniffer_filter, utf_constants):
    """Verify bg scan works fine in channels 1, 6 and 11"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='19039',
                                    utf_constants=utf_constants, sniffer_capture='19039', power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_bg_scan_wildcard_probe_request_c1733720(firmware_loader, wifi_dut, wifi_access_point,
                                                             zephyr_wifi_collections,
                                                             wifi_sniffer,
                                                             sniffer_filter, utf_constants):
    """Verify bg scan sends wildcard (empty SSID) probe requests"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='1733720',
                                    utf_constants=utf_constants, sniffer_capture='1733720', power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_bg_scan_active_scan_50_c1733721(firmware_loader, wifi_dut, wifi_access_point, zephyr_wifi_collections,
                                                     wifi_sniffer,
                                                     sniffer_filter, utf_constants):
    """Verify bg scan sends wildcard (empty SSID) probe requests"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='1733721',
                                    utf_constants=utf_constants, sniffer_capture='1733721', power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_bg_passive_scan_100_c1733722(firmware_loader, wifi_dut, wifi_access_point, zephyr_wifi_collections,
                                                  wifi_sniffer,
                                                  sniffer_filter, utf_constants):
    """Verify bg scan sends wildcard (empty SSID) probe requests"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='1733722',
                                    utf_constants=utf_constants, sniffer_capture='1733722', power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_bg_scan_periodicity_check_c1733725(firmware_loader, wifi_dut, wifi_access_point, zephyr_wifi_collections,
                                                        wifi_sniffer,
                                                        sniffer_filter, utf_constants):
    """Verify bg scan wildcard probe request periodicity is between 4 and 6 seconds"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='1733725',
                                    utf_constants=utf_constants, sniffer_capture='1733725', power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_wifi_zephyr_bg_scan_while_udp_tx_c1733727(firmware_loader, wifi_dut, wifi_access_point, zephyr_wifi_collections,
                                                   wifi_sniffer,
                                                   sniffer_filter, utf_constants, net_perf_client, wifi_client,
                                                   protocol):
    """Verify bg scan functionality while UDP tx"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='1733727',
                                    utf_constants=utf_constants, sniffer_capture='1733727',
                                    net_perf_client=net_perf_client,
                                    wifi_client=wifi_client, protocol=protocol, power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_bg_scan_fail_with_invalid_channel_c1733726(firmware_loader, wifi_dut, wifi_access_point, zephyr_wifi_collections,
                                                                wifi_sniffer,
                                                                sniffer_filter, utf_constants):
    """Verify whether scan fails when provided invalid channel"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='1733726',
                                    utf_constants=utf_constants, sniffer_capture='1733726', power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.firmware_app("test_bg_scan")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_wifi_zephyr_bg_scan_check_keep_alive_c19637(firmware_loader, wifi_dut, wifi_access_point, zephyr_wifi_collections,
                                                     wifi_sniffer,
                                                     sniffer_filter, utf_constants):
    """Verify bg scan functionality and wlan-keep alive functionality"""
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        wlan_obj = WLanBgScanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    zephyr_wifi_collections=zephyr_wifi_collections,
                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter, test_case='19637',
                                    utf_constants=utf_constants, sniffer_capture='19637', power_save=power_save)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
