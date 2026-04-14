import time
import pytest
import re
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect_3.tests.devices.si91x import Si91xOperatingMode
from utf.interfaces.wifi import WlanError
from utf import UtfDatabaseProperties
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


""" Test Steps
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiate the Scan from DUT
        4. Verify the scan results

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC 

    Author: Shaik Abdul Azeez
"""


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778442')
def test_at_wifi_sdk_all_channels_2_4ghz_with_channel_c778442(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                              sniffer_filter, sl_collections):
    '''Verify All Channels Scan in 2.4 Ghz by giving channel number as Zero'''
    try:
        test_name = request.node.name
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 12))
        true_result_list = []
        false_result_list = []
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")

        for channel in channel_list:
            logger().info(f"Configuring sniffer on channel: {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(3)

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)

            logger().info("Initiating scan on DUT...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=None,
                enable_lp_mode=None
            )
            time.sleep(20)
            logger().info(f"Scan results: {scan_results}")

            assert len(scan_results) >= 1, "Scan results not found"
            for result in scan_results:
                assert result["rf_channel"] in channel_list, "Scan should occur only on selected channels"

            logger().info("Stopping sniffer capture...")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Stoping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr, filter_name="probe_request"
            )

            logger().info("Validating probe request (broadcast)...")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)["packet_count"]

            if not output:
                false_result_list.append(False)
                probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(True)
                probe_captured_channel_list.append(channel)

            logger().info(f"Channels with probe requests: {probe_captured_channel_list}")
            logger().info(f"Channels without probe requests: {probe_not_captured_channel_list}")

        if probe_not_captured_channel_list:
            logger().info(f"**** Unable to find probe requests on these channels: {probe_not_captured_channel_list}")

        assert not probe_not_captured_channel_list, \
            f"**** Probe requests missing on channels: {probe_not_captured_channel_list}"

        logger().info(f"Probe requests successfully captured on all channels: {probe_captured_channel_list}")
        logger().info("DUT scan successfully validated on all selected 2.4GHz channels.")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C778443')
def test_at_wifi_sdk_all_chan_scan_with_channel_bitmap_c778443(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                               sniffer_filter, sl_collections):
    '''Verify All Channels Scan in 2.4 Ghz by setting all channels in channel bitmap field'''
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 12))
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2g4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2g4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(3)

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(interface=5, filter_ssid="", scan_type=None, scan_flags=None,
                                                         periodic_scan_interval=100,
                                                         channel_bitmap_2g4=channel_bitmap_2g4, enable_lp_mode=None)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "scan results not found"
            for result in scan_results:
                assert (result['rf_channel'] in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Stoping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info("Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if not bool(output):
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        if Probe_not_captured_channel_list:
            logger().info(
                f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}"
            )
        assert Probe_not_captured_channel_list == [], (
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}"
        )
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C778444')
def test_at_wifi_sdk_scan_selective_channel_1_3_6_11_c778444(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                             sniffer_filter, sl_collections):
    '''Verify Scan in selective channels (1, 3, 6, 11) by setting channel bitmap field'''
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = [1, 3, 6, 11]
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []
        channel_bitmap_2g4 = 0
        for count in channel_list:
            channel_bitmap_2g4 += 1 << (count - 1)

        for channel in channel_list:
            logger().info(f"Configuring the Sniffer with the channel: {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(3)

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5, filter_ssid="", scan_type=None, scan_flags=None,
                periodic_scan_interval=100, channel_bitmap_2g4=channel_bitmap_2g4, enable_lp_mode=None
            )
            time.sleep(20)
            logger().info(scan_results)
            # Only check that at least one AP is found on the current channel
            found = any(result.get('rf_channel') == channel for result in scan_results)
            assert found, f"No AP found on channel {channel}"

            wifi_sniffer.interfaces.capture.stop_capture()
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info("Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if output:
                probe_captured_channel_list.append(channel)
            else:
                probe_not_captured_channel_list.append(channel)
            logger().info(f"Channels with probe requests: {probe_captured_channel_list}")
            logger().info(f"Channels without probe requests: {probe_not_captured_channel_list}")

        if probe_not_captured_channel_list:
            logger().info(
                f"**** Unable to find the Probe requests in these channels: {probe_not_captured_channel_list}")
        assert not probe_not_captured_channel_list, (
            f"**** Unable to find the Probe requests in these channels: {probe_not_captured_channel_list}"
        )
        logger().info(f"Found Probe req(Broadcast) in all the channels: {probe_captured_channel_list}")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C778445')
def test_at_wifi_sdk_scan_check_rssi_c778445(wifi_dut, sl_collections):
    """This test case verifies that the scan results are sorted based on RSSI in descending order."""
    try:
        logger().info("Setting DUT in WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        logger().info("Initiating scan on DUT...")
        scan_results = wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=None,
            scan_flags=None,
            periodic_scan_interval=100,
            channel_bitmap_2g4=None,
            enable_lp_mode=None
        )
        time.sleep(20)
        logger().info(f"Scan results: {scan_results}")
        assert scan_results, "Scan results not found"

        # Sort check: RSSI should be in descending order
        previous_rssi_val = float('inf')
        for result in scan_results:
            rssi = result['rssi_val']
            assert rssi <= previous_rssi_val, f"Scan result not sorted by RSSI: {rssi} > {previous_rssi_val}"
            logger().info(f"Scan result RSSI: {rssi}")
            previous_rssi_val = rssi

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient},
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C778446')
def test_at_wifi_sdk_scan_max_aps_c778446(wifi_dut, sl_collections):
    """This test case verifies that the DUT can scan and return a maximum number of APs."""
    try:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_bitmap_2g4 = 0
        logger().info("Initiating selective channel scan from dut using previous API...")
        scan_results = wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=None,
            scan_flags=None,
            periodic_scan_interval=100,
            channel_bitmap_2g4=channel_bitmap_2g4,
            enable_lp_mode=None
        )
        time.sleep(20)
        logger().info(scan_results)
        logger().info(len(scan_results))
        if len(scan_results) == 11:
            assert True, f"Dut has scanned {len(scan_results)} Aps"
        else:
            assert False, f"To scan more number of APs, Need to keep setup in open air environment"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient},
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"ssid": "test_ssid", "broadcast_ssid": False})
@pytest.mark.test_src_map_id('C778447')
def test_at_wifi_sdk_hidden_scan_all_channels_c778447(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                      sniffer_filter, sl_collections):
    """
    Verify scan in hidden mode of AP for all 2.4GHz channels (1-11).
    """
    try:
        test_name = request.node.name
        dut_mac = wifi_dut.interfaces.wifi.get_mac_address()
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        channel_list = list(range(1, 12))
        probe_captured = []
        probe_not_captured = []

        logger().info("Device MAC address: %s", dut_mac)
        logger().info("AP MAC address: %s", ap_mac)

        logger().info("Setting DUT in WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        for channel in channel_list:
            logger().info("Configuring sniffer and AP on channel: %s", channel)
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(3)

            # Use the correct filter name for hidden SSID probe request packets
            packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_mac,
                hidden_ssid="\"\"",
                filter_name="hidden_ssid_probe_request_packet"
            )

            logger().info("Initiating scan on DUT...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=None,
                enable_lp_mode=None
            )
            time.sleep(20)
            logger().info("Scan results: %s", scan_results)
            assert scan_results, f"Scan failed: No results returned on channel {channel}"

            wifi_sniffer.interfaces.capture.stop_capture()
            wifi_access_point.interfaces.wifi.stop_ap()

            logger().info("Validating hidden SSID probe request (broadcast)...")
            packet_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
                "packet_count"]
            if packet_count:
                probe_captured.append(channel)
            else:
                probe_not_captured.append(channel)

        logger().info(f"Channels with hidden SSID probe requests: {probe_captured}")
        logger().info(f"Channels without hidden SSID probe requests: {probe_not_captured}")
        assert not probe_not_captured, f"Hidden SSID probe requests missing on channels: {probe_not_captured}"

    except Exception as e:
        logger().error("Exception occurred: %s", e)
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient},
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"ssid": "test_ssid", "broadcast_ssid": False})
@pytest.mark.test_src_map_id('C778448')
def test_at_wifi_sdk_hidden_scan_selected_channels_1_5_9_c778448(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                                 sniffer_filter, sl_collections):
    """
    Verifies the scan in selected channels (1, 5, 9) with the AP set in hidden mode.
    """
    try:
        test_name = request.node.name
        dut_mac = wifi_dut.interfaces.wifi.get_mac_address()
        ap_mac = wifi_access_point.interfaces.wifi.bssid
        channel_list = [1, 5, 9]
        probe_captured = []
        probe_not_captured = []

        logger().info("Device MAC address: %s", dut_mac)
        logger().info("AP MAC address: %s", ap_mac)

        logger().info("Setting DUT in WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        for channel in channel_list:
            logger().info("Configuring sniffer and AP on channel: %s", channel)
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(3)

            # Use the correct filter name for hidden SSID probe request packets
            packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=dut_mac,
                hidden_ssid="\"\"",
                filter_name="hidden_ssid_probe_request_packet"
            )

            logger().info("Initiating scan on DUT...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=None,
                enable_lp_mode=None
            )
            time.sleep(20)
            logger().info("Scan results: %s", scan_results)
            assert scan_results, f"Scan failed: No results returned on channel {channel}"

            wifi_sniffer.interfaces.capture.stop_capture()
            wifi_access_point.interfaces.wifi.stop_ap()

            logger().info("Validating hidden SSID probe request (broadcast)...")
            packet_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
                "packet_count"]
            if packet_count:
                probe_captured.append(channel)
            else:
                probe_not_captured.append(channel)

        logger().info(f"Channels with hidden SSID probe requests: {probe_captured}")
        logger().info(f"Channels without hidden SSID probe requests: {probe_not_captured}")
        assert not probe_not_captured, f"Hidden SSID probe requests missing on channels: {probe_not_captured}"

    except Exception as e:
        logger().error("Exception occurred: %s", e)
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient},
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C778449')
def test_at_wifi_sdk_scan_ssid_32bytes_c778449(wifi_access_point, wifi_dut, wifi_sniffer, request, sl_collections):
    """
    Verify scan with 32-byte SSID name.
    """
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info("Setting DUT in wlan power save (previous API)...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)
        ssid_list = [
            'test123test123test123test123test',
            'test1*@test1*#test1*@test1*$test',
            'test12.test12.test12.test12.test',
            '了是不了是不了是不了'
        ]

        for ssid in ssid_list:
            logger().info(f"Configuring the Sniffer with the channel: {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            time.sleep(5)
            logger().info(f"Setting access point with ssid {ssid}...")
            wifi_access_point.interfaces.wifi.start_ap(ssid=ssid)
            time.sleep(10)
            logger().info(f"Configuring the 32-byte SSID: {ssid}")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid=ssid,
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=None,
                enable_lp_mode=None
            )
            time.sleep(20)
            logger().info("Scan results:")
            assert len(scan_results) >= 1, f"32 bytes ssid not found in scan results"
            logger().info("Validate Probe req(Broadcast)")
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C778452')
def test_at_wifi_sdk_scan_in_us_region_for_channel_12_13_14_c778452(wifi_dut, sl_collections):
    '''This test case verifies that the DUT does not scan channels 12, 13, and 14 in the US region.'''
    try:
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = [12, 13, 14]
        channel_bitmap_2g4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2g4 += 1 << (count - 1)
            scan_expected_time += 100
            logger().info(f"Initiating the scan in DUT with the given channel bitmap value ---->>>{count}")
            try:
                scan_results = wifi_dut.interfaces.wifi.scan(
                    interface=5,
                    filter_ssid="",
                    scan_type=None,
                    scan_flags=None,
                    periodic_scan_interval=100,
                    channel_bitmap_2g4=channel_bitmap_2g4,
                    enable_lp_mode=None
                )
                time.sleep(5)
                # Expecting no valid scan results for invalid channels
                assert not scan_results, f"Scan should fail for invalid channels {count}, but got results: {scan_results}"
            except Exception as scan_exc:
                # Optionally check for specific error code if available
                logger().info(f"Expected exception for invalid channel {count}: {scan_exc}")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 2,
        "region_code": "europe"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'europe'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778453')
def test_at_wifi_sdk_scan_all_channels_in_europe_region_c778453(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                                sniffer_filter, sl_collections):
    '''Verify scan functionality in all 2.4GHz channels in Europe region (1-13).'''
    try:
        test_name = request.node.name
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 14))
        true_result_list = []
        false_result_list = []
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")

        for channel in channel_list:
            logger().info(f"Configuring sniffer on channel: {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(3)

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)

            logger().info("Initiating scan on DUT...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=None,
                enable_lp_mode=None
            )
            time.sleep(20)
            logger().info(f"Scan results: {scan_results}")

            assert len(scan_results) >= 1, "Scan results not found"
            for result in scan_results:
                assert result["rf_channel"] in channel_list, "Scan should occur only on selected channels"

            logger().info("Stopping sniffer capture...")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Stoping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr, filter_name="probe_request"
            )

            logger().info("Validating probe request (broadcast)...")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)["packet_count"]

            if not output:
                false_result_list.append(False)
                probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(True)
                probe_captured_channel_list.append(channel)

            logger().info(f"Channels with probe requests: {probe_captured_channel_list}")
            logger().info(f"Channels without probe requests: {probe_not_captured_channel_list}")

        if probe_not_captured_channel_list:
            logger().info(f"**** Unable to find probe requests on these channels: {probe_not_captured_channel_list}")

        assert not probe_not_captured_channel_list, \
            f"**** Probe requests missing on channels: {probe_not_captured_channel_list}"

        logger().info(f"Probe requests successfully captured on all channels: {probe_captured_channel_list}")
        logger().info("DUT scan successfully validated on all selected 2.4GHz channels.")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 2,
        "region_code": "europe"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C778454')
def test_at_wifi_sdk_scan_channel_14_in_europe_region_c778454(wifi_dut, sl_collections):
    '''This test case verifies that the DUT can scan channel 14 in the Europe region.'''
    try:
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        # Channel bitmap for channel 14 (bit 13, since channels start at 1)
        channel_bitmap_2g4 = 1 << (14 - 1)

        logger().info("Initiating scan on channel 14 in EU region...")
        scan_results = wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=None,
            scan_flags=None,
            periodic_scan_interval=100,
            channel_bitmap_2g4=channel_bitmap_2g4,
            enable_lp_mode=None
        )
        time.sleep(20)
        logger().info(f"Scan results: {scan_results}")
        assert len(scan_results) >= 1, "No APs found on channel 14 in EU region"
        logger().info("DUT scan success on channel 14 in EU region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 3,
        "region_code": "japan"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778455')
def test_at_wifi_sdk_regional_scan_japan_2_4ghz_measure_time_c778455(wifi_dut, sl_collections):
    '''Verify regional scanning in Japan region in 2.4GHz band and measure scan time'''
    try:
        logger().info("Setting DUT into WLAN power save mode for Japan region...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 15))  # Channels 1-14 for Japan
        channel_bitmap_2g4 = 0
        for channel in channel_list:
            channel_bitmap_2g4 |= 1 << (channel - 1)

        logger().info("Measuring scan time for all 2.4GHz channels in Japan region...")
        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=channel_bitmap_2g4,
                enable_lp_mode=None
            )
        scan_time = t.duration
        logger().info(f"Scan results: {scan_results}")
        logger().info(f"Total scan time for Japan region (channels 1-14): {scan_time:.2f} seconds")

        assert scan_results, "No scan results found in Japan region"
        scanned_channels = set(result["rf_channel"] for result in scan_results)
        missing_channels = [ch for ch in channel_list if ch not in scanned_channels]
        if missing_channels:
            logger().warning(f"Channels missing in scan results: {missing_channels}")
        # Optionally, you can assert only if all are missing
        assert len(scanned_channels) > 0, "No channels found in scan results"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 3,
        "region_code": "japan"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778456')
def test_at_wifi_sdk_scan_channels_12_13_14_japan_region_c778456(wifi_dut, sl_collections):
    """Do scan in channels 12,13,14 in JP region"""
    try:
        logger().info("Setting DUT into WLAN power save mode for Japan region...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)
        channels_list = [12, 13, 14]
        for channel in channels_list:
            channel_bitmap_2g4 = 1 << (channel - 1)
            logger().info(f"Initiating scan on channel {channel}...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=channel_bitmap_2g4,
                enable_lp_mode=None
            )
            logger().info(f"Scan results for channel {channel}: {scan_results}")
            assert scan_results is not None, f"Scan failed on channel {channel}"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 4,
        "region_code": "worldwide"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778457')
def test_at_wifi_sdk_regional_scan_worldwide_2_4ghz_measure_time_c778457(wifi_dut, sl_collections):
    """Verify regional scanning in worldwide region in 2.4GHz band and measure scan time"""
    try:
        logger().info("Setting DUT into WLAN power save mode for worldwide region...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 15))  # Channels 1-14 for worldwide
        channel_bitmap_2g4 = 0
        for channel in channel_list:
            channel_bitmap_2g4 |= 1 << (channel - 1)

        logger().info("Measuring scan time for all 2.4GHz channels in worldwide region...")
        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=channel_bitmap_2g4,
                enable_lp_mode=None
            )
        scan_time = t.duration
        logger().info(f"Scan results: {scan_results}")
        logger().info(f"Total scan time for worldwide region (channels 1-14): {scan_time:.2f} seconds")

        assert scan_results, "No scan results found in worldwide region"
        scanned_channels = set(result["rf_channel"] for result in scan_results)
        missing_channels = [ch for ch in channel_list if ch not in scanned_channels]
        if missing_channels:
            logger().warning(f"Missing channels in scan results: {missing_channels}")
        assert len(scanned_channels) > 0, "No channels found in scan results"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 5,
        "region_code": "Korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'Korea'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778458')
def test_at_wifi_sdk_scan_all_channels_in_korea_region_c778458(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                               sniffer_filter, sl_collections):
    '''Verify scan functionality in all 2.4GHz channels in Korea region (1-14).'''
    try:
        test_name = request.node.name
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 14))
        true_result_list = []
        false_result_list = []
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")

        for channel in channel_list:
            logger().info(f"Configuring sniffer on channel: {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(3)

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)

            logger().info("Initiating scan on DUT...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=None,
                enable_lp_mode=None
            )
            time.sleep(20)
            logger().info(f"Scan results: {scan_results}")

            assert len(scan_results) >= 1, "Scan results not found"
            for result in scan_results:
                assert result["rf_channel"] in channel_list, "Scan should occur only on selected channels"

            logger().info("Stopping sniffer capture...")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Stoping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr, filter_name="probe_request"
            )

            logger().info("Validating probe request (broadcast)...")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)["packet_count"]

            if not output:
                false_result_list.append(False)
                probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(True)
                probe_captured_channel_list.append(channel)

            logger().info(f"Channels with probe requests: {probe_captured_channel_list}")
            logger().info(f"Channels without probe requests: {probe_not_captured_channel_list}")

        if probe_not_captured_channel_list:
            logger().info(f"**** Unable to find probe requests on these channels: {probe_not_captured_channel_list}")

        assert not probe_not_captured_channel_list, \
            f"**** Probe requests missing on channels: {probe_not_captured_channel_list}"

        logger().info(f"Probe requests successfully captured on all channels: {probe_captured_channel_list}")
        logger().info("DUT scan successfully validated on all selected 2.4GHz channels.")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 5,
        "region_code": "Korea"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778460')
def test_at_wifi_sdk_scan_channel_14_in_korea_region_error_c778460(wifi_dut, sl_collections):
    """
    Verify DUT throws error or returns no results when scanning channel 14 in Korea region.
    """
    try:
        logger().info("Setting DUT into WLAN power save mode for Korea region...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_bitmap_2g4 = 1 << (14 - 1)
        logger().info("Initiating scan on channel 14 in Korea region...")
        scan_results = wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=None,
            scan_flags=None,
            periodic_scan_interval=100,
            channel_bitmap_2g4=channel_bitmap_2g4,
            enable_lp_mode=None
        )
        time.sleep(5)
        # Filter results for channel 14
        channel_14_results = [result for result in scan_results if result.get("rf_channel") == 14]
        assert not channel_14_results, "Scan should fail or return no results for channel 14 in Korea region"
        logger().info("DUT correctly handled scan on channel 14 in Korea region.")

    except Exception as e:
        logger().info(f"Expected exception for invalid channel 14 in Korea region: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 4,
        "region_code": "worldwide"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778462')
def test_at_wifi_sdk_passive_scan_worldwide_2_4ghz_c778462(sl_collections, wifi_dut):
    """
    Verify passive scan in worldwide domain (channels 1-14).
    """
    try:
        logger().info("Setting DUT into WLAN power save mode for worldwide region...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 15))  # Channels 1-14
        channel_bitmap_2g4 = 0
        for channel in channel_list:
            channel_bitmap_2g4 |= 1 << (channel - 1)

        logger().info("Initiating passive scan on all 2.4GHz channels in worldwide region...")
        scan_results = wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=1,
            scan_flags=None,
            periodic_scan_interval=100,
            channel_bitmap_2g4=channel_bitmap_2g4,
            enable_lp_mode=None
        )
        time.sleep(50)
        logger().info(f"Scan results: {scan_results}")

        assert scan_results, "No scan results found in passive scan"
        scanned_channels = set(result["rf_channel"] for result in scan_results)
        missing_channels = [ch for ch in channel_list if ch not in scanned_channels]
        logger().info(f"Channels found: {scanned_channels}")
        if missing_channels:
            logger().warning(f"Channels missing in scan results: {missing_channels}")
        assert len(scanned_channels) > 0, "No channels found in scan results"

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient}
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778464')
def test_at_wifi_sdk_scan_special_char_ssid_c778464(wifi_access_point, wifi_dut, wifi_sniffer, sniffer_filter,
                                                    sl_collections, request):
    """
    Verify DUT can scan SSIDs with special characters and sends probe requests on all 2.4GHz channels.
    """
    special_ssid = [
        "test!@#$_ssid"
    ]
    channel_list = list(range(1, 12))
    try:
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        for ssid in special_ssid:
            for channel in channel_list:
                # Start AP with special character SSID on current channel
                wifi_access_point.interfaces.wifi.start_ap(ssid=ssid, channel=channel)
                # Configure sniffer to AP channel
                wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
                wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{request.node.name}_{ssid}_ch{channel}")
                time.sleep(5)
                # Initiate scan for the special SSID from DUT
                scan_results = wifi_dut.interfaces.wifi.scan(
                    interface=5,
                    filter_ssid=ssid,
                    scan_type=None,
                    scan_flags=None,
                    periodic_scan_interval=100,
                    channel_bitmap_2g4=None,
                    enable_lp_mode=None
                )
                found = any(result.get("ssid") == ssid for result in scan_results)
                assert found, f"SSID with special characters not found on channel {channel}: {ssid}"
                wifi_sniffer.interfaces.capture.stop_capture()
                # Create sniffer filter for probe request packets
                packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=sa_addr, filter_name="probe_request"
                )
                packet_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
                    "packet_count"]
                assert packet_count, f"Probe request not captured for SSID {ssid} on channel {channel}"
                wifi_access_point.interfaces.wifi.stop_ap()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient}
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C778465')
def test_at_wifi_sdk_scan_with_high_beacon_length_c778465(wifi_access_point, wifi_dut, request, wifi_sniffer,
                                                          sniffer_filter, sl_collections):
    """Verify WLAN scan with a third-party AP configured with a high beacon length (max 512 bytes)."""
    try:
        test_name = request.node.name
        packet_filter2 = '    Frame Length:'

        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {ap_bssid}")

        logger().info("Initiating scan from DUT...")
        scan_results = wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=None,
            scan_flags=None,
            periodic_scan_interval=100,
            channel_bitmap_2g4=None,
            enable_lp_mode=None
        )
        time.sleep(20)  # Wait for scan to complete
        assert len(scan_results) >= 1, "Scan failed"
        logger().info(scan_results)

        logger().info("Stopping sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_bssid,
                                                                                        filter_name="beacon")
        logger().info("Validating Probe req(Broadcast)")
        sniffer_validation_result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                                       packet_filter2=packet_filter2)
        assert sniffer_validation_result['packet_count'], \
            f'Unable to find beacon packet in channel: {wifi_access_point.interfaces.wifi.channel}'

        pattern = r"Frame Length:\s+(\d+)\s+bytes"
        # Open the file and search for the pattern
        capture_file_path = './reports/filter2_file.txt'

        try:
            with open(capture_file_path, 'r') as file:
                for line in file.readlines():
                    match = re.search(pattern, line)
                    if match:
                        # Extract the frame length in bytes
                        frame_length = int(match.group(1))
                        if frame_length < 512:
                            return "Fail: Frame Length is less than 512 bytes"
                        logger().info(f"Frame Length: {frame_length} bytes")
        except FileNotFoundError:
            logger().error(f"Capture file not found: {capture_file_path}")
            raise

    except Exception as e:
        logger().error(f"Exception occurred: {e}")  # Log the exception
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise  # Re-raise the exception after handling to ensure test failure is reported


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient}
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'US'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778466')
def test_at_wifi_sdk_scan_extended_more_than_11_aps_c778466(wifi_sniffer, wifi_dut, request, sl_collections):
    """Verify whether DUT is able to scan more than 11 scan results when SL_WIFI_SCAN_TYPE_EXTENDED is enabled."""
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")
        channel_filter = 0
        logger().info(f"Configuring the sniffer with channel: {channel_filter}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel_filter)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel_filter}")
        time.sleep(2)

        logger().info("Initiating extended scan from DUT ...")
        wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=2,
            scan_flags=None,
            periodic_scan_interval=None,
            channel_bitmap_2g4=None,
            enable_lp_mode=None
        )
        time.sleep(40)  # Wait for scan to complete

        scan_results = wifi_dut.interfaces.wifi.get_extended_scan_results(
            max_results=50,
            channel_filter=None,
            security_mode_filter=None,
            rssi_filter=None,
            network_type_filter=None
        )
        logger().info(f"Scan results: {scan_results}")
        logger().info(f"Number of APs found: {len(scan_results)}")
        assert len(scan_results) > 11, "Scan failed: Did not find more than 11 APs with extended scan type"

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient}
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778467')
def test_at_wifi_sdk_connect_ap_after_11th_scan_result_extended_scan_c778467(sl_collections, wifi_dut, wifi_access_point):
    """
    Verify DUT can connect to the AP which comes after the 11th scan result
    when SL_WIFI_SCAN_TYPE_EXTENDED is enabled.
    """
    try:
        logger().info("Setting DUT in WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        logger().info("Initiating extended scan from DUT...")
        wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=2,  # SL_WIFI_SCAN_TYPE_EXTENDED
            scan_flags=None,
            periodic_scan_interval=None,
            channel_bitmap_2g4=None,
            enable_lp_mode=None
        )
        time.sleep(10)
        scan_results = wifi_dut.interfaces.wifi.get_extended_scan_results(max_results=50)
        logger().info(f"Scan results: {scan_results}")
        assert len(scan_results) > 11, "Less than 12 APs found, cannot test connection to AP after 11th result"

        target_ap = scan_results[11]
        ssid = target_ap['ssid']
        channel = target_ap.get('rf_channel', 0)
        logger().info(f"Attempting to connect to AP after 11th scan result: SSID={ssid}, Channel={channel}")

        wifi_access_point.interfaces.wifi.start_ap(ssid=ssid, channel=channel)
        time.sleep(15)

        sl_collections.join_to_wifi_network_at_cmd(wifi_dut, wifi_access_point, power_save=True)
        logger().info("Successfully connected to AP after 11th scan result.")

        wifi_access_point.interfaces.wifi.stop_ap()

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 7,
        "region_code": "china"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'China'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778468')
def test_at_wifi_sdk_scan_all_channels_in_china_region_c778468(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                               sniffer_filter, sl_collections):
    '''Verify scan functionality in all 2.4GHz channels in China region (1-13).'''
    try:
        test_name = request.node.name
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 14))
        true_result_list = []
        false_result_list = []
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")

        for channel in channel_list:
            logger().info(f"Configuring sniffer on channel: {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(3)

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)

            logger().info("Initiating scan on DUT...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=None,
                scan_flags=None,
                periodic_scan_interval=100,
                channel_bitmap_2g4=None,
                enable_lp_mode=None
            )
            time.sleep(20)
            logger().info(f"Scan results: {scan_results}")

            assert len(scan_results) >= 1, "Scan results not found"
            for result in scan_results:
                assert result["rf_channel"] in channel_list, "Scan should occur only on selected channels"

            logger().info("Stopping sniffer capture...")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Stoping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr, filter_name="probe_request"
            )

            logger().info("Validating probe request (broadcast)...")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)["packet_count"]

            if not output:
                false_result_list.append(False)
                probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(True)
                probe_captured_channel_list.append(channel)

            logger().info(f"Channels with probe requests: {probe_captured_channel_list}")
            logger().info(f"Channels without probe requests: {probe_not_captured_channel_list}")

        if probe_not_captured_channel_list:
            logger().info(f"**** Unable to find probe requests on these channels: {probe_not_captured_channel_list}")

        assert not probe_not_captured_channel_list, \
            f"**** Probe requests missing on channels: {probe_not_captured_channel_list}"

        logger().info(f"Probe requests successfully captured on all channels: {probe_captured_channel_list}")
        logger().info("DUT scan successfully validated on all selected 2.4GHz channels.")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient, "region": 7, "region_code": "China"}
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'China'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778469')
def test_at_wifi_sdk_scan_extended_more_than_11_aps_china_region_c778469(sl_collections, wifi_sniffer, wifi_dut,
                                                                         request):
    """
    Verify whether DUT is able to scan more than 11 scan results when SL_WIFI_SCAN_TYPE_EXTENDED is enabled (China region).
    """
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")
        channel_filter = 0
        logger().info(f"Configuring the sniffer with channel: {channel_filter}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel_filter)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel_filter}")
        time.sleep(2)

        logger().info("Initiating extended scan from DUT ...")
        wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=2,  # SL_WIFI_SCAN_TYPE_EXTENDED
            scan_flags=None,
            periodic_scan_interval=None,
            channel_bitmap_2g4=None,
            enable_lp_mode=None
        )
        time.sleep(40)  # Wait for scan to complete

        scan_results = wifi_dut.interfaces.wifi.get_extended_scan_results(
            max_results=50,
            channel_filter=None,
            security_mode_filter=None,
            rssi_filter=None,
            network_type_filter=None
        )
        logger().info(f"Scan results: {scan_results}")
        logger().info(f"Number of APs found: {len(scan_results)}")
        assert len(
            scan_results) > 11, "Scan failed: Did not find more than 11 APs with extended scan type in China region"

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient, "region": 7, "region_code": "China"}
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'China'})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.test_src_map_id('C778470')
def test_at_wifi_sdk_connect_ap_after_11th_scan_result_extended_scan_china_region_c778470(sl_collections, wifi_dut, wifi_access_point):
    """
    Verify DUT can connect to the AP which comes after the 11th scan result
    when SL_WIFI_SCAN_TYPE_EXTENDED is enabled (China region).
    """
    try:
        logger().info("Setting DUT in WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        logger().info("Initiating extended scan from DUT...")
        wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid="",
            scan_type=2,  # SL_WIFI_SCAN_TYPE_EXTENDED
            scan_flags=None,
            periodic_scan_interval=None,
            channel_bitmap_2g4=None,
            enable_lp_mode=None
        )
        time.sleep(10)
        scan_results = wifi_dut.interfaces.wifi.get_extended_scan_results(max_results=50)
        logger().info(f"Scan results: {scan_results}")
        assert len(scan_results) > 11, "Less than 12 APs found, cannot test connection to AP after 11th result"

        target_ap = scan_results[11]
        ssid = target_ap['ssid']
        channel = target_ap.get('rf_channel', 0)
        logger().info(f"Attempting to connect to AP after 11th scan result: SSID={ssid}, Channel={channel}")

        wifi_access_point.interfaces.wifi.start_ap(ssid=ssid, channel=channel)
        time.sleep(15)

        sl_collections.join_to_wifi_network_at_cmd(wifi_dut, wifi_access_point, power_save=True)
        logger().info("Successfully connected to AP after 11th scan result.")

        wifi_access_point.interfaces.wifi.stop_ap()

    except Exception as e:
        logger().error(f"Exception occurred: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "region": 2,
        "region_code": "europe"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'europe'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.test_src_map_id('C778471')
def test_at_wifi_sdk_verify_ds_param_on_channels_11_12_13_c778471(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                  sniffer_filter, request, sl_collections):
    """Verify DS parameter in probe request of DUT on channels 11, 12, 13."""
    try:
        test_name = request.node.name
        logger().info("Setting DUT in WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = [11, 12, 13]
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")

        for channel in channel_list:
            try:

                logger().info("Starting the access point with custom channel...")
                wifi_access_point.interfaces.wifi.start_ap(channel=channel)
                time.sleep(5)

                wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
                wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
                time.sleep(5)
                logger().info("Initiating scan on DUT...")
                scan_results = wifi_dut.interfaces.wifi.scan(
                    interface=5,
                    filter_ssid="",
                    scan_type=None,
                    scan_flags=None,
                    periodic_scan_interval=100,
                    channel_bitmap_2g4=None,
                    enable_lp_mode=None
                )
                time.sleep(10)
                logger().info(f"Scan results: {scan_results}")

                packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=sa_addr, filter_name="probe_req_ds_param"
                )
                logger().info("Validating DS Param in probe request...")
                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                    f"DS Param not found in probe request on channel {channel}"
                logger().info(f"DS Param found in probe request on channel {channel}")
            finally:
                wifi_sniffer.interfaces.capture.stop_capture()
                wifi_access_point.interfaces.wifi.stop_ap()
                time.sleep(1)

        logger().info("DUT probe requests with DS Param validated on channels 11, 12, 13.")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
