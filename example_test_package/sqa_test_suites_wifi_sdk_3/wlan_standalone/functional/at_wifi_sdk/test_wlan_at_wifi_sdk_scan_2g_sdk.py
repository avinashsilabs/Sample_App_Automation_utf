import time
import pytest
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
def test_at_wifi_sdk_all_channels_2_4ghz_with_channel_c778442(wifi_dut, wifi_sniffer, request, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.configure_power_perf(dtim_alignment_type=4, dtim_skip=0)

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
def test_at_wifi_sdk_all_chan_scan_with_channel_bitmap_c778443(wifi_access_point, wifi_dut, wifi_sniffer, request, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.configure_power_perf(dtim_alignment_type=4, dtim_skip=0)

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
                                                         periodic_scan_interval=100, channel_bitmap_2g4=channel_bitmap_2g4, enable_lp_mode=None)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "scan results not found"
            for result in scan_results:
                assert (result['rf_channel'] in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Stoping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, filter_name="probe_request")
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
def test_at_wifi_sdk_scan_selective_channel_1_3_6_11_c778444(wifi_access_point, wifi_dut, wifi_sniffer, request, sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.configure_power_perf(dtim_alignment_type=4, dtim_skip=0)

        channel_list = [1, 3, 6, 11]
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
                                                         periodic_scan_interval=100, channel_bitmap_2g4=channel_bitmap_2g4, enable_lp_mode=None)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "scan results not found"
            for result in scan_results:
                assert (result['rf_channel'] in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Stoping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, filter_name="probe_request")
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
def test_at_wifi_sdk_scan_check_rssi_c778445(wifi_dut, sl_collections):
    """This test case verifies that the scan results are sorted based on RSSI in descending order."""
    try:
        logger().info("Setting DUT in WLAN power save mode...")
        wifi_dut.interfaces.wifi.configure_power_perf(dtim_alignment_type=4, dtim_skip=0)

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
def test_at_wifi_sdk_scan_max_aps_c778446(wifi_dut, sl_collections):
    """This test case verifies that the DUT can scan and return a maximum number of APs."""
    try:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.configure_power_perf(dtim_alignment_type=4, dtim_skip=0)

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
def test_at_wifi_sdk_hidden_scan_all_channels_c778447(wifi_access_point, wifi_dut, wifi_sniffer, request, sniffer_filter, sl_collections):
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
        wifi_dut.interfaces.wifi.configure_power_perf(dtim_alignment_type=4, dtim_skip=0)

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
            packet_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)["packet_count"]
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
def test_at_wifi_sdk_hidden_scan_selected_channels_1_5_9_c778448(wifi_access_point, wifi_dut, wifi_sniffer,request, sniffer_filter, sl_collections):
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
        wifi_dut.interfaces.wifi.configure_power_perf(dtim_alignment_type=4, dtim_skip=0)

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
            packet_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)["packet_count"]
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
        wifi_dut.interfaces.wifi.configure_power_perf(dtim_alignment_type=4, dtim_skip=0)
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