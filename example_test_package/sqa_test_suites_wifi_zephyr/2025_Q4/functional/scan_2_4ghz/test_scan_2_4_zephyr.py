import time
import re
import pytest
from utf.utils.logger import get_logger
from utf_wifi_zephyr.utils.sl_status import SLStatus
from utf.utils.time_measurer import TimeMeasurer


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configuration of DUT in 2G : gnbax
        2. Initiate the Scan from DUT
        3. Verify the scan results
        4. Verify Scan functionality with all possible options provided in the scan API

    setup requirement:
        1. DUT(SiWG917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC

    Author: Vinod.G
"""


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
# This test case verifies All Channels Scan in 2.4 Ghz by giving channel number as Zero
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_all_scan_channels_c19056(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                              zephyr_wifi_collections):
    """ Verify Scan functionality when channel is set to 0 in scan API """
    try:
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(2)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan Response Based on RSSI
def test_wifi_zephyr_scan_check_rssi_c19060(wifi_dut, wifi_access_point, zephyr_wifi_collections):
    """ The test case verifies whether the RSSI of the scanned APs are in ascending order or not """
    try:

        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        time.sleep(2)
        logger().info(scan_results)
        scan_count = len(scan_results)
        assert scan_count > 0, "Scan results not found"
        previous_rssi = 0

        for count in scan_results:
            assert previous_rssi >= count.rssi, "scan result is not based on the rssi"
            previous_rssi = count.rssi
            logger().info(f"scan results are based on rssi: {count.rssi}")
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_scan_ssid_32bytes_c19064(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                              zephyr_wifi_collections):
    """ The test case verifies whether DUT is able to scan AP ssid when ssid length is 32 bytes """
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        ssid_list = ['test123test123test123test123test', 'test1*@test1*#test1*@test1*$test',
                     'test12.test12.test12.test12.test', '了是不了是不了是不了']

        for ssid in ssid_list:
            logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            time.sleep(1)
            # initiates the access point with channel given in list
            logger().info(f"Setting access point with ssid {ssid}...")
            wifi_access_point.interfaces.wifi.start_ap(ssid=ssid)
            time.sleep(1)
            logger().info(f"\n######=====>>>>Configuring the 32byte SSID: {ssid}\n")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=wifi_access_point.interfaces.wifi.channel, ssid=ssid)
            time.sleep(1)
            logger().info("\nscan_results\n")
            assert len(scan_results) >= 1, f"32 bytes ssid not found in scan results"
            logger().info(f"Validate Probe req(Broadcast)")
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_ssid', "broadcast_ssid": False})
# This case verifies the scan in hidden mode of AP for all channels
def test_wifi_zephyr_hidden_scan_all_channels_c19062(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                     zephyr_wifi_collections):
    """ This case verifies the scan in hidden mode of AP for all channels """
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr,
            hidden_ssid="\"\"",
            filter_name="hidden_ssid_probe_request_packet")
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        time.sleep(1)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan failed"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            f'Unable to find probe request broadcast packet in channel:{wifi_access_point.interfaces.wifi.channel}'
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan functionality with max scan of dut
def test_wifi_zephyr_scan_max_aps_c19061(wifi_dut, wifi_access_point, zephyr_wifi_collections):
    """This test case verifies whether DUT is able to scan 11 APs """
    try:
        channel_bitmap_2_4 = 0
        # enables the scan in DUT with the given channel bitmap value
        logger().info("Initiating selective channel scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
        time.sleep(1)
        logger().info(scan_results)
        logger().info(len(scan_results))
        if len(scan_results) == 11:
            assert True, f"Dut has scanned {len(scan_results)} Aps"
        else:
            assert False, f"To scan more number of APs, Need to keep setup in open air environment"
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan functionality for channles 1-11
def test_wifi_zephyr_all_chan_scan_with_channel_bitmap_c19057(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                              zephyr_wifi_collections, sniffer_filter):
    """ This test case verifies the scan functionality for channles 1-11 """
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(1)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(1)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "Scan results not found"
            channel_selected = 0
            for count in scan_results:
                assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# Verifies the scan functionality with the channel 1,6,8
def test_wifi_zephyr_scan_selective_channel_c19058(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                   zephyr_wifi_collections):
    """ Verifies the scan functionality with the channel 1,6,8 """
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        channel_list = [1, 6, 8]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(1)
            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, )
            time.sleep(2)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list), f"Scan should happen only in selected channels"

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")

            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# Verifies the scan functionality with the channel 1,3,6,11
def test_wifi_zephyr_scan_selective_channel_c19059(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                   zephyr_wifi_collections):
    """  Verifies the scan functionality with the channel 1,3,6,11 """
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        channel_list = [1, 3, 6, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(1)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(2)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "Scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "hidden_ssid", "broadcast_ssid": False})
# Verifies the scan in selected channels with the ap set in hidden mode
def test_wifi_zephyr_hidden_scan_sel_chan_c19063(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                 zephyr_wifi_collections):
    """ Verifies the scan in selected channels when the AP is set in hidden mode """
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        channel_list = [1, 5, 9]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(1)
            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                         scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(2)
            logger().info(scan_results)
            assert len(scan_results) >= 1

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr,
                hidden_ssid="\"\"",
                filter_name="hidden_ssid_probe_request_packet")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "region": 'europe'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_scan_when_config_ap_is_not_available_c538001(wifi_dut, wifi_access_point, request, wifi_sniffer,
                                                                  sniffer_filter, zephyr_wifi_collections):
    """Trigger scan command when configured access point
       is not available(Number of scan results should be 0))"""

    try:
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(1)
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(2)

        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=0)
        time.sleep(1)
        logger().info(scan_results)
        assert len(
            scan_results) == 0, "DUT received scan results when AP is not available in the vicinity which is not expected"

        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "ssid": 'Explore@WiFi', "region": 'europe'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_verify_dut_scan_spe_char_ssid_or_not_c538003(wifi_dut, wifi_access_point, request, wifi_sniffer,
                                                                  sniffer_filter, zephyr_wifi_collections):
    """Verify whether DUT is able to scan special characters SSID or not"""

    try:
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid='Explore@WiFi', scan_bitmap_2_4=0, scan_type=0)
            time.sleep(2)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

            if bool(output) is False:
                false_result_list.append(bool(output))
                probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert probe_not_captured_channel_list == [], logger().info(f"**** unable to find the Probe requests  in all "
                                                                    f"these channels:{probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_scan_with_high_beacon_length_c538006(wifi_access_point, wifi_dut, request, wifi_sniffer,
                                                          sniffer_filter, zephyr_wifi_collections):
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
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0, scan_type=0)
        time.sleep(2)  # Wait for scan to complete
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
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise  # Re-raise the exception after handling to ensure test failure is reported


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_wifi_scan_no_ap_in_closed_room_c687827(wifi_dut, wifi_access_point, request, wifi_sniffer,
                                                            sniffer_filter, zephyr_wifi_collections):
    """Verify Wi-Fi scan results when there is no AP available in the envirnoment(Closed room))))"""

    try:
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(2)
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(2)

        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=0)

        time.sleep(2)

        logger().info(scan_results)
        assert len(
            scan_results) == 0, "DUT received scan results when AP is not available in the vicinity which is not expected"

        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_active_channel_scan_dwell_time_50msec_c19071(wifi_dut, wifi_access_point, zephyr_wifi_collections):
    """ The test case verifies the scan functionality in all channels when dwell time is set to 50msec """
    try:
        channel_bitmap_2_4 = 0
        dwell_time_active = 50
        scan_time_threshold = (11 * dwell_time_active + 100) / 1000
        # enables the scan in DUT with the given channel bitmap value
        logger().info("Initiating selective channel scan from dut...")
        scan_results, scan_time = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                                scan_bitmap_2_4=channel_bitmap_2_4, measure_scan_time=1,
                                                                dwell_time_active=dwell_time_active)
        time.sleep(2)
        logger().info(scan_results)
        logger().info(len(scan_results))

        assert len(scan_results) >= 1, "DUT is unable to scan even one AP"

        logger().info(f"scan time--------------> {scan_time}")

        scan_time = float(scan_time.split(':')[-1])
        assert scan_time <= scan_time_threshold, (f"Observed active scan time is more than expected value:"
                                                  f"{scan_time_threshold} Seconds")
        logger().info(f"\n\n******** Time taken for active scan is --> '{scan_time}' seconds, which is within the "
                      f"expected threshold value '{scan_time_threshold}' seconds ********")

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_scan_bss_count_one_c19072(wifi_dut, wifi_access_point, zephyr_wifi_collections):
    """ The test case verifies scan functionality when the max bss count is set to 1"""
    try:
        channel_bitmap_2_4 = 0
        # enables the scan in DUT with the given channel bitmap value
        logger().info("Initiating selective channel scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4,
                                                     max_bss_count=1)
        time.sleep(1)
        logger().info(scan_results)
        logger().info(len(scan_results))
        assert len(
            scan_results) == 1, "DUT displays more than one AP info when max_bss_count is set to 1 which is not expected"

        logger().info("DUT displays only one AP info when max_bss_count is set to 1 which is expected")

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "region": 'europe'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_neg_scan_channel_12_c19073(wifi_dut, wifi_access_point, request, wifi_sniffer,
                                                sniffer_filter, zephyr_wifi_collections):
    """The test case verifies scan functionality in channel 12 in default region"""

    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {12}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=12)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(2)

        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=0, channel=12)
        time.sleep(1)
        logger().info(scan_results)
        assert len(
            scan_results) == 0, "DUT received scan results when channel no is set to 12 which is not expected"

        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_active_channel_scan_dwell_time_default_c19074(wifi_dut, wifi_access_point,
                                                                   zephyr_wifi_collections):
    """ The test case measures the time taken in each channel when dwell time is set to 0"""
    try:
        channel_bitmap_2_4 = 0
        dwell_time_active = 0
        scan_time_threshold = (11 * 100 + 100) / 1000
        # enables the scan in DUT with the given channel bitmap value
        logger().info("Initiating selective channel scan from dut...")
        scan_results, scan_time = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                                scan_bitmap_2_4=channel_bitmap_2_4, measure_scan_time=1,
                                                                dwell_time_active=dwell_time_active)
        time.sleep(2)
        logger().info(scan_results)
        logger().info(len(scan_results))

        assert len(scan_results) >= 1, "DUT is unable to scan even one AP"

        logger().info(f"scan time--------------> {scan_time}")

        scan_time = float(scan_time.split(':')[-1])
        assert scan_time <= scan_time_threshold, (f"Observed active scan time is more than expected value:"
                                                  f"{scan_time_threshold} Seconds")
        logger().info(f"\n\n******** Time taken for active scan is --> '{scan_time}' seconds, which is within the "
                      f"expected threshold value '{scan_time_threshold}' seconds ********")

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_scan_for_10_min_c19075(wifi_dut, wifi_access_point, zephyr_wifi_collections):
    """ The test case verifies scan functionality in loop for 10 minutes"""
    try:
        channel_bitmap_2_4 = 0
        # enables the scan in DUT with the given channel bitmap value

        with TimeMeasurer() as t:
            t_end = time.time() + 60 * 10
            while time.time() < t_end:
                logger().info("Initiating selective channel scan from dut...")
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
                time.sleep(1)
                logger().info(scan_results)
                logger().info(len(scan_results))
                if len(scan_results) == 11:
                    assert True, f"Dut has scanned {len(scan_results)} Aps"
                else:
                    assert False, f"To scan more number of APs, Need to keep setup in open air environment"
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_zephyr_scan_neg_band_5ghz_c751134(wifi_dut, zephyr_wifi_collections):
    """
    Negative Case : The test case verifies whether the scan API failed with error when 5ghz band selected
    """
    try:
        wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=0, bands=2,
                                      expected_status=SLStatus.SL_STATUS_FAIL)
    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)



