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
    wifi={"oper_mode": Si91xOperatingMode.WiFiClient}
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
def test_at_wifi_sdk_passive_scan_all_channels_c778475(wifi_access_point, wifi_dut, wifi_sniffer, sniffer_filter, sl_collections, request):
    """
    Verify passive scan functionality by enabling passive scan.
    """
    try:
        test_name = request.node.name
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        channel_list = list(range(1, 12))
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

            logger().info("Initiating passive scan on DUT...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=1,  # 1 for passive scan
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

            logger().info("Stopping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, filter_name="probe_request")

            logger().info("Validating that no probe request (broadcast) is sent during passive scan...")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)["packet_count"]
            assert output == 0, f"Probe request found on channel {channel} during passive scan"

        logger().info("Passive scan successfully validated on all selected 2.4GHz channels. No probe requests sent.")

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
def test_at_wifi_sdk_passive_scan_eu_specific_channels_lp_enabled_c778482(wifi_access_point, wifi_dut, wifi_sniffer, sniffer_filter, sl_collections, request):
    """
    Verify passive scan functionality on EU-specific channels (12, 13) with LP enabled.
    """
    try:
        test_name = request.node.name
        logger().info("Enabling LP mode and WLAN power save on DUT...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)
        
        channel_list = [12, 13]  # EU-specific channels
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

            logger().info("Initiating passive scan on DUT (LP enabled)...")
            scan_results = wifi_dut.interfaces.wifi.scan(
                interface=5,
                filter_ssid="",
                scan_type=1,  # 1 for passive scan
                scan_flags=None,
                periodic_scan_interval=None,
                channel_bitmap_2g4=None,
                enable_lp_mode=1
            )
            time.sleep(20)
            logger().info(f"Scan results: {scan_results}")

            assert len(scan_results) >= 1, "Scan results not found"
            for result in scan_results:
                assert result["rf_channel"] in channel_list, "Scan should occur only on selected channels"

            logger().info("Stopping sniffer capture...")
            wifi_sniffer.interfaces.capture.stop_capture()

            logger().info("Stopping the access point with custom channel...")
            wifi_access_point.interfaces.wifi.stop_ap()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr, filter_name="probe_request"
            )

            logger().info("Validating that no probe request (broadcast) is sent during passive scan...")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)["packet_count"]
            assert output == 0, f"Probe request found on channel {channel} during passive scan"

        logger().info("Passive scan successfully validated on EU-specific channels (12, 13) with LP enabled. No probe requests sent.")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
