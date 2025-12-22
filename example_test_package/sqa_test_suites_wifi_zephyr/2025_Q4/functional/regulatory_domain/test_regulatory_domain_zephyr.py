import pytest
import time
from utf.utils.logger import get_logger

"""
    setup requirement:
        1. DUT(Si917_SDK)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in WLAN mode 
        2. Set the region code, and validate the region code
        3. Join the access point and enable the dhcp
        4. Initiate ping from the dut
      

    Author: Vinod.G
"""


def logger():
    return get_logger(__name__)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Korea", "channel": 12})
def test_zephyr_verify_connection_in_korea_region_c19511(wifi_dut, wifi_access_point, wifi_sniffer,
                                                         zephyr_wifi_collections,
                                                         request):
    """
    Verify whether DUT is able to connect in channel 12 in korea region
    """
    try:
        capture_filename = request.node.name
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)
        set_region_code = "KR"
        wifi_dut.interfaces.wifi.wifi_reg_domain(country_code=set_region_code)
        region_code = wifi_dut.interfaces.wifi.wifi_get_reg_domain()

        assert set_region_code == region_code, "region code set, and the region code received using wifi_get_reg_domain is not same"

        result = zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                              ping_count=10,
                                                              associated=False, retry_count=3)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        logger().info(f'DUT ip {device_ip}')
        logger().info("pinging to dut.....")
        ping_status = zephyr_wifi_collections.ping_with_custom_size(device_ip, ping_counts=60, byte_size=300)
        assert ping_status, "DUT is not responding to ping request"
        logger().info("ping to DUT is successful....")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as err:
        zephyr_wifi_collections.exception_handling(wifi_dut, err)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Australia", "channel": 13})
def test_zephyr_verify_connection_in_us_region_when_aus_selected_in_ap_c19511(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                              zephyr_wifi_collections,
                                                                              request):
    """
    Verify whether DUT is able to scan in channel 13 when US region is selected
    """
    try:
        capture_filename = request.node.name
        logger().info(f"Configuring the sniffer with access point channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(3)
        set_region_code = "US"
        wifi_dut.interfaces.wifi.wifi_reg_domain(country_code=set_region_code)
        region_code = wifi_dut.interfaces.wifi.wifi_get_reg_domain()
        assert set_region_code == region_code, "region code set, and the region code received using wifi_get_reg_domain is not same"
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=0, channel=13)
        time.sleep(1)
        logger().info(scan_results)
        assert len(
            scan_results) == 0, "DUT received scan results when channel no is set to 13 which is not expected"

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as err:
        zephyr_wifi_collections.exception_handling(wifi_dut, err)




