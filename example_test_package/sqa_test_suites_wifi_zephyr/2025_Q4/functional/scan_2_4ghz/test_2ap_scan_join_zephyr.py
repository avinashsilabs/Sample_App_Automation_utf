import time
import pytest
from utf.utils.logger import get_logger
import re


def logger():
    return get_logger(__name__)


"""
setup requirement:
        1. DUT(SiWG917) - 1
        2. Raspberry PI4 - 1
        3. Access Point(Third Party AP's) - 2
        4. NUC

    Test Steps:
        1. Configuration of DUT in 2G : gnbax
        2. Initiate the Scan from DUT
        3. Verify the scan results
        4. Connect to AP
        5. Verify whether DUT is able to connect to right AP when two AP are configured with same SSID name but different security modes

    Author: Vinod.G
"""


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
            'ssid': 'same-security',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 1
        },
        1: {
            'ssid': 'same-security',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 1}
    }
)
@pytest.mark.test_src_map_id('C19065')
def test_wifi_zephyr_2aps_same_security_c19065(wifi_dut, wifi_access_points, zephyr_wifi_collections):
    """ The test case verifies scan results of the DUT when two APs configured with same SSID, and same security"""
    try:
        logger().info("enable the scan in dut on channel 0...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_points[0].interfaces.wifi.ssid)
        time.sleep(1)
        logger().info(scan_results)
        scan_list = list(scan_results)
        ssid_count = 0
        security_match = 0
        logger().info(f"scan_list : {scan_list}")
        logger().info("Validating the scan list...")
        for item in scan_list:
            ssid = str(item).split(" ")[9]
            security = str(item).split(" ")[3]
            if (ssid == wifi_access_points[0].interfaces.wifi.ssid) or (
                    ssid == wifi_access_points[1].interfaces.wifi.ssid):
                ssid_count = ssid_count + 1
                if security == 2:
                    security_match = security_match + 1
        logger().info(f"ssid count:{ssid_count}")
        assert ssid_count == 2, "Two aps are not scanned "
        assert security_match == 2, "Security type displayed in scan result is wrong"
        logger().info(f'2 Aps with same ssid: {wifi_access_points[0].interfaces.wifi.ssid} are scanned successfully')
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
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
            'ssid': 'diff_security',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 11,
            'region': 'US'
        },
        1: {
            'ssid': 'diff_security',
            'security': 'Open',
            'passphrase': '123123123',
            'channel': 1,
            'region': 'US'
        }
    }
)
@pytest.mark.test_src_map_id('C19066')
def test_wifi_zephyr_2aps_diff_security_c19066(wifi_dut, wifi_access_points, zephyr_wifi_collections):
    """ The test case verifies scan results of the DUT when two APs configured with same SSID,but with different security"""
    try:
        logger().info("enable the scan in dut on channel 0...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_points[0].interfaces.wifi.ssid)
        time.sleep(1)
        logger().info("scan_results...")
        scan_list = list(scan_results)
        ssid_count = 0
        security_type_open = 0
        security_type_wpa2 = 0
        logger().info(f"scan_list : {scan_list}")
        logger().info("Validating the scan list...")
        for item in scan_list:
            security = str(item).split(" ")[3]
            ssid = str(item).split(" ")[9]
            if (ssid == wifi_access_points[0].interfaces.wifi.ssid) or (
                    ssid == wifi_access_points[1].interfaces.wifi.ssid):
                ssid_count = ssid_count + 1
                if security == 2:
                    security_type_wpa2 = security_type_wpa2 + 1
                if security == 2:
                    security_type_open = security_type_open + 1
        logger().info(f"ssid count:{ssid_count}")
        assert ssid_count == 2, "Two aps are not scanned "
        assert security_type_wpa2 == 1, "AP security type displayed in scan result is wrong"
        assert security_type_open == 1, "AP security type displayed in scan result is wrong"
        logger().info(
            f'2 aps with same ssid :{wifi_access_points[1].interfaces.wifi.ssid}and different password :WPA2 and '
            f'WPA scanned successfully')
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},

    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
            'ssid': 'same-security',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 1
        },
        1: {
            'ssid': 'same-security',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 1}
    }
)
@pytest.mark.test_src_map_id('C19709')
def test_wifi_zephyr_wifi_connect_to_AP_with_best_rssi_value_c19709(wifi_dut, wifi_access_points, wifi_sniffer,
                                                                    zephyr_wifi_collections,
                                                                    request,
                                                                    utf_constants):
    """  The test case verifies whether the DUT is able to connect to the better RSSI AP when two APS are with same ssid name and in same security mode """
    ap_mac_address = wifi_access_points[0].interfaces.wifi.bssid
    logger().info(f"\n **** AP1 MAC ADDRESS ={ap_mac_address} ****\n")
    ap_mac_address2 = wifi_access_points[1].interfaces.wifi.bssid
    logger().info(f"\n **** AP2 MAC ADDRESS ={ap_mac_address2} ****\n")

    try:
        test_case = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_points[0].interfaces.wifi.ssid)

        logger().info(f"scan results   {scan_results}")

        rssi_list = []
        bssid_list = []
        rssi = 0
        bssid = ""
        for count in scan_results:
            if wifi_access_points[0].interfaces.wifi.ssid in str(count):
                scan_data = str(count)
                """Extract rssi and bssid from the data string."""
                rssi_match = re.search(r'rssi:\s*(-?\d+)', scan_data)
                bssid_match = re.search(r'bssid:\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', scan_data)
                rssi = int(rssi_match.group(1)) if rssi_match else None
                bssid = bssid_match.group(1) if bssid_match else None
                rssi_list.append(rssi)
                bssid_list.append(bssid)

        assert len(rssi_list) == 2, "The required two APs are not in the scan list"
        expected_bssid = ""

        if rssi_list[0] > rssi_list[1]:
            expected_bssid = bssid_list[0]
        else:
            expected_bssid = bssid_list[1]

        zephyr_wifi_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_points[0],
                                                     ping_after_power_save=True,
                                                     retry_count=3, associated=wifi_dut.interfaces.wifi.associated)

        state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
            timeout=15)

        assert int(state) == 9, "DUT is not in connected state"
        assert ssid == wifi_access_points[
            0].interfaces.wifi.ssid, "SSID details retrieved using WIFI_IFACE_STATUS API are wrong"
        assert int(
            channel) == wifi_access_points[
                   0].interfaces.wifi.channel, "Channel info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(security) == 1, "Security info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert bssid.upper() == expected_bssid.upper(), "BSSID info retrieved using WIFI_IFACE_STATUS API is wrong or DUT is not connected to the AP which has better RSSI"
        logger().info(f"DUT connected to the better RSSI AP when two APs are in the vicinity with the same SSID and same security")

        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
