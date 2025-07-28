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
@pytest.mark.config(
    "wifi_access_points",
    wifi={
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
            'channel': 1
        }
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_at_wifi_sdk_2aps_same_security_c778450(wifi_dut, wifi_access_points, sl_collections):
    '''Verify scan response when 2 Aps having same SSID and same security mode'''

    try:
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        logger().info("Initiating scan on DUT...")
        scan_results = wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid=wifi_access_points[0].interfaces.wifi.ssid,
            scan_type=None,
            scan_flags=None,
            periodic_scan_interval=100,
            channel_bitmap_2g4=None,
            channel_bitmap_5g=None,
            enable_lp_mode=None
        )
        time.sleep(20)
        logger().info(scan_results)
        scan_list = list(scan_results)
        ssid_count = 0
        logger().info(f"scan_list : {scan_list}")
        logger().info("Validating the scan list...")
        for item in scan_list:
            ssid = item.get("ssid", "")
            if ssid == wifi_access_points[0].interfaces.wifi.ssid or ssid == wifi_access_points[1].interfaces.wifi.ssid:
                ssid_count += 1
        logger().info(f"ssid count:{ssid_count}")
        assert ssid_count == 2, "Two aps are not scanned "
        logger().info(f'2 Aps with same ssid: {wifi_access_points[0].interfaces.wifi.ssid} are scanned successfully')
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_at_wifi_sdk_2aps_diff_security_c778451(wifi_dut, wifi_access_points, sl_collections):
    '''Verify scan response when 2 Aps having same SSID and different security mode'''
    try:
        logger().info("Setting DUT into WLAN power save mode...")
        wifi_dut.interfaces.wifi.enable_power_save(dtim_alignment_type=4, dtim_skip=0)

        logger().info("Initiating scan on DUT...")
        scan_results = wifi_dut.interfaces.wifi.scan(
            interface=5,
            filter_ssid=wifi_access_points[0].interfaces.wifi.ssid,
            scan_type=None,
            scan_flags=None,
            periodic_scan_interval=100,
            channel_bitmap_2g4=None,
            channel_bitmap_5g=None,
            enable_lp_mode=None
        )
        time.sleep(20)
        logger().info("scan_results...")
        scan_list = list(scan_results)
        ssid_count = 0
        logger().info(f"scan_list : {scan_list}")
        logger().info("Validating the scan list...")
        for item in scan_list:
            ssid = item.get("ssid", "")
            if ssid == wifi_access_points[0].interfaces.wifi.ssid or ssid == wifi_access_points[1].interfaces.wifi.ssid:
                ssid_count += 1
        logger().info(f"ssid count:{ssid_count}")
        assert ssid_count == 2, "Two aps are not scanned "
        logger().info(
            f'2 aps with same ssid :{wifi_access_points[1].interfaces.wifi.ssid} and different security :WPA2 and Open scanned successfully')
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)