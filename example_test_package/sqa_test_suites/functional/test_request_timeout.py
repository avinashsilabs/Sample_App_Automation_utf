from utf.interfaces.wifi import WlanError

from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveModes
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Start the sniffer before connection
        3. Set the keep alive timer in various time intervals(10sec & 30sec) 
        4. Association of Third party AP's
        5. Get the valid IP address
        6. Enable the power save mode in DUT & BT
        7. Stop the sniffer  
        8. Analyizing all sniffer capture packets and find the arp announcement packet 
        9. Validate the arp announcement packets with time delta as per keep alive timer
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


class FilterPacket:
    '''This function is responsible to create a list for ARP announcement packet time delta '''
    def delta_between_arp_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff_list.append(float(time_delta_from_previous_packet))

        filter_file.close()
        return time_diff_list


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
def test_request_timeout_keep_alive_10sec(wifi_sniffer, wifi_dut, wifi_access_point):
    """=============================this test_case to validate keep-alive for 10secs=========================="""
    time_delta = 10
    arp_time_delta_obj = FilterPacket()
    keep_alive_time = 4

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_request_timeout_keep_alive_10sec')
    time.sleep(5)
    wifi_dut.interfaces.wifi.set_timeout(feature=keep_alive_time, timeout=10)
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    time.sleep(5)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")

    time.sleep(60)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    wifi_sniffer.interfaces.capture.sniffer_validation()
    arp_packets_time_delta_list = arp_time_delta_obj.delta_between_arp_packet()
    arp_packets_time_delta_list.pop(0)
    arp_packets_time_delta_list.pop(0)
    logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
    for time_diff in arp_packets_time_delta_list:
        logger().info(int(time_diff))
        is_between = int(time_diff) in range(time_delta, time_delta + 1)
        if is_between is False:
            logger().info(is_between)
            status = is_between
            break
        else:
            logger().info(is_between)
            status = is_between
    assert status
    wifi_dut.interfaces.wifi.leave()
    time.sleep(1)


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
def test_request_timeout_keep_alive_30sec(wifi_sniffer, wifi_dut, wifi_access_point):
    """=============================this test_case to validate keep-alive for 10secs=========================="""
    time_delta = 30
    arp_time_delta_obj = FilterPacket()
    keep_alive_time = 4

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_request_timeout_keep_alive_30sec')
    time.sleep(5)
    wifi_dut.interfaces.wifi.set_timeout(feature=keep_alive_time, timeout=30)
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    time.sleep(5)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )
    mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"Actual MAC_Address: {mac_address}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")

    time.sleep(60)
    wifi_sniffer.interfaces.capture.stop_capture()
    time.sleep(1)
    wifi_sniffer.interfaces.capture.sniffer_validation()
    arp_packets_time_delta_list = arp_time_delta_obj.delta_between_arp_packet()
    arp_packets_time_delta_list.pop(0)
    arp_packets_time_delta_list.pop(0)
    logger().info(f'APR packet time delta list after removing 0 = {arp_packets_time_delta_list}')
    for time_diff in arp_packets_time_delta_list:
        logger().info(int(time_diff))
        is_between = int(time_diff) in range(time_delta, time_delta + 1)
        if is_between is False:
            logger().info(is_between)
            status = is_between
            break
        else:
            logger().info(is_between)
            status = is_between
    assert status
    wifi_dut.interfaces.wifi.leave()
    time.sleep(1)

@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
def test_request_timeout_scan_100misc(wifi_sniffer, wifi_dut, wifi_access_point):
    """=============================this test_case to validate scan for 100 Milli seconds=========================="""
    scan_timeout = 2
    wifi_dut.interfaces.wifi.set_timeout(feature=scan_timeout, timeout=100)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_request_timeout_scan_100misc')
    time.sleep(5)
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    logger().info(scan_results)
    assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")
    assert (1.2 < t.duration < 1.5)
    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")

    time.sleep(10)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
def test_request_timeout_scan_500misc(wifi_sniffer, wifi_dut, wifi_access_point):
    """=============================this test_case to validate scan for 500 Milliseconds=========================="""
    scan_timeout = 2
    wifi_dut.interfaces.wifi.set_timeout(feature=scan_timeout, timeout=500)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_request_timeout_scan_500misc')
    time.sleep(5)
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    logger().info(scan_results)
    assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")
    assert (5.5 < t.duration < 5.8)
    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    )

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")

    time.sleep(10)
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
def test_wifi_auth_timeout_with_100msec(wifi_sniffer, wifi_dut, wifi_access_point):
    """=================this test_case to validate Authentication timeout for 100 Milliseconds======================"""
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_auth_timeout_with_100msec')
    time.sleep(5)
    auth_timeout = 1
    wifi_dut.interfaces.wifi.set_timeout(feature=auth_timeout, timeout=100)
    time.sleep(5)
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")

    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        wifi_sniffer.interfaces.capture.stop_capture()
    assert exc_info.value.error_code == 0x48


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
def test_wifi_auth_timeout_with_300msec(wifi_sniffer, wifi_dut, wifi_access_point):
    """=================this test_case to validate Authentication timeout for 300 Milliseconds======================"""
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_auth_timeout_with_300msec')
    time.sleep(5)
    auth_timeout = 1
    wifi_dut.interfaces.wifi.set_timeout(feature=auth_timeout, timeout=100)
    time.sleep(2)
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)

    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual version: {result}")

    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        wifi_sniffer.interfaces.capture.stop_capture()
    assert exc_info.value.error_code == 0x48


