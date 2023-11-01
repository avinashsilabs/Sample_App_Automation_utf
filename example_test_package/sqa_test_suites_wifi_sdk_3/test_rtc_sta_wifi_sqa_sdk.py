import pytest
import time
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""
    Setup requirements:
        1. Soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Enable/Disable the RTC timer in DUT
        3. Set the RTC timer in DUT
        4. Get the RTC timer of DUT
        
    Author: Ayush

"""


class WLanRTCSTAThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, tolerance_threshold=None,
                 test_case=None, wifi_sniffer=None, channel=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.tolerance_threshold = tolerance_threshold
        self.test_case = test_case
        self.wifi_sniffer = wifi_sniffer
        self.channel = channel
        self.scan_time = None
        self.set_seconds = None
        self.set_minutes = None
        self.set_hour = None
        self.set_month_day = None
        self.set_month = None
        self.set_year = None
        self.set_week_day = None
        self.wait_time_after_scan = None
        self.time_data = None
        self.set_time_sec = None
        self.time_dif = None
        self.idle_time = None
        self.time_after_first_verification = None

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)
        self.set_seconds = 30
        self.set_minutes = 6
        self.set_hour = 10
        self.set_month_day = 10
        self.set_month = 10
        self.set_year = 2023
        self.set_week_day = 3
        self.wait_time_after_scan = 50
        self.set_time_sec = ((self.set_minutes * 60) + self.set_seconds)

        if '19048' in self.test_case:
            time.sleep(10)
            self.wifi_dut.interfaces.wifi.set_rtc(seconds=self.set_seconds, minutes=self.set_minutes,
                                                  hours=self.set_hour, day=self.set_month_day, month=self.set_month,
                                                  year=self.set_year, weekday=self.set_week_day)
            return

        firmware_version = self.wifi_dut.interfaces.wifi.version()
        logger().info(f"Firmware version-> {firmware_version}")
        logger().info(f"Time in seconds just before initiating set rtc ->  {self.set_time_sec}")

        self.wifi_dut.interfaces.wifi.set_performance_profile()
        self.wifi_dut.interfaces.wifi.enable_bt_power_save()
        self.wifi_dut.interfaces.wifi.set_rtc(seconds=self.set_seconds, minutes=self.set_minutes, hours=self.set_hour,
                                              day=self.set_month_day, month=self.set_month, year=self.set_year,
                                              weekday=self.set_week_day)

        logger().info("****Set RTC command gave success response****")

        if '19046' in self.test_case or '19047' in self.test_case or '19049' in self.test_case:
            return
        with TimeMeasurer() as t:
            for count in range(1, 3):
                try:
                    self.wifi_dut.interfaces.wifi.scan(ssid=None)
                    break
                except:
                    logger().info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                    time.sleep(1)
        self.scan_time = t.duration

        with TimeMeasurer() as t:
            logger().info(f"Time taken for scan -> {self.scan_time} seconds")
            logger().info(f"wait for {self.wait_time_after_scan} seconds")
        scan_logger_time1 = t.duration
        time.sleep(self.wait_time_after_scan)

        logger().info(f"Scan time -> {self.scan_time}")
        self.time_data = self.wifi_dut.interfaces.wifi.get_rtc()
        self.time_data['seconds'] = self.time_data['seconds'] + (self.time_data['minutes'] * 60)

        logger().info("\n\n****Validating the GET RTC time****\n\n")

        assert (self.set_hour == self.time_data['hours']) and (self.set_month_day == self.time_data['day_month']) and \
               (self.set_month == self.time_data['month']) and (self.set_year == self.time_data['year']) and \
               (self.set_week_day == self.time_data['week_day']), "RTC time is not set properly"

        logger().info(f"scan_logger_time1 = {scan_logger_time1}")
        self.idle_time = self.wait_time_after_scan + self.scan_time + scan_logger_time1
        self.time_dif = self.time_data['seconds'] - self.set_time_sec - self.idle_time

        if '19054' not in self.test_case:
            with TimeMeasurer() as t:
                logger().info(f"idle time after initiating set rtc after scan = {self.idle_time}")
                assert (self.time_dif >= self.tolerance_threshold[0]) and (
                        self.time_dif <= self.tolerance_threshold[1]), f"get time updated is " \
                                                                       f"not in tolerance " \
                                                                       f"level. Time " \
                                                                       f"difference observed is {self.time_dif}"
            self.time_after_first_verification = t.duration


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_verify_set_rtc_c19046(wifi_dut, wifi_access_point, sl_collections, wifi_sniffer):
    """
    Test Steps:
        1. Scan for the AP
        2. Set RTC time
    """
    try:
        wlan_obj = WLanRTCSTAThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    sl_collections=sl_collections, wifi_sniffer=wifi_sniffer, test_case='19046',
                                    channel=wifi_access_point.interfaces.wifi.channel)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_set_rtc_without_enabling_feature_c19047(wifi_dut, wifi_access_point, sl_collections, wifi_sniffer):
    """
    Test Steps:
        1. Scan for the AP
        2. Set RTC time
    """
    try:
        wlan_obj = WLanRTCSTAThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    sl_collections=sl_collections, wifi_sniffer=wifi_sniffer, test_case='19047',
                                    channel=wifi_access_point.interfaces.wifi.channel)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_check_set_rtc_functionality_twice_c19049(wifi_dut, wifi_access_point, sl_collections, wifi_sniffer):
    """
     Test Steps:
        1. Set RTC time
        2. Scan for the AP
        3. Set RTC time
    """
    try:
        wlan_obj = WLanRTCSTAThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    sl_collections=sl_collections, wifi_sniffer=wifi_sniffer, test_case='19049',
                                    channel=wifi_access_point.interfaces.wifi.channel)

        for count in range(2):
            wlan_obj.start()
            wlan_obj.wait_for_exit()

            logger().info(
                f"Time difference observed between set time and get time is {wlan_obj.time_dif} seconds,which is in"
                f" tolerance level for Iteration {count + 1}")
            wlan_obj.set_seconds = 30
            wlan_obj.set_minutes = 20

            wlan_obj.set_time_sec = ((wlan_obj.set_minutes * 60) + wlan_obj.set_seconds)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_wifi_sdk_check_get_rtc_functionality_c19052(wifi_dut, wifi_access_point, sl_collections, tolerance_threshold,
                                                     wifi_sniffer):
    """
     Test Steps:
        1. Set RTC time
        2. Scan for the AP
        3. Get RTC time
    """
    try:
        wlan_obj = WLanRTCSTAThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    sl_collections=sl_collections, tolerance_threshold=tolerance_threshold,
                                    wifi_sniffer=wifi_sniffer, test_case='19052',
                                    channel=wifi_access_point.interfaces.wifi.channel)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(
            f"Time difference observed between set time and get time is {wlan_obj.time_dif} seconds,"
            f"which is in tolerance level")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_wifi_sdk_get_rtc_multiple_times_c19053(wifi_dut, wifi_access_point, sl_collections, tolerance_threshold,
                                                wifi_sniffer):
    """
    Test Steps:
        1. Set RTC time
        2. Scan for the AP
        3. Get RTC time
        4. Connect to the AP
        5. Get RTC time
        6. Get DUT IP
        7. Get RTC time
    """
    try:
        wlan_obj = WLanRTCSTAThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    sl_collections=sl_collections, tolerance_threshold=tolerance_threshold,
                                    wifi_sniffer=wifi_sniffer, test_case='19053',
                                    channel=wifi_access_point.interfaces.wifi.channel)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(
            f"Time difference observed between set time and get time is {wlan_obj.time_dif} seconds,"
            f"which is in tolerance level after scan")

        with TimeMeasurer() as T:
            sl_collections.connect(wifi_access_point=wifi_access_point, wifi_dut=wifi_dut)
        connection_time = T.duration

        with TimeMeasurer() as T:
            wlan_obj.time_data = wifi_dut.interfaces.wifi.get_rtc()
            wlan_obj.time_data['seconds'] = wlan_obj.time_data['seconds'] + (wlan_obj.time_data['minutes'] * 60)
            wlan_obj.idle_time = wlan_obj.idle_time + connection_time + wlan_obj.time_after_first_verification
            wlan_obj.time_dif = wlan_obj.time_data['seconds'] - wlan_obj.idle_time - wlan_obj.set_time_sec

            assert (wlan_obj.time_dif >= tolerance_threshold[0]) and (
                    wlan_obj.time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                  f"not in tolerance " \
                                                                  f"level. Time " \
                                                                  f"difference observed is {wlan_obj.time_dif}"

            logger().info(
                f"Time difference observed between set time and get time is {wlan_obj.time_dif} seconds,"
                f"which is in tolerance level after connect")

            ip_status, ip_config = sl_collections.configure_ip(wifi_dut, ip_status=False)
            assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

            device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"DUT ip: {device_ip}")
        time_after_ping = T.duration

        wlan_obj.time_data = wifi_dut.interfaces.wifi.get_rtc()
        wlan_obj.time_data['seconds'] = wlan_obj.time_data['seconds'] + (wlan_obj.time_data['minutes'] * 60)
        wlan_obj.idle_time = wlan_obj.idle_time + time_after_ping
        wlan_obj.time_dif = wlan_obj.time_data['seconds'] - wlan_obj.idle_time - wlan_obj.set_time_sec

        assert (wlan_obj.time_dif >= tolerance_threshold[0]) and (
                wlan_obj.time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                              f"not in tolerance " \
                                                              f"level. Time " \
                                                              f"difference observed is {wlan_obj.time_dif}"

        logger().info(
            f"Time difference observed between set time and get time is {wlan_obj.time_dif} seconds,"
            f"which is in tolerance "
            f"level after getting IP")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_wifi_sdk_get_rtc_without_enabling_feature_c19054(wifi_dut, wifi_access_point, sl_collections,
                                                          tolerance_threshold, wifi_sniffer):
    """
    Test Steps:
        1. Scan for the AP
        2. Set RTC time
        3. Get RTC time
        4. Validate set time and get time are equal
    """
    try:
        wlan_obj = WLanRTCSTAThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    sl_collections=sl_collections, tolerance_threshold=tolerance_threshold,
                                    wifi_sniffer=wifi_sniffer, test_case='19054',
                                    channel=wifi_access_point.interfaces.wifi.channel)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        assert wlan_obj.set_time_sec == wlan_obj.time_data['seconds'], "Set time updated and get time " \
                                                                       "received are not same"

        logger().info("Set time updated and get time received are same, which is expected when RTC feature is"
                      " not enabled")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi="reset")
def test_wifi_sdk_get_rtc_in_incorrect_state_c19048(wifi_dut, wifi_sniffer, sl_collections):
    """
    Test Steps:
        1. Set RTC time
        2. Get RTC time
        3. Validate error code
    """
    try:
        wlan_obj = WLanRTCSTAThread(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, test_case='19048')
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
