import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xPowerSaveModes, Si91xFeatureBitMap, \
    Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger

import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


class WLanRTCAPThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_client=None, sl_collections=None,  channel=None, tolerance_threshold=None, wifi_sniffer=None,
                 utf_constants=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.channel = channel
        self.sl_collections = sl_collections
        self.tolerance_threshold = tolerance_threshold
        self.utf_constants = utf_constants
        self.wifi_sniffer = wifi_sniffer

    def run(self):
        set_seconds = 30
        set_minutes = 6
        set_hour = 10
        set_month_day = 10
        set_month = 10
        set_year = 2023
        set_week_day = 3
        wait_time = 50
        set_time_sec = ((set_minutes * 60) + set_seconds)
        ping_count = self.utf_constants.get("ping_count")

        self.wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hours=set_hour,
                                              day=set_month_day, month=set_month, year=set_year,
                                              weekday=set_week_day)
        with TimeMeasurer() as t:

            self.logger.info("********** configuring the sniffer with access point channel **********")
            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.channel)
            logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_set_get_rtc_TC19051')
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0",
                                                           static_gateway="192.168.100.76")
            logger().info(" ********** DUT works as a Ap mode ********")
            self.wifi_dut.interfaces.wifi.start_ap(channel=self.channel, ssid="Ayush123", security="Open", psk="Ayush@123", beacon_interval=100, dtim_beacon_count=1)
            self.wifi_client.interfaces.wifi.join()
            device_ip = self.wifi_client.interfaces.wifi.client_gateway_ip
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Dut IP: {device_ip}")
            logger().info(f"Host IP: {host_ip}")
            status = ping(device_ip, ping_count)
            assert status, f"unable to ping to the {device_ip}"
        ap_up_logger_time = t.duration
        time.sleep(wait_time)
        time_data = self.wifi_dut.interfaces.wifi.get_rtc()
        get_time_sec = ((time_data['minutes'] * 60) + time_data['seconds'])
        assert (set_hour == time_data['hours']) and (set_month_day == time_data['day_month']) and \
               (set_month == time_data['month']) and (set_year == time_data['year']) and \
               (set_week_day == time_data['week_day'])

        idle_time = wait_time + ap_up_logger_time
        time_dif = get_time_sec - set_time_sec - idle_time
        with TimeMeasurer() as t:
            logger().info(f"idle time after initiating set rtc after Ap is up-> {idle_time}")
            assert (time_dif >= self.tolerance_threshold[0]) and (
                        time_dif <= self.tolerance_threshold[1]), f"get time updated is " \
                                                                  f"not in tolerance " \
                                                                  f"level. Time " \
                                                                  f"difference observed is {time_dif}"

            logger().info(
                f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance "
                f"leve")

            logger().info("get_rtc is working fine in AP mode")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features":  Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "Open", "ssid": "Ayush123", "passphrase": "Ayush@123", "channel": 11,
    }
    )
@pytest.mark.config("wifi_client", wifi={"channel": 11, "ssid": "Ayush123", "security": 'Open',  "passphrase": "Ayush@123", "interface": "wlan0"})
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_wifi_sdk_set_get_rtc_TC19051(wifi_dut, wifi_client, wifi_sniffer, channel, tolerance_threshold,
                                      utf_constants, sl_collections):
    try:
        wlan_obj = WLanRTCAPThread(wifi_dut=wifi_dut, wifi_client=wifi_client, channel=channel, wifi_sniffer=wifi_sniffer,
                                   tolerance_threshold=tolerance_threshold, utf_constants=utf_constants,
                                   sl_collections=sl_collections)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features":  Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "Open", "ssid": "Ayush123", "passphrase": "Ayush@123", "channel": 11,
    }
    )
@pytest.mark.config("wifi_client", wifi={"channel": 11, "ssid": "Ayush123", "security": 'Open',  "passphrase": "Ayush@123", "interface": "wlan0"})
def test_wifi_sdk_check_set_rtc_functionality_19050(wifi_dut, sl_collections):
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2023
    set_week_day = 3

    try:
        wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hours=set_hour,
                                         day=set_month_day, month=set_month, year=set_year,
                                         weekday=set_week_day)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()
