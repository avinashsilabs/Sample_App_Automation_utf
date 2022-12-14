import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, RS9116OperatingMode, RS9116ExtCustomFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap
from utf.utils.iperf.iperf_utils import ping

import time
from utf.utils.time_measurer import TimeMeasurer


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": 0,
        "config_features": 0,
        "security": 'Open',
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config("wifi_client", wifi={'interface': 'wlan0', "channel": 3, "ssid": "check_rtc", "security": 'Open'})
@pytest.mark.parametrize("channel", [3])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
# The test case checks whether the RTC timer functionality is working fine in Access point mode
def test_wifi_set_get_rtc_TC19051(wifi_sniffer, wifi_dut, wifi_client, channel, tolerance_threshold, logger, utf_constants):
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time = 50
    ping_count = utf_constants.get("ping_count")
    set_time_sec = ((set_minutes * 60) + set_seconds)
    firmware_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Firmware version-> {firmware_version}")
    logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        mode = 'static'
        ip_address = '192.168.100.76'
        subnet = '255.255.255.0'
        gateway = '192.168.100.76'

        wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
        logger.info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger.info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_set_get_rtc_TC19051')
        logger.info(" ********** DUT works as a Ap mode ********")
        wifi_dut.interfaces.wifi.start_ap(channel=channel, ssid="check_rtc")
        logger.info(
            "This command is added to terminate existing wlan0 if it is already there. If it is not there it will "
            "throw "
            "warning please ignore below error")
        wifi_client.interfaces.wifi.join(ssid="check_rtc")
        device_ip = wifi_client.interfaces.wifi.client_gateway_ip
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger.info(f"Dut IP: {device_ip}")
        logger.info(f"Host IP: {host_ip}")
        status = ping(device_ip, ping_count)
        assert status, f"unable to ping to the {device_ip}"
    ap_up_logger_time = t.duration
    time.sleep(wait_time)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    idle_time = wait_time + ap_up_logger_time
    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after Ap is up-> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif}"

        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance "
            f"leve")

        logger.info("get_rtc is working fine in AP mode")
