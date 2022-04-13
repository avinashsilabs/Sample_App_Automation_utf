import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, \
    DeviceConstants
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import ping


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_get_rtc_deep_sleep_TC19052(
        wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold, logger
        ):
    capture_filename = "test_get_rtc_deep_sleep_TC19052"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time_after_scan = 50
    set_time_sec = ((set_minutes * 60) + set_seconds)
    firmware_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Firmware version-> {firmware_version}")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                wifi_dut.interfaces.wifi.scan(ssid=None)
                break
            except:
                logger.info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
    scan_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for scan -> {scan_time} seconds")
        logger.info(f"wait for {wait_time_after_scan} seconds")
    scan_logger_time1 = t.duration
    time.sleep(wait_time_after_scan)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    idle_time = wait_time_after_scan + scan_time + scan_logger_time1
    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after scan -> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} after scan "

        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance level ")

        logger.info("get_rtc is working fine after scan")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_set_get_rtc_twice_TC19049(
        wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold, logger
        ):
    capture_filename = "test_set_get_rtc_twice_TC19049"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time_after_scan = 50
    set_time_sec = ((set_minutes * 60) + set_seconds)
    firmware_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Firmware version-> {firmware_version}")
    logger.info(f"Time in seconds just before initiating set rtc on iteration 1->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                wifi_dut.interfaces.wifi.scan(ssid=None)
                break
            except:
                logger.info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
    scan_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for scan -> {scan_time} seconds")
        logger.info(f"wait for {wait_time_after_scan} seconds")
    scan_logger_time1 = t.duration
    time.sleep(wait_time_after_scan)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    idle_time = wait_time_after_scan + scan_time + scan_logger_time1
    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after scan on iteration 1-> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} on iteration 1 "

        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance "
            f"level on iteration 1")

        logger.info("get_rtc is working fine in iteration 1")

    set_seconds = 30
    set_minutes = 20

    wait_time_after_scan = 50
    set_time_sec = ((set_minutes * 60) + set_seconds)

    logger.info(f"Time in seconds just before initiating set rtc on iteration 2->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                wifi_dut.interfaces.wifi.scan(ssid=None)
                break
            except:
                logger.info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
    scan_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for scan -> {scan_time} seconds")
        logger.info(f"wait for {wait_time_after_scan} seconds")
    scan_logger_time1 = t.duration
    time.sleep(wait_time_after_scan)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    idle_time = wait_time_after_scan + scan_time + scan_logger_time1
    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after scan on iteration 2-> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} on iteration 1 "

        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance "
            f"level on iteration 2")

        logger.info("get_rtc is working fine in iteration 2")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_get_rtc_multiple_times_TC19053(
        wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold, logger
        ):
    capture_filename = "test_get_rtc_multiple_times_TC19053"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    ping_count = 10
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time_after_scan = 50
    set_time_sec = ((set_minutes * 60) + set_seconds)
    firmware_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Firmware version-> {firmware_version}")

    logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                wifi_dut.interfaces.wifi.scan(ssid=None)
                break
            except:
                logger.info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
    scan_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for scan -> {scan_time} seconds")
        logger.info(f"wait for {wait_time_after_scan} seconds")
    scan_logger_time1 = t.duration
    time.sleep(wait_time_after_scan)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    idle_time = wait_time_after_scan + scan_time + scan_logger_time1
    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after scan -> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} after scan "

        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance level ")

        logger.info("get_rtc is working fine after scan")
    scan_logger_time2 = t.duration

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                join_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger.info("Joining the Wifi Access Point")
                wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
                join_fail = 0
                break
            except:
                logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        if join_fail:
            logger.info(f"Joining to the AP has failed")
            assert join_fail == 0, "Joining to the AP is failed"
        for count in range(1, 3):
            ip_fail = 1
            try:
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                logger.info("DUT gets ipaddress through DHCP ")
                wifi_dut.interfaces.wifi.start_ip()
                ip_fail = 0
                break
            except:
                logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        if ip_fail:
            logger.info(f"DUT unable to get IP address")
            assert ip_fail == 0, "ip setting in DUT has failed"
    join_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for connecting to the AP, getting IP and ping for 10 sec  -> {join_time} seconds")
        logger.info(f"wait for 50 seconds")
    join_logger_time = t.duration
    wait_time_after_join = 50
    time.sleep(wait_time_after_join)

    idle_time = wait_time_after_scan + wait_time_after_join + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time
    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after join, ip-> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} after join, ip"
        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance level")
        logger.info("get_rtc is working fine after ip command")

    join_logger_time2 = t.duration

    with TimeMeasurer() as t:
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        ping(device_ip, ping_count)
    power_save_time = t.duration

    with TimeMeasurer() as t:
        logger.info(
            f"Time taken for executing power save api, ping for {ping_count} packets -> {power_save_time} seconds")
        logger.info(f"wait for 50 seconds")
    powersave_logger_time = t.duration
    wait_time_after_powersave = 50
    time.sleep(wait_time_after_powersave)
    idle_time = wait_time_after_scan + wait_time_after_join + wait_time_after_powersave + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time + join_logger_time2 + power_save_time + powersave_logger_time

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec - idle_time

    logger.info(f"idle time after initiating set rtc after power save -> {idle_time}")
    assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is not " \
                                                                                          f"in tolerance leve" \
                                                                                          f"l. Time " \
                                                                                          f"difference observed is {time_dif} after power save"
    logger.info(
        f"Time difference observed between set time and get time is {time_dif} seconds, which is in tolerance level")
    logger.info("get_rtc is working fine after power save command is initiated")

    validation = True
    packet_filter1 = f'(wlan.ta == {mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_get_rtc_after_rejoin_TC19055(
        wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold, logger
        ):
    capture_filename = "test_get_rtc_after_rejoin_TC19055"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    ping_count = 10
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time_after_scan = 50
    set_time_sec = ((set_minutes * 60) + set_seconds)
    firmware_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Firmware version-> {firmware_version}")

    logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                wifi_dut.interfaces.wifi.scan(ssid=None)
                break
            except:
                logger.info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
    scan_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for scan -> {scan_time} seconds")
        logger.info(f"wait for {wait_time_after_scan} seconds")
    scan_logger_time1 = t.duration
    time.sleep(wait_time_after_scan)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    idle_time = wait_time_after_scan + scan_time + scan_logger_time1
    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after scan -> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} after scan "

        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance level ")

        logger.info("get_rtc is working fine after scan")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
    scan_logger_time2 = t.duration

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                join_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger.info("Joining the Wifi Access Point")
                wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
                join_fail = 0
                break
            except:
                logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        if join_fail:
            logger.info(f"Joining to the AP has failed")
            assert join_fail == 0, "Joining to the AP is failed"
        for count in range(1, 3):
            ip_fail = 1
            try:
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                logger.info("DUT gets ipaddress through DHCP ")
                wifi_dut.interfaces.wifi.start_ip()
                ip_fail = 0
                break
            except:
                logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        if ip_fail:
            logger.info(f"DUT unable to get IP address")
            assert ip_fail == 0, "ip setting in DUT has failed"
    join_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for connecting to the AP, getting IP and ping for 10 sec  -> {join_time} seconds")
        logger.info(f"wait for 50 seconds")
    join_logger_time = t.duration
    wait_time_after_join = 50
    time.sleep(wait_time_after_join)

    idle_time = wait_time_after_scan + wait_time_after_join + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time
    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after join, ip-> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} after join, ip"
        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance level")
        logger.info("get_rtc is working fine after ip command")

    join_logger_time2 = t.duration

    with TimeMeasurer() as t:
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        ping(device_ip, ping_count)
    power_save_time = t.duration

    with TimeMeasurer() as t:
        logger.info(
            f"Time taken for executing power save api, ping for {ping_count} packets -> {power_save_time} seconds")
        logger.info(f"wait for 50 seconds")
    powersave_logger_time = t.duration
    wait_time_after_powersave = 50
    time.sleep(wait_time_after_powersave)
    idle_time = wait_time_after_scan + wait_time_after_join + wait_time_after_powersave + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time + join_logger_time2 + power_save_time + powersave_logger_time

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after power save -> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (
                time_dif <= tolerance_threshold[1]), f"get time updated is not " \
                                                     f"in tolerance leve" \
                                                     f"l. Time " \
                                                     f"difference observed is {time_dif} after power save"
        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds, which is in tolerance level")
        logger.info("get_rtc is working fine after power save command is initiated")
    powersave_logger_time2 = t.duration

    wait_time_after_rejoin = 50
    with TimeMeasurer() as t:
        # Disable wireless option in AP
        wifi_access_point.interfaces.wifi.stop_ap()
        # Enable wireless option in AP
        time.sleep(5)
        wifi_access_point.interfaces.wifi.start_ap()
        ping(device_ip, ping_count)
        logger.info("Ping to DUT is successful after rejoin")
        logger.info(f"wait for {wait_time_after_rejoin} seconds")
    ap_up_time = t.duration

    time.sleep(wait_time_after_rejoin)
    idle_time = wait_time_after_scan + wait_time_after_join + wait_time_after_powersave + wait_time_after_rejoin + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time + join_logger_time2 + power_save_time + powersave_logger_time + powersave_logger_time2 + ap_up_time

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after rejoin successful -> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (
                time_dif <= tolerance_threshold[1]), f"get time updated is not " \
                                                     f"in tolerance leve" \
                                                     f"l. Time " \
                                                     f"difference observed is {time_dif} after rejoin successful"
        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds, which is in tolerance level")
        logger.info("get_rtc is working fine after rejoin is successful")

    validation = True
    packet_filter1 = f'(wlan.ta == {mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "skip_radio_init": True
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# RTC timer functionality should not work when the set RTC api is executed in wrong state. Before
# Wireless initialization
def test_set_rtc_incorrect_state_TC19048(wifi_dut, logger):
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time = 10

    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)
    time.sleep(wait_time)
    # get_rtc API returns time parameters output at the instance
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.get_rtc()
    assert exc_info.value.error_code == 0x0021, "DUT sent wrong error code, expected is 0x0021"
    logger.info(f"DUT sent error code {exc_info.value.error_code} when get_rtc initiated in wrong state which is "
                f"expected")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_get_rtc_without_enabling_feature_TC19054(
        wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold, logger
        ):
    capture_filename = "test_get_rtc_without_enabling_feature_TC19054"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time_after_scan = 50
    set_time_sec = ((set_minutes * 60) + set_seconds)
    firmware_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Firmware version-> {firmware_version}")

    logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                wifi_dut.interfaces.wifi.scan(ssid=None)
                break
            except:
                logger.info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
    scan_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for scan -> {scan_time} seconds")
        logger.info(f"wait for {wait_time_after_scan} seconds")
    scan_logger_time1 = t.duration
    time.sleep(wait_time_after_scan)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec

    assert time_dif == 0, f"Set time updated and get time received are not same"

    logger.info("Set time updated and get time received are same which is expected when RTC feature is not enabled")
