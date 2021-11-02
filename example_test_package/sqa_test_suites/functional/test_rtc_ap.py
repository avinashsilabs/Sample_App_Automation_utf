import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, RS9116OperatingMode

import time


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.Disabled,
        "features": RS9116FeatureBitMap.Aggregation,
        "config_features": 0,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default
        }
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# The test case checks whether the RTC timer functionality is working fine in Access point mode
def test_wifi_set_get_rtc_testcase_6(wifi_ap_dut, wifi_client):
    # third party STA connects to the AP
    wifi_client.interfaces.wifi.join()
    # Initiate ping from third party wifi-client to DUT
    assert wifi_client.interfaces.wifi.ping("192.168.100.76") < 1
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time = 100
    set_time_sec = ((set_minutes * 60) + set_seconds)
    # This API starts RTC timer in DUT
    wifi_ap_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                        month_day=set_month_day,
                                        month=set_month, year=set_year, week_day=set_week_day)

    time.sleep(wait_time)
    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_ap_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec
    assert (time_dif - wait_time) <= 2
