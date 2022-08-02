import pytest
import time
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116PowerSaveModes, RS9116JoinFeatureBitMap

def logger():
    return get_logger(__name__)
"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut

    Author: Aravind
"""
def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)

@pytest.mark.parametrize("dtim", [1, 3, 10])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
        }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_standby_dtim_2g(wifi_dut, wifi_access_point, power_meter, dtim):

    bcast_in_tim_next_cmd = 1
    beacon_drop = 500
    bcast_in_tim = 1

    logger().info(f"configuring access point with dtim:{dtim}")
    wifi_access_point.interfaces.wifi.start_ap(dtim=dtim)

    logger().info("scan and connecting to access point.....")
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, join_feature_bitmap=RS9116JoinFeatureBitMap.Default)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info("sending filter broadcast command")

    wifi_dut.interfaces.wifi.set_filter_broadcast(beacon_drop, bcast_in_tim, bcast_in_tim_next_cmd)
    # assert status, "filter broadcast is failed"

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2)
    logger().info(f'DUT ip {device_ip}')

    time.sleep(10)

    # Init power meter by specifying module name as datalogger or scope
    power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{dtim}")
    # Init power meter module
    power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
    # set power meter out put channels
    power_meter.interfaces.power_meter.set_output_channels(["1"])
    # start capture power meter datalog/scope
    power_meter.interfaces.power_meter.start_capture()

    # Parse result as throughput object
    parsed_result = power_meter.interfaces.power_meter.power_meter_module.process_output(
        power_meter.interfaces.power_meter.results)
    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None




