import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116FeatureBitMap,RS9116ConfigFeatureBitMap,RS9116Band
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import print_dict

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Transmit mode
        2. Initiates the 2nd DUT Transmit mode.
        3. Validates the PER between the two DUT's

    Author: RaviNemali
"""
class power_number_output():
    def __init__(self, power_meter = None, dtim=None):
        self.power_meter = power_meter
        self.dtim = dtim

    def __print_throughput(self, throughput: dict):
        if throughput is not None:
            print_dict("##     ", throughput)

    def get_power_value(self):
        if self.dtim:
            # Init power meter by specifying module name as datalogger or scope
            logger().info("initiating power meter wih dtim")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log_{self.dtim}")
        else:
            logger().info("initiating power meter")
            self.power_meter.interfaces.power_meter.init_power_meter(data_log_file_name=f"UTF1_Data_Log")
        # Init power meter module

        self.power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
        # set power meter out put channels
        logger().info("setting output channels")
        self.power_meter.interfaces.power_meter.set_output_channels_settings(
            [{"channel": "1", "emulation_mode": "Current Measure", "trace_current": True, "trace_voltage": False,
              "trace_power": False}])
        # power_meter.interfaces.power_meter.set_output_channels(["1"])
        time.sleep(10)
        # start capture power meter datalog/scope
        logger().info("starting power meter capture")
        self.power_meter.interfaces.power_meter.start_capture()

        # Parse result as throughput object
        logger().info("parsing output result")
        parsed_result = self.power_meter.interfaces.power_meter.power_meter_module.process_output(
            self.power_meter.interfaces.power_meter.results)
        self.__print_throughput(parsed_result)
        assert parsed_result["Output"] is not None

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 8,
            "features": RS9116FeatureBitMap.OpenMode,
            "set_send_feature_frame": True,
            "rf_type": 1,
            "features_enable": 0,
        }
)
@pytest.mark.power_msrmt("per_wiseconnect")
@pytest.mark.parametrize("rate", [139, 775])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_active_rx_10dBm_20dBm_2_4Ghz_C20560(wifi_dut, power_msrmt, power_meter, rate):
    rsi_antenna = 1
    antenna_gain_2g = 0
    antenna_gain_5g = 0
    antenna = 1
    gain_2g = 0
    gain_5g = 0
    length = 1000
    mode = 0
    channel = 1
    power = 8

    logger().info("======= set antenna on 1st dut")
    wifi_dut.interfaces.wifi.set_wireless_antenna(antenna, gain_2g, gain_5g)

    logger().info(f"======= configure dut with diff power:{power}")
    wifi_dut.interfaces.wifi.get_receive_stats_start(channel)

    logger().info("======= invoke 2nd dut")
    power_msrmt.interfaces.power_meter.init_device()
    time.sleep(5)

    logger().info("======= set antenna on 2nd dut")
    power_msrmt.interfaces.power_meter.wireless_antenna(rsi_antenna=rsi_antenna, antenna_gain_2g=antenna_gain_2g, antenna_gain_5g=antenna_gain_5g)
    time.sleep(5)

    logger().info("======= start transmit from 2nd DUT")
    power_msrmt.interfaces.power_meter.start_transmit(power=power, rate=rate, length=length, mode=mode, channel=channel)

    time.sleep(5)
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 8,
            "features": RS9116FeatureBitMap.OpenMode,
            "set_send_feature_frame": True,
            "rf_type": 1,
            "wireless_mode": 12,
            "features_enable": 0,
        }
)
@pytest.mark.power_msrmt("per_wiseconnect")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_active_rx_LP_2_4Ghz_C20560(wifi_dut, power_msrmt, power_meter):
    rsi_antenna = 1
    antenna_gain_2g = 0
    antenna_gain_5g = 0
    antenna=1
    gain_2g=0
    gain_5g=0
    length = 1000
    mode = 0
    channel = 1
    power = 8
    rate = 139
    wireless_mode = 12

    logger().info("======= set antenna on 1st dut")
    wifi_dut.interfaces.wifi.set_wireless_antenna(antenna, gain_2g, gain_5g)

    logger().info(f"======= configure dut with diff power:{power}")
    wifi_dut.interfaces.wifi.get_receive_stats_start(channel)

    logger().info("======= invoke 2nd dut")
    power_msrmt.interfaces.power_meter.init_device(wireless_mode=wireless_mode)
    time.sleep(10)

    logger().info("======= set antenna on 2nd dut")
    power_msrmt.interfaces.power_meter.wireless_antenna(rsi_antenna=rsi_antenna, antenna_gain_2g=antenna_gain_2g,
                                                        antenna_gain_5g = antenna_gain_5g)

    logger().info("======= start transmit from 2nd DUT")
    power_msrmt.interfaces.power_meter.start_transmit(power=power, rate=rate, length=length, mode=mode, channel=channel)

    time.sleep(10)
    power_obj = power_number_output(power_meter=power_meter)
    power_obj.get_power_value()

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 8,
            "features": RS9116FeatureBitMap.OpenMode,
            "set_send_feature_frame": True,
            "rf_type": 0,
            "band": RS9116Band.FiveGHz,
            "features_enable": 0,
        }
)
@pytest.mark.power_msrmt("per_wiseconnect")
@pytest.mark.parametrize("rate", [139, 775])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_active_rx_5Ghz_C20626(utf_constants, wifi_dut, power_msrmt, power_meter, rate):
    board_ver = utf_constants.get("board_version")
    logger().info(f"board version is : {board_ver}")
    if board_ver == "1.4Q7" or "1.5Q7":
        pytest.skip(reason="board version doesn't support 5Ghz")

    else:
        rsi_antenna = 1
        antenna_gain_2g = 0
        antenna_gain_5g = 0
        antenna = 1
        gain_2g = 0
        gain_5g = 0
        length = 1000
        mode = 0
        channel = 36
        power = 8
        rf_type = 0
        band = 1

        logger().info("======= set antenna on 1st dut")
        wifi_dut.interfaces.wifi.set_wireless_antenna(antenna, gain_2g, gain_5g)

        logger().info(f"======= configure dut with diff power:{power}")
        wifi_dut.interfaces.wifi.get_receive_stats_start(channel)

        logger().info("======= invoke 2nd dut")
        power_msrmt.interfaces.power_meter.init_device(band=band, rf_type=rf_type)
        time.sleep(5)

        logger().info("======= set antenna on 2nd dut")
        power_msrmt.interfaces.power_meter.wireless_antenna(rsi_antenna=rsi_antenna, antenna_gain_2g=antenna_gain_2g,
                                                            antenna_gain_5g=antenna_gain_5g)
        time.sleep(5)

        logger().info("======= start transmit from 2nd DUT")
        power_msrmt.interfaces.power_meter.start_transmit(power=power, rate=rate, length=length, mode=mode,
                                                          channel=channel)

        time.sleep(5)
        power_obj = power_number_output(power_meter=power_meter)
        power_obj.get_power_value()


