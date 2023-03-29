import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116FeatureBitMap,RS9116ConfigFeatureBitMap
from utf.utils.logger import get_logger

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

@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 8,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "set_send_feature_frame": True,
            "rf_type":1,
            "features_enable":49,
        }
)
@pytest.mark.power_msrmt_dut("per_wiseconnect")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wlan_active_rx_10dBm_20dBm_2_4Ghz_C20560(wifi_dut, power_msrmt_dut):
    rsi_antenna = 1
    antenna_gain_2g = 0
    antenna_gain_5g = 0
    antenna=1
    gain_2g=0
    gain_5g=0
    length = 1000
    mode = 0
    channel = 1
    power=10
    rate = 139

    logger().info("======= set antenna on 1st dut")
    wifi_dut.interfaces.wifi.set_wireless_antenna(antenna, gain_2g, gain_5g)

    logger().info(f"======= configure dut with diff power:{power}")
    wifi_dut.interfaces.wifi.get_receive_stats_start(channel)

    logger().info("======= invoke 2nd dut")
    power_msrmt_dut.interfaces.power_meter.init_device()
    time.sleep(10)

    logger().info("======= set antenna on 2nd dut")
    power_msrmt_dut.interfaces.power_meter.wireless_antenna(rsi_antenna=rsi_antenna,antenna_gain_2g=antenna_gain_2g,antenna_gain_5g=antenna_gain_5g)

    logger().info("======= start transmit from 2nd DUT")
    power_msrmt_dut.interfaces.power_meter.start_transmit(power=power, rate=rate, length=length, mode=mode, channel=channel)
    time.sleep(20)