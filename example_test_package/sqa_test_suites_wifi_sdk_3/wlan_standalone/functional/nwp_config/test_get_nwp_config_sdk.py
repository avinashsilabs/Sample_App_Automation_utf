import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode
from utf_wiseconnect_3.tests.devices.si91x import (Si91xTCPIPFeatureBitMap, Si91xFeatureBitMap, \
                                                   Si91xConfigFeatureBitMap, Si91xOperatingMode,
                                                   Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap,
                                                   Si91xExtTCPIPFeatureBitMap)

def logger():
    return get_logger(__name__)

"""
    Setup requirement:
        1. SoC board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer (NUC device)
"""


@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "ext_tcpip_features": (Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT |
                               Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10)),
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0
    }
)
def test_wifi_sdk_vali_opn_part_num_with_sl_si91x_get_nwp_config_C693668(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                         request, sniffer_filter, sl_collections):
    """
    Validate the OPN part number of different OPN cards
    using sl_si91x_get_nwp_config API
    """
    try:
        test_name = request.node.name

        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        logger().info("Retrieving network configuration from the DUT.")
        wifi_dut.interfaces.wifi.sl_wifi_get_nwp_config()

        logger().info("Stopping sniffer capture.")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().error(f"An error occurred during test execution: {e}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

