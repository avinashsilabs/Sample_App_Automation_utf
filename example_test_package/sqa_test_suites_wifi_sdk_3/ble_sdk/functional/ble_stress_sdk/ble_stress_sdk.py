import pytest
from utf_wiseconnect_3.tests.devices.si91x  import Si91xCoexMode, Si91xPowerSaveModes,Si91xFeatureBitMap,Si91xConfigFeatureBitMap,Si91xTCPIPFeatureBitMap,\
    Si91xExtTCPIPFeatureBitMap,Si91xExtCustomFeatureBitMap,Si91xCustomFeatureBitMap,Si91xPowerSaveProcedureTypes,\
Si91xBTFeatureBitMap,Si91xBLEFeatureBitMap,Si91xBLECustomFeatureBitMap
from utf.utils.logger import get_logger
import time

def logger():
    return get_logger(__name__)

"""
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates ble in DUT 
        3. Initiates start Scan and stop scan for 1000 times
        4. Initiates Scan on dut for 48 hours

    Author: M.Harshitha
"""


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE|
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
                                        |Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        }
    )
]
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan"])
def test_ble_start_stop_scan_1000_times_C19810(ble_dut, ble_client):
    """Test case is to run ble start and stop scanning 1000 times"""
    try:
        iter_count = 1000
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"
        for i in range(0, iter_count):
            ble_client.interfaces.bluetooth.close()
            logger().info(f" ======= initialize ble adv in remote device for iteration {i+1}")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address, f"ble initialization failed in remote device for iteration{i}"
            logger().info(f"ble client address of remote device for iteration {i} is {bt_client_address}")
            time.sleep(2)
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
            time.sleep(5)
            ble_client.interfaces.bluetooth.stop_advertising()
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e

