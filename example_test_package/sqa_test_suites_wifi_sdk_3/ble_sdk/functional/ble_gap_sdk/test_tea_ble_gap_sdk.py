import random
import string
import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, Si91xBLEFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus

""" The testcases added in this file run below test steps for DUT-Si91x
        1. Initiates the DUT Coex wlan and BLE mode.
        2. Set local name on DUT.
    
    setup requirement:
        1. DUT(Si91x)
        2. Raspberry PI4
        
    Author: Gopinatha N 
"""


def logger():
    return get_logger(__name__)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                        Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                        Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                              Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                                   Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid |
                                   Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                                   Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                               Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                       Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        },
    )
]


def test_ble_set_local_name_more_than_16_bytes_c37543(ble_dut):
    """BLE set local name more than 16 bytes
    ble_dut:Fixture parameter to issue command in DUT
    """
    set_local_name = "SILABS_DEVICE_1234"
    logger().info(f"Setting ble local name:{set_local_name} with {len(set_local_name)} bytes")
    time.sleep(5)
    status = ble_dut.interfaces.bluetooth.bt_set_local_name(set_local_name)
    logger().info(f"ble set local name status :{status}")
    assert "SL_STATUS_BT_Invalid_NAME_LENGTH_WHEN_SET_TO_MORE_THAN_16_BYTES" in ' '.join(map(str, status)), \
        "Set local length is less than 16 Bytes,please pass 16+ bytes for this test case"
    logger().info(f"ble local name : more than 16 bytes is not setting as expected:"
                  f"{hex(SLStatus.SL_STATUS_BT_Invalid_NAME_LENGTH_WHEN_SET_TO_MORE_THAN_16_BYTES)}")


def test_ble_set_local_name_5_8_10_11_13_16_bytes_c37544(ble_dut):
    """BLE set local name set 5,8,10,11,13, and 16 bytes.
    ble_dut:Fixture parameter to issue command in DUT
    """
    local_name_set_count = 0
    local_name_not_set_count = 0
    local_names = ["SI123", "SILABS_1", "SILABS_123", "SILABS_1234", "SILABS_1234AB", "SILABS_DEVICE_12"]
    for local_name in local_names:
        try:
            set_local_name = local_name
            logger().info(f"Setting BLE local name:{set_local_name} with {len(set_local_name)} bytes.")
            time.sleep(5)
            status = ble_dut.interfaces.bluetooth.bt_set_local_name(set_local_name)
            logger().info(f"ble set local name status :{status}")
            assert "SL_STATUS_OK" in ''.join(map(str, status)), "Local name length is more than 16 bytes."
            logger().info(f"ble set local name {set_local_name} is successful with {len(set_local_name)} bytes.")
            get_local_name = ble_dut.interfaces.bluetooth.bt_get_local_name(timeout=10)
            assert set_local_name == get_local_name, "set_local_name and get_local_name are not matching"
            logger().info(f"set_local_name and get_local_name are matching ---> {get_local_name}")
            local_name_set_count += 1
        except Exception as error:
            logger().info(f"error message{error}")
            logger().info(f"ble set local name:{local_names[local_name_set_count]} is not successful with"
                          f" {len(local_names[local_name_set_count])} bytes.")
            logger().info(f"ble set local name status :"
                          f"{hex(SLStatus.SL_STATUS_BT_Invalid_NAME_LENGTH_WHEN_SET_TO_MORE_THAN_16_BYTES)}")
            local_name_not_set_count += 1
            continue
    assert local_name_set_count == len(local_names), ("All given list of elements are not successfully "
                                                      "to set local names.")
    logger().info("All given list of elements are successfully to set all local names.")


@pytest.mark.start_state("ble_dut", wifi=['init'])
def test_ble_sdk_set_local_name_gt_16_special_characters_c37556(ble_dut, sl_collections):
    """
    Verify RSI_BLE is throwing error or not when we set local name more than 16 characters with only special characters.
    """
    try:
        local_name = ''.join(random.choices("@#$%^&*(", k=18))
        logger().info(f"Setting bt local name: {local_name}")
        status_code = ble_dut.interfaces.bluetooth.bt_set_local_name(local_name)[0]
        assert status_code == 0x04E66, f"DUT sent wrong error code:'{hex(status_code)}', expected error code is 0x04E66"
        logger().info(f"DUT sent error code '{hex(status_code)}' which is expected.")
    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)


@pytest.mark.start_state("ble_dut", wifi=['init'])
def test_ble_sdk_set_local_name_gt_16_chars_with_only_numbers_c37557(ble_dut, sl_collections):
    """
    Verify RSI_BLE is throwing error or not when we set local name more than 16 characters with only Numbers.
    """
    try:
        local_name = ''.join(random.choices(string.digits, k=20))
        logger().info(f"Setting bt local name: {local_name}")
        status_code = ble_dut.interfaces.bluetooth.bt_set_local_name(local_name)[0]
        assert status_code == 0x04E66, f"DUT sent wrong error code:'{hex(status_code)}', expected error code is 0x04E66"
        logger().info(f"DUT sent error code '{hex(status_code)}' which is expected.")
    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)


@pytest.mark.start_state("ble_dut", wifi=['init'])
def test_ble_sdk_set_local_name_gt_16_chars_with_combination_of_alphanumeric_special_chars_c37558(ble_dut,
                                                                                                  sl_collections):
    """
    Verify RSI_BLE is throwing error or not when we set local name more than 16 characters with combination of
    alphanumeric and special characters.
    """
    try:
        local_name = ''.join(random.choices(string.ascii_uppercase[:10] + string.digits + "@#$%^&*(#@$", k=20))
        logger().info(f"Setting bt local name: {local_name}")
        status_code = ble_dut.interfaces.bluetooth.bt_set_local_name(local_name)[0]
        assert status_code == 0x04E66, f"DUT sent wrong error code:'{hex(status_code)}', expected error code is 0x04E66"
        logger().info(f"DUT sent error code '{hex(status_code)}' which is expected.")
    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)


@pytest.mark.start_state("ble_dut", wifi=['init'])
def test_ble_sdk_set_local_name_with_combination_of_alphanumeric_special_chars_c37559(ble_dut, sl_collections):
    """
    Verify RSI_BLE is able to accept the local name when we set local name with combination of alphanumeric and special
    characters.
    """
    try:
        set_local_name = ''.join(random.choices(string.ascii_uppercase[:10] + string.digits + "@#$%^&*(#@$", k=16))
        logger().info(f"Setting bt local name: {set_local_name}")
        status_code = ble_dut.interfaces.bluetooth.bt_set_local_name(set_local_name)[0]
        assert status_code == 0x0000, f"DUT sent wrong status code:'{hex(status_code)}', expected status code is 0x0000"
        get_local_name = ble_dut.interfaces.bluetooth.bt_get_local_name(timeout=10)
        assert set_local_name == get_local_name, "set_local_name and get_local_name are not matching"
        logger().info(f"set_local_name and get_local_name are matching ---> {get_local_name}")
    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)


@pytest.mark.start_state("ble_dut", wifi=['init'])
def test_ble_sdk_set_local_name_with_only_special_chars_c37560(ble_dut, sl_collections):
    """
    Verify RSI_BLE is able to accept the local name when we set local name with ONLY special characters.
    """
    try:
        set_local_name = ''.join(random.choices("@#$%^&*(", k=16))
        logger().info(f"Setting bt local name: {set_local_name}")
        status_code = ble_dut.interfaces.bluetooth.bt_set_local_name(set_local_name)[0]
        assert status_code == 0x0000, f"DUT sent wrong status code:'{hex(status_code)}', expected status code is 0x0000"
        get_local_name = ble_dut.interfaces.bluetooth.bt_get_local_name(timeout=10)
        assert set_local_name == get_local_name, "set_local_name and get_local_name are not matching"
        logger().info(f"set_local_name and get_local_name are matching ---> {get_local_name}")
    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)

