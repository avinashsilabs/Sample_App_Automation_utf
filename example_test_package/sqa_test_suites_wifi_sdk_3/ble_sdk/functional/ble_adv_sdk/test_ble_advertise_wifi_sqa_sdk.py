import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xFeatureBitMap,Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,Si91xBLEFeatureBitMap,
    Si91xTCPIPFeatureBitMap,Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap, Si91xOperatingMode,
)
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


""" The testcases added in this file run below test steps for DUT-Si91x
        1. Configuration of DUT in Wifi+Bluetooth dual mode
        2. Put DUT in BLE advertising mode
        3. Put RaspberryPi in scan mode
        4. Initiate connection from Raspberry pi over BLE
    setup requirement:
        1. DUT(Si91x)
        2. Raspberry PI4

    Author : M.Harshitha
"""

""" Note: Dependence on Jira WIFI_BT_UTFHELP-2842 """


def check_for_devices_in_scanned_results(ble_interface, bt_dut_address, adv_data):
    """ This function is used to check for devices in scan results """
    sw = Stopwatch()
    previously_found_devices = {}
    while sw.elapsed_sec < 30:
        found_devices = ble_interface.get_devices()
        if previously_found_devices != found_devices:
            logger().info(f"BLE scan results :{found_devices}")
            previously_found_devices = found_devices
        if (
                bt_dut_address in found_devices
                and found_devices[bt_dut_address] == adv_data
        ):
            return True
    return False

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
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.FeatureLowPower| Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        },
    )
]
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_wifi_sdk_ble_undirected_connectable_adv_c19801(wifi_dut, ble_client):
    """ Verify BLE Undirected Connectable advertisement """

    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19801_{int(time.time())}") as bt_logs:
            logger().info("Initializing BLE")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address, "Unable to fetch bluetooth address from DUT"
            logger().info(f"bt_dut_address : {bt_dut_address}")
            logger().info("Advertising the DUT in undirected_connectable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128)
            logger().info("Enabling Wlan and BLE power save ")
            if power_save:
                wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            logger().info("Initiating scan from remote BLE device")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address, "Unable to fetch remote bluetooth address"
            device_found = check_for_devices_in_scanned_results(ble_interface=ble_client.interfaces.bluetooth,
                                                                bt_dut_address=bt_dut_address,
                                                                adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            if device_found:
                logger().info("Dut found in scan results")
            logger().info("Initiating stop scanning from remote device")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "Dut not found in scan results"
            logger().info("Initiating stop advertising from DUT")
            wifi_dut.interfaces.wifi.ble_stop_advertising()
            logger().info(
                f"Getting Remote BLE characteristics by passing address {wifi_dut.interfaces.wifi.ble_address} from BTmon logs")
            bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)
            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")
            assert "Connectable undirected - ADV_IND (0x00)" in bt_logs.device_adv_type, "Expected adv type not found in bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e

@pytest.mark.skip()
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_undirected_scannable_adv_c19803(wifi_dut, ble_client):
    """ Verify BLE Undirected Scannable advertisement"""

    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19803_{int(time.time())}") as bt_logs:
            logger().info("Initializing BLE")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address, "Unable to fetch bluetooth address from DUT"
            logger().info(f"bt_dut_address : {bt_dut_address}")
            logger().info("Advertising the DUT in undirected scanable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=130)
            logger().info("Enabling Wlan and BLE power save ")
            if power_save:
                wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            logger().info("Initiating BLE scanning from remote device")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address, "Unable to fetch Bluetooth address from remote device"
            device_found = check_for_devices_in_scanned_results(ble_interface=ble_client.interfaces.bluetooth,
                                                                bt_dut_address=bt_dut_address,
                                                                adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            if device_found:
                logger().info("Dut found in scan results")
            logger().info("Initiating stop scanning from remote Raspberry PI")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "Dut not found in scan results"
            logger().info("Initiating stop advertising from DUT")
            wifi_dut.interfaces.wifi.ble_stop_advertising()
            logger().info(
                f"Getting Remote BLE characteristics by passing address{wifi_dut.interfaces.wifi.ble_address} from BTmon logs")
            bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)
            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")
            assert "Scannable undirected - ADV_SCAN_IND (0x02)" in bt_logs.device_adv_type, "Expected advertise type not found in bt logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e

@pytest.mark.skip()
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_wifi_sdk_ble_undirected_non_connectable_adv_c19804(wifi_dut, ble_client):
    """ Verify BLE Undirected Non-Connectable Advertisement"""

    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_c19804{int(time.time())}.log") as bt_logs:
            logger().info("Initializing BLE")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address, "Unable to fetch bluetooth address from DUT"
            logger().info(f"bt_dut_address : {bt_dut_address}")
            logger().info("Advertising the DUT in undirected_non_connectable_adv mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=131)
            logger().info("Enabling Wlan and BLE power save ")
            if power_save:
                wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            logger().info("Initiating scanning from Remote remote device")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None, "Unable to fetch bluetooth address from remote device"
            device_found = check_for_devices_in_scanned_results(ble_interface=ble_client.interfaces.bluetooth,
                                                                bt_dut_address=bt_dut_address,
                                                                adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
            if device_found:
                logger().info("Dut found in scan results")
            logger().info("initiating stop scanning")
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found, "dut not found in scan results"
            logger().info("initiating stop advertising")
            wifi_dut.interfaces.wifi.ble_stop_advertising()
            logger().info(
                f"Getting Remote BLE characteristics by passing address {wifi_dut.interfaces.wifi.ble_address} from BTmon logs")
            bt_logs.device_characteristics(wifi_dut.interfaces.wifi.ble_address)
            logger().info(f"fetched data from bt mon {bt_logs.device_adv_type}")
            assert (
                    "Non connectable undirected - ADV_NONCONN_IND (0x03)" in bt_logs.device_adv_type), "Expected avd type not found bt mon logs"
            logger().info(f"Verified that DUT in {bt_logs.device_adv_type} mode")
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable"])
def test_wifi_sdk_adv_with_name_of_length_16bytes_c19850(wifi_dut, ble_client):
    """Verify ble default set local name length 16-bytes"""

    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    try:
        set_local_name = "ble_123456789012"
        logger().info(f"Setting BLE local name {set_local_name}")
        wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"Getting the local name : {status}")
        assert set_local_name == status, "Set local name and get local name not matched "
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address, "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {bt_dut_address}")
        logger().info("Advertising DUT with the name ble_123456789012 ")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data="ble_123456789012")
        if power_save:
            wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                        psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        logger().info("Initiating scan from remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address, "Unable to fetch BD address from Remote BLE device"
        device_found = check_for_devices_in_scanned_results(ble_interface=ble_client.interfaces.bluetooth,
                                                            bt_dut_address=bt_dut_address,
                                                            adv_data=wifi_dut.interfaces.wifi.ble_advertising_data)
        if device_found:
            logger().info("Dut found in scan results")
        logger().info("initiating stop scanning")
        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "dut not found in scan results"
        logger().info("initiating stop advertising")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_wifi_sdk_set_localname_configured_with_17bytes_C71442(wifi_dut):
    """ Verify ble set local name configured with 17 bytes """
    try:
        logger().info("Setting BLE local name A2345678901234567 of 17 bytes")
        time.sleep(3)
        wifi_dut.interfaces.wifi.bt_set_local_name("A2345678901234567", expected_status=SLStatus.SL_STATUS_BT_Invalid_NAME_LENGTH_WHEN_SET_TO_MORE_THAN_16_BYTES)
        logger().info(
                f" Local Name set configured more than 16 bytes , observed error code 0x4E66 which is expected")
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e