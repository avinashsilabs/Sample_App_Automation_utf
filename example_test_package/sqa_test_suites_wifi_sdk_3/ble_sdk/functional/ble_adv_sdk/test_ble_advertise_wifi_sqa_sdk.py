import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utf_config import UtfConfig
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xExtCustomFeatureBitMap, Si91xOperatingMode,
)
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError


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

""" Note: Dependence on Jira WIFI_BT_UTFHELP-2840 and WIFI_BT_UTFHELP-2842 """


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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_undirected_connectable_adv_c19801(wifi_dut, ble_client, utf_constants):
    """ Verify BLE Undirected Connectable advertisement """

    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19801_{int(time.time())}") as bt_logs:
            logger().info("Initializing BLE")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address, "Unable to fetch bluetooth address from DUT"
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_connectable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=128)
            logger().info("Enabling Wlan and BLE power save ")
            if power_save:
                enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                assert enable_wifi_ps, 'failed to enable wlan power save'
                enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps, 'failed to enable bt power save'
            logger().info("Initiating scan from remote BLE device")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None, "Unable to fetch remote bluetooth address"
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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_undirected_scannable_adv_c19803(wifi_dut, ble_client):
    """ Verify BLE Undirected Scannable advertisement"""

    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_C19803{int(time.time())}") as bt_logs:
            logger().info("Initializing BLE")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address, "Unable to fetch bluetooth address from DUT"
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected scanable ADV mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=130)
            logger().info("Enabling Wlan and BLE power save ")
            if power_save:
                enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                assert enable_wifi_ps, 'failed to enable wlan power save'
                enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps, 'failed to enable bt power save'
            logger().info("Initiating BLE scanning from remote device")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None, "Unable to fetch Bluetooth address from remote device"
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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake
                    | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_ble_undirected_non_connectable_adv_c19804(wifi_dut, ble_client):
    """ Verify BLE Undirected Non-Connectable Advertisement"""

    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wifi_sdk_c19804{int(time.time())}.log") as bt_logs:
            logger().info("Initializing BLE")
            bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
            logger().info("Advertising DUT ")
            logger().info("keeping the DUT in undirected_non_connectable_adv mode")
            wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_type=131)
            logger().info("Enabling Wlan and BLE power save ")
            if power_save:
                enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                assert enable_wifi_ps, 'failed to enable wlan power save'
                enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps, 'failed to enable bt power save'
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


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.FeatureLowPower,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_adv_with_name_of_length_16bytes_c19850(wifi_dut, ble_client):
    """Verify ble default set local name length 16-bytes"""

    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    try:
        set_local_name = "ble_123456789012"
        logger().info(f"Setting BLE local name {set_local_name}")
        time.sleep(3)
        wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
        status = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"Getting the local name : {status}")
        assert set_local_name == status, "Set local name and get local name not matched "
        bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info("Advertising DUT with the name ble_123456789012 ")
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_advertising_data="ble_123456789012")
        if power_save:
            enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            assert enable_wifi_ps, 'failed to enable wlan power save'
            enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                         psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps, 'failed to enable bt power save'
        logger().info("Initiating scan from remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None, "Unable to fetch BD address from Remote BLE device"
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


@pytest.mark.config(
    "wifi_dut",
    wifi={"oper_mode": 0, "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE},
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_wifi_sdk_set_localname_configured_with_17bytes_C71442(wifi_dut):
    """ Verify ble set local name configured with 17 bytes """
    try:
        with pytest.raises(WlanError) as exc_info:
            logger().info("Setting BLE local name A2345678901234567 of 17 bytes")
            time.sleep(3)
            wifi_dut.interfaces.wifi.bt_set_local_name("A2345678901234567")
        assert exc_info.value.error_code == 0x4E66, "Observed wrong error code.expected is 0x4E66"
    except Exception as e:
        logger().info(f"\n****** Testcase failed with {e}******")
        raise e