import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
import time
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9117)
        2. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiates ble in DUT 
        4. Connect to the remote device/connect to the dut

    Author: Jyothi Nagireddy
"""


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan"])
def test_ble_sdk_dual_role_SI160ms_SW50ms_AImin160ms_AImax320ms_c19911(ble_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 160ms and Advertising maximum interval 320ms
       2.verify ble master connection with scan interval 160ms and scan window 50ms"""
    try:
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"
        logger().info(" ======= start adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(5)
        enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps, result = ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        time.sleep(5)
        logger().info(" ======= start ble scan in remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"Check the dut is listed...{found_devices}")
        assert ble_dut.interfaces.bluetooth.ble_address in found_devices
        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(wifi_dut=ble_dut, ble_client=ble_client,
                                                    ble_address=bt_dut_address, timeout=120)
        time.sleep(2)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)
        ble_dut.interfaces.bluetooth.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan"])
def test_ble_sdk_dual_role_SI500ms_SW400ms_AImin200ms_AImax200ms_c19912(ble_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 200ms and Advertising maximum interval 200ms
          2.verify ble master connection with scan interval 500ms and scan window 400ms"""
    try:
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"

        logger().info(" ======= start adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(5)
        enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps, result = ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        time.sleep(5)
        logger().info(" ======= start ble scan in remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()

        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"Check the dut is listed...{found_devices}")
        assert ble_dut.interfaces.bluetooth.ble_address in found_devices

        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(wifi_dut=ble_dut, ble_client=ble_client,
                                                    ble_address=bt_dut_address,
                                                    ble_scan_interval=int(500 / 0.625),
                                                    ble_scan_window=int(400 / 0.625),
                                                    timeout=120)

        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan"])
def test_ble_sdk_dual_role_SI500ms_SW400ms_AImin200ms_AImax200ms_c19912(ble_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 200ms and Advertising maximum interval 200ms
       2.verify ble master connection with scan interval 500ms and scan window 400ms"""
    try:
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"

        logger().info(" ======= start adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=int(200 / 0.625),
                                                           ble_adv_int_max=int(200 / 0.625))
        time.sleep(5)
        enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps, result = ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        time.sleep(5)
        logger().info(" ======= start ble scan in remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()

        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"Check the dut is listed...{found_devices}")
        assert ble_dut.interfaces.bluetooth.ble_address in found_devices

        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(wifi_dut=ble_dut, ble_client=ble_client,
                                                    ble_address=bt_dut_address,
                                                    ble_scan_interval=int(500 / 0.625),
                                                    ble_scan_window=int(400 / 0.625),
                                                    timeout=120)

        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.OpenMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan"])
def test_ble_sdk_dual_role_SI1000ms_SW500ms_AImin500ms_AImax500ms_c19913(ble_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 500ms and Advertising maximum interval 500ms
          2.verify ble master connection with scan interval 1000ms and scan window 500ms"""
    try:
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"

        logger().info(" ======= start adv in dut")

        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=int(500 / 0.625),
                                                           ble_adv_int_max=int(500 / 0.625), timeout=30)
        time.sleep(5)

        enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps, result = ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        time.sleep(5)
        logger().info(" ======= start ble scan in remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()

        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"Check the dut is listed...{found_devices}")
        assert ble_dut.interfaces.bluetooth.ble_address in found_devices

        ble_client.interfaces.bluetooth.close()
        logger().info(" ======= start adv in remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"
                                                                                        # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device"
        logger().info("ble client address of remote device is {bt_client_address}")

        logger().info(" ======= start ble scan in dut")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                        ble_scan_interval=int(1000 / 0.625),
                                                        ble_scan_window=int(500 / 0.625), timeout=120)
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan"])
def test_ble_dual_role_SI5000ms_SW3000ms_AImin1000ms_AImax1000ms_c19914(ble_dut, ble_client, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 1000ms and Advertising maximum interval 1000ms
          2.verify ble master connection with scan interval 5000ms and scan window 3000ms"""
    try:
        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"

        logger().info(" ======= start adv in dut")

        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=int(1000 / 0.625),
                                                           ble_adv_int_max=int(1000 / 0.625), timeout=30)
        time.sleep(5)
        time.sleep(5)

        enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps, result = ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'

        time.sleep(5)
        logger().info(" ======= start ble scan in remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address, "failed to initiate ble in remote device"
        time.sleep(5)
        logger().info("stop scanning ....")
        ble_client.interfaces.bluetooth.stop_scanning()

        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"Check the dut is listed...{found_devices}")
        assert ble_dut.interfaces.bluetooth.ble_address in found_devices

        ble_client.interfaces.bluetooth.close()

        logger().info(" ======= start adv in remote device")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(bt_dut_address=bt_dut_address,
                                                                                        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                                                                                                       "0x40 0x00 "  # Advertising_Interval_Max
                                                                                                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                                                                                       "0x00 "  # Own_Address_Type
                                                                                                       "0x00 "  # Peer_Address_Type
                                                                                                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                                                                                       "0x07 "  # Advertising_Channel_Map
                                                                                                       "0x00"
                                                                                        # Advertising_Filter_Policy
                                                                                        )
        assert bt_client_address, f"ble initialization failed in remote device"
        logger().info("ble client address of remote device is {bt_client_address}")

        logger().info(" ======= start ble scan in dut")
        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address,
                                                        ble_scan_interval=int(5000 / 0.625),
                                                        ble_scan_window=int(3000 / 0.625), timeout=120)
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(5)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv", "ble_stop_scan"])
def test_ble_sdk_dual_role_SI10240ms_SW5s_AImin10240ms_AImax10240ms_c19915(ble_dut, ble_clients, sl_collections):
    """1.verify ble slave connection with Advertising minimum interval 10240ms and Advertising maximum interval 10240ms
          2.verify ble master connection with scan interval 240ms and scan window 5000ms"""
    try:
        remote_le_devices = 2
        assert len(ble_clients) >= remote_le_devices

        ble_advertisers = []
        for item in range(0, 2):
            ble_advertisers.append(ble_clients[item])

        logger().info("start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "ble initialization failed in dut"
        count = 0
        for ble_client in ble_advertisers:
            count = count + 1
            sl_collections.check_ble_scan_functionality(wifi_dut=ble_dut, ble_client=ble_client,
                                                        ble_address=bt_dut_address,
                                                        ble_scan_interval=int(10240 / 0.625),
                                                        ble_scan_window=int(5000 / 0.625),
                                                        timeout=120)
            time.sleep(5)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)
            ble_client.interfaces.bluetooth.close()
        time.sleep(5)

        ble_dut.interfaces.bluetooth.ble_start_advertising(ble_adv_int_min=int(10240 / 0.625),
                                                           ble_adv_int_max=int(10240 / 0.625), timeout=30)
        time.sleep(5)

        logger().info(f"start ble scan in remote device{count}")
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address, f"ble initialization failed in remote device {count}"
        logger().info(f"ble client address {bt_client_address} of remote device {count}")
        time.sleep(2)

        enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        assert enable_wifi_ps == 0, 'failed to enable wlan power save'
        enable_bt_ps, result = ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps == 0, 'failed to enable bt power save'
        time.sleep(5)
        logger().info(f"checking, dut found in scan list of remote device {count}")
        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"BLE found devices {found_devices} and '{bt_dut_address}'")
            if bt_dut_address in found_devices and \
                    found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
                device_found = True
            break

        ble_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "dut is not found in scan list"

        ble_dut.interfaces.bluetooth.ble_stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_advertising()
        time.sleep(5)
        ble_client.interfaces.bluetooth.close()

    except Exception as error:
        sl_collections.exception_handling(ble_dut, error)



