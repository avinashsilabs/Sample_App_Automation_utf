import pytest
from utf_wiseconnect_3.tests.devices.si91x  import Si91xCoexMode, Si91xPowerSaveModes,Si91xFeatureBitMap,Si91xConfigFeatureBitMap,Si91xTCPIPFeatureBitMap,\
    Si91xExtTCPIPFeatureBitMap,Si91xExtCustomFeatureBitMap,Si91xCustomFeatureBitMap,Si91xPowerSaveProcedureTypes,\
Si91xBTFeatureBitMap,Si91xBLEFeatureBitMap,Si91xBLECustomFeatureBitMap
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
import time
import re
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers


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

    Author: M.Harshitha & Jyothi Nagireddy
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


@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_scan", "wifi_powersave_disable", "bt_powersave_disable"])
def test_enable_and_disable_whitelist_for_100_iterations_c19955(wifi_dut, ble_clients):
        assert len(ble_clients) >= 2, f"minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[1]
        ble_client2 = ble_clients[0]
        index = 5
        try:
            for i in range(0, 20):
                logger().info(f"iterable count : {i}")
                logger().info(f"\n\n**************Start DUT**************\n\n")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address is not None
                ble_client1.interfaces.bluetooth.close()
                logger().info(f"\n\n************Start ble client******************\n\n")
                bt_client_address1 = ble_client1.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
                    bt_dut_address=bt_dut_address,
                    hci_whitelist_adv_data="0x1F "  # Number of bytes that follow in the advertisement(payload length)
                                           "0x00 0x00 0x00 0x00 0x00 "  # prepend 00s at start, based on whitelist data index(5 here)
                                           "0x41, 0x55, 0x54, 0x4F, 0x4D, 0x41 "  # whitelist data
                                           "0x54, 0x49, 0x4F, 0x4E, 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
                    # append 00s at end, based on length of payload
                    hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                                   "0x20 0x00 "  # Advertising_Interval_Max
                                   "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                   "0x00 "  # Own_Address_Type
                                   "0x00 "  # Peer_Address_Type
                                   "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                   "0x07 "  # Advertising_Channel_Map
                                   "0x00"  # Advertising_Filter_Policy

                )
                time.sleep(5)
                ble_client2.interfaces.bluetooth.close()
                bt_client_address2 = ble_client2.interfaces.bluetooth.start_smp_adv_whitelist_with_hci_tool(
                    bt_dut_address=bt_dut_address,
                    # append 00s at end, based on length of payload
                    hci_adv_params="0x20 0x00 "  # Advertising_Interval_Min
                                   "0x20 0x00 "  # Advertising_Interval_Max
                                   "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                                   "0x00 "  # Own_Address_Type
                                   "0x00 "  # Peer_Address_Type
                                   "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                                   "0x07 "  # Advertising_Channel_Map
                                   "0x00"  # Advertising_Filter_Policy

                )
                time.sleep(5)
                wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=1, data_compare_index=5,
                                                                    compare_data_length=10,
                                                                    data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I',
                                                                               'O',
                                                                               'N'])
                logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
                wifi_dut.interfaces.wifi.ble_start_scanning(timeout=30)
                enable_wifi_ps = wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                assert enable_wifi_ps == 0, 'failed to enable wlan power save'
                enable_bt_ps = wifi_dut.interfaces.wifi.enable_bt_power_save(
                    psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                    psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps == 0, 'failed to enable bt power save'
                time.sleep(20)
                wifi_dut.interfaces.wifi.set_performance_profile(mode='high_performance')
                wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveDisabled,
                                          psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
                wifi_dut.interfaces.wifi.ble_stop_scanning()
                for count in range(0, 2):
                    try:
                        events = wifi_dut.interfaces.wifi.get_async_events()
                        whitelist_string = ""
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                                if "rsi_ble_simple_central_on_adv_report_event" and "adv_data:" in event.event_data:
                                    if bt_client_address1 in event.event_data:
                                            adv_data_list = re.findall(r"adv_data:[\d-]*", event.event_data)
                                            for adv_data in adv_data_list:
                                                data = adv_data.split('adv_data:')
                                                data1 = data[1].split('-')
                                                compare_data = data1[::-1]
                                                adv_data_list1 = list(reversed(compare_data[1:]))
                                                for data in adv_data_list1:
                                                    if data != '0':
                                                        data1 = int(data, base=10)
                                                        ascii_value = chr(data1)
                                                        whitelist_string = whitelist_string + ascii_value
                                                for i in range(len(adv_data_list1)):
                                                    d = chr(int(adv_data_list1[i]))
                                                    if d.isalpha():
                                                        index = i
                                                        logger().info(
                                                            f"*********index found in scan results : {index} ***************")
                                                        break
                                                assert whitelist_string == "AUTOMATION", "whitelist data not found"
                                                logger().info(
                                                    f" Whitelist advertising data is matching..found whitelist data : {whitelist_string}")
                                                assert index == 5, "index is not matched"
                                                logger().info(f"index is matching")
                                                logger().info(
                                                    f"***********found the ble client addresses: {bt_client_address1}")
                    except Exception:
                        logger().info(
                            f"\n\n **** ble connection Failed....retrying for the {count + 1} iteration ****\n\n")
                logger().info(f"******************************************")
                wifi_dut.interfaces.wifi.ble_add_whitelist_adv_data(enable=0, data_compare_index=5,
                                                                    compare_data_length=10,
                                                                    data_list=['A', 'U', 'T', 'O', 'M', 'A', 'T', 'I',
                                                                               'O',
                                                                               'N'])
                logger().info(f" \n\n******************* START SCANNING FROM DUT ***********************\n\n ")
                wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address2, timeout=30)
                time.sleep(20)
                wifi_dut.interfaces.wifi.ble_stop_scanning(timeout=10)
                whitelist_found = False
                Non_whitelist_found = False
                sw = Stopwatch()
                while sw.elapsed_sec <= 180:
                    events = wifi_dut.interfaces.wifi.get_async_events()
                    for event in events:
                        if event.event_type == AsyncEventIdentifiers.ADVERTISE:
                            scan_results = event.event_data
                            if bt_client_address2 in scan_results:
                                whitelist_found = True
                            if not(bt_client_address2) in scan_results:
                                Non_whitelist_found = True
                assert whitelist_found, f"unable to find  whitelist device in scan results"
                assert Non_whitelist_found, f"unable to find  Non whitelist in scan results"
                logger().info(f"found the whitelist and non whitelist devices")
                logger().info(f"\n\n************iteration: {i + 1}*****************\n\n")

        except Exception as e:
            logger().info(f"\n******Testcase failed with : {e}******")
            raise e

        finally:
            ble_client1.interfaces.bluetooth.close()
            ble_client2.interfaces.bluetooth.close()
            time.sleep(5)
