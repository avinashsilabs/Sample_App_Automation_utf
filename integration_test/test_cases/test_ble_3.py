import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from random import randint


def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
    },
)
def test_ble_master_rx_230_bytes_C19921(ble_dut, ble_client, sl_collections, wifi_dut):
    bt_mon_log_file_name = (f"reports/test_ble_master_rx_230_bytes_C19921"
                            f"{int(time.time())}.log")

    svc = 'HealthThermometerService'
    charc = 'CustomNotifyCharacteristic'
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):

            logger().info("******************** initializing ble in dut ********************")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
            assert bt_dut_address, "failed to initialize ble in dut"

            logger().info("******************** initializing ble in remote device ********************")
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                              service_classes=[svc])
            assert bt_client_address, "failed to initialize ble in remote device"

            logger().info("******************** start scanning in dut ********************")
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=100)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            timeout = 30
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                                     expected="RSI_BLE_SECURITY_KEYS_EVENT")

            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

            logger().info(f"******************** get all profiles ********************")
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
            assert HealthThermometerService.UUID.lower() in uuids is not None, "Could not fetch the heart rate profile"

            logger().info(" ******************** Resolving Profile ********************")
            start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
                ble_remote_dev_address=bt_client_address, uuid=int(HealthThermometerService.UUID, 16))
            assert start_handle is not None, "failed to fetch the start handle.."
            assert end_handle is not None, "failed to fetch end handle.."

            char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
                ble_remote_dev_address=bt_client_address,
                start_handle=int(start_handle, 16),
                end_handle=int(end_handle, 16),
                async_timeout=60)
            logger().info(
                f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
                f"{char_properties}")

            assert CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID in char_uuids, "Unable to find {} uuid".format(
                CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
            index = char_uuids.index(CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
            logger().info(f"UUID's are:{char_uuids}")
            logger().info(f"write_handles:{write_handles}")
            logger().info(f"index:{index}")
            assert char_properties[index].isdigit(), "Character property found is not an integer"
            assert CustomNotifyCharacteristic.prop_int == int(
                char_properties[index]), "Invalid character property found"

            write_handle = int(write_handles[index], 16)
            logger().info(f"write_handle:{write_handle}")
            assert write_handle > 0, "Unable to get write handle for configured service"

            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                           handle=(write_handle + 1), enable_notify=1)
            time.sleep(1)

            data = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data)

            time.sleep(1)

            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=bt_client_address,
                                                           handle=(write_handle + 1), enable_notify=0)

            found = False
            events = wifi_dut.interfaces.wifi.get_async_events()
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"BLE EVENT DATA IS : {event.event_data}")
                    if data in event.event_data:
                        found = True
            assert found
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()