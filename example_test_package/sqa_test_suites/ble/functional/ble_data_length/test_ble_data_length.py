import time
import pytest
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116AsyncEventType, RS9116PowerSaveModes, \
    RS9116ExtTCPIPFeatureBitMap, \
    RS9116PowerSaveProcedureTypes, RS9116FeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116ExtCustomFeatureBitMap, RS9116ConfigFeatureBitMap
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService, \
    HeartRateControlPointCharacteristic, HeartRateMeasurementCharacterstic
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import (
    HealthThermometerService,
    CustomNotifyCharacteristic,
)
import re
import string
import random

def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates ble in DUT 
        3. Connect to the remote device
        4. configure the dut with the gatt services
        5. Notify the data with gatt notify api
        6. Validate the notified data in remote device 

    Author: RaviNemali
"""

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
@pytest.mark.test_src_map_id('C19922')
def test_ble_slave_data_length_100_bytes_tx_rx_C19922(ble_dut, ble_client, utf_constants):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_100_bytes_tx_rx_C19922.log"):
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            logger().info("======= start ble in dut")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "failed to initialize ble in dut"
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1AA1)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x1BB1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x1BB1)

            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("======= enable power save")
            ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
            ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
            iter_count = utf_constants.get("iter_count")
            for i in range(1, iter_count):
                logger().info(f"======= spinning the case for count of {i}")
                time.sleep(0.2)
                logger().info("======= start scanning in remote ble device")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
                assert bt_client_address, "failed to start scan in remote device"

                device_found = False
                sw = Stopwatch()
                while sw.elapsed_sec < 30:
                    found_devices = ble_client.interfaces.bluetooth.get_devices()
                    if bt_dut_address in found_devices and \
                            found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
                        device_found = True
                        break

                ble_client.interfaces.bluetooth.stop_scanning()
                assert device_found, "no device found"

                logger().info("======= connect to ble dut")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                        min_conn_interval=int(int(80) / 1.25),
                                                        max_conn_interval=int(int(80) / 1.25),
                                                        conn_latency=0,
                                                        supervision_timeout=800)
                time.sleep(1)

                logger().info("======= get connection state")
                state = ble_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                            service_uid=service_uid,
                                                                                                            char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"
                try:
                    read_charac_value = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
                    logger().info(f"read_charac_value = {read_charac_value}")
                except Exception as e:
                    if read_charac_value != "data":
                        logger().warning(f"read_charac_value command failed:{e},\nTrying for 2nd time")
                        ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                # subscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)
                sw = Stopwatch()
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                while sw.elapsed_sec < 60:
                    ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
                    time.sleep(5)

                sw = Stopwatch()
                data1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                while sw.elapsed_sec < 60:
                    try:
                        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data1)
                        time.sleep(1)
                    except Exception as e:
                        logger().warning(f"Exception: {e}")
                        raise e
                result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
                assert result == data1, "failed to read value"

                # unsubscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("======= validate data")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(notifications)
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("======= disconnecting from dut")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()
                time.sleep(0.2)
                logger().info("======= start ble adv in dut")
                ble_dut.interfaces.bluetooth.ble_start_advertising()
    finally:
        logger().info("ble_remove_service")
        ble_dut.interfaces.wifi.ble_remove_service()
        logger().info("======= stop ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_stop_advertising()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
@pytest.mark.test_src_map_id('C19920')
def test_ble_slave_data_length_20_bytes_C19920(ble_dut, ble_client, utf_constants):
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path="./reports/test_ble_slave_data_length_20_bytes_C19920.log"):
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            logger().info("======= start ble in dut")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "failed to initialize ble in dut"
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1AA1)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x1BB1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x1BB1)

            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("======= enable power save")
            ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
            ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)

            iter_count = utf_constants.get("iter_count")
            for i in range(1, iter_count):
                logger().info(f"======= spinning the case for count of {i}")

                logger().info("======= start scanning in remote ble device")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
                assert bt_client_address, "failed to start scan in remote device"

                device_found = False
                sw = Stopwatch()
                while sw.elapsed_sec < 30:
                    found_devices = ble_client.interfaces.bluetooth.get_devices()
                    if bt_dut_address in found_devices and \
                            found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
                        device_found = True
                        break

                ble_client.interfaces.bluetooth.stop_scanning()
                assert device_found, "no device found"

                logger().info("======= connect to ble dut")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                        min_conn_interval=int(int(80) / 1.25),
                                                        max_conn_interval=int(int(80) / 1.25),
                                                        conn_latency=0,
                                                        supervision_timeout=800)
                time.sleep(1)

                logger().info("======= get connection state")
                state = ble_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                            service_uid=service_uid,
                                                                                                            char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                # subscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)
                sw = Stopwatch()
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                while sw.elapsed_sec < 60:
                    ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
                    time.sleep(5)

                # unsubscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("======= validate data")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(notifications)
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("======= disconnecting from dut")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()
                time.sleep(0.2)
                logger().info("======= start ble adv in dut")
                ble_dut.interfaces.bluetooth.ble_start_advertising()
    finally:
        logger().info("ble_remove_service")
        ble_dut.interfaces.wifi.ble_remove_service()
        logger().info("======= stop ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_stop_advertising()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
@pytest.mark.test_src_map_id('C19923')
def test_ble_slave_data_length_230_bytes_tx_C19923(ble_dut, ble_client, utf_constants):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_230_bytes_tx_C19923.log"):
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            logger().info("======= start ble in dut")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "failed to initialize ble in dut"
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1AA1)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x1BB1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x1BB1)

            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("======= enable power save")
            ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
            ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
            iter_count = utf_constants.get("iter_count")
            for i in range(1, iter_count):
                logger().info(f"======= spinning the case for count of {i}")
                logger().info("======= start scanning in remote ble device")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
                assert bt_client_address, "failed to start scan in remote device"

                device_found = False
                sw = Stopwatch()
                while sw.elapsed_sec < 30:
                    found_devices = ble_client.interfaces.bluetooth.get_devices()
                    if bt_dut_address in found_devices and \
                            found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
                        device_found = True
                        break

                ble_client.interfaces.bluetooth.stop_scanning()
                assert device_found, "no device found"

                logger().info("======= connect to ble dut")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                        min_conn_interval=int(int(80) / 1.25),
                                                        max_conn_interval=int(int(80) / 1.25),
                                                        conn_latency=0,
                                                        supervision_timeout=800)
                time.sleep(5)

                logger().info("======= get connection state")
                state = ble_dut.interfaces.bluetooth.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                            service_uid=service_uid,
                                                                                                            char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                # subscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)
                sw = Stopwatch()
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                while sw.elapsed_sec < 60:
                    ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
                    time.sleep(5)

                # unsubscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("======= validate data")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(notifications)
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("======= disconnecting from dut")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()
                time.sleep(0.2)
                logger().info("======= start ble adv in dut")
                ble_dut.interfaces.bluetooth.ble_start_advertising()
    finally:
        logger().info("ble_remove_service")
        ble_dut.interfaces.wifi.ble_remove_service()
        logger().info("======= stop ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_stop_advertising()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
@pytest.mark.test_src_map_id('C19926')
def test_ble_slave_data_length_20_bytes_duty_cycle_C19926(ble_dut, ble_client, utf_constants):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_20_bytes_duty_cycle_C19926.log"):
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            logger().info("======= start ble in dut")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "failed to initialize ble in dut"
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1AA1)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x1BB1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x1BB1)

            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("======= enable power save")
            ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
            ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)

            iter_count = utf_constants.get("iter_count")
            for i in range(1, iter_count):
                logger().info(f"======= spinning the case for count of {i}")
                logger().info("======= start scanning in remote ble device")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
                assert bt_client_address, "failed to start scan in remote device"

                device_found = False
                sw = Stopwatch()
                while sw.elapsed_sec < 30:
                    found_devices = ble_client.interfaces.bluetooth.get_devices()
                    if bt_dut_address in found_devices and \
                            found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
                        device_found = True
                        break

                ble_client.interfaces.bluetooth.stop_scanning()
                assert device_found, "no device found"

                logger().info("======= connect to ble dut")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                        min_conn_interval=int(int(80) / 1.25),
                                                        max_conn_interval=int(int(80) / 1.25),
                                                        conn_latency=0,
                                                        supervision_timeout=800)
                time.sleep(1)

                logger().info("======= get connection state")
                state = ble_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=servs, service_uid=service_uid, char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                try:
                    read_charac_value = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
                    logger().info(f"read_charac_value = {read_charac_value}")
                except Exception as e:
                    if read_charac_value != "data":
                        logger().warning(f"read_charac_value command failed:{e},\nTrying for 2nd time")
                        ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                # subscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)
                sw = Stopwatch()
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                while sw.elapsed_sec < 60:
                    ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
                    time.sleep(5)

                # unsubscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("======= validate data")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(notifications)
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("======= disconnecting from dut")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()
                time.sleep(0.2)
                logger().info("======= start ble adv in dut")
                ble_dut.interfaces.bluetooth.ble_start_advertising()
    finally:
        logger().info("ble_remove_service")
        ble_dut.interfaces.wifi.ble_remove_service()
        logger().info("======= stop ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_stop_advertising()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
@pytest.mark.test_src_map_id('C19929')
def test_ble_slave_data_length_230_bytes_duty_cycle_C19929(ble_dut, ble_client, utf_constants):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_230_bytes_duty_cycle_C19929.log"):
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            logger().info("======= start ble in dut")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "failed to initialize ble in dut"
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1AA1)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x1BB1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x1BB1)

            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("======= enable power save")
            ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
            ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)

            iter_count = utf_constants.get("iter_count")
            for i in range(1, iter_count):
                logger().info(f"======= spinning the case for count of {i}")

                logger().info("======= start scanning in remote ble device")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
                assert bt_client_address, "failed to start scan in remote device"

                device_found = False
                sw = Stopwatch()
                while sw.elapsed_sec < 30:
                    found_devices = ble_client.interfaces.bluetooth.get_devices()
                    if bt_dut_address in found_devices and \
                            found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
                        device_found = True
                        break

                ble_client.interfaces.bluetooth.stop_scanning()
                assert device_found, "no device found"

                logger().info("======= connect to ble dut")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                        min_conn_interval=int(int(80) / 1.25),
                                                        max_conn_interval=int(int(80) / 1.25),
                                                        conn_latency=0,
                                                        supervision_timeout=800)
                time.sleep(1)

                logger().info("======= get connection state")
                state = ble_dut.interfaces.bluetooth.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                            service_uid=service_uid,
                                                                                                            char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                # subscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)
                sw = Stopwatch()
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                while sw.elapsed_sec < 60:
                    ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
                    time.sleep(5)

                # unsubscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("======= validate data")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(notifications)
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("======= disconnecting from dut")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()
                time.sleep(0.2)
                logger().info("======= start ble adv in dut")
                ble_dut.interfaces.bluetooth.ble_start_advertising()
    finally:
        logger().info("ble_remove_service")
        ble_dut.interfaces.wifi.ble_remove_service()
        logger().info("======= stop ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_stop_advertising()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "ble_stop_adv"])
@pytest.mark.test_src_map_id('C19928')
def test_ble_slave_data_length_100_bytes_tx_rx_C19928(ble_dut, ble_client, utf_constants):
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_100_bytes_tx_rx_C19928.log"):
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

            logger().info("======= start ble in dut")
            bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
            assert bt_dut_address, "failed to initialize ble in dut"
            ble_dut.interfaces.bluetooth.ble_add_service(uid=0x1AA1)
            ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x1BB1)
            ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x1BB1)

            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()

            logger().info("======= enable power save")
            ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
            ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)

            iter_count = utf_constants.get("iter_count")
            for i in range(1, iter_count):
                logger().info(f"======= spinning the case for count of {i}")

                logger().info("======= start scanning in remote ble device")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
                assert bt_client_address, "failed to start scan in remote device"

                device_found = False
                sw = Stopwatch()
                while sw.elapsed_sec < 30:
                    found_devices = ble_client.interfaces.bluetooth.get_devices()
                    if bt_dut_address in found_devices and \
                            found_devices[bt_dut_address] == ble_dut.interfaces.bluetooth.ble_advertising_data:
                        device_found = True
                        break

                ble_client.interfaces.bluetooth.stop_scanning()
                assert device_found, "no device found"

                logger().info("======= connect to ble dut")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                                        min_conn_interval=int(int(80) / 1.25),
                                                        max_conn_interval=int(int(80) / 1.25),
                                                        conn_latency=0,
                                                        supervision_timeout=800)
                time.sleep(1)

                logger().info("======= get connection state")
                state = ble_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "======= device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                            service_uid=service_uid,
                                                                                                            char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                # subscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
                                                                                        char_uid=char_uid)

                sw = Stopwatch()
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                while sw.elapsed_sec < 60:
                    ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
                    time.sleep(5)

                sw = Stopwatch()
                data1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                while sw.elapsed_sec < 60:
                    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data1)
                    time.sleep(2)

                result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
                assert result == data1, "failed to read data"
                # unsubscribe to notifications
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("======= validate data")
                notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                logger().info(notifications)
                assert len(notifications) > 0, "received data is empty"
                assert notifications[0] == data, "failed to fetch data"

                logger().info("======= disconnecting from dut")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()
                time.sleep(0.2)
                logger().info("======= start ble adv in dut")
                ble_dut.interfaces.bluetooth.ble_start_advertising()
    finally:
        logger().info("ble_remove_service")
        ble_dut.interfaces.wifi.ble_remove_service()
        logger().info("======= stop ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_stop_advertising()


# ======= Data length Master Test cases
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.test_src_map_id('C19921')
def test_ble_master_rx_230_bytes_C19921(firmware_loader, ble_dut, ble_client, utf_constants):
    data = "hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarx"
    NOTIFY_DURATION_SEC = 60
    ITERATIONS = utf_constants.get("iter_count")
    NOTIFY_PAYLOAD_STR = data
    EXPECTED_PAYLOAD = NOTIFY_PAYLOAD_STR.encode("ascii")
    EXPECTED_LEN = len(EXPECTED_PAYLOAD)
    NOTIFY_SEND_INTERVAL_SEC = 1.0
    HTS_UUID = HealthThermometerService.UUID.lower()
    CUSTOM_NOTIFY_UUID = CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID.lower()
    HTS_SERVICE_CLASS_NAME = "HealthThermometerService"
    HTS_CUSTOM_NOTIFY_CLASS_NAME = "CustomNotifyCharacteristic"
    ATT_HEX_RX = re.compile(rb"att_hex\s*-\s*([0-9a-fA-F]+)")

    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
    assert bt_dut_address, "failed to initialize ble in dut"

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=bt_dut_address,
        service_classes=["HeartRateService", "HealthThermometerService"],
        register_agent=False,
    )
    assert bt_client_address, "failed to initialize ble in remote device"

    try:
        ble_dut.interfaces.bluetooth.bt_power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        ble_dut.interfaces.bluetooth.power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
    except Exception as ps_err:
        logger().info(f"power_save setup raised (non-fatal): {ps_err}")

    connect_kwargs = dict(
        ble_remote_dev_address=bt_client_address,
        ble_scan_interval=64,
        ble_scan_window=48,
        ble_conn_interval_min=24,
        ble_conn_interval_max=40,
        ble_conn_latency=0,
        ble_supervision_timeout=400,
        ble_privacy_enable=0,
        expected="RSI_BLE_ENHC_CONN_EVENT",
        timeout=120,
    )

    def safe_disconnect():
        try:
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
        except Exception as disc_err:
            logger().info(f"cleanup ble_disconnect raised (expected if already disconnected): {disc_err}")

    def _read_state():
        s = ble_dut.interfaces.bluetooth.ble_get_device_state()
        return s, (int(s) if s.isdigit() else -1)

    def _establish_stable_link():
        last_state = None
        state_int = -1
        for attempt in range(1, 4):
            logger().info(f"BLE connect attempt {attempt}/3 with params={connect_kwargs}")
            try:
                ble_dut.interfaces.bluetooth.ble_connect(**connect_kwargs)
            except Exception as connect_err:
                logger().info(f"ble_connect raised on attempt {attempt}: {connect_err}")
            sw = Stopwatch()
            while sw.elapsed_sec < 5:
                last_state, state_int = _read_state()
                if state_int == BLEDeviceState.Connected:
                    break
                time.sleep(0.5)
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: did not reach Connected within 5s "
                    f"(last={last_state}); retrying"
                )
                safe_disconnect()
                time.sleep(3)
                continue
            settle_sw = Stopwatch()
            while settle_sw.elapsed_sec < 20:
                time.sleep(1)
                last_state, state_int = _read_state()
                if state_int != BLEDeviceState.Connected:
                    break
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: link dropped during 20s settle "
                    f"(state={last_state}); retrying"
                )
                safe_disconnect()
                time.sleep(3)
                continue
            logger().info(f"BLE link stable after attempt {attempt} (state={last_state})")
            return True, last_state, state_int
        return False, last_state, state_int

    def _find_custom_notify_handle():
        profile_uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(
            ble_remote_dev_address=bt_client_address
        )
        def _norm(u):
            s = str(u).lower().replace("0x", "")
            return "0x" + s.zfill(4)
        normalised = [_norm(u) for u in profile_uuids]
        logger().info(f"discovered profiles (normalised): {normalised}")
        assert HTS_UUID in normalised, (
            f"HealthThermometerService ({HTS_UUID}) not advertised by peer; "
            f"got {normalised}"
        )
        start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HTS_UUID, 16),
        )
        assert start_handle and end_handle, "failed to resolve HealthThermometerService handles"
        char_uuids, value_handles, char_props = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
        )
        char_uuids_norm = [_norm(u) for u in char_uuids]
        logger().info(
            f"HealthThermometerService chars: uuids={char_uuids_norm}, "
            f"handles={value_handles}, props={char_props}"
        )
        assert CUSTOM_NOTIFY_UUID in char_uuids_norm, (
            f"CustomNotifyCharacteristic ({CUSTOM_NOTIFY_UUID}) not present "
            f"inside HealthThermometerService; chars={char_uuids_norm}"
        )
        idx = char_uuids_norm.index(CUSTOM_NOTIFY_UUID)
        # Per BLE spec the property bitmap for notify-only must include 0x10.
        prop_str = str(char_props[idx])
        if prop_str.isdigit():
            assert int(prop_str) & CustomNotifyCharacteristic.prop_int, (
                f"CustomNotifyCharacteristic at index {idx} does not advertise the "
                f"notify property bit; raw char_property={prop_str}"
            )
        value_handle = int(value_handles[idx], 16)
        assert value_handle > 0, "CustomNotifyCharacteristic value handle was empty"
        return value_handle

    iteration_results = []
    try:
        for iteration in range(1, ITERATIONS + 1):
            logger().info(f"[iter {iteration}] start scanning in DUT")
            ble_dut.interfaces.bluetooth.ble_start_scanning(
                ble_client_address=bt_client_address, timeout=60
            )
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)

            # Step 7: connect with retry/settle.
            link_stable, last_state, state_int = _establish_stable_link()
            assert link_stable and state_int == BLEDeviceState.Connected, (
                f"[iter {iteration}] DUT not Connected after 3 attempts, "
                f"last state={last_state}"
            )

            try:
                try:
                    ble_dut.interfaces.bluetooth.ble_set_data_length(
                        ble_remote_dev_address=bt_client_address,
                        tx_len=251,
                        tx_time=2120,
                    )
                except Exception as dle_err:
                    logger().info(f"[iter {iteration}] set_data_length best-effort: {dle_err}")
                value_handle = _find_custom_notify_handle()
                since_time = time.perf_counter_ns()
                ble_dut.interfaces.bluetooth.ble_set_att_int_value_async(
                    ble_remote_dev_address=bt_client_address,
                    char_property=(value_handle + 1),
                    value=1,
                )
                time.sleep(0.5)
                send_count = 0
                verified_payload_count = 0
                last_send_mono = -float("inf")
                rx_sw = Stopwatch()
                while rx_sw.elapsed_sec < NOTIFY_DURATION_SEC:
                    now_mono = time.monotonic()
                    if (now_mono - last_send_mono) >= NOTIFY_SEND_INTERVAL_SEC:
                        ble_client.interfaces.bluetooth.send_gatt_charc_notification(
                            HTS_SERVICE_CLASS_NAME,
                            HTS_CUSTOM_NOTIFY_CLASS_NAME,
                            NOTIFY_PAYLOAD_STR,
                        )
                        send_count += 1
                        last_send_mono = now_mono

                    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
                    if events:
                        since_time = time.perf_counter_ns()
                        for ev in events:
                            if getattr(ev, "event_type", None) != RS9116AsyncEventType.GATT_WRITE_EVENT:
                                continue
                            edata = getattr(ev, "event_data", None)
                            if isinstance(edata, (bytes, bytearray)):
                                edata_b = bytes(edata)
                            else:
                                edata_b = str(edata or "").encode("latin-1", errors="replace")
                            m_hex = ATT_HEX_RX.search(edata_b)
                            if not m_hex:
                                continue
                            payload = bytes.fromhex(m_hex.group(1).decode("ascii"))
                            received_str = payload.decode("ascii", errors="replace")
                            if payload == EXPECTED_PAYLOAD:
                                verified_payload_count += 1
                                if verified_payload_count == 1:
                                    logger().info(
                                        f"[iter {iteration}] first verified "
                                        f"payload decoded: {received_str!r} "
                                        f"(len={len(payload)})"
                                    )
                            else:
                                logger().warning(
                                    f"[iter {iteration}] payload mismatch: "
                                    f"received={received_str!r} (len={len(payload)}), "
                                    f"expected={NOTIFY_PAYLOAD_STR!r} (len={EXPECTED_LEN})"
                                )
                    time.sleep(0.2)

                assert verified_payload_count > 0, (
                    f"[iter {iteration}] DUT did not receive any notification ")
                iteration_results.append(
                    {
                        "iteration": iteration,
                        "sent": send_count,
                        "received_full_payload": verified_payload_count,
                    }
                )
            finally:
                logger().info(f"[step 11][iter {iteration}] disconnecting from peer")
                safe_disconnect()
                time.sleep(3)
    finally:
        logger().info(f"iteration summary: {iteration_results}")
        safe_disconnect()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.test_src_map_id('C19924')
def test_ble_master_rx_100_bytes_C19924(firmware_loader, ble_dut, ble_client, utf_constants):
    data = "hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarx"
    NOTIFY_DURATION_SEC = 60
    ITERATIONS = utf_constants.get("iter_count")
    NOTIFY_PAYLOAD_STR = data
    EXPECTED_PAYLOAD = NOTIFY_PAYLOAD_STR.encode("ascii")
    EXPECTED_LEN = len(EXPECTED_PAYLOAD)
    NOTIFY_SEND_INTERVAL_SEC = 1.0
    HTS_UUID = HealthThermometerService.UUID.lower()
    CUSTOM_NOTIFY_UUID = CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID.lower()
    HTS_SERVICE_CLASS_NAME = "HealthThermometerService"
    HTS_CUSTOM_NOTIFY_CLASS_NAME = "CustomNotifyCharacteristic"
    ATT_HEX_RX = re.compile(rb"att_hex\s*-\s*([0-9a-fA-F]+)")

    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
    assert bt_dut_address, "failed to initialize ble in dut"

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=bt_dut_address,
        service_classes=["HeartRateService", "HealthThermometerService"],
        register_agent=False,
    )
    assert bt_client_address, "failed to initialize ble in remote device"

    try:
        ble_dut.interfaces.bluetooth.bt_power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        ble_dut.interfaces.bluetooth.power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
    except Exception as ps_err:
        logger().info(f"power_save setup raised (non-fatal): {ps_err}")

    connect_kwargs = dict(
        ble_remote_dev_address=bt_client_address,
        ble_scan_interval=64,
        ble_scan_window=48,
        ble_conn_interval_min=24,
        ble_conn_interval_max=40,
        ble_conn_latency=0,
        ble_supervision_timeout=400,
        ble_privacy_enable=0,
        expected="RSI_BLE_ENHC_CONN_EVENT",
        timeout=120,
    )

    def safe_disconnect():
        try:
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
        except Exception as disc_err:
            logger().info(f"cleanup ble_disconnect raised (expected if already disconnected): {disc_err}")

    def _read_state():
        s = ble_dut.interfaces.bluetooth.ble_get_device_state()
        return s, (int(s) if s.isdigit() else -1)

    def _establish_stable_link():
        last_state = None
        state_int = -1
        for attempt in range(1, 4):
            logger().info(f"BLE connect attempt {attempt}/3 with params={connect_kwargs}")
            try:
                ble_dut.interfaces.bluetooth.ble_connect(**connect_kwargs)
            except Exception as connect_err:
                logger().info(f"ble_connect raised on attempt {attempt}: {connect_err}")
            sw = Stopwatch()
            while sw.elapsed_sec < 5:
                last_state, state_int = _read_state()
                if state_int == BLEDeviceState.Connected:
                    break
                time.sleep(0.5)
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: did not reach Connected within 5s "
                    f"(last={last_state}); retrying"
                )
                safe_disconnect()
                time.sleep(3)
                continue
            settle_sw = Stopwatch()
            while settle_sw.elapsed_sec < 20:
                time.sleep(1)
                last_state, state_int = _read_state()
                if state_int != BLEDeviceState.Connected:
                    break
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: link dropped during 20s settle "
                    f"(state={last_state}); retrying"
                )
                safe_disconnect()
                time.sleep(3)
                continue
            logger().info(f"BLE link stable after attempt {attempt} (state={last_state})")
            return True, last_state, state_int
        return False, last_state, state_int

    def _find_custom_notify_handle():
        profile_uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(
            ble_remote_dev_address=bt_client_address
        )
        def _norm(u):
            s = str(u).lower().replace("0x", "")
            return "0x" + s.zfill(4)
        normalised = [_norm(u) for u in profile_uuids]
        logger().info(f"discovered profiles (normalised): {normalised}")
        assert HTS_UUID in normalised, (
            f"HealthThermometerService ({HTS_UUID}) not advertised by peer; "
            f"got {normalised}"
        )
        start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HTS_UUID, 16),
        )
        assert start_handle and end_handle, "failed to resolve HealthThermometerService handles"
        char_uuids, value_handles, char_props = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
        )
        char_uuids_norm = [_norm(u) for u in char_uuids]
        logger().info(
            f"HealthThermometerService chars: uuids={char_uuids_norm}, "
            f"handles={value_handles}, props={char_props}"
        )
        assert CUSTOM_NOTIFY_UUID in char_uuids_norm, (
            f"CustomNotifyCharacteristic ({CUSTOM_NOTIFY_UUID}) not present "
            f"inside HealthThermometerService; chars={char_uuids_norm}"
        )
        idx = char_uuids_norm.index(CUSTOM_NOTIFY_UUID)
        # Per BLE spec the property bitmap for notify-only must include 0x10.
        prop_str = str(char_props[idx])
        if prop_str.isdigit():
            assert int(prop_str) & CustomNotifyCharacteristic.prop_int, (
                f"CustomNotifyCharacteristic at index {idx} does not advertise the "
                f"notify property bit; raw char_property={prop_str}"
            )
        value_handle = int(value_handles[idx], 16)
        assert value_handle > 0, "CustomNotifyCharacteristic value handle was empty"
        return value_handle

    iteration_results = []
    try:
        for iteration in range(1, ITERATIONS + 1):
            logger().info(f"[iter {iteration}] start scanning in DUT")
            ble_dut.interfaces.bluetooth.ble_start_scanning(
                ble_client_address=bt_client_address, timeout=60
            )
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)

            # Step 7: connect with retry/settle.
            link_stable, last_state, state_int = _establish_stable_link()
            assert link_stable and state_int == BLEDeviceState.Connected, (
                f"[iter {iteration}] DUT not Connected after 3 attempts, "
                f"last state={last_state}"
            )

            try:
                try:
                    ble_dut.interfaces.bluetooth.ble_set_data_length(
                        ble_remote_dev_address=bt_client_address,
                        tx_len=251,
                        tx_time=2120,
                    )
                except Exception as dle_err:
                    logger().info(f"[iter {iteration}] set_data_length best-effort: {dle_err}")
                value_handle = _find_custom_notify_handle()
                since_time = time.perf_counter_ns()
                ble_dut.interfaces.bluetooth.ble_set_att_int_value_async(
                    ble_remote_dev_address=bt_client_address,
                    char_property=(value_handle + 1),
                    value=1,
                )
                time.sleep(0.5)
                send_count = 0
                verified_payload_count = 0
                last_send_mono = -float("inf")
                rx_sw = Stopwatch()
                while rx_sw.elapsed_sec < NOTIFY_DURATION_SEC:
                    now_mono = time.monotonic()
                    if (now_mono - last_send_mono) >= NOTIFY_SEND_INTERVAL_SEC:
                        ble_client.interfaces.bluetooth.send_gatt_charc_notification(
                            HTS_SERVICE_CLASS_NAME,
                            HTS_CUSTOM_NOTIFY_CLASS_NAME,
                            NOTIFY_PAYLOAD_STR,
                        )
                        send_count += 1
                        last_send_mono = now_mono

                    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
                    if events:
                        since_time = time.perf_counter_ns()
                        for ev in events:
                            if getattr(ev, "event_type", None) != RS9116AsyncEventType.GATT_WRITE_EVENT:
                                continue
                            edata = getattr(ev, "event_data", None)
                            if isinstance(edata, (bytes, bytearray)):
                                edata_b = bytes(edata)
                            else:
                                edata_b = str(edata or "").encode("latin-1", errors="replace")
                            m_hex = ATT_HEX_RX.search(edata_b)
                            if not m_hex:
                                continue
                            payload = bytes.fromhex(m_hex.group(1).decode("ascii"))
                            received_str = payload.decode("ascii", errors="replace")
                            if payload == EXPECTED_PAYLOAD:
                                verified_payload_count += 1
                                if verified_payload_count == 1:
                                    logger().info(
                                        f"[iter {iteration}] first verified "
                                        f"payload decoded: {received_str!r} "
                                        f"(len={len(payload)})"
                                    )
                            else:
                                logger().warning(
                                    f"[iter {iteration}] payload mismatch: "
                                    f"received={received_str!r} (len={len(payload)}), "
                                    f"expected={NOTIFY_PAYLOAD_STR!r} (len={EXPECTED_LEN})"
                                )
                    time.sleep(0.2)

                assert verified_payload_count > 0, (
                    f"[iter {iteration}] DUT did not receive any notification ")
                iteration_results.append(
                    {
                        "iteration": iteration,
                        "sent": send_count,
                        "received_full_payload": verified_payload_count,
                    }
                )
            finally:
                logger().info(f"[step 11][iter {iteration}] disconnecting from peer")
                safe_disconnect()
                time.sleep(3)
    finally:
        logger().info(f"iteration summary: {iteration_results}")
        safe_disconnect()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.test_src_map_id('C19925')
def test_ble_master_tx_rx_230_bytes_C19925(firmware_loader, ble_dut, ble_client, utf_constants):
    data = "hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarx"
    NOTIFY_DURATION_SEC = 60
    ITERATIONS = utf_constants.get("iter_count")
    NOTIFY_PAYLOAD_STR = data
    EXPECTED_PAYLOAD = NOTIFY_PAYLOAD_STR.encode("ascii")
    EXPECTED_LEN = len(EXPECTED_PAYLOAD)
    NOTIFY_SEND_INTERVAL_SEC = 1.0
    HTS_UUID = HealthThermometerService.UUID.lower()
    CUSTOM_NOTIFY_UUID = CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID.lower()
    HTS_SERVICE_CLASS_NAME = "HealthThermometerService"
    HTS_CUSTOM_NOTIFY_CLASS_NAME = "CustomNotifyCharacteristic"
    ATT_HEX_RX = re.compile(rb"att_hex\s*-\s*([0-9a-fA-F]+)")

    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
    assert bt_dut_address, "failed to initialize ble in dut"

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=bt_dut_address,
        service_classes=["HeartRateService", "HealthThermometerService"],
        register_agent=False,
    )
    assert bt_client_address, "failed to initialize ble in remote device"

    try:
        ble_dut.interfaces.bluetooth.bt_power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        ble_dut.interfaces.bluetooth.power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
    except Exception as ps_err:
        logger().info(f"power_save setup raised (non-fatal): {ps_err}")

    connect_kwargs = dict(
        ble_remote_dev_address=bt_client_address,
        ble_scan_interval=64,
        ble_scan_window=48,
        ble_conn_interval_min=24,
        ble_conn_interval_max=40,
        ble_conn_latency=0,
        ble_supervision_timeout=400,
        ble_privacy_enable=0,
        expected="RSI_BLE_ENHC_CONN_EVENT",
        timeout=120,
    )

    def _safe_disconnect():
        try:
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
        except Exception as disc_err:
            logger().info(f"cleanup ble_disconnect raised (expected if already disconnected): {disc_err}")

    def _read_state():
        s = ble_dut.interfaces.bluetooth.ble_get_device_state()
        return s, (int(s) if s.isdigit() else -1)

    def _establish_stable_link():
        last_state = None
        state_int = -1
        for attempt in range(1, 4):
            logger().info(f"BLE connect attempt {attempt}/3 with params={connect_kwargs}")
            try:
                ble_dut.interfaces.bluetooth.ble_connect(**connect_kwargs)
            except Exception as connect_err:
                logger().info(f"ble_connect raised on attempt {attempt}: {connect_err}")
            sw = Stopwatch()
            while sw.elapsed_sec < 5:
                last_state, state_int = _read_state()
                if state_int == BLEDeviceState.Connected:
                    break
                time.sleep(0.5)
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: did not reach Connected within 5s "
                    f"(last={last_state}); retrying"
                )
                _safe_disconnect()
                time.sleep(3)
                continue
            settle_sw = Stopwatch()
            while settle_sw.elapsed_sec < 20:
                time.sleep(1)
                last_state, state_int = _read_state()
                if state_int != BLEDeviceState.Connected:
                    break
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: link dropped during 20s settle "
                    f"(state={last_state}); retrying"
                )
                _safe_disconnect()
                time.sleep(3)
                continue
            logger().info(f"BLE link stable after attempt {attempt} (state={last_state})")
            return True, last_state, state_int
        return False, last_state, state_int

    def _find_custom_notify_handle():
        profile_uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(
            ble_remote_dev_address=bt_client_address
        )
        def _norm(u):
            s = str(u).lower().replace("0x", "")
            return "0x" + s.zfill(4)
        normalised = [_norm(u) for u in profile_uuids]
        logger().info(f"discovered profiles (normalised): {normalised}")
        assert HTS_UUID in normalised, (
            f"HealthThermometerService ({HTS_UUID}) not advertised by peer; "
            f"got {normalised}"
        )
        start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HTS_UUID, 16),
        )
        assert start_handle and end_handle, "failed to resolve HealthThermometerService handles"
        char_uuids, value_handles, char_props = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
        )
        char_uuids_norm = [_norm(u) for u in char_uuids]
        logger().info(
            f"HealthThermometerService chars: uuids={char_uuids_norm}, "
            f"handles={value_handles}, props={char_props}"
        )
        assert CUSTOM_NOTIFY_UUID in char_uuids_norm, (
            f"CustomNotifyCharacteristic ({CUSTOM_NOTIFY_UUID}) not present "
            f"inside HealthThermometerService; chars={char_uuids_norm}"
        )
        idx = char_uuids_norm.index(CUSTOM_NOTIFY_UUID)
        # Per BLE spec the property bitmap for notify-only must include 0x10.
        prop_str = str(char_props[idx])
        if prop_str.isdigit():
            assert int(prop_str) & CustomNotifyCharacteristic.prop_int, (
                f"CustomNotifyCharacteristic at index {idx} does not advertise the "
                f"notify property bit; raw char_property={prop_str}"
            )
        value_handle = int(value_handles[idx], 16)
        assert value_handle > 0, "CustomNotifyCharacteristic value handle was empty"
        return value_handle

    iteration_results = []
    try:
        for iteration in range(1, ITERATIONS + 1):
            logger().info(f"[iter {iteration}] start scanning in DUT")
            ble_dut.interfaces.bluetooth.ble_start_scanning(
                ble_client_address=bt_client_address, timeout=60
            )
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)

            # Step 7: connect with retry/settle.
            link_stable, last_state, state_int = _establish_stable_link()
            assert link_stable and state_int == BLEDeviceState.Connected, (
                f"[iter {iteration}] DUT not Connected after 3 attempts, "
                f"last state={last_state}"
            )

            try:
                try:
                    ble_dut.interfaces.bluetooth.ble_set_data_length(
                        ble_remote_dev_address=bt_client_address,
                        tx_len=251,
                        tx_time=2120,
                    )
                except Exception as dle_err:
                    logger().info(f"[iter {iteration}] set_data_length best-effort: {dle_err}")
                value_handle = _find_custom_notify_handle()
                since_time = time.perf_counter_ns()
                ble_dut.interfaces.bluetooth.ble_set_att_int_value_async(
                    ble_remote_dev_address=bt_client_address,
                    char_property=(value_handle + 1),
                    value=1,
                )
                time.sleep(0.5)
                send_count = 0
                verified_payload_count = 0
                last_send_mono = -float("inf")
                rx_sw = Stopwatch()
                while rx_sw.elapsed_sec < NOTIFY_DURATION_SEC:
                    now_mono = time.monotonic()
                    if (now_mono - last_send_mono) >= NOTIFY_SEND_INTERVAL_SEC:
                        ble_client.interfaces.bluetooth.send_gatt_charc_notification(
                            HTS_SERVICE_CLASS_NAME,
                            HTS_CUSTOM_NOTIFY_CLASS_NAME,
                            NOTIFY_PAYLOAD_STR,
                        )
                        send_count += 1
                        last_send_mono = now_mono

                    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
                    if events:
                        since_time = time.perf_counter_ns()
                        for ev in events:
                            if getattr(ev, "event_type", None) != RS9116AsyncEventType.GATT_WRITE_EVENT:
                                continue
                            edata = getattr(ev, "event_data", None)
                            if isinstance(edata, (bytes, bytearray)):
                                edata_b = bytes(edata)
                            else:
                                edata_b = str(edata or "").encode("latin-1", errors="replace")
                            m_hex = ATT_HEX_RX.search(edata_b)
                            if not m_hex:
                                continue
                            payload = bytes.fromhex(m_hex.group(1).decode("ascii"))
                            received_str = payload.decode("ascii", errors="replace")
                            if payload == EXPECTED_PAYLOAD:
                                verified_payload_count += 1
                                if verified_payload_count == 1:
                                    logger().info(
                                        f"[iter {iteration}] first verified "
                                        f"payload decoded: {received_str!r} "
                                        f"(len={len(payload)})"
                                    )
                            else:
                                logger().warning(
                                    f"[iter {iteration}] payload mismatch: "
                                    f"received={received_str!r} (len={len(payload)}), "
                                    f"expected={NOTIFY_PAYLOAD_STR!r} (len={EXPECTED_LEN})"
                                )
                    time.sleep(0.2)

                assert verified_payload_count > 0, (
                    f"[iter {iteration}] DUT did not receive any notification ")
                iteration_results.append(
                    {
                        "iteration": iteration,
                        "sent": send_count,
                        "received_full_payload": verified_payload_count,
                    }
                )
            finally:
                logger().info(f"[step 11][iter {iteration}] disconnecting from peer")
                _safe_disconnect()
                time.sleep(3)
    finally:
        logger().info(f"iteration summary: {iteration_results}")
        _safe_disconnect()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.test_src_map_id('C19927')
def test_ble_master_rx_230_bytes_C19927(firmware_loader, ble_dut, ble_client, utf_constants):
    data = "hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarx"
    NOTIFY_DURATION_SEC = 60
    ITERATIONS = utf_constants.get("iter_count")
    NOTIFY_PAYLOAD_STR = data
    EXPECTED_PAYLOAD = NOTIFY_PAYLOAD_STR.encode("ascii")
    EXPECTED_LEN = len(EXPECTED_PAYLOAD)
    NOTIFY_SEND_INTERVAL_SEC = 1.0
    HTS_UUID = HealthThermometerService.UUID.lower()
    CUSTOM_NOTIFY_UUID = CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID.lower()
    HTS_SERVICE_CLASS_NAME = "HealthThermometerService"
    HTS_CUSTOM_NOTIFY_CLASS_NAME = "CustomNotifyCharacteristic"
    ATT_HEX_RX = re.compile(rb"att_hex\s*-\s*([0-9a-fA-F]+)")

    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
    assert bt_dut_address, "failed to initialize ble in dut"

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=bt_dut_address,
        service_classes=["HeartRateService", "HealthThermometerService"],
        register_agent=False,
    )
    assert bt_client_address, "failed to initialize ble in remote device"

    try:
        ble_dut.interfaces.bluetooth.bt_power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        ble_dut.interfaces.bluetooth.power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
    except Exception as ps_err:
        logger().info(f"power_save setup raised (non-fatal): {ps_err}")

    connect_kwargs = dict(
        ble_remote_dev_address=bt_client_address,
        ble_scan_interval=64,
        ble_scan_window=48,
        ble_conn_interval_min=24,
        ble_conn_interval_max=40,
        ble_conn_latency=0,
        ble_supervision_timeout=400,
        ble_privacy_enable=0,
        expected="RSI_BLE_ENHC_CONN_EVENT",
        timeout=120,
    )

    def _safe_disconnect():
        try:
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
        except Exception as disc_err:
            logger().info(f"cleanup ble_disconnect raised (expected if already disconnected): {disc_err}")

    def _read_state():
        s = ble_dut.interfaces.bluetooth.ble_get_device_state()
        return s, (int(s) if s.isdigit() else -1)

    def _establish_stable_link():
        last_state = None
        state_int = -1
        for attempt in range(1, 4):
            logger().info(f"BLE connect attempt {attempt}/3 with params={connect_kwargs}")
            try:
                ble_dut.interfaces.bluetooth.ble_connect(**connect_kwargs)
            except Exception as connect_err:
                logger().info(f"ble_connect raised on attempt {attempt}: {connect_err}")
            sw = Stopwatch()
            while sw.elapsed_sec < 5:
                last_state, state_int = _read_state()
                if state_int == BLEDeviceState.Connected:
                    break
                time.sleep(0.5)
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: did not reach Connected within 5s "
                    f"(last={last_state}); retrying"
                )
                _safe_disconnect()
                time.sleep(3)
                continue
            settle_sw = Stopwatch()
            while settle_sw.elapsed_sec < 20:
                time.sleep(1)
                last_state, state_int = _read_state()
                if state_int != BLEDeviceState.Connected:
                    break
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: link dropped during 20s settle "
                    f"(state={last_state}); retrying"
                )
                _safe_disconnect()
                time.sleep(3)
                continue
            logger().info(f"BLE link stable after attempt {attempt} (state={last_state})")
            return True, last_state, state_int
        return False, last_state, state_int

    def _find_custom_notify_handle():
        profile_uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(
            ble_remote_dev_address=bt_client_address
        )
        def _norm(u):
            s = str(u).lower().replace("0x", "")
            return "0x" + s.zfill(4)
        normalised = [_norm(u) for u in profile_uuids]
        logger().info(f"discovered profiles (normalised): {normalised}")
        assert HTS_UUID in normalised, (
            f"HealthThermometerService ({HTS_UUID}) not advertised by peer; "
            f"got {normalised}"
        )
        start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HTS_UUID, 16),
        )
        assert start_handle and end_handle, "failed to resolve HealthThermometerService handles"
        char_uuids, value_handles, char_props = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
        )
        char_uuids_norm = [_norm(u) for u in char_uuids]
        logger().info(
            f"HealthThermometerService chars: uuids={char_uuids_norm}, "
            f"handles={value_handles}, props={char_props}"
        )
        assert CUSTOM_NOTIFY_UUID in char_uuids_norm, (
            f"CustomNotifyCharacteristic ({CUSTOM_NOTIFY_UUID}) not present "
            f"inside HealthThermometerService; chars={char_uuids_norm}"
        )
        idx = char_uuids_norm.index(CUSTOM_NOTIFY_UUID)
        # Per BLE spec the property bitmap for notify-only must include 0x10.
        prop_str = str(char_props[idx])
        if prop_str.isdigit():
            assert int(prop_str) & CustomNotifyCharacteristic.prop_int, (
                f"CustomNotifyCharacteristic at index {idx} does not advertise the "
                f"notify property bit; raw char_property={prop_str}"
            )
        value_handle = int(value_handles[idx], 16)
        assert value_handle > 0, "CustomNotifyCharacteristic value handle was empty"
        return value_handle

    iteration_results = []
    try:
        for iteration in range(1, ITERATIONS + 1):
            logger().info(f"[iter {iteration}] start scanning in DUT")
            ble_dut.interfaces.bluetooth.ble_start_scanning(
                ble_client_address=bt_client_address, timeout=60
            )
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)

            # Step 7: connect with retry/settle.
            link_stable, last_state, state_int = _establish_stable_link()
            assert link_stable and state_int == BLEDeviceState.Connected, (
                f"[iter {iteration}] DUT not Connected after 3 attempts, "
                f"last state={last_state}"
            )

            try:
                try:
                    ble_dut.interfaces.bluetooth.ble_set_data_length(
                        ble_remote_dev_address=bt_client_address,
                        tx_len=251,
                        tx_time=2120,
                    )
                except Exception as dle_err:
                    logger().info(f"[iter {iteration}] set_data_length best-effort: {dle_err}")
                value_handle = _find_custom_notify_handle()
                since_time = time.perf_counter_ns()
                ble_dut.interfaces.bluetooth.ble_set_att_int_value_async(
                    ble_remote_dev_address=bt_client_address,
                    char_property=(value_handle + 1),
                    value=1,
                )
                time.sleep(0.5)
                send_count = 0
                verified_payload_count = 0
                last_send_mono = -float("inf")
                rx_sw = Stopwatch()
                while rx_sw.elapsed_sec < NOTIFY_DURATION_SEC:
                    now_mono = time.monotonic()
                    if (now_mono - last_send_mono) >= NOTIFY_SEND_INTERVAL_SEC:
                        ble_client.interfaces.bluetooth.send_gatt_charc_notification(
                            HTS_SERVICE_CLASS_NAME,
                            HTS_CUSTOM_NOTIFY_CLASS_NAME,
                            NOTIFY_PAYLOAD_STR,
                        )
                        send_count += 1
                        last_send_mono = now_mono

                    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
                    if events:
                        since_time = time.perf_counter_ns()
                        for ev in events:
                            if getattr(ev, "event_type", None) != RS9116AsyncEventType.GATT_WRITE_EVENT:
                                continue
                            edata = getattr(ev, "event_data", None)
                            if isinstance(edata, (bytes, bytearray)):
                                edata_b = bytes(edata)
                            else:
                                edata_b = str(edata or "").encode("latin-1", errors="replace")
                            m_hex = ATT_HEX_RX.search(edata_b)
                            if not m_hex:
                                continue
                            payload = bytes.fromhex(m_hex.group(1).decode("ascii"))
                            received_str = payload.decode("ascii", errors="replace")
                            if payload == EXPECTED_PAYLOAD:
                                verified_payload_count += 1
                                if verified_payload_count == 1:
                                    logger().info(
                                        f"[iter {iteration}] first verified "
                                        f"payload decoded: {received_str!r} "
                                        f"(len={len(payload)})"
                                    )
                            else:
                                logger().warning(
                                    f"[iter {iteration}] payload mismatch: "
                                    f"received={received_str!r} (len={len(payload)}), "
                                    f"expected={NOTIFY_PAYLOAD_STR!r} (len={EXPECTED_LEN})"
                                )
                    time.sleep(0.2)

                assert verified_payload_count > 0, (
                    f"[iter {iteration}] DUT did not receive any notification ")
                iteration_results.append(
                    {
                        "iteration": iteration,
                        "sent": send_count,
                        "received_full_payload": verified_payload_count,
                    }
                )
            finally:
                logger().info(f"[step 11][iter {iteration}] disconnecting from peer")
                _safe_disconnect()
                time.sleep(3)
    finally:
        logger().info(f"iteration summary: {iteration_results}")
        _safe_disconnect()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.test_src_map_id('C19930')
def test_ble_master_rx_100_bytes_duty_cycle_C19930(firmware_loader, ble_dut, ble_client, utf_constants):
    NOTIFY_DURATION_SEC = 60
    ITERATIONS = utf_constants.get("iter_count")
    NOTIFY_PAYLOAD_STR = "A" * 100
    EXPECTED_PAYLOAD = NOTIFY_PAYLOAD_STR.encode("ascii")
    EXPECTED_LEN = len(EXPECTED_PAYLOAD)
    NOTIFY_SEND_INTERVAL_SEC = 1.0
    HTS_UUID = HealthThermometerService.UUID.lower()
    CUSTOM_NOTIFY_UUID = CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID.lower()
    HTS_SERVICE_CLASS_NAME = "HealthThermometerService"
    HTS_CUSTOM_NOTIFY_CLASS_NAME = "CustomNotifyCharacteristic"
    ATT_HEX_RX = re.compile(rb"att_hex\s*-\s*([0-9a-fA-F]+)")

    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
    assert bt_dut_address, "failed to initialize ble in dut"

    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=bt_dut_address,
        service_classes=["HeartRateService", "HealthThermometerService"],
        register_agent=False,
    )
    assert bt_client_address, "failed to initialize ble in remote device"

    try:
        ble_dut.interfaces.bluetooth.bt_power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
        ble_dut.interfaces.bluetooth.power_save(
            RS9116PowerSaveModes.PowerSaveMode2,
            RS9116PowerSaveProcedureTypes.FastPowerSave,
        )
    except Exception as ps_err:
        logger().info(f"power_save setup raised (non-fatal): {ps_err}")

    connect_kwargs = dict(
        ble_remote_dev_address=bt_client_address,
        ble_scan_interval=64,
        ble_scan_window=48,
        ble_conn_interval_min=24,
        ble_conn_interval_max=40,
        ble_conn_latency=0,
        ble_supervision_timeout=400,
        ble_privacy_enable=0,
        expected="RSI_BLE_ENHC_CONN_EVENT",
        timeout=120,
    )

    def _safe_disconnect():
        try:
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
        except Exception as disc_err:
            logger().info(f"cleanup ble_disconnect raised (expected if already disconnected): {disc_err}")

    def _read_state():
        s = ble_dut.interfaces.bluetooth.ble_get_device_state()
        return s, (int(s) if s.isdigit() else -1)

    def _establish_stable_link():
        last_state = None
        state_int = -1
        for attempt in range(1, 4):
            logger().info(f"BLE connect attempt {attempt}/3 with params={connect_kwargs}")
            try:
                ble_dut.interfaces.bluetooth.ble_connect(**connect_kwargs)
            except Exception as connect_err:
                logger().info(f"ble_connect raised on attempt {attempt}: {connect_err}")
            sw = Stopwatch()
            while sw.elapsed_sec < 5:
                last_state, state_int = _read_state()
                if state_int == BLEDeviceState.Connected:
                    break
                time.sleep(0.5)
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: did not reach Connected within 5s "
                    f"(last={last_state}); retrying"
                )
                _safe_disconnect()
                time.sleep(3)
                continue
            settle_sw = Stopwatch()
            while settle_sw.elapsed_sec < 20:
                time.sleep(1)
                last_state, state_int = _read_state()
                if state_int != BLEDeviceState.Connected:
                    break
            if state_int != BLEDeviceState.Connected:
                logger().warning(
                    f"attempt {attempt}: link dropped during 20s settle "
                    f"(state={last_state}); retrying"
                )
                _safe_disconnect()
                time.sleep(3)
                continue
            logger().info(f"BLE link stable after attempt {attempt} (state={last_state})")
            return True, last_state, state_int
        return False, last_state, state_int

    def _find_custom_notify_handle():
        profile_uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(
            ble_remote_dev_address=bt_client_address
        )
        def _norm(u):
            s = str(u).lower().replace("0x", "")
            return "0x" + s.zfill(4)
        normalised = [_norm(u) for u in profile_uuids]
        logger().info(f"discovered profiles (normalised): {normalised}")
        assert HTS_UUID in normalised, (
            f"HealthThermometerService ({HTS_UUID}) not advertised by peer; "
            f"got {normalised}"
        )
        start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
            ble_remote_dev_address=bt_client_address,
            uuid=int(HTS_UUID, 16),
        )
        assert start_handle and end_handle, "failed to resolve HealthThermometerService handles"
        char_uuids, value_handles, char_props = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
            ble_remote_dev_address=bt_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
        )
        char_uuids_norm = [_norm(u) for u in char_uuids]
        logger().info(
            f"HealthThermometerService chars: uuids={char_uuids_norm}, "
            f"handles={value_handles}, props={char_props}"
        )
        assert CUSTOM_NOTIFY_UUID in char_uuids_norm, (
            f"CustomNotifyCharacteristic ({CUSTOM_NOTIFY_UUID}) not present "
            f"inside HealthThermometerService; chars={char_uuids_norm}"
        )
        idx = char_uuids_norm.index(CUSTOM_NOTIFY_UUID)
        # Per BLE spec the property bitmap for notify-only must include 0x10.
        prop_str = str(char_props[idx])
        if prop_str.isdigit():
            assert int(prop_str) & CustomNotifyCharacteristic.prop_int, (
                f"CustomNotifyCharacteristic at index {idx} does not advertise the "
                f"notify property bit; raw char_property={prop_str}"
            )
        value_handle = int(value_handles[idx], 16)
        assert value_handle > 0, "CustomNotifyCharacteristic value handle was empty"
        return value_handle

    iteration_results = []
    try:
        for iteration in range(1, ITERATIONS + 1):
            logger().info(f"[iter {iteration}] start scanning in DUT")
            ble_dut.interfaces.bluetooth.ble_start_scanning(
                ble_client_address=bt_client_address, timeout=60
            )
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(2)

            # Step 7: connect with retry/settle.
            link_stable, last_state, state_int = _establish_stable_link()
            assert link_stable and state_int == BLEDeviceState.Connected, (
                f"[iter {iteration}] DUT not Connected after 3 attempts, "
                f"last state={last_state}"
            )

            try:
                try:
                    ble_dut.interfaces.bluetooth.ble_set_data_length(
                        ble_remote_dev_address=bt_client_address,
                        tx_len=251,
                        tx_time=2120,
                    )
                except Exception as dle_err:
                    logger().info(f"[iter {iteration}] set_data_length best-effort: {dle_err}")
                value_handle = _find_custom_notify_handle()
                since_time = time.perf_counter_ns()
                ble_dut.interfaces.bluetooth.ble_set_att_int_value_async(
                    ble_remote_dev_address=bt_client_address,
                    char_property=(value_handle + 1),
                    value=1,
                )
                time.sleep(0.5)
                send_count = 0
                verified_payload_count = 0
                last_send_mono = -float("inf")
                rx_sw = Stopwatch()
                while rx_sw.elapsed_sec < NOTIFY_DURATION_SEC:
                    now_mono = time.monotonic()
                    if (now_mono - last_send_mono) >= NOTIFY_SEND_INTERVAL_SEC:
                        ble_client.interfaces.bluetooth.send_gatt_charc_notification(
                            HTS_SERVICE_CLASS_NAME,
                            HTS_CUSTOM_NOTIFY_CLASS_NAME,
                            NOTIFY_PAYLOAD_STR,
                        )
                        send_count += 1
                        last_send_mono = now_mono

                    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
                    if events:
                        since_time = time.perf_counter_ns()
                        for ev in events:
                            if getattr(ev, "event_type", None) != RS9116AsyncEventType.GATT_WRITE_EVENT:
                                continue
                            edata = getattr(ev, "event_data", None)
                            if isinstance(edata, (bytes, bytearray)):
                                edata_b = bytes(edata)
                            else:
                                edata_b = str(edata or "").encode("latin-1", errors="replace")
                            m_hex = ATT_HEX_RX.search(edata_b)
                            if not m_hex:
                                continue
                            payload = bytes.fromhex(m_hex.group(1).decode("ascii"))
                            received_str = payload.decode("ascii", errors="replace")
                            if payload == EXPECTED_PAYLOAD:
                                verified_payload_count += 1
                                if verified_payload_count == 1:
                                    logger().info(
                                        f"[iter {iteration}] first verified "
                                        f"payload decoded: {received_str!r} "
                                        f"(len={len(payload)})"
                                    )
                            else:
                                logger().warning(
                                    f"[iter {iteration}] payload mismatch: "
                                    f"received={received_str!r} (len={len(payload)}), "
                                    f"expected={NOTIFY_PAYLOAD_STR!r} (len={EXPECTED_LEN})"
                                )
                    time.sleep(0.2)

                assert verified_payload_count > 0, (
                    f"[iter {iteration}] DUT did not receive any notification ")
                iteration_results.append(
                    {
                        "iteration": iteration,
                        "sent": send_count,
                        "received_full_payload": verified_payload_count,
                    }
                )
            finally:
                logger().info(f"[step 11][iter {iteration}] disconnecting from peer")
                _safe_disconnect()
                time.sleep(3)
    finally:
        logger().info(f"iteration summary: {iteration_results}")
        _safe_disconnect()
