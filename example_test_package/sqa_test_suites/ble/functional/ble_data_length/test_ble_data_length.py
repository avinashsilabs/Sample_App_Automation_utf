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
    HeartRateControlPointCharacteristic


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
def test_ble_slave_data_length_100_bytes_tx_rx_C19922(ble_dut, ble_client):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path="./reports/test_ble_slave_data_length_100_bytes_tx_rx_C19922.log"):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        logger().info("======= start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "failed to initialize ble in dut"
        ble_dut.interfaces.bluetooth.ble_add_service(uid=0x6E)
        ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x6F)
        ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x6F)

        logger().info("======= start ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("======= enable power save")
        ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
        ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
        number_of_iterations = 11
        for i in range(1, number_of_iterations):
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
            ble_client.interfaces.bluetooth.connect(bt_dut_address)
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

            data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
                time.sleep(5)

            sw = Stopwatch()
            while sw.elapsed_sec < 60:
                data1 = "rxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedata"
                try:
                    ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data1)
                    time.sleep(1)
                except Exception as e:
                    logger().warning(f"Exception: {e}")
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
        ble_dut.interfaces.wifi.ble_stop_advertising()


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
def test_ble_slave_data_length_20_bytes_C19920(ble_dut, ble_client):
    with BleLogs(start_collecting_logs=True, bt_log_path="./reports/test_ble_slave_data_length_20_bytes_C19920.log"):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        logger().info("======= start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "failed to initialize ble in dut"
        ble_dut.interfaces.bluetooth.ble_add_service(uid=0x6E)
        ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x6F)
        ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x6F)

        logger().info("======= start ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("======= enable power save")
        ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
        ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

        for i in range(1, 11):
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
            ble_client.interfaces.bluetooth.connect(bt_dut_address)
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

            data = "testwentybytesofdata"
            sw = Stopwatch()
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
def test_ble_slave_data_length_230_bytes_tx_C19923(ble_dut, ble_client, utf_constants):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path="./reports/test_ble_slave_data_length_230_bytes_tx_C19923.log"):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        logger().info("======= start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "failed to initialize ble in dut"
        ble_dut.interfaces.bluetooth.ble_add_service(uid=0x6E)
        ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x6F)
        ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x6F)

        logger().info("======= start ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("======= enable power save")
        ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
        ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
        for i in range(1, 11):
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
            ble_client.interfaces.bluetooth.connect(bt_dut_address)
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

            data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybyuhujhsjsgshsjasgshsjsgshsvxhsbxjhsbjnj"
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

            iter_count = utf_constants.get("iter_count")
            if i == iter_count:
                logger().info("ble_remove_service")
                ble_dut.interfaces.wifi.ble_remove_service()

            logger().info("======= disconnecting from dut")
            ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            ble_client.interfaces.bluetooth.close()
            time.sleep(0.2)
            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()


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
def test_ble_slave_data_length_20_bytes_duty_cycle_C19926(ble_dut, ble_client, utf_constants):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path="./reports/test_ble_slave_data_length_20_bytes_duty_cycle_C19926.log"):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        logger().info("======= start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "failed to initialize ble in dut"
        ble_dut.interfaces.bluetooth.ble_add_service(uid=0x6E)
        ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x6F)
        ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x6F)

        logger().info("======= start ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("======= enable power save")
        ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
        ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

        for i in range(1, 11):
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
            ble_client.interfaces.bluetooth.connect(bt_dut_address)
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

            data = "testwentybytesofdata"
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

            iter_count = utf_constants.get("iter_count")
            if i == iter_count:
                logger().info("ble_remove_service")
                ble_dut.interfaces.wifi.ble_remove_service()

            logger().info("======= disconnecting from dut")
            ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            ble_client.interfaces.bluetooth.close()
            time.sleep(0.2)
            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()
        ble_dut.interfaces.wifi.ble_stop_advertising()


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
def test_ble_slave_data_length_230_bytes_duty_cycle_C19929(ble_dut, ble_client, utf_constants):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path="./reports/test_ble_slave_data_length_230_bytes_duty_cycle_C19929.log"):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        logger().info("======= start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "failed to initialize ble in dut"
        ble_dut.interfaces.bluetooth.ble_add_service(uid=0x6E)
        ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x6F)
        ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x6F)

        logger().info("======= start ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("======= enable power save")
        ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
        ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

        for i in range(1, 11):
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
            ble_client.interfaces.bluetooth.connect(bt_dut_address)
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

            data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybyuhujhsjsgshsjasgshsjsgshsvxhsbxjhsbjnj"
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

            iter_count = utf_constants.get("iter_count")
            if i == iter_count:
                logger().info("ble_remove_service")
                ble_dut.interfaces.wifi.ble_remove_service()

            logger().info("======= disconnecting from dut")
            ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            ble_client.interfaces.bluetooth.close()
            time.sleep(0.2)
            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()


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
def test_ble_slave_data_length_100_bytes_tx_rx_C19928(ble_dut, ble_client, utf_constants):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path="./reports/test_ble_slave_data_length_100_bytes_tx_rx_C19928.log"):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"

        logger().info("======= start ble in dut")
        bt_dut_address = ble_dut.interfaces.bluetooth.ble_start()
        assert bt_dut_address, "failed to initialize ble in dut"
        ble_dut.interfaces.bluetooth.ble_add_service(uid=0x6E)
        ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x6F)
        ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x6F)

        logger().info("======= start ble adv in dut")
        ble_dut.interfaces.bluetooth.ble_start_advertising()

        logger().info("======= enable power save")
        ble_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
        ble_dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

        for i in range(1, 11):
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
            ble_client.interfaces.bluetooth.connect(bt_dut_address)
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
            data = "testwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdatatestwentybytesofdata"
            while sw.elapsed_sec < 60:
                ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
                time.sleep(5)

            sw = Stopwatch()
            data1 = "rxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedatarxsidedata"
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

            iter_count = utf_constants.get("iter_count")
            if i == iter_count:
                logger().info("ble_remove_service")
                ble_dut.interfaces.wifi.ble_remove_service()

            logger().info("======= disconnecting from dut")
            ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
            ble_client.interfaces.bluetooth.close()
            time.sleep(0.2)
            logger().info("======= start ble adv in dut")
            ble_dut.interfaces.bluetooth.ble_start_advertising()


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
def test_ble_master_rx_230_bytes_C19921(firmware_loader, ble_dut, ble_client):
    logger().info("======= initializing ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address, "failed to initialize ble in dut"

    logger().info("======= initializing ble in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["HeartRateService"])
    assert bt_client_address, "failed to initialize ble in remote device"

    logger().info("======= start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert HeartRateService.UUID.lower() in uuids, "failed to fetch heartrate service"

    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
        ble_remote_dev_address=bt_client_address,
        uuid=int(HeartRateService.UUID, 16))
    assert start_handle, "failed to get start handle"
    assert end_handle, "failed dto get end hadle"

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert HeartRateControlPointCharacteristic.UUID in uuids
    index = uuids.index(HeartRateControlPointCharacteristic.UUID)

    assert char_properties[index].isdigit()
    assert HeartRateControlPointCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0, "received empty index"

    # enable notifications
    since_time = time.perf_counter_ns()
    ble_dut.interfaces.bluetooth.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                         char_property=(write_handle + 1), value=1)
    time.sleep(6)
    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
    assert len(events) > 0
    latest_val = events[-1].event_data

    # read value
    val = ble_dut.interfaces.bluetooth.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                               char_property=write_handle)
    assert int(val) <= int(latest_val)

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)


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
def test_ble_master_rx_100_bytes_C19924(firmware_loader, ble_dut, ble_client):
    data = "hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarx"

    logger().info("======= initializing ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address, "failed to initialize ble in dut"

    logger().info("======= initializing ble in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["HeartRateService"])
    assert bt_client_address, "failed to initialize ble in remote device"

    logger().info("======= start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert HeartRateService.UUID.lower() in uuids, "failed to fetch heartrate service"

    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
        ble_remote_dev_address=bt_client_address,
        uuid=int(HeartRateService.UUID, 16))
    assert start_handle, "failed to get start handle"
    assert end_handle, "failed dto get end hadle"

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert HeartRateControlPointCharacteristic.UUID in uuids
    index = uuids.index(HeartRateControlPointCharacteristic.UUID)

    assert char_properties[index].isdigit()
    assert HeartRateControlPointCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0, "received empty index"

    # enable notifications
    since_time = time.perf_counter_ns()
    ble_dut.interfaces.bluetooth.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                         char_property=(write_handle + 1), value=1)
    time.sleep(6)
    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
    assert len(events) > 0
    latest_val = events[-1].event_data

    # read value
    val = ble_dut.interfaces.bluetooth.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                               char_property=write_handle)
    assert int(val) <= int(latest_val)

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)


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
def test_ble_master_tx_rx_230_bytes_C19925(firmware_loader, ble_dut, ble_client):
    data = "hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarx"

    logger().info("======= initializing ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address, "failed to initialize ble in dut"

    logger().info("======= initializing ble in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["HeartRateService"])
    assert bt_client_address, "failed to initialize ble in remote device"

    logger().info("======= start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert HeartRateService.UUID.lower() in uuids, "failed to fetch heartrate service"

    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
        ble_remote_dev_address=bt_client_address,
        uuid=int(HeartRateService.UUID, 16))
    assert start_handle, "failed to get start handle"
    assert end_handle, "failed dto get end hadle"

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert HeartRateControlPointCharacteristic.UUID in uuids
    index = uuids.index(HeartRateControlPointCharacteristic.UUID)

    assert char_properties[index].isdigit()
    assert HeartRateControlPointCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0, "received empty index"

    # enable notifications
    since_time = time.perf_counter_ns()
    ble_dut.interfaces.bluetooth.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                         char_property=(write_handle + 1), value=1)
    time.sleep(6)
    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
    assert len(events) > 0
    latest_val = events[-1].event_data

    # read value
    val = ble_dut.interfaces.bluetooth.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                               char_property=write_handle)
    assert int(val) <= int(latest_val)

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)


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
def test_ble_master_rx_230_bytes_C19927(firmware_loader, ble_dut, ble_client):
    data = "hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarx"

    logger().info("======= initializing ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address, "failed to initialize ble in dut"

    logger().info("======= initializing ble in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["HeartRateService"])
    assert bt_client_address, "failed to initialize ble in remote device"

    logger().info("======= start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert HeartRateService.UUID.lower() in uuids, "failed to fetch heartrate service"

    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
        ble_remote_dev_address=bt_client_address,
        uuid=int(HeartRateService.UUID, 16))
    assert start_handle, "failed to get start handle"
    assert end_handle, "failed dto get end hadle"

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert HeartRateControlPointCharacteristic.UUID in uuids
    index = uuids.index(HeartRateControlPointCharacteristic.UUID)

    assert char_properties[index].isdigit()
    assert HeartRateControlPointCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0, "received empty index"

    # enable notifications
    since_time = time.perf_counter_ns()
    ble_dut.interfaces.bluetooth.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                         char_property=(write_handle + 1), value=1)
    time.sleep(6)
    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
    assert len(events) > 0
    latest_val = events[-1].event_data

    # read value
    val = ble_dut.interfaces.bluetooth.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                               char_property=write_handle)
    assert int(val) <= int(latest_val)

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)


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
def test_ble_master_rx_100_bytes_duty_cycle_C19930(firmware_loader, ble_dut, ble_client):
    data = "hundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarxhundredbytesofdatarx"

    logger().info("======= initializing ble in dut")
    bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
    assert bt_dut_address, "failed to initialize ble in dut"

    logger().info("======= initializing ble in remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                      service_classes=["HeartRateService"])
    assert bt_client_address, "failed to initialize ble in remote device"

    logger().info("======= start scanning in dut")
    ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    timeout = 120
    logger().info(f"Initiating connection this can take upto {timeout} seconds....")
    ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout,
                                             expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # Get the state of the dut
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected

    # get all profiles
    uuids = ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
    assert HeartRateService.UUID.lower() in uuids, "failed to fetch heartrate service"

    # resolve battery profile
    start_handle, end_handle = ble_dut.interfaces.bluetooth.ble_get_profile_async(
        ble_remote_dev_address=bt_client_address,
        uuid=int(HeartRateService.UUID, 16))
    assert start_handle, "failed to get start handle"
    assert end_handle, "failed dto get end hadle"

    # resolve characteristics of battery profile
    uuids, write_handles, char_properties = ble_dut.interfaces.bluetooth.ble_get_char_services_async(
        ble_remote_dev_address=bt_client_address,
        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert HeartRateControlPointCharacteristic.UUID in uuids
    index = uuids.index(HeartRateControlPointCharacteristic.UUID)

    assert char_properties[index].isdigit()
    assert HeartRateControlPointCharacteristic.prop_int == int(char_properties[index])

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0, "received empty index"

    # enable notifications
    since_time = time.perf_counter_ns()
    ble_dut.interfaces.bluetooth.ble_set_att_value_async(ble_remote_dev_address=bt_client_address,
                                                         char_property=(write_handle + 1), value=1)
    time.sleep(6)
    events = ble_dut.interfaces.bluetooth.get_async_events(since_time=since_time)
    assert len(events) > 0
    latest_val = events[-1].event_data

    # read value
    val = ble_dut.interfaces.bluetooth.ble_get_att_value_async(ble_remote_dev_address=bt_client_address,
                                                               char_property=write_handle)
    assert int(val) <= int(latest_val)

    # Disconnect
    ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
