import time
import pytest
from utf.interfaces.bluetooth.hid_recorder import HidRecorder
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes)
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.logger import get_logger
import string
import random
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService
from utf.utils.thread_base import ThreadBase
import re


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. Soc
        2. Access Point
        3. Raspberry PI4

    Test Steps:
        1. Initiates the DUT Coex wlan and BT mode
        2. Initiates ble in DUT 
        3. Connect to the remote device
        4. configure the dut with the gatt services
        5. Notify the data with gatt notify api
        6. Validate the notified data in remote device 

    Author: Saurabh Sharma
"""



class SendDataFromDut(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_client_address=None, service_uid=None, char_uid=None,
                 data=None, char_path=None, allocate_mem_addr=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.service_uid = service_uid
        self.char_uid = char_uid
        self.char_path = char_path
        self.data = data
        self.allocate_mem_addr = allocate_mem_addr

    def run(self):
        sw = Stopwatch()
        count = 0
        while sw.elapsed_sec < 600:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=self.ble_client_address,
                                                             data=self.data, data_address=self.allocate_mem_addr)
            time.sleep(3)
            logger().info("******************** Validate Data ********************")
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            logger().info(f' *********************** Notification is {notifications} ***********************')
            assert len(notifications) > 0, "received data is empty"
            assert notifications[count] == self.data, "Data Mismatched"
            logger().info("DATA RECEIVED ON REMOTE SIDE")
            count += 1
        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)


class SendDataFromRemote(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_client_address=None, data_length=None, write_handle=None,
                 allocate_mem_addr=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.data_length = data_length
        self.write_handle = write_handle
        self.allocate_mem_addr = allocate_mem_addr

    def run(self):
        sw = Stopwatch()
        notify_time = 600
        while sw.elapsed_sec < notify_time:
            since_time = time.perf_counter_ns()
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_length))
            self.ble_client.interfaces.bluetooth.send_gatt_charc_notification("HealthThermometerService",
                                                                              "CustomNotifyCharacteristic", data)
            time.sleep(5)
            found = False
            tw = Stopwatch()
            while tw.elapsed_sec < 10:
                events = self.wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                time.sleep(5)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                        received_data = re.findall(r"att_value:\s*([^\s]+)", event.event_data)
                        logger().info(f"******* Received Data on DUT : {received_data} ********")
                        logger().info(f"******* Received Data on DUT : {len(received_data[0])} ********")
                        try:
                            assert received_data[0] in data, "data mismatched"
                        except:
                            assert received_data[0][:237] in data, "data mismatched"
                        found = True
                        break
                if found:
                    break
        # disable notifications
        time.sleep(1)
        # disable notifications
        self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                        handle=(self.write_handle + 1), enable_notify=0)


def discover_service_char_of_dut_in_remote(wifi_dut, ble_client, service_uid, char_uid, ble_client_address):
    # Resolve the service, characteristics from raspi
    logger().info("Resolve the service characteristics from remote side")
    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"
    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
        services=servs, service_uid=service_uid, char_uid=char_uid)
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"
    ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
    logger().info(f' *********************** subscribe to notifications ***********************')
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
        char_path=char_path, char_uid=char_uid)
    wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
        ble_remote_dev_address=ble_client_address, buffer_mode=1, buffer_count=2)
    return char_path


def discover_service_char_of_remote_in_dut(wifi_dut, ble_client, ble_client_address):
    logger().info("\n\n ***** Performing GATT profile discovery on Remote (raspi)  ***** \n\n\n")
    # get all profiles
    logger().info("Get the profile UUID's")
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(
        ble_remote_dev_address=ble_client_address,
        async_timeout=60)
    logger().info(f"UUIds {uuids}")
    assert len(uuids) > 0, "uuids are empty"
    #  resolve profile
    logger().info("Resolve the service characteristics from dut side")
    start_handle, end_handle, data = wifi_dut.interfaces.wifi.ble_get_profile_async(
        ble_remote_dev_address=ble_client_address,
        uuid=int(HealthThermometerService.UUID, 16),
        async_timeout=60)
    logger().info(f"start_handle:{start_handle}, end_handle:{end_handle}")
    assert start_handle is not None
    assert end_handle is not None
    char_uuids, write_handles, char_properties = wifi_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address,
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
    logger().info("*******Configure Buffer Mode:1 and Buffer count:2 ****************")
    wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                        buffer_mode=1, buffer_count=2)
    # subscribe to notifications
    # enable notifications
    wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                               handle=(write_handle + 1), enable_notify=1)

    time.sleep(2)
    return write_handle


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19920')
def test_ble_slave_tx_data_length_20_bytes_C19920(wifi_dut, ble_client, sl_collections, utf_constants):
    """Validate BLE Tx as slave by configuring data length with 20bytes without Duty cycling"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_20_bytes_C19920.log"):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

                logger().info("*********************** Start BLE in DUT ***********************")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile()
                wifi_dut.interfaces.wifi.enable_bt_power_save()

                ble_client_address = sl_collections.check_ble_advertise_functionality(
                    wifi_dut=wifi_dut, ble_client=ble_client, ble_dut_address=bt_dut_address, timeout=20)

                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address)

                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=servs, service_uid=service_uid, char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                logger().info(f' *********************** subscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                    char_path=char_path, char_uid=char_uid)

                wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=ble_client_address, buffer_mode=0, buffer_count=2)

                sw = Stopwatch()
                count = 0
                while sw.elapsed_sec < 60:
                    data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                    wifi_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=ble_client_address,
                                                                     data=data)
                    time.sleep(3)
                    logger().info("******************** Validate Data ********************")
                    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                    logger().info(f' *********************** Notification is {notifications} ***********************')
                    assert len(notifications) > 0, "received data is empty"
                    assert notifications[count] == data, "Data Mismatched"
                    count += 1

                logger().info(f' *********************** unsubscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()

                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19923')
def test_ble_slave_tx_data_length_230_bytes_C19923(wifi_dut, ble_client, sl_collections, utf_constants):
    """Validate BLE Tx as slave by configuring data length with 230bytes without Duty cycling"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_230_bytes_tx_C19923.log"):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

                logger().info("*********************** Start BLE in DUT ***********************")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile()
                wifi_dut.interfaces.wifi.enable_bt_power_save()

                ble_client_address = sl_collections.check_ble_advertise_functionality(
                    wifi_dut=wifi_dut, ble_client=ble_client, ble_dut_address=bt_dut_address, timeout=20)

                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address)

                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=servs, service_uid=service_uid, char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                logger().info(f' *********************** subscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                    char_path=char_path, char_uid=char_uid)

                wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=ble_client_address, buffer_mode=1, buffer_count=2)

                sw = Stopwatch()
                count = 0
                while sw.elapsed_sec < 60:
                    data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                    wifi_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=ble_client_address,
                                                                     data=data)
                    time.sleep(3)
                    logger().info("******************** Validate Data ********************")
                    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                    logger().info(f' *********************** Notification is {notifications} ***********************')
                    assert len(notifications) > 0, "received data is empty"
                    assert notifications[count] == data, "Data Mismatched"
                    count += 1

                logger().info(f' *********************** unsubscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()

                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19926')
def test_ble_slave_tx_data_length_20_bytes_duty_cycle_C19926(wifi_dut, ble_client, sl_collections, utf_constants):
    """Validate BLE Tx as slave by configuring data length with 20bytes with Duty cycling"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_20_bytes_duty_cycle_C19926.log"):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

                logger().info("*********************** Start BLE in DUT ***********************")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile()
                wifi_dut.interfaces.wifi.enable_bt_power_save()

                ble_client_address = sl_collections.check_ble_advertise_functionality(
                    wifi_dut=wifi_dut, ble_client=ble_client, ble_dut_address=bt_dut_address, timeout=20)

                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address)

                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=servs, service_uid=service_uid, char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                logger().info(f' *********************** subscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                    char_path=char_path, char_uid=char_uid)

                wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=ble_client_address, buffer_mode=0, buffer_count=2)

                sw = Stopwatch()
                count = 0
                while sw.elapsed_sec < 60:
                    data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
                    wifi_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=ble_client_address,
                                                                     data=data)
                    time.sleep(3)
                    logger().info("******************** Validate Data ********************")
                    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                    logger().info(f' *********************** Notification is {notifications} ***********************')
                    assert len(notifications) > 0, "received data is empty"
                    assert notifications[count] == data, "Data Mismatched"
                    count += 1

                logger().info(f' *********************** unsubscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()

                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19929')
def test_ble_slave_tx_data_length_230_bytes_duty_cycle_C19929(wifi_dut, ble_client, sl_collections, utf_constants):
    """Validate BLE Tx as slave by configuring data length with 230bytes with Duty cycling"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_data_length_230_bytes_duty_cycle_C19929.log"):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"

                logger().info("*********************** Start BLE in DUT ***********************")
                bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert bt_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile()
                wifi_dut.interfaces.wifi.enable_bt_power_save()

                ble_client_address = sl_collections.check_ble_advertise_functionality(
                    wifi_dut=wifi_dut, ble_client=ble_client, ble_dut_address=bt_dut_address, timeout=20)

                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address)

                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"

                servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                assert len(servs) > 0, "no services fetched"
                assert len(chars) > 0, "fetched characters are empty"

                char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                    services=servs,
                    service_uid=service_uid,
                    char_uid=char_uid)
                assert char_path, "characters are empty"
                assert len(char_props) > 0, "length of characters is 0"

                ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

                logger().info(f' *********************** subscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                    char_path=char_path, char_uid=char_uid)

                wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=ble_client_address, buffer_mode=1, buffer_count=2)

                sw = Stopwatch()
                count = 0
                while sw.elapsed_sec < 60:
                    data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                    wifi_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=ble_client_address,
                                                                     data=data)
                    time.sleep(3)
                    logger().info("******************** Validate Data ********************")
                    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
                    logger().info(f' *********************** Notification is {notifications} ***********************')
                    assert len(notifications) > 0, "received data is empty"
                    assert notifications[count] == data, "Data Mismatched"
                    count += 1

                logger().info(f' *********************** unsubscribe to notifications ***********************')
                ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
                ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
                time.sleep(1)

                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()

                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19924')
def test_ble_master_rx_100_bytes_C19924(ble_dut, ble_client, sl_collections, wifi_dut, utf_constants):
    bt_mon_log_file_name = f"reports/test_ble_master_rx_100_bytes_C19924{int(time.time())}.log"
    """Validate BLE RX as master by configuring data length with 100bytes without Duty cycling"""
    svc = 'HealthThermometerService'
    charc = 'CustomNotifyCharacteristic'
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):

                logger().info("******************** initializing ble in dut ********************")
                bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
                assert bt_dut_address, "failed to initialize ble in dut"

                logger().info("******************** initializing ble in remote device ********************")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=bt_dut_address, service_classes=[svc])
                assert bt_client_address, "failed to initialize ble in remote device"

                logger().info("******************** start scanning in dut ********************")
                ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=100)
                ble_dut.interfaces.bluetooth.ble_stop_scanning()

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                              psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

                logger().info(f".... initiating ble connection ....")
                ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address)

                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                logger().info(f"******************** get all profiles ********************")
                uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
                assert HealthThermometerService.UUID.lower() in uuids is not None, "Could not fetch health thermometer profile"

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
                notify_time = 300
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                sw = Stopwatch()
                while sw.elapsed_sec < notify_time:
                    since_time = time.perf_counter_ns()
                    ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data)
                    time.sleep(0.3)
                    found = False
                    tw = Stopwatch()
                    while tw.elapsed_sec < 10:
                        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                        time.sleep(5)
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                                logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                                received_data = re.findall(r"(\b[A-Z0-9]{100}\b)", event.event_data)
                                logger().info(f"******* Received Data on DUT : {received_data} ********")
                                try:
                                    assert received_data[0] in data, "data mismatched"
                                except:
                                    assert received_data[0][:237] in data, "data mismatched"
                                found = True
                                break
                        if found:
                            break

                time.sleep(1)
                ble_dut.interfaces.bluetooth.ble_set_att_value(
                    ble_remote_dev_address=bt_client_address, handle=(write_handle + 1), enable_notify=0)

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19930')
def test_ble_master_rx_100_bytes_duty_cycle_C19930(ble_dut, ble_client, sl_collections, wifi_dut, utf_constants):
    bt_mon_log_file_name = f"reports/test_ble_master_rx_100_bytes_C19930{int(time.time())}.log"
    """Validate BLE RX as master by configuring data length with 100bytes with Duty cycling"""
    svc = 'HealthThermometerService'
    charc = 'CustomNotifyCharacteristic'
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
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

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                              psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

                logger().info(f".... initiating ble connection ....")
                ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address)

                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                logger().info(f"******************** get all profiles ********************")
                uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
                assert HealthThermometerService.UUID.lower() in uuids is not None, "Could not fetch health thermometer profile"

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
                notify_time = 300
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                sw = Stopwatch()
                while sw.elapsed_sec < notify_time:
                    since_time = time.perf_counter_ns()
                    ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data)
                    time.sleep(0.3)
                    found = False
                    tw = Stopwatch()
                    while tw.elapsed_sec < 10:
                        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                        time.sleep(5)
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                                logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                                received_data = re.findall(r"(\b[A-Z0-9]{100}\b)", event.event_data)
                                logger().info(f"******* Received Data on DUT : {received_data} ********")
                                try:
                                    assert received_data[0] in data, "data mismatched"
                                except:
                                    assert received_data[0][:237] in data, "data mismatched"
                                found = True
                                break
                        if found:
                            break

                time.sleep(1)
                ble_dut.interfaces.bluetooth.ble_set_att_value(
                    ble_remote_dev_address=bt_client_address, handle=(write_handle + 1), enable_notify=0)

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19921')
def test_ble_master_rx_230_bytes_C19921(ble_dut, ble_client, sl_collections, wifi_dut, utf_constants):
    bt_mon_log_file_name = (f"reports/test_ble_master_rx_230_bytes_C19921"
                            f"{int(time.time())}.log")

    """Validate BLE RX as master by configuring data length with 230bytes without Duty cycling"""

    svc = 'HealthThermometerService'
    charc = 'CustomNotifyCharacteristic'
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):

                logger().info("******************** initializing ble in dut ********************")
                bt_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start()
                assert bt_dut_address, "failed to initialize ble in dut"

                logger().info("******************** initializing ble in remote device ********************")
                bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=bt_dut_address, service_classes=[svc])
                assert bt_client_address, "failed to initialize ble in remote device"

                logger().info("******************** start scanning in dut ********************")
                ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=bt_client_address, timeout=100)
                ble_dut.interfaces.bluetooth.ble_stop_scanning()

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                              psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

                logger().info(f".... initiating ble connection ....")
                ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address)

                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                logger().info(f"******************** get all profiles ********************")
                uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
                assert HealthThermometerService.UUID.lower() in uuids is not None, "Could not fetch health thermometer profile"

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
                notify_time = 300
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                sw = Stopwatch()
                while sw.elapsed_sec < notify_time:
                    since_time = time.perf_counter_ns()
                    ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data)
                    time.sleep(3)
                    found = False
                    tw = Stopwatch()
                    while tw.elapsed_sec < 10:
                        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                        time.sleep(5)
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                                logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                                received_data = re.findall(r"(\b[A-Z0-9]{230}\b)", event.event_data)
                                logger().info(f"******* Received Data on DUT : {received_data} ********")
                                try:
                                    assert received_data[0] in data, "data mismatched"
                                except:
                                    assert received_data[0][:237] in data, "data mismatched"
                                found = True
                                break
                        if found:
                            break

                time.sleep(1)
                ble_dut.interfaces.bluetooth.ble_set_att_value(
                    ble_remote_dev_address=bt_client_address, handle=(write_handle + 1), enable_notify=0)

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19927')
def test_ble_master_rx_230_bytes_duty_cycle_C19927(ble_dut, ble_client, sl_collections, wifi_dut, utf_constants):
    bt_mon_log_file_name = (f"reports/test_ble_master_rx_230_bytes_C19927"
                            f"{int(time.time())}.log")

    """Validate BLE RX as master by configuring data length with 230bytes with Duty cycling"""

    svc = 'HealthThermometerService'
    charc = 'CustomNotifyCharacteristic'
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
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

                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                              psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

                logger().info(f".... initiating ble connection ....")
                ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=bt_client_address)

                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                logger().info(f"******************** get all profiles ********************")
                uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
                assert HealthThermometerService.UUID.lower() in uuids is not None, "Could not fetch health thermometer profile"

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
                notify_time = 300
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                sw = Stopwatch()
                while sw.elapsed_sec < notify_time:
                    since_time = time.perf_counter_ns()
                    ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data)
                    time.sleep(3)
                    found = False
                    tw = Stopwatch()
                    while tw.elapsed_sec < 10:
                        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                        time.sleep(5)
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                                logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                                received_data = re.findall(r"(\b[A-Z0-9]{230}\b)", event.event_data)
                                logger().info(f"******* Received Data on DUT : {received_data} ********")
                                try:
                                    assert received_data[0] in data, "data mismatched"
                                except:
                                    assert received_data[0][:237] in data, "data mismatched"
                                found = True
                                break
                        if found:
                            break

                time.sleep(1)
                ble_dut.interfaces.bluetooth.ble_set_att_value(
                    ble_remote_dev_address=bt_client_address, handle=(write_handle + 1), enable_notify=0)

                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"

                ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
                ble_client.interfaces.bluetooth.close()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.remove_device(bt_dut_address=bt_dut_address)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19922')
def test_ble_slave_tx_rx_100_bytes_C19922(wifi_dut, ble_client, sl_collections, utf_constants):
    """ Validate BLE Tx and Rx as slave by configuring data length with 100bytes without Duty cycling"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_tx_rx_100_bytes_C19922.log"):
            iter_count = utf_constants.get("iter_count")
            logger().info(f"iter_count:{iter_count}")
            for count in range(iter_count):
                service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
                logger().info("*********************** Start BLE in DUT ***********************")
                ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
                logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
                assert ble_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_start_advertising()
                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.enable_bt_power_save()
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                ble_client_address = sl_collections.scan_from_remote_device(wifi_dut=wifi_dut, ble_client=ble_client,
                                                                            ble_dut_address=ble_dut_address,
                                                                            services=["HealthThermometerService"])
                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address)
                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)
                logger().info("******************** get connection state ******************")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"
                char_path = discover_service_char_of_dut_in_remote(wifi_dut, ble_client, service_uid, char_uid,
                                                                   ble_client_address)
                time.sleep(5)
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                allocated_mem_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(data))
                logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
                wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data),
                                                     write_content=data)
                write_handle = discover_service_char_of_remote_in_dut(wifi_dut=wifi_dut, ble_client=ble_client,
                                                                      ble_client_address=ble_client_address)
                time.sleep(5)
                obj1 = SendDataFromDut(wifi_dut, ble_client, ble_client_address, service_uid, char_uid, data, char_path,
                                       allocated_mem_addr)
                obj2 = SendDataFromRemote(wifi_dut, ble_client, ble_client_address, 100, write_handle)
                obj1.start()
                time.sleep(2)
                obj2.start()
                time.sleep(2)
                obj1.wait_for_exit()
                obj2.wait_for_exit()
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()
                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19925')
def test_ble_master_tx_rx_230_bytes_C19925(wifi_dut, ble_client, sl_collections, utf_constants):
    """ Validate BLE Tx and Rx as Master by configuring data length with 230bytes without Duty cycling."""
    bt_mon_log_file_name = (f"reports/test_ble_master_tx_rx_230_bytes_C19925"
                            f"{int(time.time())}.log")
    svc = 'HealthThermometerService'
    charc = "CustomNotifyCharacteristic"
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
                logger().info("*********************** Start BLE in DUT ***********************")
                ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
                assert ble_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
                assert ble_dut_address, "failed to initialize ble in dut"
                logger().info("******************** initializing ble in remote device ********************")
                ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=ble_dut_address, service_classes=[svc])
                assert ble_client_address, "failed to initialize ble in remote device"
                logger().info("******************** start scanning in dut ********************")
                wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=100)
                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                wifi_dut.interfaces.wifi.enable_bt_power_save()
                wifi_dut.interfaces.wifi.ble_stop_scanning()
                logger().info(f".... initiating ble connection ....")
                wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address)
                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
                char_path = discover_service_char_of_dut_in_remote(wifi_dut, ble_client, service_uid, char_uid,
                                                                   ble_client_address)
                time.sleep(5)
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                allocated_mem_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(data))
                logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
                wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data),
                                                     write_content=data)
                write_handle = discover_service_char_of_remote_in_dut(wifi_dut=wifi_dut, ble_client=ble_client,
                                                                      ble_client_address=ble_client_address)
                time.sleep(5)
                obj1 = SendDataFromDut(wifi_dut, ble_client, ble_client_address, service_uid, char_uid, data, char_path,
                                       allocated_mem_addr)
                obj2 = SendDataFromRemote(wifi_dut, ble_client, ble_client_address, 230, write_handle)
                obj1.start()
                time.sleep(2)
                obj2.start()
                time.sleep(2)
                obj1.wait_for_exit()
                obj2.wait_for_exit()
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()
                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19928')
def test_ble_slave_tx_rx_100_bytes_C19928(wifi_dut, ble_client, sl_collections, utf_constants):
    """ Validate BLE Tx and Rx as slave by configuring data length with 100bytes with Duty cycling"""
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path="./reports/test_ble_slave_tx_rx_100_bytes_C19928.log"):
            iter_count = utf_constants.get("iter_count")
            logger().info(f"iter_count:{iter_count}")
            for count in range(iter_count):
                service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
                logger().info("*********************** Start BLE in DUT ***********************")
                ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
                assert ble_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_start_advertising()
                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                wifi_dut.interfaces.wifi.enable_bt_power_save()
                ble_client_address= sl_collections.scan_from_remote_device(wifi_dut=wifi_dut, ble_client=ble_client,
                                                                           ble_dut_address=ble_dut_address,
                                                                           services=["HealthThermometerService"])
                logger().info("*********************** connect to ble dut ***********************")
                ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address)
                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)
                logger().info("******************** get connection state")
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "********************* device is in disconnection state"
                char_path = discover_service_char_of_dut_in_remote(wifi_dut, ble_client, service_uid, char_uid,
                                                                   ble_client_address)
                time.sleep(5)
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                allocated_mem_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(data))
                logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
                wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data),
                                                     write_content=data)
                write_handle = discover_service_char_of_remote_in_dut(wifi_dut=wifi_dut, ble_client=ble_client,
                                                                      ble_client_address=ble_client_address)
                time.sleep(5)
                obj1 = SendDataFromDut(wifi_dut, ble_client, ble_client_address, service_uid, char_uid, data, char_path,
                                       allocated_mem_addr)
                obj2 = SendDataFromRemote(wifi_dut, ble_client, ble_client_address, 100, write_handle)
                obj1.start()
                time.sleep(2)
                obj2.start()
                time.sleep(2)
                obj1.wait_for_exit()
                obj2.wait_for_exit()
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()
                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(ble_dut_address)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr)
        ble_client.interfaces.bluetooth.close()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "enable_duty_cycle": True,
        "duty_cycle": 1,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C19931')
def test_ble_master_tx_rx_230_bytes_C19931(wifi_dut, ble_client, sl_collections, utf_constants):
    """ Validate BLE Tx and Rx as Master by configuring data length with 230bytes without Duty cycling."""
    bt_mon_log_file_name = (f"reports/test_ble_master_tx_rx_230_bytes_C19931"
                            f"{int(time.time())}.log")
    svc = 'HealthThermometerService'
    charc = "CustomNotifyCharacteristic"
    try:
        with BleLogs(start_collecting_logs=True, bt_log_path=bt_mon_log_file_name):
            iter_count = utf_constants.get("iter_count")
            for count in range(iter_count):
                service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
                char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
                logger().info("*********************** Start BLE in DUT ***********************")
                ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=0)
                assert ble_dut_address, "failed to initialize ble in dut"
                wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
                wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
                wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)
                assert ble_dut_address, "failed to initialize ble in dut"
                logger().info("******************** initializing ble in remote device ********************")
                ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(
                    bt_dut_address=ble_dut_address, service_classes=[svc])
                assert ble_client_address, "failed to initialize ble in remote device"
                logger().info("******************** start scanning in dut ********************")
                wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=100)
                logger().info(f"....Applying performance profile mode and Enable_bt_power_save")
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                wifi_dut.interfaces.wifi.enable_bt_power_save()
                wifi_dut.interfaces.wifi.ble_stop_scanning()
                logger().info(f".... initiating ble connection ....")
                wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address)
                logger().info(".... checking for ble connectivity stability ....")
                time.sleep(60)
                state = wifi_dut.interfaces.wifi.ble_get_device_state()
                state_int = int(state) if state.isdigit() else -1
                assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
                char_path = discover_service_char_of_dut_in_remote(wifi_dut, ble_client, service_uid, char_uid,
                                                                   ble_client_address)
                time.sleep(5)
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=230))
                allocated_mem_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(data))
                logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
                wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data),
                                                     write_content=data)
                write_handle = discover_service_char_of_remote_in_dut(wifi_dut=wifi_dut, ble_client=ble_client,
                                                                      ble_client_address=ble_client_address)
                time.sleep(5)
                obj1 = SendDataFromDut(wifi_dut, ble_client, ble_client_address, service_uid, char_uid, data, char_path,
                                       allocated_mem_addr)
                obj2 = SendDataFromRemote(wifi_dut, ble_client, ble_client_address, 230, write_handle)
                obj1.start()
                time.sleep(2)
                obj2.start()
                time.sleep(2)
                obj1.wait_for_exit()
                time.sleep(2)
                obj2.wait_for_exit()
                logger().info("******************** ble_remove_service ***********************")
                wifi_dut.interfaces.wifi.ble_remove_service()
                logger().info("*********************** Disconnecting from DUT ***********************")
                ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr)
        ble_client.interfaces.bluetooth.close()



@pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            },
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | Si91xFeatureBitMap.WPSSupportDisabled,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                                   Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        },
    )

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C537347')
def test_ble_hogp_smp_master_mode_C537347(ble_dut, ble_client, sl_collections):
    with BleLogs(
            start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_hogp_smp_master_mode_C537347.log_{int(time.time())}",
    ) as bt_logs:
        ble_dut_addr = ble_dut.interfaces.wifi.ble_gatt_start()
        assert ble_dut_addr, "FAILED TO LOAD BT ADDRESS..."
        try:
            logger().info("....ADDING HID SERVICE....")
            ble_dut.interfaces.wifi.ble_add_hid_service()
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_addr)
            assert ble_client_address, f"ble initialization failed in remote device"

            time.sleep(5)
            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=ble_client_address)
            time.sleep(2)
            logger().info("..ENTERING POWER SAVE MODE..")
            enable_wifi_ps = ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            assert enable_wifi_ps == 0, '..FAILED TO ENABLE WIFI POWER SAVE..'
            enable_bt_ps = ble_dut.interfaces.wifi.enable_bt_power_save(
                psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps == 0, '..FAILED TO ENABLE BT POWER SAVE..'
            logger().info("stop scanning")
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            logger().info(f"Initiating ble connection...")
            ble_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=60)
            logger().info(f"Ble connection is successful")
            time.sleep(60)
            logger().info("Check connection status of BLE")
            status = ble_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(status) if status.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
            logger().info("..ENTERING POWER SAVE MODE..")

            test_data = ["0xb", "0x0", "0x12", "0x0", "0xa", "0x0"]
            test_data_expected_from_raspi = [
                "11,00,00,0b,00,00,00,00,00,00,00,00",
                "11,00,00,00,00,00,00,00,00,00,00,00",
                "11,00,00,12,00,00,00,00,00,00,00,00",
                "11,00,00,00,00,00,00,00,00,00,00,00",
                "11,00,00,0a,00,00,00,00,00,00,00,00",
                "11,00,00,00,00,00,00,00,00,00,00,00",
            ]
            with HidRecorder() as hid_recorder:
                for item in test_data:
                    ble_dut.interfaces.wifi.ble_hid_send_interrupt(item)
                    time.sleep(0.5)
                hid_logs = hid_recorder.logs()

            assert len(hid_logs) == len(test_data), "LENGTH OF HID DATA DOESN'T MATCH..."
            for i in range(len(test_data)):
                assert hid_logs[i] == test_data_expected_from_raspi[i], f"HID DATA {hid_logs[i]} DOESN'T MATCH WITH " \
                                                                        f"EXPECTED DATA {test_data_expected_from_raspi[i]}..."
            time.sleep(2)
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=ble_client_address)
            time.sleep(5)
        except Exception as Ex:
            sl_collections.exception_handling(wifi_dut=ble_dut, exception=Ex)
        finally:
            ble_client.interfaces.bluetooth.remove_device(ble_dut_addr)
