import pytest
import pandas as pd
import string
import re
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (BodySensorLocationCharacteristic,
                                                                                HeartRateControlPointCharacteristic,
                                                                                HeartRateMeasurementCharacterstic)
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService, HealthThermometerMeasurementCharacteristic
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap
)
from utf.interfaces.bluetooth.bluetooth_interface import (
    BluetoothInterface,
    BTRole,
    BTProfile,
    BTEvents,
    BLEPermissions,
    )
from utf.utf_config import UtfConfig
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
import time, os
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from datetime import timedelta, datetime
import random
import string
import threading


def logger():
    return get_logger(__name__)


lock = threading.Lock()
"""
    * setup requirement:
        1. DUT(RS9117) SOC board
        2. REF(RS9117) SOC board
        3. Teledyne sniffer (to capture BLE OTA logs)
        4. NUC and nRF(To capture and validate OTA logs using Tshark) - optional
        5. Ellysis (to Capture OTA logs) - optional
    
"""


class TxIndicationFunctionality:
    def __init__(self, ble_dut=None, ble_client=None, ble_client_address=None, char_path=None, char_uuid=None,
                 data=None, indication_time=None, data_length=None, allocated_mem_addr=None, handle=None, indication_count=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.char_path = char_path
        self.char_uuid = char_uuid
        self.data = data
        self.indication_time = indication_time
        self.data_length = data_length
        self.allocated_mem_addr = allocated_mem_addr
        self.handle = handle
        self.indication_count = indication_count

    def run(self):
        self.indication_count = 15
        def write():
            logger().info(f"****** Indication value****************")
            self.ble_dut.interfaces.bluetooth.ble_indicate_value(ble_remote_dev_address=self.ble_client_address,
                                                                 handle=self.handle, data=self.data,
                                                                 data_length=self.data_length, data_address=self.allocated_mem_addr)#, async_timeout=30)
            time.sleep(25)

        indication_count = 0
        if self.indication_count:
            for i in range(self.indication_count):
                with lock:
                    write()
                time.sleep(1)
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.indication_time:
                with lock:
                    write()
                    indication_count +=1

        if not self.indication_count:
            self.indication_count = indication_count
        logger().info(f"Indication_count: {self.indication_count}")


class WriteWithResponseFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, write_handle=None, data=None,
                 data_length=None, write_time=None, write_count=None, allocated_mem_addr=None):
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.write_handle = write_handle
        self.data = data
        self.data_length = data_length
        self.write_time = write_time
        self.write_count = write_count
        self.allocated_mem_addr = allocated_mem_addr
        self.write_data_count = None

    def run(self):
        logger().info(f"*******Write With Response Start****************")
        write_data_count = 0

        def write():

            self.ble_dut.interfaces.bluetooth.ble_set_att_value_async(
                ble_remote_dev_address=self.ble_client_address,
                char_property=self.write_handle, data=self.data, data_length=self.data_length,
                data_address=self.allocated_mem_addr)#, async_timeout=30)
            logger().info("******************** Write With Response functionality ***********************")
            time.sleep(20)

        if self.write_count:
            for i in range(self.write_count):
                with lock:
                    write()
                time.sleep(1)
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.write_time:
                with lock:
                    write()
                    write_data_count += 1
        if not self.write_count:
            self.write_count = write_data_count
        logger().info(f"------WRITE-DATA-COUNT------:{self.write_count}")


class WriteWithoutResponseFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, data=None, data_length=None,
                 write_handle=None, write_time=None, write_count=None, allocated_mem_addr=None,
                 bt_mon_log_file_name=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.data = data
        self.data_length = data_length
        self.write_handle = write_handle
        self.write_time = write_time
        self.write_count = write_count
        self.allocated_mem_addr = allocated_mem_addr
        self.bt_mon_log_file_name = bt_mon_log_file_name

    def run(self):
        logger().info(f"*******Write Without Response Start****************")
        self.write_count = 15
        def write():
            time.sleep(2)
            self.ble_dut.interfaces.wifi.ble_set_att_cmd(ble_remote_dev_address=self.ble_client_address,
                                                         handle=self.write_handle, data_length=self.data_length,
                                                         data=self.data, data_address=self.allocated_mem_addr)

        data_count = 0
        if self.write_count:
            for i in range(self.write_count):
                with lock:
                    write()
                time.sleep(1)
        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.write_time:
                with lock:
                    write()
                    data_count += 1

        if not self.write_count:
            self.write_count = data_count
        logger().info(f"*******Write Without Response End****************")


class TxNotificationFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_client_address=None, data=None, service_uid=None, char_uid=None,
                 char_path=None, allocated_mem_addr=None, notification_count=None):
        super().__init__()
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_client_address = ble_client_address
        self.data = data
        self.service_uid = service_uid
        self.char_uid = char_uid
        self.char_path = char_path
        self.allocated_mem_addr = allocated_mem_addr
        self.notification_count = notification_count

    def run(self):
        self.notification_count = 15
        logger().info(f"NOTIFICATION COUNT:{self.notification_count}")
        def write():
            logger().info("******************** Start TX Notifications functionality ***********************")
            self.ble_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=self.ble_client_address,
                                                                 data=self.data, data_address=self.allocated_mem_addr)
            time.sleep(5)
            logger().info("******************** Validate Data ********************")
        notification_count = 0
        time.sleep(1)

        if self.notification_count:
            for i in range(self.notification_count):
                logger().info(f"******tx notification count {notification_count} and range:{i}")
                with lock:
                    write()
                time.sleep(1)

        else:
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                with lock:
                    write()
                    notification_count += 1

        if not self.notification_count:
            self.notification_count = notification_count
        logger().info(f"TX_Notification count: {self.notification_count}")


class RxNotificationFunctionality:
    def __init__(self, ble_dut=None, ble_clients=None, ble_dut_address=None, data=None, svc=None, charc=None,
                 rx_notification_count=None, notify_time=600, allocated_mem_addr=None):
        self.ble_dut = ble_dut
        self.ble_clients = ble_clients
        self.ble_dut_address = ble_dut_address
        self.data = data
        self.svc = svc
        self.charc = charc
        self.rx_notification_count = rx_notification_count
        self.notify_time = notify_time
        self.allocated_mem_addr = allocated_mem_addr

    def run(self):
        self.rx_notification_count = 15
        def write():
            logger().info("---------write data to ble client-------------")
            self.ble_clients.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=self.ble_dut_address,
                                                                 data=self.data, data_address=self.allocated_mem_addr)
            time.sleep(3)
            logger().info("---------send_gatt_charc_notification-------------")
        rx_notification_count = 0
        time.sleep(1)
        try:
            if self.rx_notification_count:
                for i in range(self.rx_notification_count):
                    logger().info(f"******rx notification count {rx_notification_count} and range:{i}")
                    with lock:
                        logger().info("lock")
                        write()
                    time.sleep(1)
            else:
                sw = Stopwatch()
                while sw.elapsed_sec <= self.notify_time:
                    with lock:
                        write()
                        rx_notification_count += 1
        except Exception as e:
            logger().info(e)
        if not self.rx_notification_count:
            self.rx_notification_count = rx_notification_count

        logger().info(f"RX_Notification count: {self.rx_notification_count}")


def configure_buffer_mode(self, mode=None, count=None):
    logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} ****************")
    self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                            buffer_mode=mode,
                                                            buffer_count=count)
    logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} Success ****************")


def ble_ae_slave(ble_dut, remote_wiseconnect3, ble_dut_address, ble_client_address, sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=None):
    ble_dut.interfaces.wifi.ble_set_smp(set_smp=0)
    remote_wiseconnect3.interfaces.wifi.ble_set_smp(set_smp=1)
    remote_wiseconnect3.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)
    adv_type = 1
    sl_collections.ble_ae_set_params(pheripheral_dev=ble_dut, adv_event_prop=adv_type, own_address_type=0,
                                     peer_addr_type=0, peer_address=ble_client_address, adv_handle=0,
                                     pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, scan_req_notify_enable=1,
                                     adv_filter_policy=0, sec_adv_max_skip=1, adv_min_interval=48, adv_max_interval=48)
    adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
    sl_collections.ble_set_ae_data(ble_dut=ble_dut, dut_address=ble_dut_address, adv_data_type=1,
                                   data_len=len(adv_data), adv_data=adv_data, adv_handle=0)
    sl_collections.ble_set_ae_data(ble_dut=ble_dut, dut_address=ble_dut_address, adv_data_type=3,
                                   data_len=len(adv_data), adv_data=adv_data, adv_handle=0,
                                   scan_resp_len=0)
    sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address, duration=0,
                                            max_ae_events=0, adv_handle=0, adv_async_required=0)
    time.sleep(60)
    remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_params(ble_addr_type=0,
                                                   scanning_phys=1,
                                                   scanning_filter_policy=0,
                                                   scan_type=1,
                                                   scan_type_sec=1,
                                                   ScanInterval=48,
                                                   ScanWindow=48,
                                                   remote_addr_type=0,
                                                   scan_interval_sec=48,
                                                   scan_window_sec=30)

    remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(enable=1,
                                                   filter_duplicates=0,
                                                   duration=0,
                                                   period=0, remote_address=ble_dut_address)
    time.sleep(5)
    remote_wiseconnect3.interfaces.wifi.ble_ae_set_scan_enable(enable=0,
                                                   filter_duplicates=0,
                                                   duration=0, period=0,
                                                   remote_address=ble_dut_address)
    time.sleep(20)
    logger().info("getting the device state")
    state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"\nDevice state: {state_int}")
    retries = 3
    for retry in range(retries):
        try:
            remote_wiseconnect3.interfaces.wifi.ble_extended_connect_with_params(remote_dev_addr=ble_dut_address,
                                                                     remote_addr_type=0,
                                                                     initiator_filter_policy=0,
                                                                     init_phys=7,
                                                                     ConnIntervalMin=50,
                                                                     ConnIntervalMax=50)
            time.sleep(60)
            logger().info("\nChecking connection status of BLE")
            state = remote_wiseconnect3.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"\nDevice state: {state_int}")
            assert state_int == 8, "DUT BLE device is not in connected state"
            break
        except Exception as ex:
            logger().info(f"Exception occurred while connecting to BLE device: {str(ex)}")
            logger().info(f"BLE connection failed with retries {retry + 1}")
            if retry == retries - 1:
                raise

    tw = Stopwatch()
    link_key2 = ""
    while tw.elapsed_sec < 180:
        events = ble_dut.interfaces.bluetooth.get_async_events()  # since_time=0)
        logger().info(f"---------------->Events: {events}")
        for event in events:
            logger().info(f"---------------->Event Data: {event.event_data}")
            if "link_key" in event.event_data:
                event_data = event.event_data
                link_key_data = re.findall("((?<=link_key:: ).*:)", event_data)[-1]
                logger().info(f"link_key_data : {link_key_data}")
                link_key = '0x' + "".join(
                    [i.strip() if len(i.strip()) == 2 else '0' + i.strip() for i in link_key_data.split(":")][:16])
                if link_key1 != link_key:
                    logger().info(f"LINK-GENERATED:{link_key}")
                    link_key2 = link_key
                    break
            else:
                continue
        if link_key1 != link_key2 and link_key2:
            logger().info(f"LINK-GENERATED:{link_key2}")
            break
    logger().info(f"-------link_key1--------:{link_key1}")
    logger().info(f"----------link_key2----------:{link_key2}")
    logger().info(f"**************Second Link Key Extracted: {link_key2}***************")
    assert len(link_key2) == 34, f"link key is not proper format"
    return link_key2

def ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address, adv_data, pri_adv_phy=1, sec_adv_phy=1):
    ble_dut.interfaces.wifi.ble_set_smp(set_smp=1)
    remote_wiseconnect3.interfaces.wifi.ble_set_smp(set_smp=0)
    logger().info("\n\n ***** Configuring AE advertising parameters ***** \n\n")
    ble_dut.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)
    adv_type = 1
    logger().info("SET PARAMS FROM REMOTE WISECONNECT3 TO BLE DUT")
    logger().info("\n\n ***** Configuring AE advertising parameters ***** \n\n")
    remote_wiseconnect3.interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=adv_type,
                                                          primary_adv_intterval_min=48,
                                                          primary_adv_intterval_max=48,
                                                          own_addr_type=0,
                                                          peer_addr_type=0,
                                                          remote_dev_addr=ble_dut_address,
                                                          primary_adv_phy=pri_adv_phy,
                                                          sec_adv_max_skip=1,
                                                          sec_adv_phy=sec_adv_phy,
                                                          scan_req_notify_enable=1,
                                                          adv_filter_policy=0,
                                                          timeout=30)
    logger().info("\n ***** Successfully Configured AE advertising parameters ***** \n\n")

    logger().info(f"adv_data: {adv_data}")
    remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                        data_len=len(adv_data), data=adv_data)
    logger().info(
        f"\n\n ***** AE advertising Data configured successfully on {ble_client_address} with data type: BLE_AE_ADV_DATA_TYPE***** \n\n")
    remote_wiseconnect3.interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0, operation=0,
                                                        data_len=len(adv_data), data=adv_data)
    remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=1, no_of_sets=1, adv_handle=0, duration=0,
                                                                 max_ae_events=0,
                                                                 )
    time.sleep(60)
    ble_dut.interfaces.bluetooth.ble_ae_set_scan_params(ble_addr_type=0,
                                                        scanning_phys=1,
                                                        scanning_filter_policy=0,
                                                        scan_type=1,
                                                        scan_type_sec=1,
                                                        ScanInterval=48,
                                                        ScanWindow=48,
                                                        remote_addr_type=0,
                                                        scan_interval_sec=48,
                                                        scan_window_sec=30)

    ble_dut.interfaces.bluetooth.ble_ae_set_scan_enable(enable=1,
                                                        filter_duplicates=0,
                                                        duration=0,
                                                        period=0, remote_address=ble_client_address)
    logger().info("\n\nenable power save in ble dut")
    
    time.sleep(20)
    ble_dut.interfaces.wifi.ble_ae_set_scan_enable(enable=0, filter_duplicates=0, duration=0, period=0,
                                                   remote_address=ble_client_address)
                            
    ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                 psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
    ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
    retries = 3
    for retry in range(retries):
        try:
            ble_dut.interfaces.bluetooth.ble_extended_connect_with_params(remote_dev_addr=ble_client_address,
                                                                          remote_addr_type=0, initiator_filter_policy=0,
                                                                          init_phys=7, ConnIntervalMin=50, ConnIntervalMax=50)
            time.sleep(60)
            logger().info("\nChecking connection status of BLE")
            state = ble_dut.interfaces.bluetooth.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            logger().info(f"CONNECTED STATE: {BLEDeviceState.Connected}")
            assert state_int == 8, "DUT BLE device is not in connected state"
            break
        except Exception as ex:
            logger().info(f"Exception occurred while connecting to BLE device: {str(ex)}")
            logger().info(f"BLE connection failed with retries {retry + 1}")
            if retry == retries - 1:
                raise
    logger().info(f"ble client address 1: {ble_client_address}")
    tw = Stopwatch()
    link_key1 = ""
    while tw.elapsed_sec < 120:
        events = ble_dut.interfaces.bluetooth.get_async_events()  # since_time=0)
        for event in events:
            if "link_key" in event.event_data:
                event_data = event.event_data
                link_key_data = re.findall("(?<=link_key:: ).*:", event_data)[0]
                logger().info(f"link_key_data : {link_key_data}")
                link_key1 = '0x' + "".join(
                    [i.strip() if len(i.strip()) == 2 else '0' + i.strip() for i in link_key_data.split(":")][:16])
            else:
                continue
        if link_key1:
            break
    logger().info(f"**************First Link Key Extracted: {link_key1}***************")
    assert len(link_key1) == 34, f"link key is not proper format"
    return link_key1


def service_discovery_on_remote(ble_dut, ble_client_address, service_uuid=None, char_uuid=None, characteristic=None):
    logger().info("\n\n ***** Performing GATT profile discovery on Remote (raspi)  ***** \n\n\n")
    # get all profiles
    uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address, async_timeout=120)
    if len(uuids)==0:
        time.sleep(2)
        uuids = ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address,
                                                               async_timeout=120)
        logger().info(f"UUIds {uuids}")
    start_handle, end_handle, data = ble_dut.interfaces.wifi.ble_get_profile_async(
        ble_remote_dev_address=ble_client_address,
        uuid=int(str(service_uuid), 16),
        async_timeout=60)
    logger().info(f"start_handle:{start_handle}, end_handle:{end_handle}")
    assert start_handle is not None
    assert end_handle is not None
    #
    char_uuids, write_handles, char_properties = ble_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address,
        start_handle=int(start_handle, 16),
        end_handle=int(end_handle, 16),
        async_timeout=60)
    logger().info(
        f"characteristics uuids :{char_uuids}  write_handles{write_handles} : Characteristics_properties"
        f"{char_properties}")

    assert char_uuid in char_uuids, "Unable to find {} uuid".format(char_uuid)
    index = char_uuids.index(char_uuid)
    logger().info(f"UUID's are:{char_uuids}")
    logger().info(f"write_handles:{write_handles}")
    logger().info(f"index:{index}")
    logger().info(f"characteristic:{characteristic}")
    logger().info(f"char_properties:{int(char_properties[index])}")
    logger().info(type(characteristic))
    logger().info(type(int(char_properties[index])))
    logger().info("validateing the characteristic property")
    assert char_properties[index].isdigit(), "Character property found is not an integer"
    assert characteristic == int(char_properties[index]), "Invalid character property found"
    write_handle = int(write_handles[index], 16)
    logger().info(f"write_handle:{write_handle}")
    assert write_handle > 0, "Unable to get write handle for configured service"

    return write_handle

def service_discovery_on_dut(ble_dut, service_uid=None, char_uid=None):
    time.sleep(3)
    servs, chars = ble_dut.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    time.sleep(5)
    logger().info(f"{servs} {chars}")
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"

    char_path, char_props = ble_dut.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
        services=servs,
        service_uid=service_uid,
        char_uid=char_uid)
    time.sleep(5)
    logger().info(f"{char_props}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"
    logger().info("------CHARACTERISTICS----")
    return char_path, char_props

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C662086')
def test_dut_master_and_slave_tx_rx_notification_C662086(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C662086")
        write_handle_1 = None
        write_handle_2 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)  # capability=3, set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        logger().info(f"BLE-CLIENT-ADDRESS_2:{ble_client_address_2}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=2, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(adv_data),
                                                        write_content=adv_data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1aa1",
                                                   BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************_1")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address_2, "0xAABB",
                                                   "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_dut_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                              allocated_mem_addr=allocated_mem_addr, data=adv_data,
                                                ble_client_address=ble_client_address, notification_count=50)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_2 + 1), enable_notify=1)
        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                              ble_dut_address=ble_dut_address, data=adv_data, svc=svc,
                                              charc=charc, rx_notification_count=50,
                                              allocated_mem_addr=allocated_mem_addr_2)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 23)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (sniffer_data_df[
                                                               '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 23)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C663031')
def test_dut_master_and_slave_tx_rx_notification_C663031(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        write_handle_1 = None
        write_handle_2 = None
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C663031")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address, adv_data, pri_adv_phy=3, sec_adv_phy=3)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2, sl_collections, pri_adv_phy=3, sec_adv_phy=3, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(adv_data),
                                                        write_content=adv_data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1aa1",
                                                   BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        write_handle_2 = service_discovery_on_remote(
            ble_dut, ble_client_address_2, "0xAABB",
                                                   "0x1aa1",
            BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_dut_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=adv_data,
                                                ble_client_address=ble_client_address, notification_count=50)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_2 + 1), enable_notify=1)
        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                              ble_dut_address=ble_dut_address, data=adv_data, svc=svc,
                                              charc=charc, rx_notification_count=50,
                                              allocated_mem_addr=allocated_mem_addr_2)

        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 23)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (sniffer_data_df[
                                                               '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 23)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)

    #663031
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C538065')
def test_dut_master_and_slave_tx_rx_notification_C538065(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 1M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C538065")
        write_handle_1 = None
        write_handle_2 = None
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)#0xAABB)#
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)#0x1AA1)#
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)#0x1AA1)#
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address, adv_data, pri_adv_phy=1, sec_adv_phy=1)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2, sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(adv_data), write_content=adv_data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(adv_data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(adv_data),
                                                        write_content=adv_data)
        # write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, HealthThermometerService.UUID,
        #                                              CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID, BLEPermissions.DEFAULT)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1aa1", BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        write_handle_2 = service_discovery_on_remote(
            ble_dut, ble_client_address_2, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} ****************")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_dut_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{0} and Buffer count:{2} Success ****************")
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                              allocated_mem_addr=allocated_mem_addr, data=adv_data,
                                                ble_client_address=ble_client_address, notification_count=5)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_2 + 1), enable_notify=1)
        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                              ble_dut_address=ble_dut_address, data=adv_data, svc=svc,
                                              charc=charc, rx_notification_count=5,
                                              allocated_mem_addr=allocated_mem_addr_2)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread2.start()
        time.sleep(4)
        thread1.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        logger().info(f"link-key:{link_key1}, {link_key2}")
        logger().info(f"type of link key:{type(link_key1)} {type(link_key2)}")
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 23)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 23)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_dut_master_and_slave_tx_tx_notification_C663033(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    #   Working
    try:
        write_handle_1 = None
        write_handle_2 = None
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_tx_notification_C663033")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=2, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        write_handle_2 = service_discovery_on_remote(
            ble_dut, ble_client_address_2, "0xAABB", "0x1aa1",
            BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        logger().info("Notification has enabled")
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=50)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_2 + 1), enable_notify=1)
        logger().info("Notification has enabled")
        ble_fun_2 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=50)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            logger().info(f"-------link_key2--------:{link_key2}")
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
            logger().info("link key is added to sniffer")
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (sniffer_data_df[
                                                               '+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun_2.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_dut_master_and_slave_tx_tx_notification_C663034(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # working
    try:
        write_handle_1 = None
        write_handle_2 = None
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_tx_notification_C663034")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=3, sec_adv_phy=3)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=3, sec_adv_phy=3, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        try:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, "0xAABB", "0x1aa1",
                BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, HealthThermometerService.UUID,
                CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        logger().info("Notification has enabled")
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=50)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_2 + 1), enable_notify=1)
        logger().info("Notification has enabled")
        ble_fun_2 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=50)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (sniffer_data_df[
                                                               '+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun_2.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)

#
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_dut_master_and_slave_tx_write_without_response_C663037(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 1M
        """
    # Working
    try:
        write_handle_1 = None
        write_handle_2 = None
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_write_without_response_C663037")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)  # 0xAABB)#
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)  # 0x1AA1)#
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)  # 0x1AA1)#
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1802)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a06)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a06)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2)
        logger().info(f"link_key1: {link_key1}")
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=2, link_key1=link_key1)
        logger().info(f"link_key2: {link_key2}")
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        try:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, "0xAABB", "0x1aa1",
                BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, ImmediateAlertService.UUID, ImmediateAlertLevelCharacteristic.LLA_UUID,
                BLEPermissions.DEFAULT)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                               allocated_mem_addr=allocated_mem_addr, data=data,
                                               ble_client_address=ble_client_address, notification_count=50)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                           buffer_mode=0,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                     ble_client_address=ble_client_address_2,
                                                     write_handle=write_handle_2, data_length=230, data=data,
                                                     write_count=50, allocated_mem_addr=allocated_mem_addr)
        thread1 = threading.Thread(target=ble_fun1.run)
        thread2 = threading.Thread(target=ble_fun2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun2.write_count / 2), "No ATT_WRITE_CMD packets are present"
        logger().info("ATT_WRITE_CMD packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_dut_master_and_slave_tx_write_without_response_C663041(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 1M
        """
    # Working
    try:
        write_handle_1 = None
        write_handle_2 = None
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_write_without_response_C663041")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)  # 0xAABB)#
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)  # 0x1AA1)#
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)  # 0x1AA1)#
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1802)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a06)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a06)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=3, sec_adv_phy=3)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=3, sec_adv_phy=3, link_key1=link_key1)

        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=1,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        try:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, "0xAABB", "0x1aa1",
                BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, ImmediateAlertService.UUID, ImmediateAlertLevelCharacteristic.LLA_UUID,
                BLEPermissions.DEFAULT)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                               allocated_mem_addr=allocated_mem_addr, data=data,
                                               ble_client_address=ble_client_address, notification_count=50)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                           buffer_mode=1,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                     ble_client_address=ble_client_address_2,
                                                     write_handle=write_handle_2, data_length=230, data=data,
                                                     write_count=50, allocated_mem_addr=allocated_mem_addr)
        thread1 = threading.Thread(target=ble_fun1.run)
        thread2 = threading.Thread(target=ble_fun2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun2.write_count / 2), "No ATT_WRITE_CMD packets are present"
        logger().info("ATT_WRITE_CMD packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C663094')
def test_dut_master_and_slave_tx_tx_notification_C663094(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # WORKING
    try:
        write_handle_1 = None
        write_handle_2 = None
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_tx_notification_C663094")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address, adv_data, pri_adv_phy=1, sec_adv_phy=1)
        time.sleep(2)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2, sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1aa1",
                                                   BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                                           buffer_mode=1,
                                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        write_handle_2 = service_discovery_on_remote(
            ble_dut, ble_client_address_2, "0xAABB", "0x1aa1",
            BLEPermissions.DEFAULT)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                           buffer_mode=1,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        logger().info("Notification has enabled")
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                              allocated_mem_addr=allocated_mem_addr, data=data, ble_client_address=ble_client_address, notification_count=50)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                       handle=(write_handle_2 + 1), enable_notify=1)
        logger().info("Notification has enabled")
        ble_fun_2 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data, ble_client_address=ble_client_address_2, notification_count=50)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_2.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)
@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_dut_master_and_slave_tx_write_without_response_C663097(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 1M
        """
    #   working
    try:
        write_handle_1 = None
        write_handle_2 = None
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_write_without_response_C663097")
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)#0xAABB)#
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)#0x1AA1)#
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)#0x1AA1)#
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data= "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1802)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a06)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a06)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address, adv_data, pri_adv_phy=1, sec_adv_phy=1)
        time.sleep(2)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2, sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=link_key1)

        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1aa1",
                                                   BLEPermissions.DEFAULT)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                                           buffer_mode=1,
                                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        write_handle_2 = service_discovery_on_remote(
            ble_dut, ble_client_address_2, ImmediateAlertService.UUID, ImmediateAlertLevelCharacteristic.LLA_UUID,
            BLEPermissions.DEFAULT)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                              allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=50)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                                           buffer_mode=1,
                                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        ble_fun2 = WriteWithoutResponseFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                     ble_client_address=ble_client_address_2,
                                                     write_handle=write_handle_2, data_length=230, data=data,
                                                     write_count=50, allocated_mem_addr=allocated_mem_addr)
        thread1 = threading.Thread(target=ble_fun1.run)
        thread2 = threading.Thread(target=ble_fun2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_WRITE_CMD") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun2.write_count / 2), "No ATT_WRITE_CMD packets are present"
        logger().info("ATT_WRITE_CMD packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,# | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE, #| Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,# | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_dut_master_and_slave_tx_indication_C663095(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx indications with DLE disabled and phy rate set to 1M
        """
    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_indication_C663095")
        logger().info("ble-started")
        write_handle_1 = None
        write_handle_2 = None
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)#0xAABB)#
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)#0x1AA1)#
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)#0x1AA1)#
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data= "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=1)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=link_key1)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB", "0x1bb1",
                                                     BLEPermissions.DEFAULT)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                                           buffer_mode=1,
                                                                           buffer_count=2)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        write_handle_2 = service_discovery_on_remote(
            ble_dut, ble_client_address_2, "0xAABB", "0x1bb1", BLEPermissions.DEFAULT)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=remote_wiseconnect3,
                                             ble_client_address=ble_client_address, data=data, data_length=230,
                                             allocated_mem_addr=allocated_mem_addr, handle=12, indication_count=5)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                                           buffer_mode=1,
                                                                           buffer_count=2)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_2 + 1), enable_notify=1)
        ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=remote_wiseconnect3s[0],
                                             ble_client_address=ble_client_address_2, data=data, data_length=230,
                                             allocated_mem_addr=allocated_mem_addr, handle=12, indication_count=5)
        thread1 = threading.Thread(target=ble_fun1.run)
        thread2 = threading.Thread(target=ble_fun2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun1.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"
        logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] == 233)]) >= int(
            ble_fun2.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"

        logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)
        if write_handle_2:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0)
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.test_src_map_id('C663035')
def test_dut_master_and_slave_tx_indication_C663035(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx indications with DLE disabled and phy rate set to 1M
        """
    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_indication_C663035")
        logger().info("ble-started")
        write_handle_1 = None
        write_handle_2 = None
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)#0xAABB)#
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)#0x1AA1)#
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)#0x1AA1)#
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data= "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        time.sleep(2)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2)
        time.sleep(2)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=2, link_key1=link_key1)
        time.sleep(2)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB", "0x1bb1",
                                                     BLEPermissions.DEFAULT)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                                           buffer_mode=1,
                                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        try:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address_2, "0xAABB", "0x1bb1",
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, HealthThermometerService.UUID,
                                                       HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID,
                                                       BLEPermissions.DEFAULT)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=remote_wiseconnect3,
                                             ble_client_address=ble_client_address, data=data, data_length=230,
                                             allocated_mem_addr=allocated_mem_addr, handle=12, indication_count=15)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                                           buffer_mode=1,
                                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_2 + 1), enable_notify=1)
        ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=remote_wiseconnect3s[0],
                                             ble_client_address=ble_client_address_2, data=data, data_length=230,
                                             allocated_mem_addr=allocated_mem_addr, handle=12, indication_count=15)
        thread1 = threading.Thread(target=ble_fun1.run)
        thread2 = threading.Thread(target=ble_fun2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        #Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun1.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"
        logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun2.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"
        
        logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)
        if write_handle_2:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0)
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.check
@pytest.mark.ble_sniffer("frontline_sniffer")
def skip_test_dut_master_and_slave_tx_indication_C663036(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx indications with DLE disabled and phy rate set to 1M
        """
    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_indication_C663036")
        logger().info("ble-started")
        write_handle_1 = None
        write_handle_2 = None
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)#0xAABB)#
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)#0x1AA1)#
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)#0x1AA1)#
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data= "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0xAABB)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x1bb1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x1bb1)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=3, sec_adv_phy=3)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=3, sec_adv_phy=3, link_key1=link_key1)
        try:
            write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB", "0x1bb1",
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                         HealthThermometerService.UUID,
                                                         HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID,
                                                         BLEPermissions.DEFAULT)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                           buffer_mode=1,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        try:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address_2, "0xAABB", "0x1bb1",
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, HealthThermometerService.UUID,
                HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID,
                BLEPermissions.DEFAULT)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun1 = TxIndicationFunctionality(ble_dut, ble_client=remote_wiseconnect3,
                                             ble_client_address=ble_client_address, data=data, data_length=230,
                                             allocated_mem_addr=allocated_mem_addr, handle=12, indication_count=15)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} ****************")
        ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address_2,
                                                           buffer_mode=1,
                                                           buffer_count=1)
        logger().info(f"*******Configure Buffer Mode:{1} and Buffer count:{2} Success ****************")
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_2 + 1), enable_notify=1)
        ble_fun2 = TxIndicationFunctionality(ble_dut, ble_client=remote_wiseconnect3s[0],
                                             ble_client_address=ble_client_address_2, data=data, data_length=230,
                                             allocated_mem_addr=allocated_mem_addr, handle=12, indication_count=15)
        thread1 = threading.Thread(target=ble_fun1.run)
        thread2 = threading.Thread(target=ble_fun2.run)
        thread1.start()
        thread2.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun1.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"
        logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun2.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"

        logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)
        if write_handle_2:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_2 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C768424')
def test_dut_master_and_slave_tx_rx_notification_C768424(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 1M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C768424")
        write_handle_1 = None
        write_handle_2 = None
        write_handle_3 = None
        write_handle_4 = None
        time.sleep(2)
        logger().info("ble-started")

        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=1)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(data),
                                                        write_content=data)
        allocated_mem_addr_3 = remote_wiseconnect3s[0].interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3s[0].interfaces.wifi.load_memory(address=allocated_mem_addr_3, size=len(data),
                                                            write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode=1, buffer_count=1)
        try:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address,HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(remote_wiseconnect3, ble_dut_address, buffer_mode=1, buffer_count=1)
        write_handle_3 = service_discovery_on_remote(remote_wiseconnect3s[0], ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        try:
            write_handle_4 = service_discovery_on_remote(ble_dut, ble_client_address_2, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_4 = service_discovery_on_remote(
                ble_dut, ble_client_address_2,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address_2, buffer_mode=1, buffer_count=1)
        buffer_configuration_mode(remote_wiseconnect3s[0], ble_dut_address, buffer_mode=1, buffer_count=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                       handle=(write_handle_2 + 1), enable_notify=1)

        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_2)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_3 + 1), enable_notify=1)
        ble_fun_3 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_4 + 1), enable_notify=1)
        ble_fun_4 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_3)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread3 = threading.Thread(target=ble_fun_3.run)
        thread4 = threading.Thread(target=ble_fun_4.run)
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "P") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_3.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_4.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        if write_handle_3:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_3 + 1), enable_notify=0)
        if write_handle_4:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_4 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3.interfaces.wifi.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)
        

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C768425')
def test_dut_master_and_slave_tx_rx_notification_C768425(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 1M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C768425")
        write_handle_1 = None
        write_handle_2 = None
        write_handle_3 = None
        write_handle_4 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=2, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(data),
                                                        write_content=data)
        allocated_mem_addr_3 = remote_wiseconnect3s[0].interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3s[0].interfaces.wifi.load_memory(address=allocated_mem_addr_3, size=len(data),
                                                            write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode=1, buffer_count=1)
        try:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(remote_wiseconnect3, ble_dut_address, buffer_mode=1, buffer_count=1)
        write_handle_3 = service_discovery_on_remote(remote_wiseconnect3s[0], ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        try:
            write_handle_4 = service_discovery_on_remote(ble_dut, ble_client_address_2,HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_4 = service_discovery_on_remote(
                ble_dut, ble_client_address_2,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address_2, buffer_mode=1, buffer_count=1)
        buffer_configuration_mode(remote_wiseconnect3s[0], ble_dut_address, buffer_mode=1, buffer_count=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                       handle=(write_handle_2 + 1), enable_notify=1)

        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_2)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_3 + 1), enable_notify=1)
        ble_fun_3 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_4 + 1), enable_notify=1)
        ble_fun_4 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_3)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread3 = threading.Thread(target=ble_fun_3.run)
        thread4 = threading.Thread(target=ble_fun_4.run)
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "P") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_3.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_4.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        if write_handle_3:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_3 + 1), enable_notify=0)
        if write_handle_4:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_4 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3.interfaces.wifi.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C768426')
def test_dut_master_and_slave_tx_rx_notification_C768426(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 1M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C768426")
        write_handle_1 = None
        write_handle_2 = None
        write_handle_3 = None
        write_handle_4 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=3, sec_adv_phy=3)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=3, sec_adv_phy=3, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(data),
                                                        write_content=data)
        allocated_mem_addr_3 = remote_wiseconnect3s[0].interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3s[0].interfaces.wifi.load_memory(address=allocated_mem_addr_3, size=len(data),
                                                            write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode=1, buffer_count=1)
        try:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address,HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(remote_wiseconnect3, ble_dut_address, buffer_mode=1, buffer_count=1)
        write_handle_3 = service_discovery_on_remote(remote_wiseconnect3s[0], ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        try:
            write_handle_4 = service_discovery_on_remote(ble_dut, ble_client_address_2, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_4 = service_discovery_on_remote(
                ble_dut, ble_client_address_2,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address_2, buffer_mode=1, buffer_count=1)
        buffer_configuration_mode(remote_wiseconnect3s[0], ble_dut_address, buffer_mode=1, buffer_count=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                       handle=(write_handle_2 + 1), enable_notify=1)

        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_2)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_3 + 1), enable_notify=1)
        ble_fun_3 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_4 + 1), enable_notify=1)
        ble_fun_4 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_3)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread3 = threading.Thread(target=ble_fun_3.run)
        thread4 = threading.Thread(target=ble_fun_4.run)
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "P") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_3.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_4.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        if write_handle_3:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_3 + 1), enable_notify=0)
        if write_handle_4:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_4 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3.interfaces.wifi.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)

@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C768427')
def test_dut_master_and_slave_tx_rx_notification_C768427(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 1M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C768427")
        write_handle_1 = None
        write_handle_2 = None
        write_handle_3 = None
        write_handle_4 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=1)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(data),
                                                        write_content=data)
        allocated_mem_addr_3 = remote_wiseconnect3s[0].interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3s[0].interfaces.wifi.load_memory(address=allocated_mem_addr_3, size=len(data),
                                                            write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode=1, buffer_count=1)
        try:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(remote_wiseconnect3, ble_dut_address, buffer_mode=1, buffer_count=1)
        write_handle_3 = service_discovery_on_remote(remote_wiseconnect3s[0], ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        try:
            write_handle_4 = service_discovery_on_remote(ble_dut, ble_client_address_2, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_4 = service_discovery_on_remote(
                ble_dut, ble_client_address_2,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address_2, buffer_mode=1, buffer_count=1)
        buffer_configuration_mode(remote_wiseconnect3s[0], ble_dut_address, buffer_mode=1, buffer_count=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                       handle=(write_handle_2 + 1), enable_notify=1)

        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_2)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_3 + 1), enable_notify=1)
        ble_fun_3 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_4 + 1), enable_notify=1)
        ble_fun_4 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_3)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread3 = threading.Thread(target=ble_fun_3.run)
        thread4 = threading.Thread(target=ble_fun_4.run)
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_3.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_4.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        if write_handle_3:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_3 + 1), enable_notify=0)
        if write_handle_4:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_4 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3.interfaces.wifi.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C768428')
def test_dut_master_and_slave_tx_rx_notification_C768428(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C768428")
        write_handle_1 = None
        write_handle_2 = None
        write_handle_3 = None
        write_handle_4 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(
            set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(
            set_smp=0)  # capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address,
                                  adv_data, pri_adv_phy=1, sec_adv_phy=2)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2,
                                 sl_collections, pri_adv_phy=1, sec_adv_phy=2, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(data),
                                                        write_content=data)
        allocated_mem_addr_3 = remote_wiseconnect3s[0].interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3s[0].interfaces.wifi.load_memory(address=allocated_mem_addr_3, size=len(data),
                                                            write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode=1, buffer_count=1)
        try:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(remote_wiseconnect3, ble_dut_address, buffer_mode=1, buffer_count=1)
        write_handle_3 = service_discovery_on_remote(remote_wiseconnect3s[0], ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        try:
            write_handle_4 = service_discovery_on_remote(ble_dut, ble_client_address_2, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_4 = service_discovery_on_remote(
                ble_dut, ble_client_address_2,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address_2, buffer_mode=1, buffer_count=1)
        buffer_configuration_mode(remote_wiseconnect3s[0], ble_dut_address, buffer_mode=1, buffer_count=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                       handle=(write_handle_2 + 1), enable_notify=1)

        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_2)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_3 + 1), enable_notify=1)
        ble_fun_3 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=10)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_4 + 1), enable_notify=1)
        ble_fun_4 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=10,
                                                allocated_mem_addr=allocated_mem_addr_3)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread3 = threading.Thread(target=ble_fun_3.run)
        thread4 = threading.Thread(target=ble_fun_4.run)
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_3.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_4.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        if write_handle_3:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_3 + 1), enable_notify=0)
        if write_handle_4:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_4 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3.interfaces.wifi.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C768429')
def test_dut_master_and_slave_tx_rx_notification_C768429(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C768429")
        write_handle_1 = None
        write_handle_2 = None
        write_handle_3 = None
        write_handle_4 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=230))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address, adv_data, pri_adv_phy=3, sec_adv_phy=3)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2, sl_collections, pri_adv_phy=3, sec_adv_phy=3, link_key1=link_key1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(data),
                                                            write_content=data)
        allocated_mem_addr_3 = remote_wiseconnect3s[0].interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3s[0].interfaces.wifi.load_memory(address=allocated_mem_addr_3, size=len(data),
                                                        write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1aa1",
                                                   BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode=1, buffer_count=1)
        try:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                                                         BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address,
                BLEPermissions.DEFAULT)
        buffer_configuration_mode(remote_wiseconnect3, ble_dut_address, buffer_mode=1, buffer_count=1)
        write_handle_3 = service_discovery_on_remote(remote_wiseconnect3s[0], ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        try:
            write_handle_4 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                BLEPermissions.DEFAULT)
        except:
            write_handle_4 = service_discovery_on_remote(ble_dut, ble_client_address_2, "0xAABB", "0x1aa1",
                                                         BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address_2, buffer_mode=1, buffer_count=1)
        buffer_configuration_mode(remote_wiseconnect3s[0], ble_dut_address, buffer_mode=1, buffer_count=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=5)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                       handle=(write_handle_2 + 1), enable_notify=1)

        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=5,
                                                allocated_mem_addr=allocated_mem_addr_2)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_3 + 1), enable_notify=1)
        ble_fun_3 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=5)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_4 + 1), enable_notify=1)
        ble_fun_4 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=5,
                                                allocated_mem_addr=allocated_mem_addr_3)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread3 = threading.Thread(target=ble_fun_3.run)
        thread4 = threading.Thread(target=ble_fun_4.run)
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_3.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "* C") & (sniffer_data_df[
                                                               '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 233)]) >= int(
            ble_fun_4.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        if write_handle_3:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_3 + 1), enable_notify=0)
        if write_handle_4:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_4 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3.interfaces.wifi.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


@pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
        "remote_wiseconnect3",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
@pytest.mark.config(
    "remote_wiseconnect3s",
    wifi={
        0: {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.SSL,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": Si91xBTFeatureBitMap.RFTypeSelection | Si91xBTFeatureBitMap.BLEFeatureBitmapValid,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "ble_features" : Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV| Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX| Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS| Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
             "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.check
@pytest.mark.test_src_map_id('C768430')
def test_dut_master_and_slave_tx_rx_notification_C768430(ble_dut, remote_wiseconnect3, remote_wiseconnect3s, sl_collections, ble_sniffer):
    """ Verify the BLE AE DUAL Role(1M+1S) connection and tx/rx notifications with DLE disabled and phy rate set to 2M
        """
    # Working
    try:
        logger().info("TESTCASE EXECUTION STARTED")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(
            capture_file="test_dut_master_and_slave_tx_rx_notification_C768430")
        write_handle_1 = None
        write_handle_2 = None
        write_handle_3 = None
        write_handle_4 = None
        logger().info("ble-started")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)  # capability=3, set_smp=1)
        logger().info("ble-started-remote-side")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)  # set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address:{ble_client_address}")
        ble_client_address_2  = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)#capability=3, set_smp=0)
        logger().info(f"ble_client-address_2:{ble_client_address_2}")
        logger().info(f"BLE-DUT-ADDRESS:{ble_dut_address}")
        logger().info(f"BLE-CLIENT-ADDRESS:{ble_client_address}")
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        adv_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=20))
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=0x1809)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=0x2a1e)
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=0x2a1e)
        link_key1 = ble_ae_master(ble_dut, remote_wiseconnect3, sl_collections, ble_client_address, ble_dut_address, adv_data, pri_adv_phy=1, sec_adv_phy=1)
        link_key2 = ble_ae_slave(ble_dut, remote_wiseconnect3s[0], ble_dut_address, ble_client_address_2, sl_collections, pri_adv_phy=1, sec_adv_phy=1, link_key1=link_key1)
        ble_dut.interfaces.bluetooth.ble_set_phy(ble_client_address, tx_phy=4, rx_phy=4, coded_phy=1)
        ble_dut.interfaces.bluetooth.ble_set_phy(ble_client_address_2, tx_phy=4, rx_phy=4, coded_phy=1)
        time.sleep(10)
        remote_wiseconnect3.interfaces.wifi.ble_set_phy(ble_dut_address, tx_phy=4, rx_phy=4, coded_phy=1)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_phy(ble_dut_address, tx_phy=4, rx_phy=4, coded_phy=1)
        allocated_mem_addr = ble_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)
        allocated_mem_addr_2 = remote_wiseconnect3.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3.interfaces.wifi.load_memory(address=allocated_mem_addr_2, size=len(data),
                                                            write_content=data)
        allocated_mem_addr_3 = remote_wiseconnect3s[0].interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        remote_wiseconnect3s[0].interfaces.wifi.load_memory(address=allocated_mem_addr_3, size=len(data),
                                                        write_content=data)
        write_handle_1 = service_discovery_on_remote(remote_wiseconnect3, ble_dut_address, "0xAABB",
                                                   "0x1aa1",
                                                   BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode=1, buffer_count=1)
        try:
            write_handle_2 = service_discovery_on_remote(
                ble_dut, ble_client_address, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                BLEPermissions.DEFAULT)
        except:
            write_handle_2 = service_discovery_on_remote(ble_dut, ble_client_address, "0xAABB", "0x1aa1",
                                                         BLEPermissions.DEFAULT)
        buffer_configuration_mode(remote_wiseconnect3, ble_dut_address, buffer_mode=1, buffer_count=1)
        write_handle_3 = service_discovery_on_remote(remote_wiseconnect3s[0], ble_dut_address,
                                                     "0xAABB",
                                                     "0x1aa1",
                                                     BLEPermissions.DEFAULT)
        try:
            write_handle_4 = service_discovery_on_remote(
                ble_dut, ble_client_address_2, HealthThermometerService.UUID, CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
                BLEPermissions.DEFAULT)
        except:
            write_handle_4 = service_discovery_on_remote(ble_dut, ble_client_address_2, "0xAABB", "0x1aa1",
                                                         BLEPermissions.DEFAULT)
        buffer_configuration_mode(ble_dut, ble_client_address_2, buffer_mode=1, buffer_count=1)
        buffer_configuration_mode(remote_wiseconnect3s[0], ble_dut_address, buffer_mode=1, buffer_count=1)
        remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                              handle=(write_handle_1 + 1), enable_notify=1)
        ble_fun_1 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address, notification_count=5)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address,
                                                       handle=(write_handle_2 + 1), enable_notify=1)

        ble_fun_2 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3,
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=5,
                                                allocated_mem_addr=allocated_mem_addr_2)
        remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_3 + 1), enable_notify=1)
        ble_fun_3 = TxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                allocated_mem_addr=allocated_mem_addr, data=data,
                                                ble_client_address=ble_client_address_2, notification_count=5)
        ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                       handle=(write_handle_4 + 1), enable_notify=1)
        ble_fun_4 = RxNotificationFunctionality(ble_dut, ble_clients=remote_wiseconnect3s[0],
                                                ble_dut_address=ble_dut_address, data=data, svc=svc,
                                                charc=charc, rx_notification_count=5,
                                                allocated_mem_addr=allocated_mem_addr_3)
        thread1 = threading.Thread(target=ble_fun_1.run)
        thread2 = threading.Thread(target=ble_fun_2.run)
        thread3 = threading.Thread(target=ble_fun_3.run)
        thread4 = threading.Thread(target=ble_fun_4.run)
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        time.sleep(2)
        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address_2)
        master_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            master_address = master_address + hex_data_part
        slave_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            slave_address1 = slave_address1 + hex_data_part
        logger().info(f"slave_address1:{slave_address1}")
        slave_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            slave_address2 = slave_address2 + hex_data_part
        logger().info(f"slave_address2:{slave_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([master_address, slave_address1, slave_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), master_address, slave_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), master_address, slave_address2)
        ble_sniffer.interfaces.sniffer.stop_capture()
        logger().info("Sniffer stop successful")
        captured_files = str(ble_sniffer.interfaces.sniffer.local_capture_files).split(';')
        time.sleep(30)
        exported_csv_file = ble_sniffer.interfaces.sniffer.export_to_csv("LE", "ATT")
        for captured_file in captured_files:
            captured_file = captured_file.replace("/tmp/reports", "/app/reports")
            file_size = os.path.getsize(captured_file)
            assert file_size > 0
        exported_csv_file = exported_csv_file.replace("/tmp/reports", "/app/reports")
        file_size = os.path.getsize(exported_csv_file)
        assert file_size > 0
        sniffer_data_df = ble_sniffer.interfaces.sniffer.import_data_from_csv_to_df_obj(exported_csv_file)
        logger().info(sniffer_data_df.head())
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               # sniffer_data_df['+PHY Type (LE BB)'] == "500k") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "P") & (sniffer_data_df[
                                                                 '+BD Address (LE PKT)'] == f"0x{ble_client_address.lower()}") & (
                               # sniffer_data_df['+PHY Type (LE BB)'] == "500k") &(
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_2.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "P") & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               # sniffer_data_df['+PHY Type (LE BB)'] == "500k") &(
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_3.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == "C") & (sniffer_data_df[
                                                               '+BD Address (LE PKT)'] == f"0x{ble_client_address_2.lower()}") & (
                               sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                               # sniffer_data_df['+PHY Type (LE BB)'] == "500k") & (
                               sniffer_data_df[
                                   '+PDU Length (L2CAP)'] >= 23)]) >= int(
            ble_fun_4.rx_notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as error:
        logger().info(f"Exception occurred: {error}")
        raise
    finally:
        if write_handle_1:
            remote_wiseconnect3.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                  handle=(write_handle_1 + 1), enable_notify=0)

        if write_handle_2:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_2 + 1), enable_notify=0)
        if write_handle_3:
            remote_wiseconnect3s[0].interfaces.wifi.ble_set_att_value(ble_remote_dev_address=ble_dut_address,
                                                                      handle=(write_handle_3 + 1), enable_notify=0)
        if write_handle_4:
            ble_dut.interfaces.bluetooth.ble_set_att_value(ble_remote_dev_address=ble_client_address_2,
                                                           handle=(write_handle_4 + 1), enable_notify=0)
        ble_dut.interfaces.bluetooth.ble_remove_service()
        remote_wiseconnect3.interfaces.wifi.ble_remove_service()
        remote_wiseconnect3s[0].interfaces.wifi.ble_remove_service()
        state = ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        ble_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        logger().info("\nChecking connection status of BLE after disconnection")
        state = remote_wiseconnect3s[0].interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"\nDevice state: {state_int}")
        remote_wiseconnect3s[0].interfaces.wifi.ble_disconnect(ble_dut_address)
        remote_wiseconnect3.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0, duration=0,
                                                                     max_ae_events=0
                                                                     )
        sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address,
                                                duration=0,
                                                max_ae_events=0, adv_handle=0, adv_async_required=0,
                                                adv_enable=0)


def buffer_configuration_mode(ble_dut, ble_client_address, buffer_mode, buffer_count):
    logger().info(f"*******Configure Buffer Mode:{buffer_mode} and Buffer count:{buffer_count} ****************")
    ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=ble_client_address,
                                                       buffer_mode=buffer_mode,
                                                       buffer_count=buffer_count)
    logger().info(f"*******Configure Buffer Mode:{buffer_mode} and Buffer count:{buffer_count} Success ****************")
