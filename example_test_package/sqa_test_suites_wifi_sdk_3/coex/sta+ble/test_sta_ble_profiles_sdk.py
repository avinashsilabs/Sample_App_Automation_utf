import time
import pytest
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
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
)

from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
import re
from test_sta_ble_sdk import (
    BleThreadFunctionality,
    SnifferValidationProcess,
    WifiJoinThread,
)
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService, BodySensorLocationCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import HealthThermometerService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService, \
    ImmediateAlertLevelCharacteristic
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. set scan ,connect, data transfer
        6. Connect BLE as master/slave
        7. Query for profiles ,char ,descriptors
       

    Author: Swathi.Chinthala

"""



# this thread used for sta+ble as a slave
class BleGattThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        ble_client=None,
        ble_test_type=None,
        sl_collections=None,
        ble_pairing=0,
        service_class=None,
        gatt=True
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_pairing = ble_pairing
        self.service_class = service_class
        self.ble_client_address = None
        self.gatt = gatt
        if self.gatt:
            # Set up DUT for BLE advertising
            logger().info("start ble GATT service in DUT")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                set_smp=self.ble_pairing)
        else:
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(
                set_smp=self.ble_pairing
            )
        assert (
                self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"ble_dut_address : {self.ble_dut_address}")
        time.sleep(5)

    def ble_disconnect(self, disconnect_from="remote"):

        self.sl_collections.ble_disconnect(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            disconnect_from=disconnect_from,
            ble_client_address=self.ble_client_address,
        )

    def add_services_hear_rate(self):


        # adding service, attributes, values
        index = 1
        # ble_add_service 6157 -> Heart rate service(0x180D)
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x180D)

        # ble_add_char_serv_att 10807 26 1 2 -> Heart rate measurement(0x2A37)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A37, service_handler_num=index,
                                                            value_handler_num=index + 1)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A37, value_handler_num=index + 1)

        # ble_add_char_serv_att 10808 26 1 2 -> Body sensor location(0x2A38)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A38, service_handler_num=index + 2,
                                                            value_handler_num=index + 3)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A38, value_handler_num=index + 3)

        # ble_add_char_serv_att 10809 26 1 2 -> Heart rate control point(0x2A39)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A39, service_handler_num=index + 4,
                                                            value_handler_num=index + 5)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A39, value_handler_num=index + 5)

    def add_services_immediate_alert(self):

        # adding services, attributes and values
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x1802)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A06)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A06)


    def resolve_services_heartrate(self):
        service_uid = "0000180d-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00002a37-0000-1000-8000-00805f9b34fb"
        char_uid2 = "00002a38-0000-1000-8000-00805f9b34fb"
        char_uid3 = "00002a39-0000-1000-8000-00805f9b34fb"

        servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid1)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"

        char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid2)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"

        char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid3)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"

        self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

    def add_services_proximity(self):
        # adding services, attributes and values
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x1803)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A06)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A06)


    def run(self):

        if self.ble_test_type == "scan_and_connect_from_remote":

            self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                ble_pairing=self.ble_pairing, services=self.service_class)

        if self.ble_test_type == "slave":

            logger().info("Starting DUT BLE advertising")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            time.sleep(5)
            self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                ble_pairing=self.ble_pairing, services=self.service_class)


        if self.ble_test_type == "master":
            logger().info("start ble GATT service in DUT")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                set_smp=self.ble_pairing)
            assert (
                    self.ble_dut_address is not None
            ), "Unable to fetch bluetooth address from DUT"
            logger().info(f"ble_dut_address : {self.ble_dut_address}")
            time.sleep(5)

            logger().info("Configuring heart rate profile with advertising on remote device")
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.ble_dut_address,
                service_classes=self.service_class
            )
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address, timeout=60)
            logger().info(f"Remote device found in scan results ,BLE scanning is successful")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            self.wifi_dut.interfaces.wifi.ble_advertising = False
            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                             ble_client_address=self.ble_client_address, mode="master", retries=3, ble_pairing=self.ble_pairing)
            logger().info("BLE Connection success")




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        #| Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 4096},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
def test_Coex_sdk_read_char_uuid_wlan_conn_C133434(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure heart rate profile in remote BLE and start adv
        3. Scan & connect DUT as master
        3.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleGattThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            ble_pairing=0,
            service_class=["HeartRateService"]

        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        for count in range(0, iter_count):

            ble_obj.start()
            ble_obj.wait_for_exit()

            logger().info("Fetching HeartRateService profile from RD1")
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_obj.ble_client_address,
                                                                    timeout=30)
            assert HeartRateService.UUID.lower() in uuids, "Unable to get HeartRateService profile of RD from DUT"

            start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(
                ble_remote_dev_address=ble_obj.ble_client_address, uuid=int(HeartRateService.UUID, 16), timeout=30)
            assert start_handle, "Unable to fetch the RD address"
            assert end_handle, "Unable to get HeartRateService profile from RD"
            #
            # # Rasied Jira for below API: https://jira.silabs.com/browse/WIFI_BT_UTFHELP-1576
            logger().info("Getting characteristics value of heart rate profile by passing uuid of service class")
            wifi_dut.interfaces.wifi.ble_get_char_value_by_uuid(ble_obj.ble_client_address, start_handle, end_handle,
                                                                uuid=int("0x2A38", 16),  timeout=30)
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            logger().info("Checking connection stability for 60 seconds")
            time.sleep(60)
            wifi_obj.disconnect()
            sl_collections.ble_disconnect(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                ble_dut_address=ble_obj.ble_dut_address,
                disconnect_from="dut",
                ble_client_address=ble_obj.ble_client_address,
            )

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 4096},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_Coex_sdk_BLE_services_wlan_connected_C133446(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure heart rate profile in remote BLE and start adv
        3. Scan & connect DUT as master
        3.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        ble_obj = BleGattThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            ble_pairing=0,
        )

        service_uid = "00001803-0000-1000-8000-00805f9b34fb"
        char_uid = "00002a06-0000-1000-8000-00805f9b34fb"
        # adding services, attributes and values
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x1803)
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A06)
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A06)

        ble_obj.start()
        ble_obj.wait_for_exit()

        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()

        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"
        ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        service_uid = "00001803-0000-1000-8000-00805f9b34fb"
        char_uid = "00002a06-0000-1000-8000-00805f9b34fb"
        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"

        for data in range(3):
            logger().info(f"The data being sent is {data}")
            ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data)
            time.sleep(3)
            received = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path, type=int)
            assert received == data, "sent and received data isn't matching"
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        logger().info("Checking connection stability for 60 seconds")
        time.sleep(60)
        wifi_obj.disconnect()
        sl_collections.ble_disconnect(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_dut_address=ble_obj.ble_dut_address,
            disconnect_from="dut",
            ble_client_address=ble_obj.ble_client_address,
        )

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 4096},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
def test_Coex_sdk_supported_profiles_wlan_conneced_C133557(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure heart rate profile in remote BLE and start adv
        3. Scan & connect DUT as master
        3.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleGattThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            ble_pairing=0,
            service_class=["BatteryService", "HeartRateService", "HealthThermometerService"]
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        for count in range(0, iter_count):
            wifi_obj.start()
            wifi_obj.wait_for_exit()

            ble_obj.start()
            ble_obj.wait_for_exit()

            logger().info("Fetching HeartRateService profile from RD1")
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_obj.ble_client_address,
                                                                    timeout=30)
            uuid_dict = {"0x180f": "BatteryService", "0x180d": "HeartRateService", "0x1809": "HealthThermometerService"}
            uuid_list = [BatteryService.UUID, HeartRateService.UUID, HealthThermometerService.UUID]
            for uuid in uuid_list:
                uuid = uuid.lower()
                assert uuid in uuids, f"Unable to get '{uuid_dict[uuid]}' profile from RD1"
            logger().info(f"Successfully fetched all the profiles from RD1")

            logger().info("Checking connection stability for 60 seconds")
            time.sleep(60)
            wifi_obj.disconnect()
            sl_collections.ble_disconnect(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                ble_dut_address=ble_obj.ble_dut_address,
                disconnect_from="dut",
                ble_client_address=ble_obj.ble_client_address,
            )

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 4096},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
def test_Coex_sdk_supported_particular_profile_wlan_conneced_C133558(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure heart rate profile in remote BLE and start adv
        3. Scan & connect DUT as master
        3.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleGattThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            ble_pairing=0,
            service_class=["BatteryService", "HeartRateService", "HealthThermometerService"]
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )

        for count in range(0, iter_count):
            wifi_obj.start()
            wifi_obj.wait_for_exit()

            ble_obj.start()
            ble_obj.wait_for_exit()

            logger().info("Fetching HeartRateService profile from RD1")
            uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_obj.ble_client_address,
                                                                    timeout=30)
            uuid_dict = {"0x180f": "BatteryService", "0x180d": "HeartRateService", "0x1809": "HealthThermometerService"}
            uuid_list = [BatteryService.UUID, HeartRateService.UUID, HealthThermometerService.UUID]
            for uuid in uuid_list:
                uuid = uuid.lower()
                assert uuid in uuids, f"Unable to get '{uuid_dict[uuid]}' profile from RD1"
            logger().info(f"Successfully fetched all the profiles from RD1")

            start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(
                ble_remote_dev_address=ble_obj.ble_client_address,
                uuid=int(BatteryService.UUID, 16))
            assert start_handle is not None, "Unable to fetch the RD1 address"
            assert end_handle is not None, "Unable to get BatteryService profile from RD1"
            logger().info("Successfully fetched BatteryService profile from RD1")

            logger().info("Checking connection stability for 60 seconds")
            time.sleep(60)
            wifi_obj.disconnect()
            sl_collections.ble_disconnect(
                wifi_dut=wifi_dut,
                ble_client=ble_client,
                ble_dut_address=ble_obj.ble_dut_address,
                disconnect_from="dut",
                ble_client_address=ble_obj.ble_client_address,
            )

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        #| Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 4096},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_Coex_sdk_BLE_link_loss_TCP_TX_C133439(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure heart rate profile in remote BLE and start adv
        3. Scan & connect DUT as master
        3.
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleGattThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_remote",
            ble_pairing=0,
        )
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            traffic_type="TX",
            timeout=100
        )

        wifi_obj.join_to_ap()
        ble_obj.add_services_proximity()
        logger().info("Starting DUT BLE advertising")
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(5)

        wifi_obj.start()

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wait_for_exit()

        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, "no services fetched"
        assert len(chars) > 0, "fetched characters are empty"

        service_uid = "00001803-0000-1000-8000-00805f9b34fb"
        char_uid = "00002a06-0000-1000-8000-00805f9b34fb"
        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                    service_uid=service_uid,
                                                                                                    char_uid=char_uid)
        logger().info(f"char_path is {char_path}")
        assert char_path, "characters are empty"
        assert len(char_props) > 0, "length of characters is 0"

        for data in range(3):
            logger().info(f"The data being sent is {data}")
            ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data)
            time.sleep(3)
            received = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path, type=int)
            assert received == data, "sent and received data isn't matching"

        wifi_obj.wait_for_exit()
        logger().info("Checking connection stability for 60 seconds")
        time.sleep(60)
        wifi_obj.disconnect()
        sl_collections.ble_disconnect(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_dut_address=ble_obj.ble_dut_address,
            disconnect_from="dut",
            ble_client_address=ble_obj.ble_client_address,
        )

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



