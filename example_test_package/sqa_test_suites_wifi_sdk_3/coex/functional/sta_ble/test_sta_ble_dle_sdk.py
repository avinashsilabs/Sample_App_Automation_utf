import time
import pytest
import string
import random
import re
from utf.utf_config import UtfConfig
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
    Si91xAwsQos
)
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from test_sta_ble_sdk import BleThreadFunctionality, SnifferValidationProcess, ScanTime_JoinTime, WifiJoinThread
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth.bluetooth_interface import (
    BluetoothInterface,
    BTRole,
    BTProfile,
    BTEvents,
    BLEPermissions,
)
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (BodySensorLocationCharacteristic,
                                                                                HeartRateControlPointCharacteristic,
                                                                                HeartRateMeasurementCharacterstic)
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import threading
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point -dlink (Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point(tkip) and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. set Region ,scan ,connect, data transfer
        6. BLE slave/master connection
        7. BLE scan
        8. BLE Advertise

    Author: Swathi.Chinthala

"""


# this thread used for Wi-Fi join
class WifiThread(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""

    def __init__(
            self,
            wifi_sniffer=None,
            wifi_dut=None,
            wifi_access_point=None,
            testcase=None,
            wifi_client=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            sniffer_filter=None,
            timeout=60,
            skip_scan=False
    ):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.timeout = timeout
        self.skip_scan = skip_scan
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")

    def scan(self):

        logger().info("Initiating wlan scan")
        # enables the scan in dut on channel
        scan_status, scan_results = self.sl_collections.scan(self.wifi_dut, scan_status=False, retry_count=3,
                                                             channel=0)
        logger().info(f"scan results : {scan_results}")
        assert len(scan_results) > 0, "scan failed"

    def join_to_ap(self):

        if not self.wifi_dut.interfaces.wifi.associated:
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                power_save=self.power_save,
                associated=self.wifi_dut.interfaces.wifi.associated,
                retry_count=3,
                ping_before_power_save=True,
                ping_after_power_save=True,
                ping_count=self.ping_count,
                skip_scan=self.skip_scan
            )
            self.dut_mac_address = self.dut_addr["dut_mac_address"]
            logger().info(
                f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************"
            )
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")
            return self.dut_addr

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def sniffer_validation_join(self):
        sniff_obj = SnifferValidationProcess(
            wifi_sniffer=self.wifi_sniffer,
            wifi_access_point=self.wifi_access_point,
            dut_mac_address=self.dut_mac_address,
            ap_mac_address=self.ap_mac_address,
            sniffer_filter=self.sniffer_filter,
            sl_collections=self.sl_collections,
        )
        sniff_obj.sniffer_validation_join()

    def run(self):
        if self.test_type == "join":
            self.join_to_ap()


# this thread used for sta+ble as a slave
class BleThread(ThreadBase):
    def __init__(
            self,
            wifi_dut=None,
            ble_client=None,
            ble_test_type=None,
            sl_collections=None,
            ble_scan_type=1,
            ble_scan_filter_type=0,
            ble_pairing=0,
            dev_state=8,
            gatt=True,
            service_class=None,
            conn_interval=200,
            char_path=None, char_uid=None, data=None,
            data_length=20, data_duration=60, periodic_delay=1, service_uid=None,
            address=None,
            service_uuid=None,
            char_uuid=None,
            characteristic=None,
            bond_info=0,
            ble_adv_int_min=160,
            ble_adv_int_max=320,
            ble_scan_interval=160,
            ble_scan_window=50,
            set_smp=0,
            ble_init_required=True,
            ble_dut_address=None,
            svc=None,
            charc=None
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.ble_scan_type = ble_scan_type
        self.ble_pairing = ble_pairing
        self.dev_state = dev_state
        self.gatt = gatt
        self.conn_interval = conn_interval
        self.service_class = service_class
        self.service_uid = service_uid
        self.char_path = char_path
        self.char_uid = char_uid
        self.data = data
        self.data_length = data_length
        self.data_duration = data_duration
        self.periodic_delay = periodic_delay
        self.ble_client_address = None
        self.write_handle = None
        self.ble_scan_filter_type = ble_scan_filter_type
        self.address = address
        self.service_uuid = service_uuid
        self.char_uuid = char_uuid
        self.characteristic = characteristic
        self.bond_info = bond_info
        self.ble_adv_int_min = ble_adv_int_min
        self.ble_adv_int_max = ble_adv_int_max
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.set_smp = set_smp
        self.ble_init_required = ble_init_required
        self.ble_dut_address = ble_dut_address
        self.svc = svc
        self.charc = charc

        if self.ble_init_required:

            if self.gatt:
                # Set up DUT for BLE advertising
                logger().info("start ble GATT service in DUT")
                self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                    set_smp=self.set_smp, bond_info=self.bond_info)
            else:
                # Set up DUT for BLE advertising
                logger().info("Initialising BLE")
                self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(
                    set_smp=self.set_smp
                )
            assert (
                    self.ble_dut_address is not None
            ), "Unable to fetch bluetooth address from DUT"
            logger().info(f"bt_dut_address : {self.ble_dut_address}")
            time.sleep(5)

    def add_whitelist(self):
        self.ble_client_address = self.ble_client.interfaces.bluetooth.get_ble_address()
        self.wifi_dut.interfaces.wifi.ble_set_scan_response_data()
        logger().info(" **** ADDING REMOTE DEVICE TO WHITELIST **** ")
        self.wifi_dut.interfaces.wifi.ble_add_white_list(self.ble_client_address)

    def add_service(self, service_uuid):
        logger().info(f"***** Configuring ble GATT service {hex(service_uuid)} in DUT *****")
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=hex(service_uuid))

    def connect_from_dut(self):
        self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                        ble_client_address=self.ble_client_address, mode="master", retries=3,
                                        ble_pairing=self.ble_pairing,
                                        dev_state=self.dev_state,
                                        max_conn_interval=self.conn_interval,
                                        min_conn_interval=self.conn_interval,
                                        ble_dut_address=self.ble_dut_address,
                                        timeout=30)

    def ble_disconnect(self, disconnect_from="remote"):

        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == self.dev_state, "DUT BLE device is not in connected state"

        if disconnect_from == "remote":
            logger().info(f"Initiating BLE disconnection from raspi")
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info(f"Initiating BLE disconnection from DUT")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        self.ble_client.interfaces.bluetooth.close()
        time.sleep(5)

    def add_characteristic(self, characteristic_uuid):
        logger().info(f"***** Configuring ble GATT characteristic {hex(characteristic_uuid)} in DUT *****")
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=hex(characteristic_uuid))

    def ble_connect(self, role="master"):

        if role == "master":
            self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.ble_dut_address,
                service_classes=self.service_class
            )
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                             ble_scan_filter_type=self.ble_scan_filter_type,
                                                             ble_scan_interval=int(self.ble_scan_interval / 0.625),
                                                             ble_scan_window=int(self.ble_scan_window / 0.625),
                                                             timeout=60,
                                                             )
            logger().info(f"Remote device found in scan results ,BLE scanning is successful")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            self.wifi_dut.interfaces.wifi.ble_advertising = False
            self.connect_from_dut()

        else:
            logger().info("Starting DUT BLE advertising")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_max=int(self.ble_adv_int_max / 0.625),
                                                                ble_adv_int_min=int(self.ble_adv_int_min / 0.625))
            time.sleep(5)
            self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                ble_pairing=self.ble_pairing, services=self.service_class,
                dev_state=self.dev_state,
                max_conn_interval=self.conn_interval,
                min_conn_interval=self.conn_interval,
                timeout=30
            )
            async_events = self.wifi_dut.interfaces.wifi.get_async_events()
            logger().info(f"async_events:{async_events}")

    def advertise_remote_device(self):
        self.ble_client_address = self.sl_collections.advertise_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def advertise_dut(self):
        logger().info(f"Advertising the DUT")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_max=int(self.ble_adv_int_max / 0.625),
                                                            ble_adv_int_min=int(self.ble_adv_int_min / 0.625),
                                                            timeout=20)

    def scan_and_connect_from_remote(self):
        self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
            dev_state=self.dev_state,
            services=self.service_class,
            max_conn_interval=self.conn_interval,
            min_conn_interval=self.conn_interval,
            timeout=30
        )

    def scan_and_connect_from_dut(self):
        self.sl_collections.scan_and_connect_from_dut(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_client_address=self.ble_client_address,
            dev_state=self.dev_state,
            max_conn_interval=self.conn_interval,
            min_conn_interval=self.conn_interval
        )

    def check_scan_functionality_dut(self):
        self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_address=self.ble_dut_address,
            ble_scan_type=self.ble_scan_type,
            timeout=60,
            services=self.service_class,
            ble_scan_interval=int(self.ble_scan_interval / 0.625),
            ble_scan_window=int(self.ble_scan_window / 0.625),
        )

    def check_adv_functionality_dut(self):
        self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            timeout=20,
            ble_adv_int_max=int(self.ble_adv_int_max / 0.625),
            ble_adv_int_min=int(self.ble_adv_int_min / 0.625),
        )

    def configure_buffer_mode(self, mode=None, count=None):
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} ****************")
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                                 buffer_mode=mode,
                                                                 buffer_count=count)
        logger().info(f"*******Configure Buffer Mode:{mode} and Buffer count:{count} Success ****************")

    def service_discovery_on_remote(self):
        self.char_path = self.sl_collections.service_discovery_on_remote(self.ble_client,
                                                                         service_uid=self.service_uid,
                                                                         char_uid=self.char_uid)
        logger().info(f"self.char_path:{self.char_path}")

    def service_discovery_on_dut(self):

        self.write_handle = self.sl_collections.service_discovery_on_dut(ble_dut=self.wifi_dut,
                                                                         ble_client_address=self.ble_client_address,
                                                                         service_uuid=self.service_uuid,
                                                                         char_uuid=self.char_uuid,
                                                                         characteristic=self.characteristic)

    def enable_notifications_from_dut(self):
        logger().info(f"****** enabling notifications on remote****************")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=self.char_path,
                                                                                     char_uid=self.char_uid)
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                                 buffer_mode=1, buffer_count=2)
        sw = Stopwatch()
        count = 0
        logger().info(f"Send notifications from DUT")
        while sw.elapsed_sec <= self.data_duration:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(self.ble_client_address, data=self.data,
                                                                  data_address=self.address)
            time.sleep(self.periodic_delay)
            count += 1
        time.sleep(10)
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        assert len(notifications) > 0, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        assert len(notifications) == count, "number of notifications received are not matching with sent"
        logger().info(f"length of notifications received on remote :{len(notifications)}")
        assert notifications[0] in self.data, "failed to fetch data"
        # assert notifications in self.data, "failed to fetch data"

        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)

    def gatt_indication(self):
        logger().info(f"****** Indication Start****************")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=self.char_path,
                                                                                     char_uid=self.char_uid)
        indication_count = 0
        sw = Stopwatch()
        while sw.elapsed_sec < self.data_duration:
            self.wifi_dut.interfaces.wifi.ble_indicate_value(ble_remote_dev_address=self.ble_client_address,
                                                             handle=12, data=self.data, data_address=self.address,
                                                             data_length=self.data_length)
            indication_count += 1
            time.sleep(self.periodic_delay)

        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        try:
            assert len(notifications) == indication_count
        except:
            assert len(notifications) == indication_count - 1
        logger().info(f"Received Notifications : : {notifications}")

        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(1)
        logger().info("******************** ble_remove_service ***********************")


    def enable_notifications_remote(self):

        if self.write_handle:
            logger().info(f"Enabling notification on dut")
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=1)

            tw = Stopwatch()
            Data_received_on_dut = []
            while tw.elapsed_sec < self.data_duration:
                if self.svc:
                    self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(self.svc, self.charc, self.data)
                logger().info("---------send_gatt_charc_notification-------------")
                time.sleep(7)
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        if "rsi_ble_on_gatt_write_event_gatt" in event.event_data:
                            received_data = re.findall(r"att_value: (.*)", event.event_data)
                            Data_received_on_dut = received_data + Data_received_on_dut
                            # received_data = ord(received_data[0])
                            logger().info(f"received_data:{Data_received_on_dut}")
            assert len(Data_received_on_dut) > 0, "Notifications not received on DUT"
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=0)


    def scan_from_remote_device(self):
        self.ble_client_address = self.sl_collections.scan_from_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def run(self):
        if self.ble_test_type == "advertise":
            self.check_adv_functionality_dut()

        if self.ble_test_type == "scan":
            self.check_scan_functionality_dut()

        if self.ble_test_type == "slave":
            self.ble_connect(role="slave")

        if self.ble_test_type == "master":
            self.ble_connect(role="master")

        if self.ble_test_type == "scan_from_remote_device":
            self.scan_from_remote_device()

        if self.ble_test_type == "connect_from_remote":
            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                            ble_dut_address=self.ble_dut_address, mode="slave",
                                            retries=3, ble_pairing=self.ble_pairing, dev_state=self.dev_state,
                                            max_conn_interval=self.conn_interval,
                                            min_conn_interval=self.conn_interval,
                                            timeout=20)

        if self.ble_test_type == "scan_and_connect_from_dut":
            self.scan_and_connect_from_dut()

        if self.ble_test_type == "scan_and_connect_from_remote":
            self.scan_and_connect_from_remote()

        if self.ble_test_type == "notify_tx":
            self.enable_notifications_from_dut()

        if self.ble_test_type == "notify_rx":
            self.enable_notifications_remote()

        if self.ble_test_type == "indications_tx":
            self.gatt_indication()

        if self.ble_test_type == "connect_as_master_notify_rx":
            self.ble_connect(role="master")
            self.service_discovery_on_dut()
            self.enable_notifications_remote()

        # if self.ble_test_type == "gatt_write_without_resp":
        #     self.gatt_write_without_resp(write_handle=self.write_handle, data_length=self.data_length, data=self.data)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                          "ble": {"count": 1, "stack_len": 2048, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_sta_ble_sdk_ble_conn_wlan_conn_dhcp_C540347(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                     request, utf_constants, sl_collections, wifi_client,
                                                     sniffer_filter):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing a BLE connection and WLAN connection with DHCP.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the Wi-Fi DUT to join the access point and enable DHCP.
    3. Perform a BLE connection as a central device.
    4. Initiate a WLAN connection and enable DHCP.
    5. Perform a ping test to validate the WLAN connection.
    5. Validate the BLE connection and WLAN connection should happen simultaneously.
    6. Disconnect BLE and Wi-Fi connections and clean up resources.
    """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "join"

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            skip_scan=True
        )
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="connect_from_remote",
            dev_state=8,
            ble_pairing=1

        )
        ble_obj.advertise_dut()
        ble_obj.scan_from_remote_device()
        wifi_obj.scan()
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                          "ble": {"count": 1, "stack_len": 2048, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_sta_ble_sdk_ble_whitelist_UDP_TX_C535084(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                  request, utf_constants, sl_collections, wifi_client,
                                                  sniffer_filter, net_perf_client, protocol):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing a UDP transmission while utilizing BLE whitelist functionality.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the Wi-Fi DUT to join the access point and enable UDP transmission.
    3. Start the UDP transmission from the Wi-Fi DUT to the remote server.
    4. Perform BLE whitelist addition and establish a BLE connection as central.
    5. Validate the UDP transmission and BLE connection.
    6. Disconnect BLE and Wi-Fi connections
    7. Repeat the process for multiple iterations.
    """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "iperf"

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
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            net_perf_client=net_perf_client,
            protocol=protocol,
            timeout=60,
            traffic_type="TX"
        )
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=0,
            ble_scan_filter_type=1,
            bond_info=1,
            set_smp=1

        )
        for count in range(0, iter_count):
            wifi_obj.join_to_ap()
            ble_obj.add_whitelist()
            wifi_obj.start()
            ble_obj.start()
            wifi_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            wifi_obj.disconnect()
            ble_obj.ble_disconnect()
            ble_client.interfaces.bluetooth.close()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_sta_ble_sdk_wlan_scan_ble_slave_tx_dle_C538009(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut, ble_client,
        request, utf_constants, sl_collections,
        wifi_client,
        sniffer_filter
):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing a WLAN scan while simultaneously transmitting BLE notifications as a slave.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the Wi-Fi DUT to perform a WLAN scan.
    3. Configure the BLE DUT to connect as a slave and transmit notifications to a remote BLE client.
    4. Perform service discovery on the BLE client and enable notifications.
    5. Validate the WLAN scan results and BLE notifications.
    6. Disconnect BLE and Wi-Fi connections and clean up resources.
    """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan"

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
            scan_count=70
        )
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=20, data_duration=120,
            periodic_delay=0.5,
            ble_pairing=1,
            gatt=True,
            address=address2,
            conn_interval=45
        )

        # Create Custom services on DUT
        # Create Custom services, attributes, values
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj.start()
        ble_obj.ble_connect(role="slave")
        ble_obj.service_discovery_on_remote()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.memory_free(address2)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation_scan()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "disassociated",
    ],
)
def test_sta_ble_sdk_wlan_scan_ble_master_rx_C538010(
        wifi_sniffer,
        wifi_access_point, wifi_dut, ble_client,
        request, utf_constants, sl_collections, wifi_client,
        sniffer_filter
):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing a WLAN scan while simultaneously receiving BLE notifications as a master.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the Wi-Fi DUT to perform a WLAN scan.
    3. Configure the BLE DUT to connect as a master and receive notifications from a remote BLE client.
    4. Perform service discovery on the BLE DUT and enable notifications.
    5. Validate the WLAN scan results and BLE notifications.
    6. Disconnect BLE and Wi-Fi connections and clean up resources.
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "scan"

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
            scan_count=100
        )
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="connect_as_master_notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HeartRateService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HeartRateService.UUID,
            char_uuid=HeartRateMeasurementCharacterstic.HR_Measure_UUID,
            characteristic=HeartRateMeasurementCharacterstic,
            set_smp=1
        )
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        time.sleep(2)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_obj.sniffer_validation_scan()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 2048, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_sta_ble_sdk_tcp_tx_ble_slave_C133549(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                              request, utf_constants, sl_collections, wifi_client,
                                              sniffer_filter, net_perf_client, protocol):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing a TCP transmission while simultaneously transmitting BLE notifications.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the Wi-Fi DUT to join the access point and enable TCP transmission.
    3. Configure the BLE DUT to advertise and connect with a remote BLE client.
    4. Perform service discovery on the BLE client and enable notifications.
    5. Transmit BLE notifications from the DUT to the BLE client.
    6. Validate the TCP transmission and BLE notifications.
    7. Disconnect BLE and Wi-Fi connections and clean up resources.
    """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        iter_count = utf_constants.get("iter_count")

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
            net_perf_client=net_perf_client,
            protocol=protocol,
            timeout=300
        )
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        index = 1
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=20, data_duration=60,
            periodic_delay=1,
            ble_pairing=1,
            gatt=True,
            bond_info=1
        )
        # Create Custom services on DUT
        # Create Custom services, attributes, values
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.ble_connect(role="slave")
        wifi_obj.set_power_save()
        wifi_obj.start()
        logger().info("iter_count mentioned in harness :{}".format(iter_count))
        for count in range(0, iter_count):
            if count != 0:
                ble_obj.ble_connect(role="slave")
            ble_obj.service_discovery_on_remote()
            ble_obj.start()
            ble_obj.wait_for_exit()
            time.sleep(2)
            ble_obj.ble_disconnect()
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                          "ble": {"count": 1, "stack_len": 2048, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4985")
def test_sta_ble_sdk_set_att_value_diff_length_tcp_tx_ble_slave_C133437(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                        ble_client,
                                                                        request, utf_constants, sl_collections,
                                                                        wifi_client,
                                                                        sniffer_filter, net_perf_client, protocol):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing a TCP transmission while varying the BLE attribute value lengths.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the Wi-Fi DUT to join the access point and enable TCP transmission.
    3. Configure the BLE DUT to advertise and connect with a remote BLE client.
    4. Perform service discovery on the BLE client and enable notifications.
    5. Transmit BLE notifications with varying attribute value lengths from the DUT to the BLE client.
    6. Validate the TCP transmission and BLE notifications.
    7. Disconnect BLE and Wi-Fi connections and clean up resources.
    """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        iter_count = utf_constants.get("iter_count")

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
            net_perf_client=net_perf_client,
            protocol=protocol,
            timeout=300
        )
        notify_size_list = [1, 20, 50]  # , 230]
        notify_size_list.extend(random.sample(range(2, 229), 5))
        addr_list = []
        data_list = []
        for size in notify_size_list:
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=size))
            address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
            wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(data), write_content=data)
            addr_list.append(address1)
            data_list.append(data)

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="gatt_write_without_resp",
            dev_state=8,
            service_class=["ImmediateAlertService"],
            gatt=True,
            service_uuid=ImmediateAlertService.UUID,
            char_uuid=ImmediateAlertLevelCharacteristic.LLA_UUID,
            characteristic=ImmediateAlertLevelCharacteristic
        )

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.advertise_dut()
        wifi_obj.set_power_save()
        wifi_obj.start()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.service_discovery_on_dut()
        # Configure Buffer Mode
        ble_obj.configure_buffer_mode(mode=0, count=2)
        for i in range(0, len(notify_size_list)):
            ble_obj.gatt_write_without_resp(ble_obj.write_handle, data_length=notify_size_list[i], data=data_list[i],
                                            address=addr_list[i],
                                            bt_mon_log_file_name=(
                                                f"reports/test_sta_ble_sdk_set_att_value_diff_length_tcp_tx_ble_slave_C133437"
                                                f"{int(time.time())}.log")
                                            )
        ble_obj.ble_disconnect()
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 4095, "priority": 8},
                          "ble": {"count": 1, "stack_len": 2048, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_sta_ble_sdk_http_dle_ble_periodic_tx_C537979(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                      request, utf_constants, sl_collections, wifi_client,
                                                      sniffer_filter, http_server, index_path):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing an HTTP download with BLE periodic transmissions.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the HTTP server to serve a file for download.
    3. Configure the BLE DUT to advertise and connect with a remote BLE client.
    4. Perform service discovery on the BLE client and enable periodic notifications with delay 10s.
    5. Start the HTTP download from the Wi-Fi DUT to the HTTP server.
    6. Simultaneously transmit BLE notifications from the DUT to the BLE client.
    7. Validate the HTTP download and BLE notifications.
    8. Disconnect BLE and Wi-Fi connections and clean up resources.
    """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"

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
            http_server=http_server,
            index_path=index_path
        )
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        index = 1
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(data), write_content=data)
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=20, data_duration=300,
            periodic_delay=10,
            address=address1,
            ble_pairing=1,
            gatt=True
        )

        # Create Custom services on DUT
        # Create Custom services, attributes, values
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)
        ble_obj.ble_connect(role="slave")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj.join_to_ap()
        ble_obj.service_discovery_on_remote()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        time.sleep(5)
        wifi_obj.disconnect()
        wifi_dut.interfaces.wifi.memory_free(address1)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        ble_obj.ble_disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="he_cap_radio_tap")

        logger().info(f"***** Validating HE Capabilities ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "Unable to find HE Capabilities"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
        http_server.interfaces.http.stop_server()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 4095, "priority": 8},
                          "ble": {"count": 1, "stack_len": 2048, "priority": 8}}

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'bgnax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_sta_ble_sdk_http_dl_ble_periodic_tx_dle_C537980(wifi_sniffer, wifi_access_point, wifi_dut, ble_client,
                                                         request, utf_constants, sl_collections, wifi_client,
                                                         sniffer_filter, http_server, index_path):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing an HTTP download with BLE periodic transmissions.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the HTTP server to serve a file for download.
    3. Configure the BLE DUT to advertise and connect with a remote BLE client.
    4. Perform service discovery on the BLE client and enable periodic notifications with delay 30s.
    5. Start the HTTP download from the Wi-Fi DUT to the HTTP server.
    6. Simultaneously transmit BLE notifications from the DUT to the BLE client.
    7. Validate the HTTP download and BLE notifications.
    8. Disconnect BLE and Wi-Fi connections and clean up resources.
    """
    ble_dut_addr = ""
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"

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
            http_server=http_server,
            index_path=index_path
        )
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(data), write_content=data)
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=240, data_duration=300,
            periodic_delay=30,
            address=address1,
            ble_pairing=1,
            gatt=True
        )

        # Create Custom services on DUT
        # Create Custom services, attributes, values
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)
        ble_obj.ble_connect(role="slave")
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_obj.join_to_ap()
        ble_obj.service_discovery_on_remote()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        time.sleep(2)
        logger().info("******************** ble_remove_service ***********************")
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.memory_free(address1)
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="he_cap_radio_tap")

        logger().info(f"***** Validating HE Capabilities ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "Unable to find HE Capabilities"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
        http_server.interfaces.http.stop_server()


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096, "priority": 8},
                          "ble": {"count": 1, "stack_len": 2048, "priority": 8}},
        # "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_coex_sdk_httpget_url_2048_ble_smp_tx_C476959(http_server, wifi_dut, http_client,
                                                      wifi_access_point, wifi_sniffer,
                                                      sl_collections, sniffer_filter,
                                                      request, utf_constants, wifi_client,
                                                      ble_client):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing an HTTP GET request with a URL length of 2048 bytes while simultaneously transmitting BLE notifications.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the HTTP server to serve a URL with a length of 2048 bytes.
    3. Configure the BLE DUT to advertise and connect with a remote BLE client.
    4. Perform service discovery on the BLE client and enable notifications.
    5. Start the HTTP GET request from the Wi-Fi DUT to the HTTP server.
    6. Simultaneously transmit BLE notifications from the DUT to the BLE client.
    7. Validate the HTTP GET response and BLE notifications.
    8. Disconnect BLE and Wi-Fi connections and clean up resources.

    """
    ble_obj = None
    try:
        index_path = "url_exact_2048_bytes/" * 97 + "2048url.htm"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "http_get"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(index_path) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(index_path), write_content=index_path)
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        index = 1
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)
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
            http_server=http_server,
            index_path=index_path,
            http_client=http_client,
            address=address1,
        )
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=20, data_duration=300,
            conn_interval=45,
            periodic_delay=0.5,
            address=address2
        )

        # Create Custom services on DUT
        # Create Custom services, attributes, values
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1, data=data)

        logger().info(f"iter count is configured as {iter_count}")
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.service_discovery_on_remote()
        ble_obj.start()
        for count in range(0, iter_count):
            if count != 0:
                wifi_obj.join_to_ap()
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.disconnect()
            time.sleep(5)
        ble_obj.stop()
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.memory_free(address1)
        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.HTTPClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
        "clear_certs"
    ],
)
def test_coex_sdk_https_get_url_2048_ble_RX_C476960(http_server, wifi_dut, http_client,
                                                    wifi_access_point, wifi_sniffer,
                                                    sl_collections, sniffer_filter,
                                                    request, utf_constants, wifi_client,
                                                    ble_client):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing an HTTPS GET request with a URL length of 2048 bytes while simultaneously receiving BLE notifications.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the HTTPS server to serve a URL with a length of 2048 bytes.
    3. Configure the BLE DUT to scan and connect with a remote BLE client.
    4. Perform service discovery on the BLE DUT and enable notifications.
    5. Start the HTTPS GET request from the Wi-Fi DUT to the HTTPS server.
    6. Simultaneously receive BLE notifications on the DUT from the BLE client.
    7. Validate the HTTPS GET response and BLE notifications.
    8. Disconnect BLE and Wi-Fi connections and clean up resources.

    """
    ble_obj = None
    try:
        index_path = "url_exact_2048_bytes/" * 97 + "2048url.htm"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "http_get"
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(index_path) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(index_path), write_content=index_path)
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
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            http_server=http_server,
            index_path=index_path,
            http_client=http_client,
            https=1,
            address=address1
        )
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=30,
            service_class=["HeartRateService"],
            gatt=True,
            ble_pairing=1,
            bond_info=1,
            service_uuid=HeartRateService.UUID,
            char_uuid=HeartRateMeasurementCharacterstic.HR_Measure_UUID,
            characteristic=HeartRateMeasurementCharacterstic,
            set_smp=1
        )
        logger().info(f"iter count is configured as {iter_count}")

        for count in range(0, iter_count):
            ble_obj.check_scan_functionality_dut()
            wifi_obj.join_to_ap()
            logger().info("Initiating stop scan from dut")
            wifi_dut.interfaces.wifi.ble_stop_scanning()
            ble_obj.connect_from_dut()
            ble_obj.service_discovery_on_dut()
            ble_obj.start()
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            ble_obj.wait_for_exit()
            ble_obj.ble_disconnect(disconnect_from="dut")
            ble_client.interfaces.bluetooth.stop_advertising()
            ble_client.interfaces.bluetooth.close()
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            wifi_obj.disconnect()
        wifi_dut.interfaces.wifi.memory_free(address1)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2', "passphrase": 'thisisatestnetwork',
                                               "standard": 'bgnax'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.HTTPClient
                          | Si91xTCPIPFeatureBitMap.SSL,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
        "clear_certs"
    ],
)
def test_coex_sdk_httpsget_url_1536_ble_smp_C476963(http_server, wifi_dut, http_client,
                                                    wifi_access_point, wifi_sniffer,
                                                    sl_collections, sniffer_filter,
                                                    request, utf_constants, wifi_client,
                                                    ble_client):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing an HTTPS GET request with a URL length of 1536 bytes while simultaneously transmitting BLE notifications.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the HTTPS server to serve a URL with a length of 1536 bytes.
    3. Configure the BLE DUT to advertise and connect with a remote BLE client.
    4. Start the HTTPS GET request from the Wi-Fi DUT to the HTTPS server.
    5. Disconnect WiFi connection and connect again
    6. Again start the HTTPS GET request from the Wi-Fi DUT to the HTTPS server.
    7. Again Disconnect WLAN and repeat the process form mutiple iterations
    8. BLE connection should be maintained throughout the iterations.


    """
    ble_obj = None
    try:
        index_path = "url_exact_1536_bytes/" * 73 + ".htm"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "http_get"
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(index_path) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(index_path), write_content=index_path)
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
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            http_server=http_server,
            index_path=index_path,
            http_client=http_client,
            https=1,
            address=address1
        )
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            conn_interval=45,
        )
        logger().info(f"iter count is configured as {iter_count}")
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        ble_obj.scan_and_connect_from_remote()
        for count in range(0, iter_count):
            if count != 0:
                wifi_obj.join_to_ap()
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            wifi_obj.disconnect()
        ble_obj.ble_disconnect()
        ble_client.interfaces.bluetooth.close()
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        wifi_dut.interfaces.wifi.memory_free(address1)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config("wifi_access_point", wifi={"security": 'WPA2'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.HTTPLongerURL |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 4096, "priority": 8}},
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
def test_coex_sdk_httpget_url_1536_ble_smp_tx_C476964(http_server, wifi_dut, http_client,
                                                      wifi_access_point, wifi_sniffer,
                                                      sl_collections, sniffer_filter,
                                                      request, utf_constants, wifi_client,
                                                      ble_client):
    """
    This test case verifies the coexistence of Wi-Fi and BLE functionalities by performing an HTTP GET request with a URL length of 1536 bytes while simultaneously transmitting BLE notifications.

    Test Steps:
    1. Configure the Wi-Fi DUT in coexistence mode (Wi-Fi + BLE).
    2. Set up the HTTP server to serve a URL with a length of 1536 bytes.
    3. Configure the BLE DUT to advertise and connect with a remote BLE client.
    4. Perform service discovery on the BLE client and enable notifications.
    5. Start the HTTP GET request from the Wi-Fi DUT to the HTTP server.
    6. Simultaneously transmit BLE notifications from the DUT to the BLE client.
    7. Validate the HTTP GET response and BLE notifications.
    8. Disconnect BLE and Wi-Fi connections and clean up resources.
    """

    ble_obj = None
    try:
        index_path = "url_exact_1536_bytes/" * 73 + ".htm"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "http_get"
        address1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(index_path) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address1, size=len(index_path), write_content=index_path)
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
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            http_server=http_server,
            index_path=index_path,
            http_client=http_client,
            address=address1
        )
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"
        # data = "sAmPe_TeXtsAmPe_TeXt"  # 20bytes of data
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            bond_info=1,
            char_path=None, char_uid=char_uid1, data=data,
            service_uid=service_uid,
            data_length=240, data_duration=120,
            periodic_delay=0.5,
            address=address2,
            conn_interval=45
        )

        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        logger().info(f"iter count is configured as {iter_count}")
        for count in range(0, iter_count):
            ble_obj.advertise_dut()
            wifi_obj.join_to_ap()
            ble_obj.scan_and_connect_from_remote()
            ble_obj.service_discovery_on_remote()
            ble_obj.start()
            time.sleep(10)
            wifi_obj.start()
            wifi_obj.wait_for_exit()
            time.sleep(5)
            ble_obj.stop()
            wifi_obj.disconnect()
            ble_obj.ble_disconnect()
            ble_client.interfaces.bluetooth.close()
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        wifi_dut.interfaces.wifi.memory_free(address1)
        wifi_dut.interfaces.wifi.memory_free(address2)
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)
