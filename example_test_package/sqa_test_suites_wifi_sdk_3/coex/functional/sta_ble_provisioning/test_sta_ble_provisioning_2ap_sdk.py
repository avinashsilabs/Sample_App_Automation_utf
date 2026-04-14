import time
import pytest
import re
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_dle_sdk import BleThread
import random
import string


"""
    setup requirement:
        1. Soc
        2. Access Point
        3. Raspberry PI4
        4. NUC

    Test Steps:
        1. Configure the DUT in wlan coex mode for 2.4Ghz
        2. Initiate ble in DUT 
        3. Configure the DUT with the gatt services
        4. Initiate the ble client and connect to the DUT
        5. Credentials are sent over ble to the DUT
        6. DUT will scan list of available networks
        7. DUT will connect to the network with the credentials received from the client
        8. Validate the Acknowledgement from the DUT

    Author: Saurabh Sharma
"""


def logger():
    return get_logger(__name__)


class ProvisioningFunctionality(ThreadBase):

    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, test_case=None, ble_dut=None,
                 utf_constants=None, wifi_access_point=None, wifi_sniffer=None, bt_dut_address=None, credentials=None,
                 ble_client_address=None, char_path=None, char_uid=None, adv_int=None, min_conn_interval=160,
                 max_conn_interval=160, conn_latency=0, supervision_timeout=3200, svc=None, charc=None,
                 write_handle = None, wifi_access_points=None, device_ip=None, device_ip_two=None,
                 dut_mac_address_two=None, dut_mac_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.bt_dut_address = bt_dut_address
        self.credentials = credentials
        self.ble_client_address = ble_client_address
        self.char_path = char_path
        self.char_uid = char_uid
        self.adv_int = adv_int
        self.min_conn_interval = min_conn_interval
        self.max_conn_interval = max_conn_interval
        self.conn_latency = conn_latency
        self.supervision_timeout = supervision_timeout
        self.svc = svc
        self.charc = charc
        self.write_handle = write_handle
        self.wifi_access_points = wifi_access_points
        self.device_ip = device_ip
        self.device_ip_two = device_ip_two
        self.dut_mac_address_two = dut_mac_address_two
        self.dut_mac_address = dut_mac_address

    def run(self):
        try:
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            self.char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            self.svc = 'HealthThermometerService'
            self.charc = 'CustomNotifyCharacteristic'

            logger().info("******************** initializing ble in dut ********************")
            self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
            assert self.bt_dut_address, "failed to initialize ble in dut"

            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.bt_dut_address, services=[self.svc])

            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                            ble_dut_address=self.bt_dut_address,
                                            min_conn_interval=self.min_conn_interval,
                                            max_conn_interval=self.max_conn_interval,
                                            conn_latency=self.conn_latency,
                                            supervision_timeout=self.supervision_timeout)
            time.sleep(3)

            logger().info(".... checking ble connection stability ....")
            time.sleep(60)

            logger().info(".... get connection state ....")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, ".... device is in disconnection state ...."

            servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"

            self.char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=self.char_uid)
            assert self.char_path, "characters are empty"
            assert len(char_props) > 0, "length of characters is 0"

            logger().info(f"******************** get all profiles ********************")
            uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(
                ble_remote_dev_address=self.ble_client_address)
            assert HealthThermometerService.UUID.lower() in uuids is not None, "couldn't fetch health_thermometer " \
                                                                               "profile "

            logger().info(" ******************** Resolving Profile ********************")
            start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
                ble_remote_dev_address=self.ble_client_address, uuid=int(HealthThermometerService.UUID, 16))
            assert start_handle is not None, "failed to fetch the start handle.."
            assert end_handle is not None, "failed to fetch end handle.."

            char_uuids, write_handles, char_properties = self.ble_dut.interfaces.wifi.ble_get_char_services_async(
                ble_remote_dev_address=self.ble_client_address,
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

            self.write_handle = int(write_handles[index], 16)
            logger().info(f"write_handle:{self.write_handle}")
            assert self.write_handle > 0, "Unable to get write handle for configured service"

        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

    def credentials_send_over_ble(self):
        self.credentials = []
        data = [self.wifi_access_points[0].interfaces.wifi.ssid, self.wifi_access_points[0].interfaces.wifi.passphrase,
                self.wifi_access_points[0].interfaces.wifi.security.name.lower(),
                self.wifi_access_points[1].interfaces.wifi.ssid, self.wifi_access_points[1].interfaces.wifi.passphrase,
                self.wifi_access_points[1].interfaces.wifi.security.name.lower()]

        for length in range(len(data)):
            self.ble_dut.interfaces.bluetooth.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address, handle=(self.write_handle + 1), enable_notify=1)

            since_time = time.perf_counter_ns()

            logger().info("******************** Sending data to DUT ***********************")
            self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(self.svc, self.charc, data[length])
            time.sleep(30)
            events = self.wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                    received_data = re.findall(r"((?<=att_value:\s)[\w\W]+(?=\n))", event.event_data)
                    received_credentials = str(received_data[0])
                    logger().info(f"******* Received Data on DUT : {received_credentials} ********")

                    self.credentials.append(received_credentials)
                    logger().info(f"******* credentials appending in list : {self.credentials} ********")
                    assert received_credentials == data[length], "data mismatched"

            self.ble_dut.interfaces.bluetooth.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address, handle=(self.write_handle + 1), enable_notify=0)
            time.sleep(3)

    def power_save(self):
        logger().info(f"....Applying performance profile mode and Enable_bt_power_save....")
        self.ble_dut.interfaces.bluetooth.set_performance_profile(mode="power_save_low_latency")
        self.ble_dut.interfaces.bluetooth.enable_bt_power_save()

    def wifi_scan(self):
        scan_result_ssid_security = []
        result = self.wifi_dut.interfaces.wifi.scan()
        assert result, ".... scan results are empty ...."

        for scan in result:
            ssid = re.findall(r"((?<=ssid:\s)[\w\W]+?(?=\sbssid))", str(scan))
            security = re.findall(r"((?<=security_mode:\s)\d+)", str(scan))
            scan_result_ssid_security.append((ssid[0], security[0]))

        logger().info(f".... scan result for ssid and security is : {scan_result_ssid_security} ....")

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

        for ssid in scan_result_ssid_security:
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=self.ble_client_address, data=str(ssid))
            time.sleep(3)
            logger().info("******************** Validate Data ********************")
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            time.sleep(30)
            logger().info(f' ******* received ssid and security on remote device is : {notifications} *******')
            assert notifications, ".... received data is empty ...."

        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()
        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(5)

    def wifi_connect_ap1(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[0], passphrase=self.credentials[1], security=self.credentials[2])
        logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {self.device_ip}")

        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {self.dut_mac_address}')

        logger().info(f"DUT MAC ADDRESS :  {self.dut_mac_address} DUT IP ADDRESS : {self.device_ip}")

        self.power_save()

        logger().info(f"....Pinging to DUT after Power Save")
        status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
            ble_remote_dev_address=self.ble_client_address, data=self.device_ip)
        time.sleep(3)
        logger().info("******************** Validate Data ********************")
        notifications_data = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        logger().info(f' *********************** Notification is {notifications_data} ***********************')
        assert len(notifications_data) > 0, " .... received data is empty ...."
        assert notifications_data == [self.device_ip], ".... Device IP Mismatched or Acknowledgement not received ....."

        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()
        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(3)

    def wifi_connect_ap2(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[3], passphrase=self.credentials[4], security=self.credentials[5])
        logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        self.device_ip_two = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {self.device_ip_two}")

        self.dut_mac_address_two = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {self.dut_mac_address_two}')

        logger().info(f"DUT MAC ADDRESS :  {self.dut_mac_address_two} DUT IP ADDRESS : {self.device_ip_two}")

        self.power_save()

        logger().info(f"....Pinging to DUT after Power Save")
        status = self.sl_collections.ping(device_ip=self.device_ip_two, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
            ble_remote_dev_address=self.ble_client_address, data=self.device_ip_two)
        time.sleep(3)
        logger().info("******************** Validate Data ********************")
        notifications_data = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        logger().info(f' *********************** Notification is {notifications_data} ***********************')
        assert len(notifications_data) > 0, " .... received data is empty ...."
        assert notifications_data == [self.device_ip_two], ".... Device IP Mismatched or Acknowledgement not received ....."

        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()
        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(3)

    def access_point_leave_dut(self):
        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(1)

    def ble_remove_servie(self):
        logger().info("******************** ble_remove_service ***********************")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_cleanup_disconn(self):
        logger().info("Checking connection status of BLE")
        state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            time.sleep(5)
        elif state_int == 2:
            logger().info("Device is in scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 1:
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 3:
            logger().info("Device is in scanning status try to stop scanning")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 9:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            logger().info("Device is in advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
        elif state_int == 10:
            logger().info("Device is in connected status try to disconnect")
            self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
            logger().info("Device is advertising status try to stop advertising")
            self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
        elif state_int == 0:
            logger().info("Device is in idle status")
        else:
            logger().info("Device is in unknown state")
            self.ble_dut.interfaces.bluetooth.is_dut_bad_state = True

        self.ble_client.interfaces.bluetooth.close()
        logger().info(" *************DUT Cleanup Success *******************")


def wifi_dut_marker(IEEE802_11W=0, memory_config=0):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator..
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | IEEE802_11W | memory_config
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    }
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
             'ssid': 'AP1',
             'security': 'WPA2',
             'passphrase': '123456789',
             'channel': 1
        },
        1: {
             'ssid': 'AP2',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1}
    }
)
@pytest.mark.test_src_map_id('C20150')
def test_wifi_sdk_ble_conn_ap1_conn_ap2_conn_C20150(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_sniffer, request, utf_constants,
        wifi_access_points):
    """Verify WLAN connection to the AP1 and AP2 while BLE is in connected state"""

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_points[0].interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_sniffer=wifi_sniffer, wifi_access_points=wifi_access_points,
            test_case=20150)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.credentials_send_over_ble()
        ble_obj.wifi_connect_ap1()
        ble_obj.access_point_leave_dut()
        ble_obj.wifi_connect_ap2()
        ble_obj.wifi_dut.interfaces.wifi.ble_remove_service()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
             'ssid': 'AP1',
             'security': 'WPA2',
             'passphrase': '123456789',
             'channel': 1
        },
        1: {
             'ssid': 'AP2',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1}
    }
)
@pytest.mark.test_src_map_id('C20151')
def test_wifi_sdk_ble_conn_ap1_conn_disconn_ap2_conn_C20151(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_points, wifi_sniffer, request, utf_constants):
    """Verify WLAN connection to the AP1 and AP2 while BLE is in connected state"""

    ble_obj = None
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_points[0].interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut,
            utf_constants=utf_constants, wifi_access_points=wifi_access_points, wifi_sniffer=wifi_sniffer,
            test_case=20151)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.credentials_send_over_ble()
        ble_obj.wifi_connect_ap1()
        ble_obj.access_point_leave_dut()
        ble_obj.wifi_connect_ap2()
        ble_obj.wifi_dut.interfaces.wifi.ble_remove_service()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()

@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
             'ssid': 'AP1',
             'security': 'WPA2',
             'passphrase': '123456789',
             'channel': 1
        },
        1: {
             'ssid': 'AP1',
             'security': 'WPA2',
             'passphrase': '123123123',
             'channel': 1}
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | 0,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | 0,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=0)
                        | Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=1)
                        | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
                        | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
                        | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
                        | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                   | Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C913668')
def test_wps_pbc_lockout_with_ble_coex_C913668(
        wifi_dut,
        ble_client,
        wifi_access_points,
        sl_collections,):

    """
    Verify DUT enters WPS lockout state when two APs run PBC simultaneously,
    while BLE central connection and TX indications remain stable.
    """
    ble_obj = None
    try:
        conn_interval = 250

        # -------------------------------------------------------------
        # Step 1: Initialize BLE + connect
        # -------------------------------------------------------------

        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1
        address = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
        wifi_dut.interfaces.wifi.load_memory(address=address, size=len(data), write_content=data)
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            ble_pairing=1,
            bond_info=1,
            char_path=None, char_uid=char_uid, data=data,
            service_uid=service_uid,
            data_length=240, data_duration=120,
            periodic_delay=0.5,
            address=address,
            conn_interval=conn_interval,
            set_smp=1
        )

        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)

        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1, service_handler_num=index,
                                                       value_handler_num=index + 1)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1, value_handler_num=index + 1)

        ble_obj.advertise_dut()
        ble_obj.scan_and_connect_from_remote()
        ble_obj.service_discovery_on_remote()
        ble_obj.start()

        # -------------------------------------------------------------
        # Step 2: Enable WPS PBC on both APs simultaneously
        # -------------------------------------------------------------
        logger().info("Triggering WPS PBC on AP1 and AP2 simultaneously")

        wifi_access_points[0].interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)
        time.sleep(0.2)  # Slight delay to ensure both APs start WPS at nearly the same time
        logger().info("Enabling WPS PBC on AP2")
        wifi_access_points[1].interfaces.wifi.set_configure_wps_web(enable_wps=True, push_button=True)

        time.sleep(30)  # Allow lockout behavior

        # -------------------------------------------------------------
        # Step 3: Trigger WPS on DUT
        # -------------------------------------------------------------

        logger().info("Triggering WPS PBC on DUT (expecting lockout)...")

        try:
            wifi_dut.interfaces.wifi.start_client_wps(
                interface="client",
                wps_role=0,
                wps_mode=0,
                auto_connect=True
            )

            # If it returns OK, that is wrong in this test
            assert False, "DUT unexpectedly succeeded WPS when two APs were active"

        except Exception as e:
            err = str(e)

            logger().info(f"WPS returned exception: {err}")

            # Validate expected lockout error
            assert "0x1002B" in err or "ASSOCIATION_TIMEOUT_IN_P2P_WPS_MODE" in err, \
                f"Unexpected WPS error: {err}"

        # -------------------------------------------------------------
        # Step 4: Validate BLE still connected
        # -------------------------------------------------------------
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        assert int(state) == 8, "BLE dropped during WPS lockout"

        ble_obj.wait_for_exit()
        logger().info("BLE remained stable during lockout")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()
        if ble_obj is not None:
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

