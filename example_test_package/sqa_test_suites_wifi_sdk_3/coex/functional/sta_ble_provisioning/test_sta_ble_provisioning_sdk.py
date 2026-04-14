import time
import pytest
import re
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService

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
        5. Credentials are sent from the client to the DUT
        6. DUT will scan list of available networks
        7. DUT will connect to the network with the credentials received from the client
        8. Validate the Acknowledgement from the DUT

    Author: Saurabh Sharma
"""


def logger():
    return get_logger(__name__)


class ProvisioningFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, test_case=None, ble_dut=None, ble_pairing=0,
                 utf_constants=None, wifi_access_point=None, wifi_sniffer=None, bt_dut_address=None, credentials=None,
                 ble_client_address=None, char_path=None, char_uid=None, adv_int=None, min_conn_interval=160,
                 max_conn_interval=160, conn_latency=0, supervision_timeout=3200):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.ble_pairing = ble_pairing
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

    def run(self):
        try:
            service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            self.char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
            svc = 'HealthThermometerService'
            charc = 'CustomNotifyCharacteristic'

            logger().info("******************** initializing ble in dut ********************")
            self.bt_dut_address = self.ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
            assert self.bt_dut_address, "failed to initialize ble in dut"

            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1)

            if self.test_case == 20143 or self.test_case == 20144 or self.test_case == 20145 or self.test_case == 20146 or self.test_case == 20147 or self.test_case == 20148 or self.test_case == 20149 or self.test_case == 20152 or self.test_case == 201159 or self.test_case == 201275 or self.test_case == 661503 or self.test_case == 198666:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()

            if self.test_case == 20158 or self.test_case == 20159 or self.test_case == 20160:
                self.wifi_dut.interfaces.wifi.ble_start_advertising(
                    ble_adv_int_min=int(self.adv_int / 0.625), ble_adv_int_max=int(self.adv_int / 0.625), timeout=20)

            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.bt_dut_address, services=[svc])

            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                            ble_dut_address=self.bt_dut_address,
                                            min_conn_interval=self.min_conn_interval,
                                            max_conn_interval=self.max_conn_interval,
                                            conn_latency=self.conn_latency,
                                            supervision_timeout=self.supervision_timeout)
            time.sleep(3)

            if self.test_case in [20145, 20149]:
                self.wifi_dut.interfaces.wifi.ble_update_conn_param(
                    ble_remote_dev_address=self.ble_client_address, ble_conn_interval_min=3200,
                    ble_conn_interval_max=3200, ble_conn_latency=0, ble_supervision_timeout=2000)

            logger().info(f"....Applying performance profile mode and Enable_bt_power_save....")
            self.ble_dut.interfaces.bluetooth.set_performance_profile(mode="power_save_low_latency")
            self.ble_dut.interfaces.bluetooth.enable_bt_power_save()

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

            # self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=self.char_path)

            if self.test_case == 20145 or self.test_case == 20147 or self.test_case == 20148 or self.test_case == 20149 or self.test_case == 201159 or self.test_case == 201275 or self.test_case == 661503 or self.test_case == 198666:
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

                write_handle = int(write_handles[index], 16)
                logger().info(f"write_handle:{write_handle}")
                assert write_handle > 0, "Unable to get write handle for configured service"

                self.credentials = []
                data = [self.wifi_access_point.interfaces.wifi.ssid, self.wifi_access_point.interfaces.wifi.passphrase,
                        self.wifi_access_point.interfaces.wifi.security.name.lower()]

                for length in range(len(data)):
                    self.ble_dut.interfaces.bluetooth.ble_set_att_value(
                        ble_remote_dev_address=self.ble_client_address, handle=(write_handle + 1), enable_notify=1)

                    since_time = time.perf_counter_ns()

                    logger().info("******************** Sending data to DUT ***********************")
                    self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(svc, charc, data[length])
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
                        ble_remote_dev_address=self.ble_client_address, handle=(write_handle + 1), enable_notify=0)
                    time.sleep(3)

        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

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
            # assert notifications == [str(ssid)], ".... SSID or Security Mismatch or Acknowledgement not received ....."
        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()
        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(5)

    def wifi_connect(self):
        if self.test_case == 201275:
            self.wifi_dut.interfaces.wifi.join(
                ssid=self.credentials[0], passphrase=self.credentials[1], security='wpa', enc='tkip')
            logger().info("....Successfully connected to the AP....")
        else:
            self.wifi_dut.interfaces.wifi.join(
                ssid=self.credentials[0], passphrase=self.credentials[1], security=self.credentials[2])
            logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {device_ip}")

        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')

        logger().info(f"DUT MAC ADDRESS :  {dut_mac_address} DUT IP ADDRESS : {device_ip}")

        logger().info(f"....Pinging to DUT before Power Save")
        status = self.sl_collections.ping(device_ip=device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
            ble_remote_dev_address=self.ble_client_address, data=device_ip)
        time.sleep(3)
        logger().info("******************** Validate Data ********************")
        notifications_data = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        logger().info(f' *********************** Notification is {notifications_data} ***********************')
        assert len(notifications_data) > 0, " .... received data is empty ...."
        assert notifications_data == [device_ip], ".... Device IP Mismatched or Acknowledgement not received ....."

        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(3)

    def firmware_version(self):
        fw_version = self.wifi_dut.interfaces.wifi.get_fw_version()
        logger().info(f"....Firmware version of DUT is {fw_version}....")

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
            ble_remote_dev_address=self.ble_client_address, data=fw_version)
        time.sleep(3)
        logger().info("******************** Validate Data ********************")
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        logger().info(f' *********************** Notification is {notifications} ***********************')
        assert len(notifications) > 0, " .... received data is empty ...."
        assert notifications == [fw_version], ".... Firmware Version Mismatched or Acknowledgement not received ....."

        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(1)

    def wifi_connect_wrong_psk(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[0], passphrase='thisisnotatestnetwork', security=self.credentials[2],
            expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
        logger().info("....De-Authentication received when trying to connect with AP using wrong PSK....")

    def ble_remove_servie(self):
        logger().info("******************** ble_remove_service ***********************")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_disconnect(self):
        logger().info("*********************** Disconnecting from DUT ***********************")
        self.ble_client.interfaces.bluetooth.disconnect(self.bt_dut_address)
        # self.ble_client.interfaces.bluetooth.close()

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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C20143')
def test_wifi_sdk_ble_conn_wlan_scan_provisioning_C20143(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify BLE connection and WLAN scan using STA+BLE provisioning Application"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20143)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C20144')
def test_wifi_sdk_ble_conn_disconn_along_wlan_scan_C20144(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify BLE connect and disconnect with DUT along with WLAN scan"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20144)

        iter_count = utf_constants.get("iter_count")
        for count in range(iter_count):
            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.wifi_scan()
            ble_obj.ble_remove_servie()
            ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C20145')
def test_wifi_sdk_ble_conn_along_wlan_conn_C20145(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify BLE and WLAN connection using STA+BLE provisioning app by configuring Maximum BLE Conn interval"""
    try:
        bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_conn_along_wlan_conn_C20145"
                                f"{int(time.time())}.log")
        test_name = request.node.name
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):

            logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

            ble_obj = ProvisioningFunctionality(
                wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
                utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                test_case=20145, min_conn_interval=200, max_conn_interval=200)

            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.wifi_scan()
            ble_obj.wifi_connect()
            ble_obj.ble_remove_servie()

            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C20146')
def test_wifi_sdk_ble_conn_and_firmware_version_C20146(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify Firmware version of DUT after BLE connection"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20146)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.firmware_version()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C20147')
def test_wifi_sdk_ble_conn_along_wrong_psk_C20147(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify wifi scan and connect with AP using wrong PSK while BLE is in connected state"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20147)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect_wrong_psk()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'thisisableprovisioningtestplannn'})
@pytest.mark.test_src_map_id('C20148')
def test_wifi_sdk_ble_conn_and_wifi_conn_with_32_bytes_ssid_C20148(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify Wifi connection with 32 bytes SSID AP  while BLE is in connected state"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20148)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"passphrase": 'thisiswifibleprovisioningtestplanthisisableprovisioningtestplan'})
@pytest.mark.test_src_map_id('C20149')
def test_wifi_sdk_ble_conn_and_wifi_conn_with_63_bytes_psk_C20149(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify Wifi connection with 63 bytes PSK AP while BLE is in the connected state by configuring
    Maximum BLE Conn interval"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20149, min_conn_interval=200, max_conn_interval=200)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()
        ble_obj.ble_remove_servie()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.test_src_map_id('C20152')
def test_wifi_sdk_ble_conn_and_verify_ssid_security_provisioning_C20152(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify the SSID, Security_Type and max scan list of AP while BLE is in connected state"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20152)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C20158')
def test_wifi_sdk_ble_conn_20ms_adv_wlan_scan_provisioning_C20158(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify WLAN scan by enabling BLE 20ms advertising interval on DUT"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            adv_int=20, test_case=20158)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C20159')
def test_wifi_sdk_ble_conn_500ms_adv_wlan_scan_provisioning_C20159(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify WLAN scan by enabling BLE 500ms advertising interval on DUT"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            adv_int=500, test_case=20159)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()



@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.test_src_map_id('C20160')
def test_wifi_sdk_ble_conn_250ms_adv_wlan_scan_provisioning_C20160(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify wifi scan by enabling 250ms advertising interval on DUT"""
    try:
        bt_mon_log_file_name = (f"reports/test_wifi_sdk_ble_conn_250ms_adv_wlan_scan_provisioning_C20160"
                                f"{int(time.time())}.log")
        test_name = request.node.name

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=bt_mon_log_file_name):

            logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

            ble_obj = ProvisioningFunctionality(
                wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
                utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                adv_int=250, test_case=20160)

            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.wifi_scan()
            ble_obj.ble_remove_servie()
            ble_obj.ble_disconnect()

            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'OPEN'})
@pytest.mark.test_src_map_id('C201159')
def test_wifi_sdk_ble_conn_along_wlan_conn_open_security_C201159(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify WLAN connection to the AP with Open security using STA+BLE provisioning Application"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=201159)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker(IEEE802_11W=Si91xExtCustomFeatureBitMap.IEEE802_11W, memory_config=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C661503')
def test_wifi_sdk_ble_conn_along_wlan_conn_WPA3_security_C661503(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify WLAN connection to the AP with WPA3 security using STA+BLE provisioning Application"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=661503)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


@wifi_dut_marker()
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPAWPA2MixedMode', "cipher": "TKIP_AES", "passphrase": '123456789'})
@pytest.mark.test_src_map_id('C201275')
def test_wifi_sdk_ble_conn_along_wlan_conn_WPA_security_C201275(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, request, utf_constants):
    """Verify WLAN connection to the AP with WPA security using STA+BLE provisioning Application"""
    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=201275)

        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()
        ble_obj.ble_remove_servie()
        ble_obj.ble_disconnect()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
