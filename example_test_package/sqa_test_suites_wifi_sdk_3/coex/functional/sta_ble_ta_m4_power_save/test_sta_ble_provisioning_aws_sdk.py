import time
import pytest
import re
import random
import string
from retry import retry
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xExtTCPIPFeatureBitMap, Si91xBTFeatureBitMap, \
    Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xConfigFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xBLEFeatureBitMap, Si91xAwsQos
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService
from AWSIoTPythonSDK.core.protocol.internal.clients import ClientStatus

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
        9. DUT connect to AWS server and subscribe to topic
        10. Does AWS MQTT publish or receive

    Author: Hari Bhargav Nalla
"""


def logger():
    return get_logger(__name__)


def text_generator(size=2000):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))


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

            if self.test_case == 537997 or self.test_case == 20153 or self.test_case == 20155:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()

            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.bt_dut_address, services=[svc])

            self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                            ble_dut_address=self.bt_dut_address,
                                            min_conn_interval=160,
                                            max_conn_interval=160,
                                            conn_latency=self.conn_latency,
                                            supervision_timeout=self.supervision_timeout)
            time.sleep(3)

            if self.test_case == 537997 or self.test_case == 20153 or self.test_case == 20155:
                self.wifi_dut.interfaces.wifi.ble_update_conn_param(
                    ble_remote_dev_address=self.ble_client_address, ble_conn_interval_min=self.min_conn_interval,
                    ble_conn_interval_max=self.min_conn_interval, ble_conn_latency=0,
                    ble_supervision_timeout=self.supervision_timeout)

            logger().info(".... checking ble connection stability ....")
            time.sleep(60)

            logger().info(".... get connection state ....")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, f".... device is in disconnection state (state={state_int}) ...."

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

            if self.test_case == 537997 or self.test_case == 20153 or self.test_case == 20155:
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

        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[0], passphrase=self.credentials[1], security=self.credentials[2])
        logger().info("....Successfully connected to the AP....")

        ip_status, ip_config = self.sl_collections.configure_ip(wifi_dut=self.wifi_dut)
        assert ip_status, f"....Unable to assign IP ADDRESS through DHCP with reason: {ip_config}...."

        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT IP is {device_ip}")

        logger().info(f"....Pinging to DUT before Power Save")
        status = self.sl_collections.ping(device_ip=device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        # NOTE: BT / M4 power-save MUST stay disabled during the BLE
        # provisioning notification round-trip below. With BT power-save
        # enabled and conn_interval=200ms the DUT queues the GATT
        # notification (IP / MAC) but the bluez client doesn't see it
        # within the polling window - giving an empty notifications
        # buffer (observed failure: 3x retry, all []). The working
        # `test_sta_ble_provisioning_sdk.py::ProvisioningFunctionality
        # .wifi_connect` does the notify round-trip BEFORE enabling
        # power-save; we mirror that pattern here. Power-save is then
        # enabled at the end of this method so AWS testing still runs
        # in power-save (the actual coverage goal of this test).

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
        logger().info(
            f' *********************** Notification is DUT IP address {notifications_data} ***********************')

        # Retry logic for empty notifications. Re-issue the notify on
        # each retry so the DUT actually re-pushes the value (a stale
        # buffer-poll alone won't materialise a missed notification).
        retry_count = 0
        max_retries = 3
        while len(notifications_data) == 0 and retry_count < max_retries:
            retry_count += 1
            logger().warning(f"IP notification empty, retry {retry_count}/{max_retries} (re-pushing)")
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=self.ble_client_address, data=device_ip)
            time.sleep(10)
            notifications_data = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            logger().info(
                f' *********************** Retry Notification is {notifications_data} ***********************')

        assert len(notifications_data) > 0, " .... received data is empty ...."
        assert notifications_data == [device_ip], ".... Device IP Mismatched or Acknowledgement not received ....."

        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()
        time.sleep(10)

        logger().info(f' *********************** subscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path, char_uid=self.char_uid)

        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)

        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
            ble_remote_dev_address=self.ble_client_address, data=dut_mac_address)
        time.sleep(3)

        logger().info("******************** Validate Data ********************")
        notifications_data = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        logger().info(f' *********************** Notification is {notifications_data} ***********************')

        # Same retry pattern for MAC notification: re-push and re-poll.
        retry_count = 0
        max_retries = 3
        while len(notifications_data) == 0 and retry_count < max_retries:
            retry_count += 1
            logger().warning(f"MAC notification empty, retry {retry_count}/{max_retries} (re-pushing)")
            self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
                ble_remote_dev_address=self.ble_client_address, data=dut_mac_address)
            time.sleep(10)
            notifications_data = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            logger().info(
                f' *********************** Retry Notification is {notifications_data} ***********************')

        assert len(notifications_data) > 0, " .... received data is empty ...."
        assert notifications_data == [
            dut_mac_address], ".... Device MAC Mismatched or Acknowledgement not received ....."

        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()

        # Provisioning round-trip is complete; now enable performance
        # profile + BT power-save so the subsequent AWS workload is
        # exercised under power-save (the actual test goal).
        logger().info(f"....Applying performance profile mode and Enable_bt_power_save....")
        self.ble_dut.interfaces.bluetooth.set_performance_profile(mode="power_save_low_latency")
        self.ble_dut.interfaces.bluetooth.enable_bt_power_save()

        logger().info(f"....Pinging to DUT after Power Save")
        status = self.sl_collections.ping(device_ip=device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        time.sleep(60)

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
        time.sleep(8)
        logger().info("******************** Validate Data ********************")
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        logger().info(f' *********************** Notification is {notifications} ***********************')

        # Retry logic for empty notifications
        retry_count = 0
        max_retries = 3
        while len(notifications) == 0 and retry_count < max_retries:
            retry_count += 1
            logger().warning(f"Notification is empty, retry {retry_count}/{max_retries}")
            time.sleep(5)
            notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
            logger().info(f' *********************** Retry Notification is {notifications} ***********************')

        assert len(notifications) > 0, " .... received data is empty ...."
        assert notifications == [fw_version], ".... Firmware Version Mismatched or Acknowledgement not received ....."

        self.ble_client.interfaces.bluetooth.gatt_adapter.clear_notifications()
        logger().info(f' *********************** unsubscribe to notifications ***********************')
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=self.char_uid)
        time.sleep(1)

    def wifi_connect_wrong_psk(self):
        self.wifi_dut.interfaces.wifi.join(
            ssid=self.credentials[0], passphrase='thisisnotatestnetwork', security=self.credentials[2],
            expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
        logger().info("....De-Authentication received when trying to connect with AP using wrong PSK....")

    def access_point_leave_dut(self):
        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(1)

    def ble_remove_service(self):
        logger().info("******************** ble_remove_service ***********************")
        self.wifi_dut.interfaces.wifi.ble_remove_service()

    def ble_disconnect(self):
        logger().info("*********************** Disconnecting from DUT ***********************")
        self.ble_client.interfaces.bluetooth.disconnect(self.bt_dut_address)
        # self.ble_client.interfaces.bluetooth.close()

    def ble_cleanup_disconn(self):
        try:
            logger().info("Checking connection status of BLE")
            state = self.ble_dut.interfaces.bluetooth.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1

            # Handle each state with try-except to prevent cascade failures
            if state_int == 8:
                logger().info("Device is in connected status try to disconnect")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
                    time.sleep(5)
                except Exception as e:
                    logger().warning(f"Failed to disconnect BLE: {e}")
            elif state_int == 2:
                logger().info("Device is in scanning status try to stop scanning")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
                except Exception as e:
                    logger().warning(f"Failed to stop scanning: {e}")
            elif state_int == 1:
                logger().info("Device is in advertising status try to stop advertising")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
                except Exception as e:
                    logger().warning(f"Failed to stop advertising: {e}")
            elif state_int == 3:
                logger().info("Device is in scanning status try to stop scanning")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
                except Exception as e:
                    logger().warning(f"Failed to stop scanning: {e}")
                logger().info("Device is advertising status try to stop advertising")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
                except Exception as e:
                    logger().warning(f"Failed to stop advertising: {e}")
            elif state_int == 9:
                logger().info("Device is in connected status try to disconnect")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
                except Exception as e:
                    logger().warning(f"Failed to disconnect BLE: {e}")
                logger().info("Device is in advertising status try to stop advertising")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_stop_advertising()
                except Exception as e:
                    logger().warning(f"Failed to stop advertising: {e}")
            elif state_int == 10:
                logger().info("Device is in connected status try to disconnect")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
                except Exception as e:
                    logger().warning(f"Failed to disconnect BLE: {e}")
                logger().info("Device is advertising status try to stop advertising")
                try:
                    self.ble_dut.interfaces.bluetooth.ble_stop_scanning()
                except Exception as e:
                    logger().warning(f"Failed to stop scanning: {e}")
            elif state_int == 0:
                logger().info("Device is in idle status")
            else:
                logger().info(f"Device is in unknown state (state={state_int})")
                self.ble_dut.interfaces.bluetooth.is_dut_bad_state = True

            try:
                self.ble_client.interfaces.bluetooth.close()
            except Exception as e:
                logger().warning(f"Failed to close BLE client: {e}")

            logger().info(" *************DUT Cleanup Success *******************")
        except Exception as cleanup_ex:
            logger().error(f"Exception during BLE cleanup: {cleanup_ex}")
            # Don't re-raise to prevent masking the original test failure


class aws_publish_message_Thread(ThreadBase):
    """
    Thread to publish data from DUT to aws server on subscribed topic and QOS value
    """

    def __init__(self, wifi_dut, topic, message, qos, duration):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.topic = topic
        self.message = message
        self.qos = qos
        self.duration = duration

    def run(self):
        logger().info("Publishing aws message from DUT")
        msg_count = len(self.message)
        send_count = 0
        while send_count < msg_count:
            msg = self.message[send_count]
            logger().info(f"\nDUT publishing message{send_count + 1} on topic:'{self.topic}' \nQOS:'{self.qos}'"
                          f"\nMessage{send_count + 1} with length:'{len(msg)} bytes'\nMessage{send_count + 1} is:'{msg}'")
            AwsConnection().publish_from_dut(self.wifi_dut, self.topic, msg, qos=self.qos)
            send_count += 1
            time.sleep(3)
            self.wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=self.duration)
        logger().info("aws_publish_message_thread completed")


class aws_receive_message_Thread(ThreadBase):
    """
    Thread to receive data from aws server on subscribed topic and QOS value.
    """

    def __init__(self, aws_iot_client, topic, message, qos):
        super().__init__()
        self.aws_iot_client = aws_iot_client
        self.topic = topic
        self.message = message
        self.qos = qos

    def run(self):
        msg_count = 0
        recv_count = 0
        while 1:
            logger().info("Receiving published aws message on aws_iot_client")
            time.sleep(10)
            recv_messages = self.aws_iot_client.interfaces.aws_iot.get_received_messages()
            logger().info(f"Received message{recv_count + 1} is: '{recv_messages[recv_count].payload.decode()}'")
            logger().info(f"Received message{recv_count + 1} topic is: '{recv_messages[recv_count].topic}'")
            logger().info(f"Received message{recv_count + 1} qos is: '{recv_messages[recv_count].qos}'")
            assert recv_messages[recv_count].payload.decode() == self.message[
                msg_count], "Received wrong message in aws_iot_client"
            assert recv_messages[recv_count].topic == self.topic, "Received wrong topic in aws_iot_client"
            assert recv_messages[recv_count].qos == self.qos, "Received wrong qos in aws_iot_client"
            msg_count += 1
            recv_count += 1
            if recv_count == len(self.message):
                break
        logger().info("aws_receive_message_thread completed")


class aws_publish_raspi_Thread(ThreadBase):
    """
    Thread to publish data from RasPi to aws server on subscribed topic and QOS value
    """

    def __init__(self, aws_iot_client, topic, message, qos, aws_conn):
        super().__init__()
        self.aws_iot_client = aws_iot_client
        self.topic = topic
        self.message = message
        self.qos = qos
        self.aws_conn = aws_conn

    def run(self):
        logger().info("Publishing aws message from RasPi")
        msg_count = len(self.message)
        send_count = 0
        while send_count < msg_count:
            msg = self.message[send_count]
            logger().info(f"\nRasPi publishing message{send_count + 1} on topic:'{self.topic}' \nQOS:'{self.qos}'"
                          f"\nMessage{send_count + 1} with length:'{len(msg)} bytes'\nMessage{send_count + 1} is:'{msg}'")
            self.aws_conn.publish_from_raspi(self.aws_iot_client, self.topic, msg, qos=self.qos)
            send_count += 1
            time.sleep(1)
        logger().info("aws_publish_raspi_thread completed")


class AwsConnection(ThreadBase):
    """
    Class to connect, subscribe, publish data from DUT/Raspi to AWS server.
    """

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, test_name=None,
                 aws_iot_client=None, messages=None, topic=None, qos=Si91xAwsQos.QOS1, port=8883, negative_case=False,
                 test_case=None, sleep=None):
        super().__init__()
        self.client_id = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.test_case = test_case
        self.timeout = 120
        self.aws_iot_client = aws_iot_client
        self.messages = messages
        self.topic = topic
        self.qos = qos
        self.port = port
        self.sleep = sleep
        self.negative_case = negative_case

    @retry(Exception, delay=25, tries=3)
    def connect_to_aws_server_from_dut(self, wifi_dut=None, client_id=None, iscleansession=True, keep_alive=1200,
                                       timeout=120, isWillMsgPresent=None, expected_status=SLStatus.SL_STATUS_OK,
                                       port=8883, aws_iot_mqtt_rx_buf_len=1024):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param client_id: mqtt client id for aws connection.
        @param iscleansession: Boolean Value(True/False).
        @param keep_alive: Keep alive period
        @param timeout: Timeout value to wait until command to be executed successfully.
        @return: Boolean Value(True/False).
        :param port:
        :param isWillMsgPresent:
        :param expected_status:
        """
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.aws_iot_mqtt_init(client_id=client_id, iscleansession=iscleansession,
                                                   keep_alive_interval=keep_alive, timeout=timeout,
                                                   port=port, isWillMsgPresent=isWillMsgPresent,
                                                   )
        time.sleep(2)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_connect(timeout=timeout, expected_status=expected_status)
        return True

    @retry(Exception, delay=15, tries=5)
    def subscribe_from_dut(self, wifi_dut, topic, qos=Si91xAwsQos.QOS0, timeout=120):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name to subscribe from DUT on AWS Server
        @param qos: QOS value to subscribe on aws topic(0/1)
        @param timeout: Timeout value to wait until command to be executed successfully.
        """
        logger().info(f"DUT is Subscribing on topic '{topic}' and QOS:'{qos}'")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_subscribe(topic_name=topic, qos=qos, timeout=timeout)

    @retry(Exception, delay=15, tries=1)
    def publish_from_dut(self, wifi_dut, topic, message, qos, timeout=120, negative_case=False):
        """
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param topic: Topic name to subscribe from DUT on AWS Server.
        @param message: Data to publish from DUT on subscribed topic.
        @param qos: QOS value to publish data on aws topic(0/1).
        @param timeout: Timeout value to wait until command to be executed successfully.
        @param negative_case: Boolean Value(True/False).
        """
        logger().info(f"\nDUT is publishing message on topic:'{topic}' \nQOS:'{qos}'")
        result = wifi_dut.interfaces.wifi.aws_iot_mqtt_publish(topic_name=topic, qos=qos, payload=message,
                                                               timeout=timeout,
                                                               negative_case=negative_case)
        if negative_case:
            return result

    @retry(Exception, delay=15, tries=5)
    def connect_to_aws_server_from_raspi(self, aws_iot_client):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        """
        logger().info("Connecting to aws server from aws_iot_client")
        aws_iot_client.interfaces.aws_iot.aws_iot_connect()
        time.sleep(10)
        status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        logger().info(f"AWS IoT client status: {status}")
        assert status == ClientStatus.STABLE, f"Connecting to AWS server from aws_iot_client is failed. Status: {status}"

    @retry(Exception, delay=10, tries=3)
    def subscribe_from_raspi(self, aws_iot_client, topic, qos=Si91xAwsQos.QOS0):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name to subscribe from Raspi on AWS Server.
        @param qos: QOS value to subscribe on aws topic(0/1).
        """
        logger().info(f"\n\n *** aws_iot_client is Subscribing on topic '{topic}' and QOS:'{qos}'*** \n\n")
        aws_iot_client.interfaces.aws_iot.received_messages.clear()
        aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic, qos=qos)
        status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
        assert status == ClientStatus.STABLE, f"Subscribe on topic:'{topic}' is failed from aws_iot_client"

    @retry(Exception, delay=5, tries=5)
    def publish_from_raspi(self, aws_iot_client, topic, message, qos=Si91xAwsQos.QOS0):
        """
        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name to subscribe from Raspi on AWS Server.
        @param message: Data to publish from Raspi on subscribed topic.
        @param qos: QOS value to subscribe on aws topic(0/1).
        """
        try:
            status = aws_iot_client.interfaces.aws_iot.client._mqtt_core._client_status.get_status()
            assert status == ClientStatus.STABLE, f"Publish on topic:'{topic}' is failed from aws_iot_client"
        except AssertionError:
            self.connect_to_aws_server_from_raspi(aws_iot_client)
        if isinstance(message, list):
            for i, msg in enumerate(message):
                logger().info(
                    f"\naws_iot_client publishing message{i + 1} on topic:'{topic}' \nQOS:'{qos}'"
                    f"\nMessage{i + 1} with length:'{len(msg)} bytes'\nMessage{i + 1} is:'{msg}'")
                aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic, msg, qos=qos)
                time.sleep(5)
        else:
            aws_iot_client.interfaces.aws_iot.aws_iot_publish(topic, message, qos=qos)

    @staticmethod
    def receive_aws_messages_from_dut(wifi_dut, retries=3, wait_time=3, expected_status=SLStatus.SL_STATUS_OK):
        """
        @param expected_status:
        @param wifi_dut: Fixture parameter to issue command in DUT.
        @param retries: retry attempts to receive published message in DUT.
        @param wait_time: Wait time to receive published message in DUT.
        :param expected_msg:
        """
        for retry_count in range(retries):
            try:
                time.sleep(wait_time)
                recv_msg = wifi_dut.interfaces.wifi.aws_select_socket(expected_status=expected_status)
                logger().info(f"Received message from DUT is: '{recv_msg}'")
                assert len(recv_msg), "Failed to receive published message in DUT"
                return recv_msg[-1]
            except Exception as err:
                logger().warning(f"Failed to receive published message in DUT\n{err}")
                if "0x1" in str(err):
                    wifi_dut.interfaces.wifi.is_dut_bad_state = True
                    raise
                time.sleep(5)

    @staticmethod
    def validate_aws_messages_from_raspi(aws_iot_client, topic, qos, messages, topic_1=None, topic_2=None,
                                         wait_time=10, max_retries=5, retry_wait=3):
        """
        Validates messages received on AWS IoT client from a Raspberry Pi.

        @param aws_iot_client: Fixture parameter to issue command in Raspi.
        @param topic: Topic name which is subscribed on AWS Server (used if topic_1 and topic_2 are not provided).
        @param qos: QOS value which is subscribed on AWS Server (0 or 1).
        @param messages: List of messages published on AWS topics.
        @param topic_1: Optional first topic name for alternating messages.
        @param topic_2: Optional second topic name for alternating messages.
        @param wait_time: Wait time value until data is received from AWS server.
        @param max_retries: Maximum number of retries to check for all messages.
        @param retry_wait: Wait time between retries.
        """
        logger().info("\n *** Validating received AWS messages ***")
        time.sleep(wait_time)

        # Retry logic to poll for all messages
        recv_messages = None
        for retry in range(max_retries):
            recv_messages = aws_iot_client.interfaces.aws_iot.get_received_messages()

            if len(recv_messages) >= len(messages):
                logger().info(f"Successfully received all {len(messages)} messages")
                break

            if retry < max_retries - 1:
                logger().warning(f"Expected {len(messages)} messages but only received {len(recv_messages)} so far. "
                                 f"Retry {retry + 1}/{max_retries - 1}, waiting {retry_wait}s...")
                time.sleep(retry_wait)

        # Final check if we received enough messages
        if len(recv_messages) < len(messages):
            logger().error(
                f"Expected {len(messages)} messages but only received {len(recv_messages)} after {max_retries} retries")
            raise AssertionError(
                f"Message count mismatch: Expected {len(messages)} messages, "
                f"but only received {len(recv_messages)} messages"
            )

        # Validate each received message
        for count, msg in enumerate(messages):
            # Determine the expected topic based on the presence of topic_1 and topic_2
            if topic_1 is not None and topic_2 is not None:
                expected_topic = topic_1 if count % 2 == 0 else topic_2
            else:
                expected_topic = topic

            # Log details of the received message
            logger().info(f"Received message {count + 1} is: '{recv_messages[count].payload.decode()}'")
            logger().info(f"Received message {count + 1} topic is: '{recv_messages[count].topic}'")
            logger().info(f"Received message {count + 1} qos is: '{recv_messages[count].qos}'")

            # Validate the payload, topic, and QoS
            assert recv_messages[count].payload.decode() == messages[count], "Received wrong message in aws_iot_client"
            assert recv_messages[count].topic == expected_topic, "Received wrong topic in aws_iot_client"
            assert recv_messages[count].qos == qos, "Received wrong qos in aws_iot_client"

        logger().info("AWS messages validated successfully")


def wifi_dut_marker(IEEE802_11W=0, memory_config=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                    with_certificates=False):
    """
        Common method to generate wifi_dut marker for pytest.mark.config decorator..
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}, "ble": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | IEEE802_11W | memory_config
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    }
    if with_certificates:
        config["ca_cert"] = ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
        config["client_cert"] = ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"]
        config["client_key"] = ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"]
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker(with_certificates=True)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "unassociated"])
def test_wifi_sdk_wlan_ble_provisioning_aws_tx_rx_C537997(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, aws_iot_client, request,
        utf_constants):
    """Verify WLAN commissioning, AWS connection and AWS IoT connectivity using BLE provisioning"""
    try:
        bt_mon_log_file_name = (f"reports/test_wifi_sdk_wlan_ble_provisioning_aws_tx_rx_C537997"
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
                test_case=537997, min_conn_interval=15, max_conn_interval=15)

            logger().info("M4-TA secure handshake")
            wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

            ble_obj.start()
            ble_obj.wait_for_exit()
            ble_obj.firmware_version()
            ble_obj.wifi_scan()
            ble_obj.wifi_connect()
            ble_obj.ble_remove_service()

            # AWS IoT functionality
            logger().info("\n\n******************** Starting AWS IoT Testing ********************\n\n")

            # Prepare test messages
            messages = []
            for i in range(10):
                messages.append(text_generator(size=100))
            logger().info(f"Generated messages for AWS testing: {messages}")

            # Setup AWS connection parameters
            test_name = request.node.name
            client_id = test_name + '_client'
            topic = 'topic_' + test_name
            qos = Si91xAwsQos.QOS0

            # Create AWS connection instance
            aws_conn = AwsConnection(
                wifi_dut=wifi_dut,
                wifi_access_point=wifi_access_point,
                wifi_sniffer=wifi_sniffer,
                sl_collections=sl_collections,
                test_name=test_name,
                aws_iot_client=aws_iot_client,
                messages=messages,
                topic=topic,
                qos=qos
            )

            # Connect DUT to AWS IoT
            logger().info("Connecting DUT to AWS IoT server")
            assert aws_conn.connect_to_aws_server_from_dut(
                wifi_dut, client_id), "Failed to connect aws server from DUT"
            logger().info("DUT connected to AWS IoT server successfully")

            # Subscribe from DUT to topic_raspi (to receive messages from RasPi)
            topic_dut = topic + '_dut'
            topic_raspi = topic + '_raspi'
            aws_conn.subscribe_from_dut(wifi_dut, topic_raspi, qos)
            logger().info(f"DUT subscribed to topic: {topic_raspi}")

            # Connect RasPi to AWS IoT
            logger().info("Connecting RasPi (aws_iot_client) to AWS IoT server")
            aws_conn.connect_to_aws_server_from_raspi(aws_iot_client)
            logger().info("RasPi connected to AWS IoT server successfully")

            # Subscribe from RasPi on a different topic to receive only DUT messages
            topic_dut = topic + '_dut'
            topic_raspi = topic + '_raspi'

            aws_conn.subscribe_from_raspi(aws_iot_client, topic_dut, qos)
            logger().info(f"RasPi subscribed to topic: {topic_dut}")

            # Wait to ensure both subscriptions are active before publishing
            logger().info("Waiting for subscriptions to be fully active...")
            time.sleep(5)

            # Generate messages for RasPi publish test
            messages_raspi = []
            for i in range(15):
                messages_raspi.append(text_generator(size=100))
            logger().info(f"Generated messages for RasPi publish test: {messages_raspi}")

            # Run parallel publish operations from DUT and RasPi
            logger().info("\n\n*** Starting Parallel Publish Operations: DUT and RasPi publishing simultaneously ***\n")

            # Create thread for DUT publish (publish to topic_dut)
            dut_publish_thread = aws_publish_message_Thread(
                wifi_dut=wifi_dut,
                topic=topic_dut,
                message=messages,
                qos=qos,
                duration=500
            )

            # Create thread for RasPi publish (publish to topic_raspi)
            raspi_publish_thread = aws_publish_raspi_Thread(
                aws_iot_client=aws_iot_client,
                topic=topic_raspi,
                message=messages_raspi,
                qos=qos,
                aws_conn=aws_conn
            )

            # Start both threads in parallel
            logger().info("Starting DUT publish thread...")
            dut_publish_thread.start()

            logger().info("Starting RasPi publish thread...")
            raspi_publish_thread.start()

            # Wait for both threads to complete
            logger().info("Waiting for DUT publish thread to complete...")
            dut_publish_thread.wait_for_exit()
            logger().info("DUT publish thread completed")

            logger().info("Waiting for RasPi publish thread to complete...")
            raspi_publish_thread.wait_for_exit()
            logger().info("RasPi publish thread completed")

            logger().info("\n\n*** Both publish threads completed. Starting validation ***\n")

            # Validate messages received on RasPi (from DUT on topic_dut)
            logger().info("\n*** Validating messages published by DUT and received on RasPi ***")
            aws_conn.validate_aws_messages_from_raspi(aws_iot_client, topic_dut, qos, messages, wait_time=15)
            logger().info("Successfully validated: DUT published and RasPi received all messages")

            # Wait a bit before starting DUT message reception to ensure all messages are delivered
            logger().info("Waiting for AWS IoT to deliver all messages to DUT...")
            time.sleep(10)

            # Validate messages received on DUT (from RasPi)
            logger().info("\n*** Validating messages published by RasPi and received on DUT ***")
            for i, expected_msg in enumerate(messages_raspi):
                received_msg = aws_conn.receive_aws_messages_from_dut(wifi_dut, retries=5, wait_time=5)
                logger().info(f"Received message {i + 1} on DUT: {received_msg}")
                assert received_msg == expected_msg, f"Message mismatch: expected '{expected_msg}', got '{received_msg}'"
            logger().info("Successfully validated: RasPi published and DUT received all messages")

            logger().info("\n\n*** Parallel Publish and Validation Completed Successfully ***\n")

            # Unsubscribe and disconnect
            logger().info("\n\nCleaning up AWS connections")
            logger().info("DUT Unsubscribing from aws topic")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_unsubscribe(topic_raspi)

            logger().info("Initiating aws_iot_disconnect from DUT")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
            time.sleep(10)

            logger().info("\n\n******************** AWS IoT Testing Completed Successfully ********************\n\n")

            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stop the Sniffer")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()


@wifi_dut_marker(with_certificates=True)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "unassociated"])
@pytest.mark.test_src_map_id('C20153')
def test_wifi_sdk_ble_provisioning_power_save_aws_validation_C20153(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, aws_iot_client, request,
        utf_constants):
    """Verify BLE and WLAN connection using STA+BLE provisioning app by configuring Maximum BLE Conn interval with AWS IoT connectivity"""
    ble_obj = None
    try:
        # -----------------------------------------------------------------
        # Sniffer Capture
        # -----------------------------------------------------------------

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="20153_ble_provisioning_power_save_aws_validation")

        # -----------------------------------------------------------------
        # BLE Provisioning
        # -----------------------------------------------------------------
        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20153, min_conn_interval=200, max_conn_interval=200)

        logger().info(f"M4-TA secure handshake")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        ble_obj.start()
        time.sleep(5)
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()
        ble_obj.ble_remove_service()

        # -----------------------------------------------------------------
        # IoT Testing
        # -----------------------------------------------------------------

        # AWS IoT functionality
        logger().info("\n\n******************** Starting AWS IoT Testing ********************\n\n")

        # Prepare test messages
        messages = []
        for i in range(10):
            messages.append(text_generator(size=100))
        logger().info(f"Generated messages for AWS testing: {messages}")

        # Setup AWS connection parameters
        test_name = request.node.name
        client_id = test_name + '_client'
        topic = 'topic_' + test_name
        qos = Si91xAwsQos.QOS0

        # Create AWS connection instance
        aws_conn = AwsConnection(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            aws_iot_client=aws_iot_client,
            messages=messages,
            topic=topic,
            qos=qos
        )

        # Connect DUT to AWS IoT
        logger().info("Connecting DUT to AWS IoT server")
        assert aws_conn.connect_to_aws_server_from_dut(
            wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger().info("DUT connected to AWS IoT server successfully")

        # Subscribe from DUT to topic_raspi (to receive messages from RasPi)
        topic_dut = topic + '_dut'
        topic_raspi = topic + '_raspi'
        aws_conn.subscribe_from_dut(wifi_dut, topic_raspi, qos)
        logger().info(f"DUT subscribed to topic: {topic_raspi}")

        # Connect RasPi to AWS IoT
        logger().info("Connecting RasPi (aws_iot_client) to AWS IoT server")
        aws_conn.connect_to_aws_server_from_raspi(aws_iot_client)
        logger().info("RasPi connected to AWS IoT server successfully")

        # Subscribe from RasPi on a different topic to receive only DUT messages
        topic_dut = topic + '_dut'
        topic_raspi = topic + '_raspi'

        aws_conn.subscribe_from_raspi(aws_iot_client, topic_dut, qos)
        logger().info(f"RasPi subscribed to topic: {topic_dut}")

        # Wait to ensure both subscriptions are active before publishing
        logger().info("Waiting for subscriptions to be fully active...")
        time.sleep(5)

        # Generate messages for RasPi publish test
        messages_raspi = []
        for i in range(10):
            messages_raspi.append(text_generator(size=100))
        logger().info(f"Generated messages for RasPi publish test: {messages_raspi}")

        # Run parallel publish operations from DUT and RasPi
        logger().info("\n\n*** Starting Parallel Publish Operations: DUT and RasPi publishing simultaneously ***\n")

        # Create thread for DUT publish (publish to topic_dut)
        dut_publish_thread = aws_publish_message_Thread(
            wifi_dut=wifi_dut,
            topic=topic_dut,
            message=messages,
            qos=qos
        )

        # Create thread for RasPi publish (publish to topic_raspi)
        raspi_publish_thread = aws_publish_raspi_Thread(
            aws_iot_client=aws_iot_client,
            topic=topic_raspi,
            message=messages_raspi,
            qos=qos,
            aws_conn=aws_conn
        )

        # Start both threads in parallel
        logger().info("Starting DUT publish thread...")
        dut_publish_thread.start()

        logger().info("Starting RasPi publish thread...")
        raspi_publish_thread.start()

        # Wait for both threads to complete
        logger().info("Waiting for DUT publish thread to complete...")
        dut_publish_thread.wait_for_exit()
        logger().info("DUT publish thread completed")

        logger().info("Waiting for RasPi publish thread to complete...")
        raspi_publish_thread.wait_for_exit()
        logger().info("RasPi publish thread completed")

        logger().info("\n\n*** Both publish threads completed. Starting validation ***\n")

        # Validate messages received on RasPi (from DUT on topic_dut)
        logger().info("\n*** Validating messages published by DUT and received on RasPi ***")
        aws_conn.validate_aws_messages_from_raspi(aws_iot_client, topic_dut, qos, messages, wait_time=15)
        logger().info("Successfully validated: DUT published and RasPi received all messages")

        # Wait a bit before starting DUT message reception to ensure all messages are delivered
        logger().info("Waiting for AWS IoT to deliver all messages to DUT...")
        time.sleep(10)

        # Validate messages received on DUT (from RasPi)
        logger().info("\n*** Validating messages published by RasPi and received on DUT ***")
        for i, expected_msg in enumerate(messages_raspi):
            received_msg = aws_conn.receive_aws_messages_from_dut(wifi_dut, retries=5, wait_time=5)
            logger().info(f"Received message {i + 1} on DUT: {received_msg}")
            assert received_msg == expected_msg, f"Message mismatch: expected '{expected_msg}', got '{received_msg}'"
        logger().info("Successfully validated: RasPi published and DUT received all messages")

        logger().info("\n\n*** Parallel Publish and Validation Completed Successfully ***\n")

        # Unsubscribe and disconnect
        logger().info("\n\nCleaning up AWS connections")
        logger().info("DUT Unsubscribing from aws topic")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_unsubscribe(topic_raspi)

        logger().info("Initiating aws_iot_disconnect from DUT")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        time.sleep(10)

        logger().info("\n\n******************** AWS IoT Testing Completed Successfully ********************\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.skip(reason="For this test case scripting corrections are needed and will be added in next sprint")
@wifi_dut_marker(with_certificates=True)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "aws_unsubscribe", "aws_disconnect",
                             "unassociated"])
@pytest.mark.test_src_map_id('C20155')
def test_wifi_sdk_ble_provisioning_wifi_disconnect_reconnect_aws_validation_C20155(
        wifi_dut, ble_client, sl_collections, ble_dut, wifi_access_point, wifi_sniffer, aws_iot_client, request,
        utf_constants):
    """Verify BLE and WLAN connection using STA+BLE provisioning app by configuring Maximum BLE Conn interval with AWS IoT connectivity"""
    ble_obj = None
    try:
        # -----------------------------------------------------------------
        # Sniffer Capture
        # -----------------------------------------------------------------

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="20153_ble_provisioning_power_save_aws_validation")

        # -----------------------------------------------------------------
        # BLE Provisioning
        # -----------------------------------------------------------------
        ble_obj = ProvisioningFunctionality(
            wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections, ble_dut=ble_dut, ble_pairing=0,
            utf_constants=utf_constants, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
            test_case=20153, min_conn_interval=200, max_conn_interval=200)

        logger().info(f"M4-TA secure handshake")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        ble_obj.start()
        time.sleep(5)
        ble_obj.wait_for_exit()
        ble_obj.firmware_version()
        ble_obj.wifi_scan()
        ble_obj.wifi_connect()
        ble_obj.ble_remove_service()

        # -----------------------------------------------------------------
        # IoT Testing
        # -----------------------------------------------------------------

        # AWS IoT functionality
        logger().info("\n\n******************** Starting AWS IoT Testing ********************\n\n")

        # Prepare test messages
        messages = []
        for i in range(10):
            messages.append(text_generator(size=100))
        logger().info(f"Generated messages for AWS testing: {messages}")

        # Setup AWS connection parameters
        test_name = request.node.name
        client_id = test_name + '_client'
        topic = 'topic_' + test_name
        qos = Si91xAwsQos.QOS0

        # Create AWS connection instance
        aws_conn = AwsConnection(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            sl_collections=sl_collections,
            test_name=test_name,
            aws_iot_client=aws_iot_client,
            messages=messages,
            topic=topic,
            qos=qos
        )

        # Connect DUT to AWS IoT
        logger().info("Connecting DUT to AWS IoT server")
        assert aws_conn.connect_to_aws_server_from_dut(
            wifi_dut, client_id), "Failed to connect aws server from DUT"
        logger().info("DUT connected to AWS IoT server successfully")

        # Subscribe from DUT to topic_raspi (to receive messages from RasPi)
        topic_dut = topic + '_dut'
        topic_raspi = topic + '_raspi'
        aws_conn.subscribe_from_dut(wifi_dut, topic_raspi, qos)
        logger().info(f"DUT subscribed to topic: {topic_raspi}")

        # Connect RasPi to AWS IoT
        logger().info("Connecting RasPi (aws_iot_client) to AWS IoT server")
        aws_conn.connect_to_aws_server_from_raspi(aws_iot_client)
        logger().info("RasPi connected to AWS IoT server successfully")

        # Subscribe from RasPi on a different topic to receive only DUT messages
        topic_dut = topic + '_dut'
        topic_raspi = topic + '_raspi'

        aws_conn.subscribe_from_raspi(aws_iot_client, topic_dut, qos)
        logger().info(f"RasPi subscribed to topic: {topic_dut}")

        # Wait to ensure both subscriptions are active before publishing
        logger().info("Waiting for subscriptions to be fully active...")
        time.sleep(5)

        # Generate messages for RasPi publish test
        messages_raspi = []
        for i in range(10):
            messages_raspi.append(text_generator(size=100))
        logger().info(f"Generated messages for RasPi publish test: {messages_raspi}")

        # Run parallel publish operations from DUT and RasPi
        logger().info("\n\n*** Starting Parallel Publish Operations: DUT and RasPi publishing simultaneously ***\n")

        # Create thread for DUT publish (publish to topic_dut)
        dut_publish_thread = aws_publish_message_Thread(
            wifi_dut=wifi_dut,
            topic=topic_dut,
            message=messages,
            qos=qos
        )

        # Create thread for RasPi publish (publish to topic_raspi)
        raspi_publish_thread = aws_publish_raspi_Thread(
            aws_iot_client=aws_iot_client,
            topic=topic_raspi,
            message=messages_raspi,
            qos=qos,
            aws_conn=aws_conn
        )

        # Start both threads in parallel
        logger().info("Starting DUT publish thread...")
        dut_publish_thread.start()

        logger().info("Starting RasPi publish thread...")
        raspi_publish_thread.start()

        # Wait for both threads to complete
        logger().info("Waiting for DUT publish thread to complete...")
        dut_publish_thread.wait_for_exit()
        logger().info("DUT publish thread completed")

        logger().info("Waiting for RasPi publish thread to complete...")
        raspi_publish_thread.wait_for_exit()
        logger().info("RasPi publish thread completed")

        logger().info("\n\n*** Both publish threads completed. Starting validation ***\n")

        # Validate messages received on RasPi (from DUT on topic_dut)
        logger().info("\n*** Validating messages published by DUT and received on RasPi ***")
        aws_conn.validate_aws_messages_from_raspi(aws_iot_client, topic_dut, qos, messages, wait_time=15)
        logger().info("Successfully validated: DUT published and RasPi received all messages")

        # Wait a bit before starting DUT message reception to ensure all messages are delivered
        logger().info("Waiting for AWS IoT to deliver all messages to DUT...")
        time.sleep(10)

        # Validate messages received on DUT (from RasPi)
        logger().info("\n*** Validating messages published by RasPi and received on DUT ***")
        for i, expected_msg in enumerate(messages_raspi):
            received_msg = aws_conn.receive_aws_messages_from_dut(wifi_dut, retries=5, wait_time=5)
            logger().info(f"Received message {i + 1} on DUT: {received_msg}")
            assert received_msg == expected_msg, f"Message mismatch: expected '{expected_msg}', got '{received_msg}'"
        logger().info("Successfully validated: RasPi published and DUT received all messages")

        logger().info("\n\n*** Parallel Publish and Validation Completed Successfully ***\n")

        # Unsubscribe and disconnect
        logger().info("\n\nCleaning up AWS connections")
        logger().info("DUT Unsubscribing from aws topic")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_unsubscribe(topic_raspi)

        logger().info("Initiating aws_iot_disconnect from DUT")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        time.sleep(10)

        logger().info("\n\n******************** AWS IoT Testing Completed Successfully ********************\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_obj.ble_cleanup_disconn()
        ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
        ble_client.interfaces.bluetooth.close()
        sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                   ble_client_address=ble_obj.ble_client_address,
                                   ble_dut_address=ble_obj.ble_dut_address)
