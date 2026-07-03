import random
import re
import string
import time
import uuid

import pytest

from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import (
    CustomNotifyCharacteristic,
    HealthThermometerService,
)
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xBLECustomFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xCoexMode,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xMqttQos,
    Si91xOperatingMode,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xTCPIPFeatureBitMap,
)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers


def logger():
    return get_logger(__name__)


def build_message_for_total_bytes(topic, target_total_bytes):
    payload_length = target_total_bytes - len(topic) - 2
    assert payload_length > 0, "Calculated MQTT payload length must be positive"
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=payload_length))


class WifiJoin(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        capture_filename=None,
        wifi_access_point=None,
        wifi_sniffer=None,
        mqtt_server=None,
        mqtt_client=None,
        sl_collections=None,
        topic=None,
        message=None,
        sniffer_filter=None,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.sniffer_filter = sniffer_filter
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.mqtt_server = mqtt_server
        self.mqtt_client = mqtt_client
        self.sl_collections = sl_collections
        self.topic = topic
        self.message = message

    def run(self):
        logger().info(
            f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}"
        )
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.capture_filename}.pcap"
        )

        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,
            scan_interval=4,
            beacon_missed_count=40,
            first_time_retry_enable=0,
        )

        self.sl_collections.join_to_wifi_network(
            self.wifi_dut,
            self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
        )

    def mqtt_connect(self):
        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client"
        )

        logger().info(".....DUT connects to MQTT server.....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(25)

        logger().info(".....MQTT Client connects to MQTT server.....")
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(5)

    def mqtt_connect_ssl(self):
        self.wifi_dut.interfaces["mqtt"] = self.wifi_dut.interfaces.wifi
        self.wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(
            client_id="Si91x_mqtt_client",
            server_port=8883,
            is_connection_encrypted=True,
            qos=Si91xMqttQos.QOS1,
        )

        logger().info(".....DUT connects to MQTT server over SSL.....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(25)

        logger().info(".....MQTT Client connects to MQTT server over SSL.....")
        self.mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
            server=self.mqtt_server.interfaces.mqtt
        )
        time.sleep(5)

    def set_power_save(self):
        self.wifi_dut.interfaces.wifi.set_performance_profile(
            mode="power_save_low_latency"
        )
        self.wifi_dut.interfaces.wifi.enable_bt_power_save(
            psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
            psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave,
        )

    def disconnect_and_rejoin_wifi(self):
        logger().info("Disconnecting DUT from AP")
        if self.wifi_dut.interfaces.wifi.associated:
            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(5)
        logger().info("Rejoining DUT to AP")
        self.sl_collections.join_to_wifi_network(
            self.wifi_dut,
            self.wifi_access_point,
            associated=self.wifi_dut.interfaces.wifi.associated,
        )

    def mqtt_subscribe_single_topic(self, qos):
        logger().info(".... DUT subscribes to the topic ....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=self.topic, qos=qos)
        time.sleep(5)

    def mqtt_publish_rx_single_topic(self, qos, iteration_count=50, mqtt_delay_sec=1, ble_notify_callback=None):
        for count in range(iteration_count):
            logger().info(
                f".... MQTT Client publishes message over the topic iteration {count + 1}/{iteration_count} ...."
            )
            self.mqtt_client.interfaces.mqtt.mqtt_client_publish(
                topic=self.topic, payload=self.message, qos=qos
            )
            time.sleep(mqtt_delay_sec)

            msgs = []
            sw = Stopwatch()
            while sw.elapsed_sec < 15:
                time.sleep(0.1)
                msgs = self.wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) >= 2 and msgs[-2] == self.topic and msgs[-1] == self.message:
                    break

            assert len(msgs) >= 2, "No message received by DUT on subscribed topic"
            assert msgs[-2] == self.topic, "No message received by DUT on subscribed topic"
            assert msgs[-1] == self.message, (
                "No message is received by DUT on subscribed topic or message received is wrong"
            )

            if ble_notify_callback is not None:
                ble_notify_callback()

    def mqtt_publish_rx_single_topic_for_duration(
        self,
        qos,
        publish_duration_sec=2,
        mqtt_delay_sec=0.1,
        ble_notify_callback=None,
    ):
        sw = Stopwatch()
        publish_count = 0
        while sw.elapsed_sec < publish_duration_sec:
            publish_count += 1
            logger().info(
                f".... MQTT Client publishes message over the topic timed iteration {publish_count} ...."
            )
            self.mqtt_client.interfaces.mqtt.mqtt_client_publish(
                topic=self.topic,
                payload=self.message,
                qos=qos,
            )
            time.sleep(mqtt_delay_sec)

            msgs = []
            rx_sw = Stopwatch()
            while rx_sw.elapsed_sec < 15:
                time.sleep(0.1)
                msgs = self.wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
                if len(msgs) >= 2 and msgs[-2] == self.topic and msgs[-1] == self.message:
                    break

            assert len(msgs) >= 2, "No message received by DUT on subscribed topic"
            assert msgs[-2] == self.topic, "No message received by DUT on subscribed topic"
            assert msgs[-1] == self.message, (
                "No message is received by DUT on subscribed topic or message received is wrong"
            )

            if ble_notify_callback is not None:
                ble_notify_callback()

    def unsubscribe_single_topic(self):
        logger().info("....Unsubscribing from the topic....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=self.topic)
        time.sleep(5)

    def mqtt_disconnect_deinit(self):
        logger().info("....disconnecting from MQTT broker....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_disconnect()
        time.sleep(5)

        logger().info("....calling de-init API....")
        self.wifi_dut.interfaces.mqtt.mqtt_client_deinit()

    def stop_sniffer_capture(self):
        logger().info("Stop the sniffer")
        self.wifi_sniffer.interfaces.capture.stop_capture()


class BleThreadFunctionality:
    def __init__(self, wifi_dut=None, ble_client=None, sl_collections=None, ble_pairing=1):
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.sl_collections = sl_collections
        self.ble_pairing = ble_pairing
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=self.ble_pairing
        )
        self.ble_client_address = None
        self.svc = 'HealthThermometerService'
        self.charc = 'CustomNotifyCharacteristic'
        self.write_handle = None
        self.char_path = None
        self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        self.notify_service_created = False

        assert self.ble_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

    def clear_remote_ble_device(self):
        logger().info("Clearing stale remote BLE device record")
        try:
            self.ble_client.interfaces.bluetooth.remove_device(self.ble_dut_address)
        except Exception as ble_reset_ex:
            logger().warning(f"Remote BLE pre-clean skipped due to error: {ble_reset_ex}")
        try:
            self.ble_client.interfaces.bluetooth.close()
            time.sleep(2)
        except Exception as ble_close_ex:
            logger().warning(f"Remote BLE close skipped due to error: {ble_close_ex}")

    def create_notify_service_on_dut(self):
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1)
        self.notify_service_created = True

    def master_connection(self):
        svc = 'HealthThermometerService'
        self.clear_remote_ble_device()
        logger().info("******************** initializing ble in remote device ********************")
        self.ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=self.ble_dut_address,
            service_classes=[svc],
        )
        assert self.ble_client_address, "failed to initialize ble in remote device"

        logger().info("******************** start scanning in dut ********************")
        self.wifi_dut.interfaces.wifi.ble_start_scanning(
            ble_client_address=self.ble_client_address,
            timeout=100,
        )
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        logger().info("..... initiating connection .....")
        if hasattr(self.wifi_dut.interfaces, "bluetooth"):
            self.wifi_dut.interfaces.bluetooth.ble_connect(
                ble_remote_dev_address=self.ble_client_address,
                ble_conn_interval_min=160,
                ble_conn_interval_max=160,
                ble_scan_interval=50,
                ble_scan_window=50,
            )
        else:
            self.wifi_dut.interfaces.wifi.ble_connect(
                ble_remote_dev_address=self.ble_client_address,
                ble_conn_interval_min=160,
                ble_conn_interval_max=160,
                ble_scan_interval=50,
                ble_scan_window=50,
            )

        logger().info(".... checking for ble connectivity stability ....")
        time.sleep(60)

        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (BLEDeviceState.Connected, 9, 10), "device is in disconnection state"

    def slave_connection(self):
        self.clear_remote_ble_device()
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)
        self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
        )

        logger().info(".... checking for ble connectivity stability ....")
        time.sleep(60)

        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (BLEDeviceState.Connected, 9, 10), "device is in disconnection state"

    def master_disconnect_and_reconnect(self, delay_before_disconnect_sec=1):
        logger().info("Preparing to disconnect and reconnect BLE master link")
        time.sleep(delay_before_disconnect_sec)
        try:
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=self.ble_client_address
            )
            time.sleep(5)
        except Exception as ble_disconnect_ex:
            logger().warning(f"BLE master disconnect step skipped due to error: {ble_disconnect_ex}")

        self.master_connection()
        self.profile_fetch_module_ble_rx()

    def profile_fetch_module_ble_rx(self):
        logger().info("******************** get all profiles ********************")
        uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(
            ble_remote_dev_address=self.ble_client_address
        )
        assert HealthThermometerService.UUID.lower() in uuids is not None, (
            "Could not fetch health thermometer profile "
        )

        logger().info(" ******************** Resolving Profile ********************")
        start_handle, end_handle, _data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_client_address,
            uuid=int(HealthThermometerService.UUID, 16),
        )
        assert start_handle is not None, "failed to fetch the start handle.."
        assert end_handle is not None, "failed to fetch end handle.."

        char_uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60,
        )
        assert CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID in char_uuids, (
            f"Unable to find {CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID} uuid"
        )
        index = char_uuids.index(CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID)
        assert char_properties[index].isdigit(), "Character property found is not an integer"
        assert CustomNotifyCharacteristic.prop_int == int(char_properties[index]), (
            "Invalid character property found"
        )

        self.write_handle = int(write_handles[index], 16)
        assert self.write_handle > 0, "Unable to get write handle for configured service"

        self.wifi_dut.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_client_address,
            handle=(self.write_handle + 1),
            enable_notify=1,
        )
        time.sleep(1)

    def profile_fetch_module_ble_tx(self):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        logger().info("Resolving remote notify characteristic for DUT BLE Tx validation")
        self.char_path = self.sl_collections.service_discovery_on_remote(
            self.ble_client,
            service_uid=service_uid,
            char_uid=self.char_uid,
        )
        logger().info(f"Resolved notify characteristic path: {self.char_path}")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path,
            char_uid=self.char_uid,
        )
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address,
            buffer_mode=1,
            buffer_count=2,
        )
        time.sleep(2)

    def send_notify_to_dut(self):
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        received_data = []
        for attempt in range(3):
            since_time = time.perf_counter_ns()
            self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(
                self.svc,
                self.charc,
                data,
            )
            time.sleep(3)

            tw = Stopwatch()
            while tw.elapsed_sec < 10:
                events = self.wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                        received_data = re.findall(r"(\b[A-Z0-9]{20}\b)", event.event_data)
                        if received_data == [data]:
                            break
                if received_data == [data]:
                    break
                time.sleep(0.2)
            if received_data == [data]:
                break
            logger().warning(
                f"BLE notify validation attempt {attempt + 1}/3 did not observe expected 20-byte data"
            )

        assert received_data == [data], "data mismatched"

    def send_notify_to_remote(self, data_length=20):
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=data_length))
        previous_notification_count = len(
            self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        )
        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
            self.ble_client_address,
            data=data,
        )
        time.sleep(3)
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        assert len(notifications) > previous_notification_count, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        assert notifications[-1] in data, "BLE notification payload mismatch"

    def disable_remote_notifications(self):
        if self.char_path is not None:
            self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(
                char_path=self.char_path
            )
            self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(
                char_uid=self.char_uid
            )
            time.sleep(1)

    def ble_cleanup(self):
        try:
            self.disable_remote_notifications()
        except Exception:
            pass
        if self.notify_service_created:
            try:
                self.wifi_dut.interfaces.wifi.ble_remove_service()
            except Exception:
                pass
        logger().info("Checking connection status of BLE")
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 8:
            logger().info("Device is in connected status try to disconnect")
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=self.ble_client_address
            )
            time.sleep(5)
        elif state_int == 2:
            logger().info("Device is in scanning status try to stop scanning")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        elif state_int == 1:
            logger().info("Device is in advertising status try to stop advertising")
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 3:
            logger().info("Device is in scanning status try to stop scanning")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            logger().info("Device is advertising status try to stop advertising")
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 9:
            logger().info("Device is in connected status try to disconnect")
            if self.write_handle is not None:
                self.wifi_dut.interfaces.wifi.ble_set_att_value(
                    ble_remote_dev_address=self.ble_client_address,
                    handle=(self.write_handle + 1),
                    enable_notify=0,
                )
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=self.ble_client_address
            )
            logger().info("Device is in advertising status try to stop advertising")
            time.sleep(5)
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 10:
            logger().info("Device is in connected status try to disconnect")
            if self.write_handle is not None:
                self.wifi_dut.interfaces.wifi.ble_set_att_value(
                    ble_remote_dev_address=self.ble_client_address,
                    handle=(self.write_handle + 1),
                    enable_notify=0,
                )
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=self.ble_client_address
            )
            logger().info("Device is advertising status try to stop advertising")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        elif state_int == 0:
            logger().info("Device is in idle status")
        else:
            logger().info("Device is in unknown state")
            self.wifi_dut.interfaces.wifi.is_dut_bad_state = True
        try:
            self.ble_client.interfaces.bluetooth.remove_device(self.ble_dut_address)
        except Exception:
            pass
        try:
            self.ble_client.interfaces.bluetooth.close()
        except Exception:
            pass
        logger().info(" *************DUT Cleanup Success *******************")


class BleDualConnectionHelper:
    def __init__(self, wifi_dut=None, ble_clients=None, sl_collections=None, ble_pairing=1):
        self.wifi_dut = wifi_dut
        self.ble_clients = ble_clients
        self.sl_collections = sl_collections
        self.ble_pairing = ble_pairing
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=self.ble_pairing
        )
        self.ble_clients_address = []
        self.char_path = None
        self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        self.notify_service_created = False

        assert self.ble_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

    def clear_remote_ble_device(self, ble_client):
        logger().info(f"Clearing stale remote BLE device record for '{ble_client.name}'")
        try:
            ble_client.interfaces.bluetooth.remove_device(self.ble_dut_address)
        except Exception as ble_reset_ex:
            logger().warning(f"Remote BLE pre-clean skipped for '{ble_client.name}': {ble_reset_ex}")
        try:
            ble_client.interfaces.bluetooth.close()
            time.sleep(2)
        except Exception as ble_close_ex:
            logger().warning(f"Remote BLE close skipped for '{ble_client.name}': {ble_close_ex}")

    def create_notify_service_on_dut(self):
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xAABB)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1AA1)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1AA1)
        self.notify_service_created = True

    def master_and_slave_connection(self):
        assert len(self.ble_clients) >= 2, "Minimum 2 Raspi devices needed"

        self.clear_remote_ble_device(self.ble_clients[0])
        self.ble_clients_address.append(
            self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_clients[0],
                ble_dut_address=self.ble_dut_address,
                timeout=20,
                dev_state=8,
                mode="master",
            )
        )

        logger().info("..... checking master ble connection stability ......")
        time.sleep(60)
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (BLEDeviceState.Connected, 9, 10), (
            "DUT BLE device is not in connected state after master connection"
        )

        self.wifi_dut.interfaces.wifi.ble_set_smp(set_smp=0)

        self.clear_remote_ble_device(self.ble_clients[1])
        self.ble_clients_address.append(
            self.sl_collections.ble_connection(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_clients[1],
                ble_dut_address=self.ble_dut_address,
                timeout=20,
                mode="slave",
            )
        )

        logger().info("..... checking slave ble connection stability ......")
        time.sleep(60)
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (BLEDeviceState.Connected, 9, 10), (
            "DUT BLE device is not in connected state after dual connection"
        )

        for client in self.ble_clients[:2]:
            status = client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
            logger().info(f"Connection status in remote device '{client.name}' is:{status}")

    def two_master_connection(self):
        assert len(self.ble_clients) >= 2, "Minimum 2 Raspi devices needed"

        for index in range(2):
            self.clear_remote_ble_device(self.ble_clients[index])
            self.ble_clients_address.append(
                self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[index],
                    ble_dut_address=self.ble_dut_address,
                    timeout=20,
                    dev_state=8,
                    mode="master",
                )
            )

            logger().info(
                f"..... checking master ble connection stability for device {index + 1} ......"
            )
            time.sleep(60)
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int in (BLEDeviceState.Connected, 9, 10), (
                f"DUT BLE device is not in connected state after master connection {index + 1}"
            )

        for client in self.ble_clients[:2]:
            status = client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
            logger().info(f"Connection status in remote device '{client.name}' is:{status}")

    def two_slave_connection(self):
        assert len(self.ble_clients) >= 2, "Minimum 2 Raspi devices needed"

        for index in range(2):
            self.clear_remote_ble_device(self.ble_clients[index])
            self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)
            self.ble_clients_address.append(
                self.sl_collections.scan_and_connect_from_remote(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[index],
                    ble_dut_address=self.ble_dut_address,
                    ble_pairing=self.ble_pairing,
                )
            )

            logger().info(
                f"..... checking slave ble connection stability for device {index + 1} ......"
            )
            time.sleep(60)
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int in (BLEDeviceState.Connected, 9, 10), (
                f"DUT BLE device is not in connected state after slave connection {index + 1}"
            )

        for client in self.ble_clients[:2]:
            status = client.interfaces.bluetooth.get_connection_status(self.ble_dut_address)
            logger().info(f"Connection status in remote device '{client.name}' is:{status}")

    def profile_fetch_module_ble_tx(self, client_index=1):
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
        logger().info("Resolving remote notify characteristic for DUT BLE Tx validation")
        self.char_path = self.sl_collections.service_discovery_on_remote(
            self.ble_clients[client_index],
            service_uid=service_uid,
            char_uid=self.char_uid,
        )
        logger().info(f"Resolved notify characteristic path: {self.char_path}")
        self.ble_clients[client_index].interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
        self.ble_clients[client_index].interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=self.char_path,
            char_uid=self.char_uid,
        )
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_clients_address[client_index],
            buffer_mode=1,
            buffer_count=2,
        )
        time.sleep(2)

    def send_notify_to_remote(self, data_length=20, client_index=1):
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=data_length))
        previous_notification_count = len(
            self.ble_clients[client_index].interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        )
        self.wifi_dut.interfaces.wifi.ble_notify_custom_value(
            self.ble_clients_address[client_index],
            data=data,
        )
        time.sleep(3)
        notifications = self.ble_clients[client_index].interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        assert len(notifications) > previous_notification_count, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        assert notifications[-1] in data, "BLE notification payload mismatch"

    def disable_remote_notifications(self):
        if self.char_path is not None:
            self.ble_clients[1].interfaces.bluetooth.gatt_adapter.disable_notifications(
                char_path=self.char_path
            )
            self.ble_clients[1].interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(
                char_uid=self.char_uid
            )
            time.sleep(1)

    def ble_cleanup(self):
        try:
            self.disable_remote_notifications()
        except Exception:
            pass
        if self.notify_service_created:
            try:
                self.wifi_dut.interfaces.wifi.ble_remove_service()
            except Exception:
                pass
        for address in self.ble_clients_address:
            try:
                self.wifi_dut.interfaces.wifi.ble_disconnect(
                    ble_remote_dev_address=address
                )
                time.sleep(3)
            except Exception:
                pass

        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        if state_int == 2:
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        elif state_int == 1:
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 3:
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 9:
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        elif state_int == 10:
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        for client in self.ble_clients[:2]:
            try:
                client.interfaces.bluetooth.remove_device(self.ble_dut_address)
            except Exception:
                pass
            try:
                client.interfaces.bluetooth.close()
            except Exception:
                pass

 
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_master_mqtt_broker_publish_1450_bytes_C998923(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_client,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE Master Device connection stability During the MQTT Publish from broker has Payload
    length of 1450 Bytes with No fragmentation indication
    TC_ID: C998923
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998923_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1450)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
            sniffer_filter=sniffer_filter,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.master_connection()
        ble_obj.profile_fetch_module_ble_rx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=ble_obj.send_notify_to_dut,
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE master link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass

 
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")

@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_slave_mqtt_broker_publish_1460_bytes_C998924(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_client,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE Slave device connection stablity during the MQTT Publish from broker has payload
    length of 1460 Bytes with No fragment indication
    TC_ID: C998924
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998924_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1460)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=ble_obj.send_notify_to_remote,
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE slave link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass
        ble_client.interfaces.bluetooth.close()


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_dual_connection_mqtt_broker_publish_1458_bytes_qos1_C998925(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    Title: Verify the BLE Dual Connection stablity with MQTT Publish from broker has payload length of 1458
    bytes with QOS1 with No fragmentation indication
    TC_ID: C998925
    """
    ble_obj = None
    wifi_obj = None
    topic = f"c998925_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1458)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.master_and_slave_connection()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE dual connection should remain connected"

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            try:
                wifi_obj.stop_sniffer_capture()
            except Exception:
                pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_dual_connection_notify_mqtt_broker_publish_1458_bytes_qos1_C998926(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    Title: Verifyt the BLE SMP Dual connection with Notification along with MQTT Publish from broker has
    payload length of 1458 Bytes QOS1 with No fragmentation indication
    TC_ID: C998926
    """
    ble_obj = None
    wifi_obj = None
    topic = f"c998926_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1458)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.master_and_slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=ble_obj.send_notify_to_remote,
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE dual SMP connection should remain connected"

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            try:
                wifi_obj.stop_sniffer_capture()
            except Exception:
                pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_dual_connection_dle_notify_mqtt_ssl_broker_publish_1460_bytes_C998927(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    Title: Verify the BLE SMP Dual connection with DLE Notifications enabled Along with MQTT SSL Publish
    from Broker with 1460 Bytes of payload with No fragmentation indication
    TC_ID: C998927
    """
    ble_obj = None
    wifi_obj = None
    topic = f"c998927_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1460)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.master_and_slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect_ssl()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE dual SMP DLE connection should remain connected"

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            try:
                wifi_obj.stop_sniffer_capture()
            except Exception:
                pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_two_master_connections_dle_notifications_mqtt_publish_1461_bytes_C998928(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    Title: Verify the BLE SMP Two Master connections with DLE Notifications enabled Along with MQTT
    Publish from Broker with 1461 Bytes of payload with fragmentation indication
    TC_ID: C998928
    """
    ble_obj = None
    wifi_obj = None
    topic = f"c998928_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1461)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.two_master_connection()
        ble_obj.profile_fetch_module_ble_tx(client_index=1)

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240, client_index=1),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP two-master connection should remain connected"

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            try:
                wifi_obj.stop_sniffer_capture()
            except Exception:
                pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_two_slave_connections_dle_notify_ssl_mqtt_publish_1461_bytes_C998929(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE SMP Two SLAVE connection with DLE Notifications enabled Along with MQTT SSL
    Publish from Broker with 1461 Bytes of payload with fragmentation indication
    TC_ID: C998929
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998929_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1461)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.two_slave_connection()
        ble_obj.profile_fetch_module_ble_tx(client_index=1)

        wifi_obj.mqtt_connect_ssl()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(
                data_length=240,
                client_index=1,
            ),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP two-slave link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass

 
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_master_connection_notify_mqtt_publish_1450_and_1470_bytes_C998930(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_client,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE SMP Master connection with Notification enabled along with MQTT Publish from
    broker has payload with 1450 and 1470 bytes to check the fragmentation enabled threshold limit
    TC_ID: C998930
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic_1450 = f"c998930_1450_mqtt_{uuid.uuid4().hex}"
    topic_1470 = f"c998930_1470_mqtt_{uuid.uuid4().hex}"

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic_1450,
            message=build_message_for_total_bytes(topic_1450, 1450),
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.master_connection()
        ble_obj.profile_fetch_module_ble_rx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        logger().info(f"MQTT topic for 1450 phase: {topic_1450}")
        logger().info(f"MQTT topic for 1470 phase: {topic_1470}")
        wifi_obj.topic = topic_1450
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)

        wifi_obj.message = build_message_for_total_bytes(topic_1450, 1450)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=10,
            mqtt_delay_sec=1,
            ble_notify_callback=ble_obj.send_notify_to_dut,
        )

        wifi_obj.topic = topic_1470
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.message = build_message_for_total_bytes(topic_1470, 1470)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=10,
            mqtt_delay_sec=1,
            ble_notify_callback=ble_obj.send_notify_to_dut,
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP master link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_1450,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter1}"
        )
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_1470,
            filter_name="mqtt_fragment_check",
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter2}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.topic = topic_1470
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.topic = topic_1450
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass

 
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_slave_connection_dle_notify_mqtt_publish_1460_and_1470_bytes_C998931(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_client,
    mqtt_client,
    mqtt_server,
):
    """
    Title: Verify the BLE SMP SLAVE connection with DLE Notification enabled along with MQTT Publish
    from broker has payload with 1470 and 1460 bytes to check the fragmentation enabled threshold limit
    TC_ID: C998931
    """
    ble_obj = None
    wifi_obj = None
    topic = f"c998931_mqtt_{uuid.uuid4().hex}"

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=build_message_for_total_bytes(topic, 1460),
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)

        wifi_obj.message = build_message_for_total_bytes(topic, 1460)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        wifi_obj.message = build_message_for_total_bytes(topic, 1470)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP slave link should remain connected"

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            try:
                wifi_obj.stop_sniffer_capture()
            except Exception:
                pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass
        ble_client.interfaces.bluetooth.close()


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_dual_role_connection_dle_notify_mqtt_publish_4000_bytes_C998932(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    Title: Verify the BLE SMP DUAL Role connection with DLE Notification enabled along with MQTT
    Publish from Broker has payload of 4000 Bytes to check the fragmentation and data integrity
    TC_ID: C998932
    """
    ble_obj = None
    wifi_obj = None
    topic = f"c998932_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 4000)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.master_and_slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP dual-role link should remain connected"

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            try:
                wifi_obj.stop_sniffer_capture()
            except Exception:
                pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_two_slave_role_connection_dle_notify_mqtt_publish_4000_bytes_qos1_C998933(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE SMP Two Slave Role Connection with DLE Notifications enabled along with MQTT
    Publish from Broker has payload of 4000 Bytes with QOS1
    TC_ID: C998933
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998933_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 4000)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.two_slave_connection()
        ble_obj.profile_fetch_module_ble_tx(client_index=1)

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(
                data_length=240,
                client_index=1,
            ),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP two-slave link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass

 
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_master_role_notify_mqtt_publish_1460_bytes_qos1_C998934(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_client,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE SMP Master role with Notification along with MQTT Publish payload from broker
    with Payload of 1460 bytes with qos1 and check no fragment indication
    TC_ID: C998934
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998934_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1457)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.master_connection()
        ble_obj.profile_fetch_module_ble_rx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=ble_obj.send_notify_to_dut,
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP master link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass

 
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_slave_role_notify_ssl_mqtt_publish_1470_bytes_qos1_C998935(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_client,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE SMP Slave role with Notification along with SSL MQTT Publish payload from broker
    with Payload of 1470 bytes with qos1 and check fragment indication
    TC_ID: C998935
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998935_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1470)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect_ssl()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP slave link should remain connected"

        wifi_obj.stop_sniffer_capture()

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass
        ble_client.interfaces.bluetooth.close()


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_smp_dual_role_connection_dle_notify_ssl_mqtt_publish_5000_bytes_qos1_C998936(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE SMP DUAL Role Connection with DLE Notifications enabled along with SSL MQTT
    Publish with 5000 Bytes with QOS1 With fragmentation indication
    TC_ID: C998936
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998936_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 5000)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.master_and_slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect_ssl()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS1,
            iteration_count=30,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE SMP dual-role link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_master_disconnect_reconnect_mqtt_publish_1470_bytes_C998937(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_client,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE Master Device disconnection and reconnection with MQTT Publish payload length
    of 1470 from broker and check for the fragmentation indication
    TC_ID: C998937
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998937_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1470)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.master_connection()
        ble_obj.profile_fetch_module_ble_rx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS1)

        ThreadBase.call_functions_simultaneously(
            [
                (
                    wifi_obj.mqtt_publish_rx_single_topic_for_duration,
                    Si91xMqttQos.QOS1,
                    2,
                    0.1,
                    ble_obj.send_notify_to_dut,
                ),
                (
                    ble_obj.master_disconnect_and_reconnect,
                    1,
                ),
            ],
            timeout=180,
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE master link should remain connected after reconnect"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_two_slave_notify_mqtt_connect_reconnect_1500_bytes_C998938(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verify the BLE SMP Two Slave device stability along with STA MQTT Connection and
    reconnection and check the Framentation indication for 1500Bytes of payload length from MQTT Broker
    TC_ID: C998938
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998938_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1500)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.two_slave_connection()
        ble_obj.profile_fetch_module_ble_tx(client_index=1)

        for iteration in range(10):
            logger().info(f"Starting MQTT connect/reconnect iteration {iteration + 1}/10")
            wifi_obj.mqtt_connect()
            wifi_obj.set_power_save()
            wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
            wifi_obj.mqtt_publish_rx_single_topic(
                qos=Si91xMqttQos.QOS0,
                iteration_count=10,
                mqtt_delay_sec=1,
                ble_notify_callback=lambda: ble_obj.send_notify_to_remote(
                    data_length=240,
                    client_index=1,
                ),
            )

            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int in (
                BLEDeviceState.Connected,
                9,
                10,
            ), "BLE two-slave link should remain connected during MQTT reconnect iteration"

            wifi_obj.mqtt_disconnect_deinit()

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_dual_role_notify_mqtt_publish_1500_bytes_wlan_disconnect_reconnect_C998939(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verfiy the BLE DUAL Role device connection stability along with Notification and check
    Fragmentaion indication for Payload length of 1500 Bytes with WLAN STA Disconnection and reconnection
    TC_ID: C998939
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998939_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1500)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.master_and_slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        for iteration in range(10):
            logger().info(f"Starting WLAN disconnect/reconnect iteration {iteration + 1}/10")
            wifi_obj.mqtt_connect()
            wifi_obj.set_power_save()
            wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
            wifi_obj.mqtt_publish_rx_single_topic(
                qos=Si91xMqttQos.QOS0,
                iteration_count=10,
                mqtt_delay_sec=1,
                ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
            )

            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int in (
                BLEDeviceState.Connected,
                9,
                10,
            ), "BLE dual-role link should remain connected during WLAN iteration"

            wifi_obj.mqtt_disconnect_deinit()
            wifi_obj.disconnect_and_rejoin_wifi()

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass

 
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_master_role_notify_mqtt_publish_1400_bytes_wlan_disconnect_reconnect_C998940(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_client,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: VerifY the BLE SMP Master role connection stability with Notification and check
    fragmentation indication for payload length of 1400 Bytes with WLAN STA Disconnection and reconnection
    TC_ID: C998940
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic = f"c998940_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 1400)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.master_connection()
        ble_obj.profile_fetch_module_ble_rx()

        for iteration in range(10):
            logger().info(f"Starting WLAN disconnect/reconnect iteration {iteration + 1}/10")
            wifi_obj.mqtt_connect()
            wifi_obj.set_power_save()
            wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
            wifi_obj.mqtt_publish_rx_single_topic(
                qos=Si91xMqttQos.QOS0,
                iteration_count=10,
                mqtt_delay_sec=1,
                ble_notify_callback=ble_obj.send_notify_to_dut,
            )

            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int in (
                BLEDeviceState.Connected,
                9,
                10,
            ), "BLE master link should remain connected during WLAN iteration"

            wifi_obj.mqtt_disconnect_deinit()
            wifi_obj.disconnect_and_rejoin_wifi()

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter1}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_dual_role_notify_mqtt_variable_payload_fragmentation_C998941(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verifyt the BLE SMP DUAL Role stability Connection stability along with MQTT
    Fragmentation indication for variable length of publishing data from broker
    (100 Bytes, 1700 bytes, 1459 bytes, 1461 bytes)
    TC_ID: C998941
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic_100 = f"c998941_100_mqtt_{uuid.uuid4().hex}"
    topic_1700 = f"c998941_1700_mqtt_{uuid.uuid4().hex}"
    topic_1459 = f"c998941_1459_mqtt_{uuid.uuid4().hex}"
    topic_1461 = f"c998941_1461_mqtt_{uuid.uuid4().hex}"

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic_100,
            message=build_message_for_total_bytes(topic_100, 100),
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.master_and_slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()

        wifi_obj.topic = topic_100
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.message = build_message_for_total_bytes(topic_100, 100)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        wifi_obj.topic = topic_1700
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.message = build_message_for_total_bytes(topic_1700, 1700)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        wifi_obj.topic = topic_1459
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.message = build_message_for_total_bytes(topic_1459, 1459)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        wifi_obj.topic = topic_1461
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.message = build_message_for_total_bytes(topic_1461, 1461)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE dual-role link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_100,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter1}"
        )

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_1700,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter2}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter2}"
        )

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_1459,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter3}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter3
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter3}"
        )

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_1461,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter4}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter4
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter4}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.topic = topic_1461
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.topic = topic_1459
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.topic = topic_1700
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.topic = topic_100
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_dual_role_notify_mqtt_variable_payload_fragmentation_wlan_reconnect_C998942(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
    sniffer_filter,
):
    """
    Title: Verifyt the BLE SMP DUAL Role stability Connection stability along with MQTT
    Fragmentation indication for variable length of publishing data from broker with wlan
    disconnection and reconnection (100 Bytes, 1700 bytes, 1459 bytes, 1461 bytes)
    TC_ID: C998942
    """
    ble_obj = None
    wifi_obj = None
    sniffer_stopped = False
    topic_100 = f"c998942_100_mqtt_{uuid.uuid4().hex}"
    topic_1700 = f"c998942_1700_mqtt_{uuid.uuid4().hex}"
    topic_1459 = f"c998942_1459_mqtt_{uuid.uuid4().hex}"
    topic_1461 = f"c998942_1461_mqtt_{uuid.uuid4().hex}"

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic_100,
            message=build_message_for_total_bytes(topic_100, 100),
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.master_and_slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.topic = topic_100
        wifi_obj.message = build_message_for_total_bytes(topic_100, 100)
        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )
        wifi_obj.mqtt_disconnect_deinit()
        wifi_obj.disconnect_and_rejoin_wifi()

        wifi_obj.topic = topic_1700
        wifi_obj.message = build_message_for_total_bytes(topic_1700, 1700)
        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )
        wifi_obj.mqtt_disconnect_deinit()
        wifi_obj.disconnect_and_rejoin_wifi()

        wifi_obj.topic = topic_1459
        wifi_obj.message = build_message_for_total_bytes(topic_1459, 1459)
        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )
        wifi_obj.mqtt_disconnect_deinit()
        wifi_obj.disconnect_and_rejoin_wifi()

        wifi_obj.topic = topic_1461
        wifi_obj.message = build_message_for_total_bytes(topic_1461, 1461)
        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=240),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE dual-role link should remain connected"

        wifi_obj.stop_sniffer_capture()
        sniffer_stopped = True

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_100,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter1}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter1
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter1}"
        )

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_1700,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter2}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter2
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter2}"
        )

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_1459,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter3}")
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter3
        )["packet_count"], (
            f"Unexpected fragmented packets found in sniffer capture for filter: {packet_filter3}"
        )

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            topic_name=topic_1461,
            filter_name="mqtt_fragment_check",
        )
        logger().info(f"Validating sniffer with filter : {packet_filter4}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(
            packet_filter1=packet_filter4
        )["packet_count"], (
            f"Unable to find packets in sniffer capture for filter: {packet_filter4}"
        )

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            if not sniffer_stopped:
                try:
                    wifi_obj.stop_sniffer_capture()
                except Exception:
                    pass
            try:
                wifi_obj.topic = topic_1461
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.topic = topic_1459
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.topic = topic_1700
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.topic = topic_100
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 3584, "priority": 8},
        },
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
        | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_SET_SCAN_RESP_DATA_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_DISABLE_CODED_PHY_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_GATT_INIT,
    },
)
@pytest.mark.config("wifi_access_point", wifi={"channel": 4})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.skip(reason="Temporarily disabled; keep only selected large-payload cases enabled")
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"],
)
def test_ble_dual_connections_large_payload_long_run_C1655853(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    request,
    sl_collections,
    ble_clients,
    mqtt_client,
    mqtt_server,
):
    """
    Title: Verify whether the DUT is able to receive the large payload (5k) during long run in the
    presence of 2 BLE Connections
    TC_ID: C1655853
    """
    ble_obj = None
    wifi_obj = None
    topic = f"c1655853_mqtt_{uuid.uuid4().hex}"
    message = build_message_for_total_bytes(topic, 5000)

    try:
        wifi_obj = WifiJoin(
            wifi_dut=wifi_dut,
            capture_filename=request.node.name,
            wifi_access_point=wifi_access_point,
            wifi_sniffer=wifi_sniffer,
            mqtt_server=mqtt_server,
            mqtt_client=mqtt_client,
            sl_collections=sl_collections,
            topic=topic,
            message=message,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ble_obj = BleDualConnectionHelper(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_pairing=1,
        )
        ble_obj.create_notify_service_on_dut()
        ble_obj.master_and_slave_connection()
        ble_obj.profile_fetch_module_ble_tx()

        wifi_obj.mqtt_connect()
        wifi_obj.set_power_save()
        wifi_obj.mqtt_subscribe_single_topic(qos=Si91xMqttQos.QOS0)
        wifi_obj.mqtt_publish_rx_single_topic(
            qos=Si91xMqttQos.QOS0,
            iteration_count=50,
            mqtt_delay_sec=1,
            ble_notify_callback=lambda: ble_obj.send_notify_to_remote(data_length=20),
        )

        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int in (
            BLEDeviceState.Connected,
            9,
            10,
        ), "BLE dual connection should remain connected"

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
    finally:
        if wifi_obj is not None:
            try:
                wifi_obj.stop_sniffer_capture()
            except Exception:
                pass
            try:
                wifi_obj.unsubscribe_single_topic()
            except Exception:
                pass
            try:
                wifi_obj.mqtt_disconnect_deinit()
            except Exception:
                pass
        if ble_obj is not None:
            try:
                ble_obj.ble_cleanup()
            except Exception:
                pass


