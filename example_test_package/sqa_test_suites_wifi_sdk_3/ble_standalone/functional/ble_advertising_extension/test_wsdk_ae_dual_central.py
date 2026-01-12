import pytest
import pandas as pd
import re

from utf.interfaces.bluetooth.bluez import HealthThermometerService
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import CustomNotifyCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth import BLEDeviceState
from example_test_package.conftest import rs_helper_ble
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
    Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
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
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService, \
    HeartRateMeasurementCharacterstic, HeartRateControlPointCharacteristic


def logger():
    return get_logger(__name__)


lock = threading.Lock()


class BLEThread:
    def __init__(self, sl_collections, ble_dut=None, remote_device=None, ble_sniffer=None, ble_client_address=None,
                 ble_dut_address=None, indication_count=None,notify_time=None,
                 pri_adv_phy=None, sec_adv_phy=None, write_count=None, write_handle=None, data_size=None,
                 remote_address=None, notification_count=None, char_uid=None,
                 service_uid=None):
        super().__init__()
        self.indication_count = indication_count
        self.remote_address = remote_address
        self.ble_dut = ble_dut
        self.remote_device = remote_device
        self.ble_sniffer = ble_sniffer
        self.sl_collections = sl_collections
        self.ble_client_address = ble_client_address
        self.ble_dut_address = ble_dut_address
        self.pri_adv_phy = pri_adv_phy
        self.sec_adv_phy = sec_adv_phy
        self.write_count = write_count
        self.write_handle = write_handle
        self.data_size = data_size
        self.notification_count = notification_count
        self.char_uid = char_uid
        self.service_uid = service_uid
        self.notify_time = notify_time

    def run(self):
        try:
            logger().info(f"*TX Notifications Start for client {self.ble_client_address}**")
            logger().info(
                f"Enabling notifications for DUT address: {self.ble_dut_address}, handle: {self.write_handle + 1}")
            # enable notifications
            self.remote_device.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_dut_address,
                                                                 handle=(self.write_handle + 1),
                                                                 enable_notify=1)
            logger().info(f"Notifications enabled successfully for {self.ble_client_address}")
            time.sleep(10)
            if self.data_size == 230:
                self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)
                logger().info(f"* Buffer Notifications Enabled **")
            else:
                self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=self.ble_client_address, buffer_mode=0, buffer_count=2)
                logger().info(f"* Buffer Notifications Enabled **")

            time.sleep(2)

            def write():
                try:
                    # Add thread identifier to data for better debugging
                    thread_id = threading.current_thread().name[-3:] if hasattr(threading.current_thread(),
                                                                                'name') else 'THR'
                    base_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_size - 3))
                    data = f"{thread_id}{base_data}"
                    logger().info(
                        f"* Sending Notification to {self.ble_client_address} with data size: {len(data)} (Thread: {thread_id}) **")
                    logger().debug(f"Notification data: {data}")

                    # Capture time right before sending notification to avoid cross-thread event collision
                    since_time = time.perf_counter_ns()
                    self.ble_dut.interfaces.wifi.ble_notify_custom_value(ble_remote_dev_address=self.ble_client_address,
                                                                         data=data, timeout=120)
                    logger().info(f"Notification sent successfully to {self.ble_client_address}")
                    time.sleep(5)
                    events = self.remote_device.interfaces.wifi.get_async_events(since_time=since_time)
                    # Look for the most recent GATT_WRITE_EVENT that matches our sent data
                    matching_event = None
                    for event in reversed(events):  # Check events in reverse order (most recent first)
                        if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                            received_data = re.findall(r"att_value:\s*([^\s]+)", event.event_data)
                            if received_data and received_data[0] == data:
                                matching_event = event
                                break
                    if matching_event:
                        logger().info(f" BLE EVENT DATA IS : {matching_event.event_data} ")
                        received_data = re.findall(r"att_value:\s*([^\s]+)", matching_event.event_data)
                        logger().info(
                            f"* Received Data on remote device {self.ble_client_address} : {received_data} **")
                        logger().info(
                            f"* length of received Data on remote device {self.ble_client_address} : {len(received_data[0])} **")
                        try:
                            assert received_data[
                                       0] == data, f"data is not matching - Expected: {data}, Received: {received_data[0]}"  # Fixed assertion
                        except AssertionError as ae:
                            logger().error(f"Data assertion failed for {self.ble_client_address}: {ae}")
                            raise ae
                        except IndexError as ie:
                            logger().error(f"No received data found for {self.ble_client_address}: {ie}")
                            raise ie
                    else:
                        # If no matching event found, log all events for debugging
                        logger().warning(f"No matching GATT_WRITE_EVENT found for data: {data}")
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                                logger().info(f"Available event data: {event.event_data}")
                except Exception as e:
                    logger().error(f"Error in write() function for {self.ble_client_address}: {e}")
                    raise e

            sent_notifications = 0
            time.sleep(1)
            logger().info(f"Starting notification transmission for client {self.ble_client_address}")
            if self.notification_count:
                logger().info(f"Sending {self.notification_count} notifications to {self.ble_client_address}")
                for i in range(self.notification_count):
                    try:
                        logger().info(
                            f"tx notification count {sent_notifications} with {self.ble_client_address} and range:{i} - Starting notification {i + 1}/{self.notification_count}")
                        with lock:
                            write()
                            logger().info(
                                f"Notification {i + 1}/{self.notification_count} completed successfully for {self.ble_client_address}")
                        sent_notifications += 1  # Increment after each notification
                    except Exception as e:
                        logger().error(
                            f"Error sending notification {i + 1}/{self.notification_count} to {self.ble_client_address}: {e}")
                        sent_notifications += 1  # Still increment counter to continue the loop
                        continue  # Continue with next notification
            else:
                logger().info(f"Sending notifications for {self.notify_time} seconds to {self.ble_client_address}")
                sw = Stopwatch()
                while sw.elapsed_sec <= self.notify_time:
                    with lock:
                        write()
                    sent_notifications += 1
                    logger().debug(
                        f"Time-based notification {sent_notifications} sent to {self.ble_client_address}, elapsed: {sw.elapsed_sec}s")
            if not self.notification_count:
                self.notification_count = sent_notifications
            logger().info(f"TX_Notification count with {self.ble_client_address}: {sent_notifications}")
            logger().info(f"Disabling notifications for {self.ble_client_address}")
        finally:
            # disable notifications
            self.remote_device.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                                 handle=(self.write_handle + 1), enable_notify=0)
            logger().info(f"* Disabled Notifications on Remote Device **")

    def gatt_indication(self):
        try:
            logger().info(f"*TX Indications Start for client {self.ble_client_address}**")
            logger().info(
                f"Enabling Indications for DUT address: {self.ble_dut_address}, handle: {self.write_handle + 1}")
            # enable indications
            self.remote_device.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_dut_address,
                                                                 handle=(self.write_handle + 1),
                                                                 enable_notify=1)
            logger().info(f"Indications enabled successfully for {self.ble_client_address}")
            time.sleep(10)
            if self.data_size == 20:
                self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=self.ble_client_address, buffer_mode=0, buffer_count=2)
                logger().info(f"* Buffer Indications Enabled **")
            else:
                self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)
                logger().info(f"* Buffer Indications Enabled **")
            time.sleep(2)
            def write():
                try:
                    # Add thread identifier to data for better debugging
                    thread_id = threading.current_thread().name[-3:] if hasattr(threading.current_thread(),
                                                                                'name') else 'THR'
                    base_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_size - 3))
                    data = f"{thread_id}{base_data}"
                    logger().info(
                        f"* Sending Indications to {self.ble_client_address} with data size: {len(data)} (Thread: {thread_id}) **")
                    logger().debug(f"Indications data: {data}")
                    # Capture time right before sending indication to avoid cross-thread event collision
                    since_time = time.perf_counter_ns()
                    self.ble_dut.interfaces.wifi.ble_indicate_value(ble_remote_dev_address=self.ble_client_address,
                                                                    handle=self.write_handle,data_length=self.data_size,
                                                                    data=data, timeout=120)
                    logger().info(f"Indications sent successfully to {self.ble_client_address}")
                    time.sleep(5)
                    events = self.remote_device.interfaces.wifi.get_async_events(since_time=since_time)
                    # Look for the most recent GATT_WRITE_EVENT that matches our sent data
                    matching_event = None
                    for event in reversed(events):  # Check events in reverse order (most recent first)
                        if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                            received_data = re.findall(r"att_value:\s*([^\s]+)", event.event_data)
                            if received_data and received_data[0] == data:
                                matching_event = event
                                break
                    if matching_event:
                        logger().info(f" BLE EVENT DATA IS : {matching_event.event_data} ")
                        received_data = re.findall(r"att_value:\s*([^\s]+)", matching_event.event_data)
                        logger().info(
                            f"* Received Data on remote device {self.ble_client_address} : {received_data} **")
                        logger().info(
                            f"* length of received Data on remote device {self.ble_client_address} : {len(received_data[0])} **")
                        try:
                            assert received_data[
                                       0] == data, f"data is not matching - Expected: {data}, Received: {received_data[0]}"
                        except AssertionError as ae:
                            logger().error(f"Data assertion failed for {self.ble_client_address}: {ae}")
                            raise ae
                        except IndexError as ie:
                            logger().error(f"No received data found for {self.ble_client_address}: {ie}")
                            raise ie
                    else:
                        # If no matching event found, log all events for debugging
                        logger().warning(f"No matching GATT_WRITE_EVENT found for data: {data}")
                        for event in events:
                            if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                                logger().info(f"Available event data: {event.event_data}")
                        raise AssertionError(f"No matching GATT_WRITE_EVENT found for sent data: {data}")
                except Exception as e:
                    logger().error(f"Error in write() function for {self.ble_client_address}: {e}")
                    raise e

            sent_indications = 0
            time.sleep(1)
            logger().info(f"Starting indication transmission for client {self.ble_client_address}")
            if self.indication_count:
                logger().info(f"Sending {self.indication_count} indications to {self.ble_client_address}")
                for i in range(self.indication_count):
                    try:
                        logger().info(
                            f"tx indication count {sent_indications} with {self.ble_client_address} and range:{i} - Starting indication {i + 1}/{self.indication_count}")
                        with lock:
                            write()
                            logger().info(
                                f"Indication {i + 1}/{self.indication_count} completed successfully for {self.ble_client_address}")
                        sent_indications += 1  # Increment after each indication
                    except Exception as e:
                        logger().error(
                            f"Error sending indication {i + 1}/{self.indication_count} to {self.ble_client_address}: {e}")
                        sent_indications += 1  # Still increment counter to continue the loop
                        continue  # Continue with next indication
            else:
                logger().info(f"Sending indications for {self.notify_time} seconds to {self.ble_client_address}")
                sw = Stopwatch()
                while sw.elapsed_sec <= self.notify_time:
                    with lock:
                        write()
                    sent_indications += 1
                    logger().debug(
                        f"Time-based indication {sent_indications} sent to {self.ble_client_address}, elapsed: {sw.elapsed_sec}s")
            if not self.indication_count:
                self.indication_count = sent_indications
            logger().info(f"TX_Indication count with {self.ble_client_address}: {sent_indications}")
            logger().info(f"Disabling indications for {self.ble_client_address}")

        finally:
            # disable indications
            self.remote_device.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                                 handle=(self.write_handle + 1), enable_notify=0)
            logger().info(f"* Disabled Indications on Remote Device **")

    def gatt_write_without_resp(self):
        logger().info(f"*Write Without Response Start**")

        logger().info(f"*Write Without Response notifications Start for client {self.ble_client_address}**")
        if self.data_size == 20:
            self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                ble_remote_dev_address=self.ble_client_address, buffer_mode=0, buffer_count=2)
            logger().info(f"* Buffer Enabled **")
        else:
            self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)
            logger().info(f"* Buffer Enabled **")
        time.sleep(2)

        def write():
            try:
                # Add thread identifier to data for better debugging
                thread_id = threading.current_thread().name[-3:] if hasattr(threading.current_thread(),
                                                                            'name') else 'THR'
                base_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_size - 3))
                data = f"{thread_id}{base_data}"
                logger().info(
                    f"* Sending Write Without Response to {self.ble_client_address} with data size: {len(data)} (Thread: {thread_id}) **")
                logger().debug(f"Write Without Response data: {data}")
                # Capture time right before sending indication to avoid cross-thread event collision
                since_time = time.perf_counter_ns()
                self.ble_dut.interfaces.wifi.ble_set_att_cmd(ble_remote_dev_address=self.ble_client_address,
                                                                handle=self.write_handle, data_length=self.data_size,
                                                                data=data, timeout=120)
                logger().info(f"Write Without Response sent successfully to {self.ble_client_address}")
                time.sleep(5)
            except Exception as e:
                logger().error(f"Error in write() function for {self.ble_client_address}: {e}")
                raise e

        sent_data_count = 0
        time.sleep(1)
        logger().info(f"Starting Write Without Response transmission for client {self.ble_client_address}")
        if self.write_count:
            logger().info(f"Sending {self.write_count} Write Without Response to {self.ble_client_address}")
            for i in range(self.write_count):
                try:
                    logger().info(
                        f"tx Write Without Response count {sent_data_count} with {self.ble_client_address} and range:{i} - Starting Write Without Response {i + 1}/{self.write_count}")
                    with lock:
                        write()
                        logger().info(
                            f"Write Without Response {i + 1}/{self.write_count} completed successfully for {self.ble_client_address}")
                    sent_data_count += 1  # Increment after each indication
                except Exception as e:
                    logger().error(
                        f"Error sending indication {i + 1}/{self.write_count} to {self.ble_client_address}: {e}")
                    sent_data_count += 1  # Still increment counter to continue the loop
                    continue  # Continue with next indication
        else:
            logger().info(f"Sending Write Without Response for {self.notify_time} seconds to {self.ble_client_address}")
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                with lock:
                    write()
                sent_data_count += 1
                logger().debug(
                    f"Time-based Write Without Response {sent_data_count} sent to {self.ble_client_address}, elapsed: {sw.elapsed_sec}s")
        if not self.indication_count:
            self.indication_count = sent_data_count
        logger().info(f"TX_Write_Without_Response count with {self.ble_client_address}: {sent_data_count}")
        logger().info(f"Disabling Write Without Response for {self.ble_client_address}")

    def gatt_write_with_resp(self):
        logger().info(f"*Write With Response Start**")

        logger().info(
            f"*Write With Response notifications Start for client {self.ble_client_address}**")
        if self.data_size == 20:
            self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                ble_remote_dev_address=self.ble_client_address, buffer_mode=0, buffer_count=2)
            logger().info(f"* Buffer Enabled **")
        else:
            self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)
            logger().info(f"* Buffer Enabled **")
        time.sleep(2)
        def write():
            try:
                # Add thread identifier to data for better debugging
                thread_id = threading.current_thread().name[-3:] if hasattr(threading.current_thread(),
                                                                            'name') else 'THR'
                base_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_size - 3))
                data = f"{thread_id}{base_data}"
                logger().info(
                    f"* Sending Write With Response to {self.ble_client_address} with data size: {len(data)} (Thread: {thread_id}) **")
                logger().debug(f"Write With Response data: {data}")
                # Capture time right before sending indication to avoid cross-thread event collision
                self.ble_dut.interfaces.bluetooth.ble_set_att_value_async(
                    ble_remote_dev_address=self.ble_client_address,
                    char_property=self.write_handle, data=data, data_length=self.data_size)
                logger().info(f"Write With Response sent successfully to {self.ble_client_address}")
                time.sleep(2)
            except Exception as e:
                logger().error(f"Error in write() function for {self.ble_client_address}: {e}")
                raise e
        sent_data_count = 0
        time.sleep(1)
        logger().info(f"Starting Write With Response transmission for client {self.ble_client_address}")
        if self.write_count:
            logger().info(f"Sending {self.write_count} Write With Response to {self.ble_client_address}")
            for i in range(self.write_count):
                try:
                    logger().info(
                        f"tx Write With Response count {sent_data_count} with {self.ble_client_address} and range:{i} - Starting Write With Response {i + 1}/{self.write_count}")
                    with lock:
                        write()
                        logger().info(
                            f"Write With Response {i + 1}/{self.write_count} completed successfully for {self.ble_client_address}")
                    sent_data_count += 1  # Increment after each indication
                except Exception as e:
                    logger().error(
                        f"Error sending write with response {i + 1}/{self.write_count} to {self.ble_client_address}: {e}")
                    sent_data_count += 1  # Still increment counter to continue the loop
                    continue  # Continue with next indication
        else:
            logger().info(f"Sending Write With Response for {self.notify_time} seconds to {self.ble_client_address}")
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                with lock:
                    write()
                sent_data_count += 1
                logger().debug(
                    f"Time-based Write With Response {sent_data_count} sent to {self.ble_client_address}, elapsed: {sw.elapsed_sec}s")
        if not self.indication_count:
            self.indication_count = sent_data_count
        logger().info(f"TX_Write_With_Response count with {self.ble_client_address}: {sent_data_count}")
        logger().info(f"Disabling Write With Response for {self.ble_client_address}")

    def start_advertising(self):
        self.ble_dut.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)
        logger().info("Starting BLE advertising...")
        self.sl_collections.ble_ae_set_params(
            pheripheral_dev=self.ble_dut,
            adv_event_prop=1,
            own_address_type=0,
            peer_addr_type=0,
            peer_address=self.ble_client_address,
            adv_handle=0,
            pri_adv_phy=self.pri_adv_phy,
            sec_adv_phy=self.sec_adv_phy,
            scan_req_notify_enable=1,
            adv_filter_policy=0,
            sec_adv_max_skip=1,
            adv_min_interval=48,
            adv_max_interval=48
        )
        self.sl_collections.ble_set_ae_data(
            ble_dut=self.ble_dut,
            dut_address=self.ble_dut_address,
            adv_data_type=1,
            data_len=31,
            adv_data="AE_PERIPHERAL_DATA_AE_PERIPHERA",
            adv_handle=0
        )

        self.ble_dut.interfaces.wifi.ble_get_max_adv_data_len(max_data_len=31)
        self.sl_collections.ble_ae_start_advertising(
            ble_dut=self.ble_dut,
            dut_address=self.ble_dut_address,
            duration=0,
            max_ae_events=0,
            adv_handle=0,
            adv_async_required=0
        )
        logger().info("\n\nenable power save in ble dut")

    def start_scanning(self):
        logger().info("Starting BLE scanning...")
        self.remote_device.interfaces.wifi.ble_ae_set_scan_params(
            ble_addr_type=0,
            scanning_phys=5,
            scanning_filter_policy=0,
            scan_type=1,
            scan_type_sec=1,
            ScanInterval=48,
            ScanWindow=48,
            remote_addr_type=0,
            scan_interval_sec=48,
            scan_window_sec=30
        )
        scan_results = self.remote_device.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=self.ble_dut_address
        )
        logger().info(f"{scan_results}*")
        self.remote_device.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=self.ble_dut_address
        )

    def connect_devices(self):
        logger().info(f"Connecting BLE DUT device...{self.ble_client_address}")
        self.remote_device.interfaces.wifi.ble_extended_connect_with_params(
            remote_dev_addr=self.ble_dut_address,
            remote_addr_type=0,
            initiator_filter_policy=0,
            init_phys=7,
            ConnIntervalMin=160,
            ConnIntervalMax=160
        )
        time.sleep(60)
        state = self.ble_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        logger().info(f"Device state: {state_int}")
        assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        # Link Key Extraction
        logger().info("Extracting link key...")
        tw = Stopwatch()
        link_key = ""
        while tw.elapsed_sec < 120:
            events = self.ble_dut.interfaces.wifi.get_async_events()
            logger().info(f"Link key events: {events}")
            for event in events:
                if "link_key" in event.event_data:
                    logger().info(f"Link key event data: {event.event_data}")
                    event_data = event.event_data
                    link_key_data = re.findall("link_key::.*", event_data)
                    link_key_data_str = re.split(":<", link_key_data[0])
                    link_key_data_hex = re.split(":", link_key_data_str[0])
                    link_key = "0x"
                    for hex_data_part in link_key_data_hex:
                        hex_data_part = hex_data_part.replace(" ", "")
                        if len(hex_data_part) == 1:
                            hex_data_part = '0' + hex_data_part
                        link_key = link_key + hex_data_part
                else:
                    continue
            if link_key:
                break
        link_key = link_key.replace(" ", "")
        link_key = link_key.replace("link_key", "")
        link_key_pattern = r"(0x[0-9a-fA-F]+)"
        # Apply the regex
        match = re.search(link_key_pattern, link_key)
        if match:
            link_key = match.group(1)  # Extract the matched link key
            print(f"Extracted Link Key: {link_key}")
        else:
            print("Link key not found.")
        assert len(link_key) > 0, "Link key is not extracted"
        self.link_key = link_key  # Store the extracted link key
        return link_key

    def perform_gatt_operations(self):
        logger().info("Performing GATT operations...")
        # uuids = self.ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_client_address)
        uuids = self.remote_device.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_dut_address)

        # Convert service_uid to hex string for comparison
        service_uuid_hex = f"{self.service_uid:04x}" if self.service_uid else "1809"
        logger().info(f"Looking for service UUID: {service_uuid_hex} in available UUIDs: {uuids}")

        # Check if our service UUID exists in the discovered UUIDs
        service_found = False
        for uuid in uuids:
            if service_uuid_hex.lower() in uuid.lower():
                service_found = True
                service_uuid_hex = uuid  # Use the exact format from device
                break

        assert service_found, f"Could not find service {service_uuid_hex} in available profiles: {uuids}"

        start_handle, end_handle, data = self.remote_device.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_dut_address,
            uuid=int(service_uuid_hex, 16)
        )
        assert start_handle is not None, "Failed to fetch the start handle."
        assert end_handle is not None, "Failed to fetch the end handle."

        char_uuids, write_handles, char_properties = self.remote_device.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_dut_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60
        )
        logger().info(
            f"Characteristics UUIDs: {char_uuids}, Write Handles: {write_handles}, Properties: {char_properties}")

        # Convert char_uid to hex string for comparison
        char_uuid_hex = f"{self.char_uid:04x}" if self.char_uid else "2a1e"
        logger().info(f"Looking for characteristic UUID: {char_uuid_hex}")

        # Check if our characteristic UUID exists
        char_found = False
        for uuid in char_uuids:
            if char_uuid_hex.lower() in uuid.lower():
                char_found = True
                break

        assert char_found, f"Unable to find characteristic {char_uuid_hex} in {char_uuids}"
        self.write_handle = int(write_handles[0], 16)
        logger().info(f"write_handle set to: {self.write_handle}")
        assert self.write_handle > 0, "Unable to get write handle for configured service"

    def cleanup(self):
        logger().info("Cleaning up BLE resources...")
        self.ble_sniffer.interfaces.sniffer.stop_capture()


@pytest.mark.parametrize(
   "test_case_id, pri_adv_phy, sec_adv_phy, k, service_uid, char_uid",
    [
        ("C768364", 1, 1, 20, 0x1aa1, 0xAABB),
        ("C768365", 1, 2, 20, 0x1aa1, 0xAABB),
        ("C768366", 3, 3, 20, 0x1aa1, 0xAABB),
        ("C768376", 1, 1, 230, 0x1aa1, 0xAABB),
        ("C768377", 1, 2, 230, 0x1aa1, 0xAABB),
        ("C768378", 3, 3, 230, 0x1aa1, 0xAABB),
    ],
)

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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_tx_notification(remote_wiseconnect3, remote_wiseconnect3s, ble_dut, ble_sniffer, sl_collections, pri_adv_phy,
                         sec_adv_phy, test_case_id, k, char_uid, service_uid):
    try:
        logger().info("Dut address:{print1}")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        logger().info("Dut address:{print2}")
        ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"test_{test_case_id}_sniffer_capture")
        logger().info("Dut address:{print3}")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        logger().info("Dut address:{print4}")
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        logger().info("Dut address:{print5}")
        ble_client_address1 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)

        logger().info(f"Dut address:{ble_dut_address}")
        logger().info(f"Remote central address1:{ble_client_address}")
        logger().info(f"Remote central address2:{ble_client_address1}")


        ble_thread = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3, ble_sniffer=ble_sniffer,
                               ble_client_address=ble_client_address, ble_dut_address=ble_dut_address,
                                pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, data_size=k,notification_count=20, service_uid=service_uid, char_uid=char_uid)
        logger().info(f"Remote central addr1:{ble_client_address}")
        logger().info(f"Remote central addr2:{ble_client_address1}")
        logger().info("Creating Custom service in Primary DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=service_uid)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=char_uid)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=char_uid)
        ble_thread.start_advertising()
        ble_thread.start_scanning()
        link_key1 = ble_thread.connect_devices()
        ble_thread.perform_gatt_operations()
        ble_thread1 = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3s[0], ble_sniffer=ble_sniffer,
                                ble_client_address=ble_client_address1, ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy,
                                sec_adv_phy=sec_adv_phy, data_size=k,notification_count=20, service_uid=service_uid, char_uid=char_uid)
        ble_thread1.start_advertising()
        ble_thread1.start_scanning()
        link_key2 = ble_thread1.connect_devices()
        ble_thread1.perform_gatt_operations()
        # Run threads sequentially - first send notifications to first central, then to second central
        thread1 = threading.Thread(target=ble_thread.run)
        thread2 = threading.Thread(target=ble_thread1.run)
        thread1.start()
        time.sleep(2)
        thread2.start()
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address1)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        master_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            master_address1 = master_address1 + hex_data_part
        logger().info(f"master_address1:{master_address1}")
        master_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            master_address2 = master_address2 + hex_data_part
        logger().info(f"master_address2:{master_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address, master_address1, master_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), slave_address, master_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), slave_address, master_address2)
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
        logger().info("validating Tx Notifications")
        logger().info(f"{ble_thread.write_count}")
        if k == 20:
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df['+PDU Length (L2CAP)'] == 23)]) >= int(
                ble_thread.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df['+PDU Length (L2CAP)'] == 23)]) >= int(
                ble_thread1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        else:
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df['+PDU Length (L2CAP)'] == 233)]) >= int(
                ble_thread.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_NTF") & (
                                   sniffer_data_df['+PDU Length (L2CAP)'] == 233)]) >= int(
                ble_thread1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
            logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as e:
        logger().error(f"Error in BLEThread: {e}")
        raise e
    finally:
        logger().info("print_test_final")
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        time.sleep(10)
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address1)
        time.sleep(10)
        logger().info(f"Removing services on primary DUT")
        ble_dut.interfaces.wifi.ble_remove_service()
        try:
            logger().info("\n\n *  Stopping Advertisement  *\n\n")
            sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address, adv_enable=0,
                                                    adv_handle=0)
        except Exception as e:
            logger().info(f"Got Exception : {str(e)}")


@pytest.mark.parametrize(
    "test_case_id, pri_adv_phy, sec_adv_phy, k, service_uid, char_uid, notify_time",
    [
        ("C768367", 1, 1, 20, 0x1bb1, 0x1AA1, 400),
        ("C768368", 1, 2, 20, 0x1bb1, 0x1AA1, 400),
        ("C768369", 3, 3, 20, 0x1bb1, 0x1AA1, 400),
        ("C768379", 1, 1, 230, 0x1bb1, 0x1AA1, 400),
        ("C768380", 1, 2, 230, 0x1bb1, 0x1AA1, 400),
        ("C768381", 3, 3, 230, 0x1bb1, 0x1AA1, 400),
    ],
)
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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
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
        "ble_custom_ext_features":  Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
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
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE,
            "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_tx_indications(remote_wiseconnect3,
                            remote_wiseconnect3s,
                            ble_dut, ble_sniffer,
                            sl_collections,
                            pri_adv_phy,
                            sec_adv_phy,
                            test_case_id, k,
                            service_uid, char_uid, notify_time):
    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"test_{test_case_id}_sniffer_capture")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=0)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=1)
        ble_client_address1 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=1)
        ble_thread = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3,
                               ble_sniffer=ble_sniffer,
                               ble_client_address=ble_client_address, ble_dut_address=ble_dut_address,
                               pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy, write_count=50, data_size=k,
                               indication_count=None, service_uid=service_uid, char_uid=char_uid, notify_time=notify_time)

        logger().info(f"Dut address:{ble_dut_address}")
        logger().info(f"Remote central address1:{ble_client_address}")
        logger().info(f"Remote central address2:{ble_client_address1}")
        logger().info("Creating Custom service in Primary DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=service_uid)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=char_uid,
                                                      permissions=34)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=char_uid)
        ble_thread.start_advertising()

        ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                           psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
        ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')

        ble_thread.start_scanning()
        link_key1 = ble_thread.connect_devices()
        ble_thread.perform_gatt_operations()
        ble_thread1 = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3s[0],
                                ble_sniffer=ble_sniffer,
                                ble_client_address=ble_client_address1, ble_dut_address=ble_dut_address,
                                pri_adv_phy=pri_adv_phy,notify_time=notify_time,
                                sec_adv_phy=sec_adv_phy, write_count=50, data_size=k, indication_count=None,
                                service_uid=service_uid, char_uid=char_uid)
        ble_thread1.start_advertising()
        ble_thread1.start_scanning()
        link_key2 = ble_thread1.connect_devices()
        ble_thread1.perform_gatt_operations()
        # Run threads sequentially - first send notifications to first central, then to second central
        thread1 = threading.Thread(target=ble_thread.gatt_indication)
        thread2 = threading.Thread(target=ble_thread1.gatt_indication)
        thread1.start()
        time.sleep(2)
        thread2.start()
        thread1.join()
        thread2.join()
        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address1)
        slave_address = "0x"
        for hex_data_part in ble_dut_address_hex:
            slave_address = slave_address + hex_data_part
        master_address1 = "0x"
        for hex_data_part in ble_client_address_hex1:
            master_address1 = master_address1 + hex_data_part
        logger().info(f"master_address1:{master_address1}")
        master_address2 = "0x"
        for hex_data_part in ble_client_address_hex2:
            master_address2 = master_address2 + hex_data_part
        logger().info(f"master_address2:{master_address2}")
        ble_sniffer.interfaces.sniffer.select_bt_devices([slave_address, master_address1, master_address2])
        time.sleep(30)
        if link_key1 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key1.upper(), slave_address, master_address1)
        if link_key2 != "":
            ble_sniffer.interfaces.sniffer.add_link_key(link_key2.upper(), slave_address, master_address2)
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
        logger().info("validating Tx Indications")
        logger().info(f"{ble_thread.write_count}")
        if k == 20:
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df['+PDU Length (L2CAP)'] == 23)]) >= int(
                ble_thread.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df['+PDU Length (L2CAP)'] == 23)]) >= int(
                ble_thread1.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
        else:
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df['+PDU Length (L2CAP)'] == 233)]) >= int(
                ble_thread.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
            assert len(sniffer_data_df.loc[
                           (sniffer_data_df['Role'] == "* P") & (
                                   sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                   sniffer_data_df['Opcode'] == "* ATT_HANDLE_VALUE_IND") & (
                                   sniffer_data_df['+PDU Length (L2CAP)'] == 233)]) >= int(
                ble_thread1.indication_count / 2), "No ATT_HANDLE_VALUE_IND packets are present"
            logger().info("ATT_HANDLE_VALUE_IND packets are sent successfully")
    except Exception as e:
        logger().error(f"Error in BLEThread: {e}")
        raise e
    finally:
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        time.sleep(10)
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address1)
        time.sleep(10)
        logger().info(f"Removing services on primary DUT")
        ble_dut.interfaces.wifi.ble_remove_service()
        try:
            logger().info("\n\n *  Stopping Advertisement  *\n\n")
            sl_collections.ble_ae_start_advertising(ble_dut=ble_dut, dut_address=ble_dut_address, adv_enable=0,
                                                    adv_handle=0)
        except Exception as e:
            logger().info(f"Got Exception : {str(e)}")
