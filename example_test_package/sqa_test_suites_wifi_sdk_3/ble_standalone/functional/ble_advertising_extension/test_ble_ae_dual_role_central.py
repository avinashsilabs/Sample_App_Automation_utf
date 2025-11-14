import pytest
import pandas as pd
import re
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    HealthThermometerMeasurementCharacteristic, HealthThermometerService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertLevelCharacteristic
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
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
    Si91xConfigFeatureBitMap, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
)
from utf.utf_config import UtfConfig
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
import time, os
import threading
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
# Add buffer allocation lock to prevent concurrent buffer operations
buffer_allocation_lock = threading.Lock()


class BLEThread:
    def __init__(self, sl_collections, ble_dut=None, remote_device=None, ble_sniffer=None, ble_client_address=None,
                 ble_dut_address=None, pri_adv_phy=None, sec_adv_phy=None, write_count=None, write_handle=None,
                 data_size=None, notification_count=None, notify_time=None, service_uuid=None, char_uuid=None,
                 operation_mode=None, write_time=None, powersave_flag=False):
        super().__init__()
        self.ble_dut = ble_dut
        self.remote_device = remote_device
        self.ble_sniffer = ble_sniffer
        self.sl_collections = sl_collections
        self.ble_client_address = ble_client_address
        self.ble_dut_address = ble_dut_address
        self.pri_adv_phy = pri_adv_phy
        self.sec_adv_phy = sec_adv_phy

        # Initialize counts with defaults to prevent None errors
        self.write_count = write_count if write_count is not None else 0
        self.notification_count = notification_count if notification_count is not None else 0

        self.write_handle = write_handle
        self.data_size = data_size
        self.notify_time = notify_time
        self.write_time = write_time
        self.operation_mode = operation_mode  # "notification" or "write_without_response"

        # Add exception container for thread error propagation
        self.thread_exception = None

        # Parameterized BLE Configuration with default values
        self.service_uuid = service_uuid
        self.char_uuid = char_uuid
        self.adv_interval_min = 48
        self.adv_interval_max = 48
        self.conn_interval_min = 160
        self.conn_interval_max = 160
        self.scan_interval = 48
        self.scan_window = 48
        self.power_save_mode = Si91xPowerSaveModes.PowerSaveMode2
        self.power_save_type = Si91xPowerSaveProcedureTypes.MaxPowerSave
        self.connection_timeout = 60
        self.notification_timeout = 120
        self.adv_data_content = "AE_PERIPHERAL_DATA_AE_PERIPHERA"
        self.use_notifications = True

        # Add exception container for thread error propagation
        self.thread_exception = None

        # Powersave control flag - can be set once from testcase
        self.powersave_flag = powersave_flag  # Flag to control if powersave should be enabled
        self.powersave_enabled = False
        self.powersave_called = False  # Flag to ensure powersave is called only once

    def enable_powersave(self):
        """Enable powersave on ble_dut once. Can only be called once per test."""
        if not self.powersave_flag:
            logger().info("Powersave flag is disabled - skipping powersave configuration")
            return

        if self.powersave_called:
            logger().warning("Powersave already called for this test instance")
            return

        if not self.ble_dut:
            logger().error("BLE DUT not available for powersave configuration")
            return

        try:
            logger().info("\n\nenable power save in ble dut")
            self.ble_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                              psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)
            self.ble_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            time.sleep(30)
            self.powersave_enabled = True
            self.powersave_called = True
            logger().info("Powersave enabled successfully on BLE DUT")
        except Exception as e:
            logger().error(f"Failed to enable powersave on BLE DUT: {e}")
            raise e

    def run(self):
        """Optimized run method that handles notification, write without response, and indication operations"""
        try:
            if self.operation_mode == "notification":
                self._run_notifications()
            elif self.operation_mode == "rx_notification":
                self._run_rx_notifications()
            elif self.operation_mode == "write_without_response":
                self._run_write_without_response()
            elif self.operation_mode == "write_with_response":
                self._run_write_with_response()
            elif self.operation_mode == "indication":
                self._run_indications()
            else:
                raise ValueError(f"Unsupported operation mode: {self.operation_mode}")
        except Exception as e:
            # Store the exception to be checked by the main thread
            self.thread_exception = e
            logger().error(f"Thread {threading.current_thread().name} failed with exception: {e}")
            raise  # Re-raise for thread termination

    def _generate_data(self):
        """Generate data based on data size"""
        # Simple data generation for write without response
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_size))
        return data

    def check_thread_exception(self):
        """Check if the thread encountered an exception and re-raise it"""
        if self.thread_exception:
            raise self.thread_exception

    def get_operation_count(self):
        """
        Get the appropriate count based on operation mode

        Returns:
            int: The count of operations performed (write_count for writes, notification_count for notifications)
        """
        if self.operation_mode in ["write_with_response", "write_without_response"]:
            count = self.write_count if self.write_count is not None else 0
            logger().debug(f"Operation mode: {self.operation_mode}, using write_count: {count}")
            return count
        elif self.operation_mode in ["notification", "rx_notification", "indication"]:
            count = self.notification_count if self.notification_count is not None else 0
            logger().debug(f"Operation mode: {self.operation_mode}, using notification_count: {count}")
            return count
        else:
            # Default to notification_count, but fall back to write_count if available
            if self.notification_count is not None:
                logger().debug(
                    f"Operation mode: {self.operation_mode}, defaulting to notification_count: {self.notification_count}")
                return self.notification_count
            elif self.write_count is not None:
                logger().debug(
                    f"Operation mode: {self.operation_mode}, falling back to write_count: {self.write_count}")
                return self.write_count
            else:
                logger().warning(f"Operation mode: {self.operation_mode}, no counts available, returning 0")
                return 0

    def log_operation_summary(self):
        """Log a summary of operation counts for debugging"""
        logger().info(f"BLEThread Summary - Operation: {self.operation_mode}, "
                      f"Write Count: {self.write_count}, Notification Count: {self.notification_count}, "
                      f"Effective Count: {self.get_operation_count()}")

    def _run_rx_notifications(self):
        """Handle RX Notifications operation (Peripheral device sending notifications to DUT)"""
        logger().info(
            f"Enabling notifications for Peripheral address: {self.ble_dut_address}, handle: {self.write_handle + 1}")
        # enable notifications on the central device to send to peripheral
        self.ble_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                       handle=(self.write_handle + 1),
                                                       enable_notify=1)
        time.sleep(10)
        logger().info(
            f"RX Notifications Start - Peripheral dut {self.ble_client_address} sending to remote {self.ble_dut_address}")

        # Note: For RX notifications, the roles are reversed:
        # self.ble_dut is actually the peripheral device
        # self.remote_device is actually the DUT
        # self.ble_client_address is actually the DUT address
        # self.ble_dut_address is actually the peripheral address

        buffer_mode = 0 if self.data_size == 20 else 1
        try:
            # Set buffer on peripheral device (self.ble_dut) for sending notifications
            self.remote_device.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_dut_address,
                                                                          buffer_mode=buffer_mode, buffer_count=2)
            time.sleep(2)
        except Exception as e:
            logger().error(f"Failed to set RX notification buffer: {e}")
            raise e

        def send_rx_notification():
            try:
                data = self._generate_data()
                # Capture time right before sending notification
                since_time = time.perf_counter_ns()

                # Peripheral device (self.ble_dut) sends notification to DUT (self.ble_client_address)
                self.remote_device.interfaces.wifi.ble_notify_custom_value(
                    ble_remote_dev_address=self.ble_dut_address,
                    data=data,
                    timeout=self.notification_timeout
                )
                time.sleep(10)
                logger().info(
                    f"RX Notification sent from peripheral {self.ble_client_address} to DUT {self.ble_dut_address}")

                # Check for GATT events on DUT (self.remote_device)
                events = self.ble_dut.interfaces.wifi.get_async_events(since_time=since_time)

                # Look for the most recent GATT_WRITE_EVENT that matches our sent data
                matching_event = None
                for event in reversed(events):  # Check events in reverse order (most recent first)
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        received_data = re.findall(r"att_value:\s*([^\s]+)", event.event_data)
                        if received_data and received_data[0] == data:
                            matching_event = event
                            break

                if matching_event:
                    logger().info(
                        f"DUT RX BLE EVENT DATA IS : {matching_event.event_data}")
                    received_data = re.findall(r"att_value:\s*([^\s]+)", matching_event.event_data)
                    logger().info(
                        f" DUT Received RX Data from {self.ble_dut_address} : {received_data} ")
                    logger().info(f"Length of DUT received RX Data : {len(received_data[0])} ")
                    try:
                        assert received_data[
                                   0] == data, f"RX data mismatch - Expected: {data}, Received: {received_data[0]}"
                    except AssertionError as ae:
                        logger().error(f"RX Data assertion failed for {self.ble_dut_address}: {ae}")
                        raise ae
                    except IndexError as ie:
                        logger().error(f"No RX received data found for {self.ble_dut_address}: {ie}")
                        raise ie
                else:
                    # If no matching event found, log all events for debugging
                    logger().warning(f"No matching RX GATT_WRITE_EVENT found for data: {data}")
                    for event in events:
                        if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                            logger().info(f"Available RX event data: {event.event_data}")
                    raise AssertionError(f"No matching RX GATT_WRITE_EVENT found for sent data: {data}")
            except Exception as e:
                logger().error(f"Error in send_rx_notification() function for {self.ble_dut_address}: {e}")
                raise e

        sent_rx_notifications = 0
        time.sleep(1)

        if self.notification_count:
            for i in range(self.notification_count):
                try:
                    logger().info(
                        f"RX notification count {sent_rx_notifications} from {self.ble_dut_address} and range:{i} - Starting RX notification {i + 1}/{self.notification_count}")
                    with lock:
                        send_rx_notification()
                        logger().info(
                            f"RX Notification {i + 1}/{self.notification_count} completed successfully from {self.ble_dut_address}")
                    sent_rx_notifications += 1
                except Exception as e:
                    logger().error(
                        f"Error sending RX notification {i + 1}/{self.notification_count} from {self.ble_dut_address}: {e}")
                    sent_rx_notifications += 1
                    raise e
        else:
            logger().info(f"Sending RX notifications for {self.notify_time} seconds from {self.ble_dut_address}")
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                with lock:
                    send_rx_notification()
                sent_rx_notifications += 1
                logger().debug(
                    f"Time-based RX notification {sent_rx_notifications} sent from {self.ble_dut_address}, elapsed: {sw.elapsed_sec}s")

        if not self.notification_count:
            self.notification_count = sent_rx_notifications

        logger().info(f"RX_Notification count from {self.ble_client_address}: {sent_rx_notifications}")
        logger().info(f"RX Notifications End from peripheral {self.ble_dut_address}")
        self.ble_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                       handle=(self.write_handle + 1),
                                                       enable_notify=0)

    def _run_write_with_response(self):
        """Handle Write With Response operation"""
        logger().info(f"Write With Response Start for client {self.ble_client_address}")
        buffer_mode = 0 if self.data_size == 20 else 1
        try:
            self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                                    buffer_mode=buffer_mode, buffer_count=2)
        except Exception as e:
            raise e

        def write_with_response():
            data = self._generate_data()
            time.sleep(2)
            # Add thread identifier to data for better debugging
            thread_id = threading.current_thread().name[-3:] if hasattr(threading.current_thread(),
                                                                        'name') else 'THR'

            # Capture time right before sending write request to avoid cross-thread event collision
            since_time = time.perf_counter_ns()

            # Use ble_set_att_req for write with response
            self.ble_dut.interfaces.bluetooth.ble_set_att_value_async(
                ble_remote_dev_address=self.ble_client_address,
                char_property=self.write_handle, data=data, data_length=len(data))
            time.sleep(5)
            logger().info(f"Write with response sent successfully to {self.ble_client_address}")

        sent_writes = 0
        time.sleep(1)

        if self.write_count:
            for i in range(self.write_count):
                try:
                    logger().info(
                        f"tx write with response count {sent_writes} with {self.ble_client_address} and range:{i} - Starting write {i + 1}/{self.write_count}")
                    with lock:
                        write_with_response()
                        logger().info(
                            f"Write with response {i + 1}/{self.write_count} completed successfully for {self.ble_client_address}")
                    sent_writes += 1
                except Exception as e:
                    logger().error(
                        f"Error sending write with response {i + 1}/{self.write_count} to {self.ble_client_address}: {e}")
                    sent_writes += 1
                    continue  # Continue with next write
        else:
            logger().info(f"Sending writes with response for {self.write_time} seconds to {self.ble_client_address}")
            sw = Stopwatch()
            while sw.elapsed_sec <= self.write_time:
                try:
                    with lock:
                        write_with_response()
                    sent_writes += 1
                    logger().info(
                        f"Time-based write with response {sent_writes} sent to {self.ble_client_address}, elapsed: {sw.elapsed_sec}s")
                    time.sleep(0.1)  # Small delay between writes
                except Exception as e:
                    logger().error(f"Error sending time-based write with response to {self.ble_client_address}: {e}")
                    sent_writes += 1
                    time.sleep(1)  # Wait longer on error before retrying

        if not self.write_count:
            self.write_count = sent_writes

        # For consistency with test validation, also set notification_count to write_count
        self.notification_count = self.write_count

        logger().info(f"TX_Write with response count with {self.ble_client_address}: {sent_writes}")
        logger().info(f"Write With Response End for client {self.ble_client_address}")

    def _run_notifications(self):
        """Handle TX Notifications operation"""
        logger().info(f"TX Notifications Start for client {self.ble_client_address}")

        # Enable notifications
        self.remote_device.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_dut_address,
            handle=(self.write_handle + 1),
            enable_notify=1
        )
        logger().info(f"Notifications enabled successfully for {self.ble_client_address}")
        time.sleep(10)
        buffer_mode = 0 if self.data_size == 20 else 1
        try:
            self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(ble_remote_dev_address=self.ble_client_address,
                                                                    buffer_mode=buffer_mode, buffer_count=2)
            time.sleep(2)
        except Exception as e:
            raise e

        def write_notification():
            try:
                data = self._generate_data()
                # Capture time right before sending notification to avoid cross-thread event collision
                since_time = time.perf_counter_ns()
                self.ble_dut.interfaces.wifi.ble_notify_custom_value(
                    ble_remote_dev_address=self.ble_client_address,
                    data=data,
                    timeout=self.notification_timeout
                )
                logger().info(f"Notification sent successfully to {self.ble_client_address}")

                time.sleep(10)
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
                        f" Received Data on remote device {self.ble_client_address} : {received_data} ")
                    logger().info(
                        f" length of received Data on remote device {self.ble_client_address} : {len(received_data[0])} ")
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
                    logger().warning(f"No matching GATT_WRITE_EVENT found for sent data: {data}")
            except Exception as e:
                logger().error(f"Error in write_notification() function for {self.ble_client_address}: {e}")
                raise e

        sent_notifications = 0
        time.sleep(1)

        if self.notification_count:
            for i in range(self.notification_count):
                try:
                    logger().info(
                        f"tx notification count {sent_notifications} with {self.ble_client_address} and range:{i} - Starting notification {i + 1}/{self.notification_count}")
                    with lock:
                        write_notification()
                        logger().info(
                            f"Notification {i + 1}/{self.notification_count} completed successfully for {self.ble_client_address}")
                    sent_notifications += 1
                except Exception as e:
                    logger().error(
                        f"Error sending notification {i + 1}/{self.notification_count} to {self.ble_client_address}: {e}")
                    sent_notifications += 1
                    raise e
        else:
            logger().info(f"Sending notifications for {self.notify_time} seconds to {self.ble_client_address}")
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                with lock:
                    write_notification()
                sent_notifications += 1
                logger().debug(
                    f"Time-based notification {sent_notifications} sent to {self.ble_client_address}, elapsed: {sw.elapsed_sec}s")

        if not self.notification_count:
            self.notification_count = sent_notifications

        logger().info(f"TX_Notification count with {self.ble_client_address}: {sent_notifications}")
        logger().info(f"Disabling notifications for {self.ble_client_address}")

        # Disable notifications
        self.remote_device.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_dut_address,
            handle=(self.write_handle + 1),
            enable_notify=0
        )

    def _run_write_without_response(self):
        """Handle Write Without Response operation"""
        logger().info(f"Write Without Response Start")

        logger().info(
            f"Write Without Response notifications Start for client {self.ble_client_address}")
        if self.data_size == 20:
            self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                ble_remote_dev_address=self.ble_client_address, buffer_mode=0, buffer_count=2)
            logger().info(f" Buffer Enabled ")
        else:
            self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                ble_remote_dev_address=self.ble_client_address, buffer_mode=1, buffer_count=2)
            logger().info(f"Buffer Enabled ")
        time.sleep(2)

        def write():
            try:
                # Add thread identifier to data for better debugging
                thread_id = threading.current_thread().name[-3:] if hasattr(threading.current_thread(),
                                                                            'name') else 'THR'
                base_data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=self.data_size - 3))
                data = f"{thread_id}{base_data}"
                logger().info(
                    f"Sending Write Without Response to {self.ble_client_address} with data size: {len(data)} (Thread: {thread_id}) ")
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

        # Update write_count if it wasn't set
        if not self.write_count:
            self.write_count = sent_data_count

        # For consistency with test validation, also set notification_count to write_count
        self.notification_count = self.write_count

        logger().info(f"TX_Write_Without_Response count with {self.ble_client_address}: {sent_data_count}")
        logger().info(f"Disabling Write Without Response for {self.ble_client_address}")

    def _run_indications(self):
        """Handle TX Indications operation with optimized buffer management"""
        thread_name = threading.current_thread().name
        logger().info(
            f"TX Indications Start for client {self.ble_client_address} in thread {thread_name}")

        # Verify handle is valid before proceeding
        if self.write_handle <= 0:
            raise ValueError(f"Invalid write handle: {self.write_handle} for client {self.ble_client_address}")

        # Enable indications first
        self.remote_device.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_dut_address,
            handle=(self.write_handle + 1),
            enable_notify=1
        )
        logger().info(f"Indications enabled successfully for {self.ble_client_address}")
        time.sleep(10)

        buffer_mode = 0 if self.data_size == 20 else 1
        with buffer_allocation_lock:  # Thread-safe buffer allocation
            try:
                self.ble_dut.interfaces.wifi.ble_set_resp_notify_buffer(
                    ble_remote_dev_address=self.ble_client_address,
                    buffer_mode=buffer_mode,
                    buffer_count=2
                )
                time.sleep(2)
            except Exception as e:
                logger().error(f"Buffer allocation failed: {e}")
                raise e

        def write_indication():
            try:
                # Add thread identifier to data for better debugging
                thread_id = thread_name.split('_')[-1][-6:] if '_' in thread_name else 'THR'
                base_data = ''.join(
                    random.choices(string.ascii_uppercase + string.digits, k=self.data_size - len(thread_id)))
                data = f"{thread_id}{base_data}"

                # Capture time right before sending indication to avoid cross-thread event collision
                since_time = time.perf_counter_ns()
                self.ble_dut.interfaces.bluetooth.ble_indicate_value(
                    ble_remote_dev_address=self.ble_client_address,
                    handle=self.write_handle,
                    data=data,
                    data_length=len(data)
                )
                logger().info(f"Indication sent successfully to {self.ble_client_address}")

                time.sleep(3)
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
                    logger().info(f"BLE EVENT DATA IS : {matching_event.event_data} ")
                    received_data = re.findall(r"att_value:\s*([^\s]+)", matching_event.event_data)
                    logger().info(
                        f"Received Data on remote device {self.ble_client_address} : {received_data} ")
                    logger().info(
                        f"length of received Data on remote device {self.ble_client_address} : {len(received_data[0])} ")
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
                logger().error(f"Error in write_indication() function for {self.ble_client_address}: {e}")
                raise e

        sent_indications = 0
        time.sleep(1)

        if self.notification_count:
            for i in range(self.notification_count):
                try:
                    logger().info(
                        f"tx indication count {sent_indications} with {self.ble_client_address} and range:{i} - Starting indication {i + 1}/{self.notification_count}")
                    with lock:
                        write_indication()
                        logger().info(
                            f"Indication {i + 1}/{self.notification_count} completed successfully for {self.ble_client_address}")
                    sent_indications += 1
                except Exception as e:
                    logger().error(
                        f"Error sending indication {i + 1}/{self.notification_count} to {self.ble_client_address}: {e}")
                    sent_indications += 1
                    continue  # Continue with next indication
        else:
            logger().info(f"Sending indications for {self.notify_time} seconds to {self.ble_client_address}")
            sw = Stopwatch()
            while sw.elapsed_sec <= self.notify_time:
                try:
                    with lock:
                        write_indication()
                    sent_indications += 1
                    logger().info(
                        f"Time-based indication {sent_indications} sent to {self.ble_client_address}, elapsed: {sw.elapsed_sec}s")
                    time.sleep(0.1)  # Small delay between indications
                except Exception as e:
                    logger().error(f"Error sending time-based indication to {self.ble_client_address}: {e}")
                    sent_indications += 1
                    time.sleep(1)  # Wait longer on error before retrying

        if not self.notification_count:
            self.notification_count = sent_indications

        logger().info(f"TX_Indication count with {self.ble_client_address}: {sent_indications}")
        logger().info(f"Disabling indications for {self.ble_client_address}")

        # Disable indications
        self.remote_device.interfaces.wifi.ble_set_att_value(
            ble_remote_dev_address=self.ble_dut_address,
            handle=(self.write_handle + 1),
            enable_notify=0
        )

    def start_advertising(self):
        self.ble_dut.interfaces.wifi.ble_get_max_no_of_supp_adv_sets(no_adv_sets=1)
        logger().info("Starting BLE advertising...")
        logger().info("\n\n Configuring AE advertising parameters\n\n")
        self.remote_device.interfaces.wifi.ble_set_ae_params(adv_handle=0, adv_event_prop=1,
                                                             primary_adv_intterval_min=48,
                                                             primary_adv_intterval_max=48,
                                                             own_addr_type=0,
                                                             peer_addr_type=0,
                                                             remote_dev_addr=self.ble_dut_address,
                                                             primary_adv_phy=self.pri_adv_phy,
                                                             sec_adv_max_skip=1,
                                                             sec_adv_phy=self.sec_adv_phy,
                                                             scan_req_notify_enable=1,
                                                             adv_filter_policy=0,
                                                             timeout=30)

        self.remote_device.interfaces.wifi.ble_set_ae_data(type=1, adv_handle=0, operation=0,
                                                           data_len=31, data="AE_PERIPHERAL_DATA_AE_PERIPHERA")
        logger().info(
            f"\n\n  AE advertising Data configured successfully on {self.ble_client_address} with data type: 1 \n\n")
        self.remote_device.interfaces.wifi.ble_set_ae_data(type=3, adv_handle=0,
                                                           operation=0,
                                                           data_len=31, data="AE_PERIPHERAL_DATA_AE_PERIPHERA")
        logger().info(
            f"\n\n AE advertising Data configured successfully on {self.ble_client_address} with data type: 3 \n\n")
        self.remote_device.interfaces.wifi.ble_get_max_adv_data_len(max_data_len=31)
        self.remote_device.interfaces.wifi.ble_start_ae_advertising(no_of_sets=1, adv_handle=0, duration=0,
                                                                    max_ae_events=0,
                                                                    )
        time.sleep(2)
        logger().info(f"\n\n AE advertising started successfully on {self.ble_client_address} \n\n")
        time.sleep(30)

    def start_scanning(self):
        logger().info("Starting BLE scanning...")
        self.ble_dut.interfaces.wifi.ble_ae_set_scan_params(
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
        scan_results = self.ble_dut.interfaces.wifi.ble_ae_set_scan_enable(
            enable=1,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=self.ble_client_address
        )
        time.sleep(10)
        logger().info(f"{scan_results}")
        self.enable_powersave()
        self.ble_dut.interfaces.wifi.ble_ae_set_scan_enable(
            enable=0,
            filter_duplicates=0,
            duration=0,
            period=0,
            remote_address=self.ble_client_address
        )

    def connect_devices(self):
        logger().info("Connecting BLE devices...")
        self.ble_dut.interfaces.wifi.ble_extended_connect_with_params(
            remote_dev_addr=self.ble_client_address,
            remote_addr_type=0,
            initiator_filter_policy=0,
            init_phys=7,
            ConnIntervalMin=160,
            ConnIntervalMax=160,timeout=180
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
        # assert len(link_key) > 0, "Link key is not extracted"
        self.link_key = link_key  # Store the extracted link key
        return link_key

    def perform_Write_no_Response_gatt_operations(self):
        logger().info("Performing GATT operations...")
        uuids = self.ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_client_address)
        remote_uuid= self.remote_device.interfaces.sapi.ble_get_profiles_async(ble_remote_dev_address=self.ble_dut_address)

        start_handle, end_handle, data = self.ble_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_client_address,
            uuid=0x1802
        )
        assert start_handle is not None, "Failed to fetch the start handle."
        assert end_handle is not None, "Failed to fetch the end handle."

        char_uuids, write_handles, char_properties = self.ble_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_client_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60
        )
        logger().info(
            f"Characteristics UUIDs: {char_uuids}, Write Handles: {write_handles}, Properties: {char_properties}")

        self.write_handle = int(write_handles[0], 16)
        assert self.write_handle > 0, "Unable to get write handle for configured service"

    def perform_gatt_operations(self):
        logger().info("Performing GATT operations...")
        uuids = self.remote_device.interfaces.sapi.ble_get_profiles_async(ble_remote_dev_address=self.ble_dut_address)
        remote_uuid= self.ble_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_client_address)

        start_handle, end_handle, data = self.remote_device.interfaces.sapi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_dut_address,
            uuid=self.service_uuid
        )
        assert start_handle is not None, "Failed to fetch the start handle."
        assert end_handle is not None, "Failed to fetch the end handle."

        char_uuids, write_handles, char_properties = self.remote_device.interfaces.sapi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_dut_address,
            start_handle=int(start_handle, 16),
            end_handle=int(end_handle, 16),
            async_timeout=60
        )
        logger().info(
            f"Characteristics UUIDs: {char_uuids}, Write Handles: {write_handles}, Properties: {char_properties}")

        self.write_handle = int(write_handles[0], 16)
        assert self.write_handle > 0, "Unable to get write handle for configured service"

    def perform_health_thermometer_gatt_operations(self):
        """Perform GATT operations specifically for health thermometer service"""
        logger().info("Performing Health Thermometer GATT operations...")
        uuids = self.remote_device.interfaces.sapi.ble_get_profiles_async(ble_remote_dev_address=self.ble_dut_address)
        assert HealthThermometerService.UUID in uuids, "Could not fetch the health thermometer profile"

        start_handle, end_handle, data = self.remote_device.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_dut_address,
            uuid=int(HealthThermometerService.UUID, 16)
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
        assert HealthThermometerMeasurementCharacteristic.Thermo_Level_UUID in char_uuids, "Unable to find health thermometer UUID"
        self.write_handle = int(write_handles[0], 16)
        assert self.write_handle > 0, "Unable to get write handle for configured service"

    def cleanup(self):
        logger().info("Cleaning up BLE resources...")
        self.ble_sniffer.interfaces.sniffer.stop_capture()

@pytest.mark.parametrize(
    "test_case_id, pri_adv_phy, sec_adv_phy, data_size, notification_count, expected_pdu_length, service_uuid, char_uuid",
    [
        ("C768388", 1, 1, 20, 20, 23, 0x1aa1, 0xAABB),
        ("C768389", 1, 2, 20, 20, 23, 0x1aa1, 0xAABB),
        ("C768390", 3, 3, 20, 20, 23, 0x1aa1, 0xAABB),
        ("C768400", 1, 1, 230, 20, 233, 0x1aa1, 0xAABB),
        ("C768401", 1, 2, 230, 20, 233, 0x1aa1, 0xAABB),
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
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_tx_notify(
        remote_wiseconnect3, remote_wiseconnect3s, ble_dut,
        ble_sniffer, sl_collections, pri_adv_phy, sec_adv_phy,
        test_case_id, data_size, notification_count, expected_pdu_length,
        service_uuid, char_uuid):
    try:
        logger().info("Initializing BLE sniffer...")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"test_{test_case_id}_sniffer_capture")

        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        ble_client_address1 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)

        # Use parameterized notification counts for each thread
        notification_count_thread1 = notification_count
        notification_count_thread2 = notification_count
        ble_thread = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3,
                               ble_sniffer=ble_sniffer, ble_client_address=ble_client_address,
                               ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                               notification_count=notification_count_thread1, data_size=data_size,
                               service_uuid=service_uuid, char_uuid=char_uuid, operation_mode="notification",
                               powersave_flag=True)

        logger().info(f"dut_ble_addr:{ble_dut_address}")
        logger().info(f"remote_device1_addr:{ble_client_address}")
        logger().info(f"remote_device2_addr:{ble_client_address1}")

        logger().info("creating health thermometer service in DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=service_uuid)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=char_uuid)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=char_uuid)

        logger().info("starting advertising, scanning and connection for first remote device")
        ble_thread.start_advertising()
        ble_thread.start_scanning()
        link_key1 = ble_thread.connect_devices()

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        allocated_mem_addr = ble_dut.interfaces.bluetooth.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        ble_dut.interfaces.bluetooth.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)

        # Get All Profiles
        ble_thread.perform_gatt_operations()

        ble_thread1 = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3s[0],
                                ble_sniffer=ble_sniffer, ble_client_address=ble_client_address1,
                                ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                                notification_count=notification_count_thread2, data_size=data_size,
                                service_uuid=service_uuid, char_uuid=char_uuid, operation_mode="notification",
                                powersave_flag=False)

        logger().info("starting advertising, scanning and connection for second remote device")
        ble_thread1.start_advertising()
        ble_thread1.start_scanning()
        link_key2 = ble_thread1.connect_devices()
        ble_thread1.perform_gatt_operations()

        thread1 = threading.Thread(target=ble_thread.run, name="BLE_Thread_1_C768388")
        thread2 = threading.Thread(target=ble_thread1.run, name="BLE_Thread_2_C768388")
        thread1.start()
        time.sleep(2)
        thread2.start()
        thread1.join()
        thread2.join()

        logger().info(f"Notification count with {ble_client_address}: {ble_thread.notification_count}")

        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address1)
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

        # Set role and opcode based on expected PDU length
        if expected_pdu_length == 233:
            role = "* C"
            opcode = "* ATT_HANDLE_VALUE_NTF"
        else:
            role = "C"
            opcode = "ATT_HANDLE_VALUE_NTF"

        assert len(sniffer_data_df.loc[(sniffer_data_df['Role'] == role) & (
                sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                               sniffer_data_df['Opcode'] == opcode) & (
                                               sniffer_data_df['+PDU Length (L2CAP)'] == expected_pdu_length)]) >= int(
            ble_thread.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[(sniffer_data_df['Role'] == role) & (
                sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                                               sniffer_data_df['Opcode'] == opcode) & (
                                               sniffer_data_df['+PDU Length (L2CAP)'] == expected_pdu_length)]) >= int(
            ble_thread1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
    except Exception as e:
        logger().error(f"Error in BLEThread: {e}")
        raise e
    finally:
        logger().info("Start Cleanup")
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        time.sleep(10)
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address1)
        time.sleep(10)

        state = ble_dut.interfaces.wifi.ble_get_device_state()
        logger().info(f"DUT state after disconnect to ref: {int(state)}  ")

        logger().info(f"Removing services on dut")
        ble_dut.interfaces.wifi.ble_remove_service()
        remote_devices = [remote_wiseconnect3, remote_wiseconnect3s[0]]
        try:
            for remote_device in remote_devices:
                logger().info("\n\n Stopping Advertisement \n\n")
                remote_device.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0)
            time.sleep(10)
        except Exception as e:
            logger().info(f"Got Exception : {str(e)}")


@pytest.mark.parametrize(
    "test_case_id, pri_adv_phy, sec_adv_phy, service_uuid, char_uuid, notify_time, data_size, expected_pdu_length",
    [
        ("C768391", 1, 1, 0xAABB, 0x1bb1, 300, 20, 23),
        ("C768392", 1, 2, 0xAABB, 0x1bb1, 300, 20, 23),
        ("C768393", 3, 3, 0xAABB, 0x1bb1, 300, 20, 23),
        ("C768403", 1, 1, 0xAABB, 0x1bb1, 300, 230, 233),
        ("C768404", 1, 2, 0xAABB, 0x1bb1, 300, 230, 233),
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
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_Indications(
        remote_wiseconnect3, remote_wiseconnect3s, ble_dut, ble_sniffer, sl_collections, pri_adv_phy, sec_adv_phy,
        test_case_id, service_uuid, char_uuid, notify_time, data_size, expected_pdu_length):
    try:
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"test_{test_case_id}_sniffer_capture")
        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        ble_client_address1 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)

        logger().info(f"dut_ble_addr:{ble_dut_address}")
        logger().info(f"remote_device1_addr:{ble_client_address}")
        logger().info(f"remote_device2_addr:{ble_client_address1}")
        logger().info("Creating health thermometer gatt service in DUT")
        ble_dut.interfaces.wifi.ble_add_service(uid=service_uuid)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=char_uuid)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=char_uuid)

        ble_thread = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3,
                               ble_sniffer=ble_sniffer, ble_client_address=ble_client_address,
                               ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                               notify_time=notify_time, data_size=data_size, service_uuid=service_uuid,
                               char_uuid=char_uuid, operation_mode="indication", powersave_flag=True)

        ble_thread.start_advertising()
        ble_thread.start_scanning()
        link_key1 = ble_thread.connect_devices()
        ble_thread.perform_gatt_operations()

        ble_thread1 = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3s[0],
                                ble_sniffer=ble_sniffer, ble_client_address=ble_client_address1,
                                ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                                notify_time=notify_time, data_size=data_size, service_uuid=service_uuid,
                                char_uuid=char_uuid, operation_mode="indication", powersave_flag=False)
        ble_thread1.start_advertising()
        ble_thread1.start_scanning()
        link_key2 = ble_thread1.connect_devices()
        ble_thread1.perform_gatt_operations()

        # Create threads with unique names for better debugging
        thread1 = threading.Thread(target=ble_thread.run, name=f"BLE_Thread_1_{ble_client_address}")
        thread2 = threading.Thread(target=ble_thread1.run, name=f"BLE_Thread_2_{ble_client_address1}")

        # Start threads with delay to prevent concurrent buffer allocation
        thread1.start()
        time.sleep(2)
        thread2.start()
        thread1.join()
        thread2.join()

        # Mapping Master and Slave Address for Adding devices for sniffer
        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address1)
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
        logger().info("validating indications sent")
        logger().info(f"Expected PDU length for {data_size} bytes: {expected_pdu_length}")

        # Set role and opcode based on expected PDU length for indications
        if expected_pdu_length == 233:
            role = "* C"
            opcode = "* ATT_HANDLE_VALUE_IND"
        else:
            role = "C"
            opcode = "ATT_HANDLE_VALUE_IND"

        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == role) & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == opcode) & (
                               sniffer_data_df['+PDU Length (L2CAP)'] == expected_pdu_length)]) >= int(
            ble_thread.notification_count / 2), f"No {opcode} packets with PDU length {expected_pdu_length} are present"
        logger().info(f"{opcode} packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == role) & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == opcode) & (
                               sniffer_data_df['+PDU Length (L2CAP)'] == expected_pdu_length)]) >= int(
            ble_thread1.notification_count / 2), f"No {opcode} packets with PDU length {expected_pdu_length} are present"
        logger().info(f"{opcode} packets are sent successfully")
    except Exception as e:
        logger().error(f"Error in BLEThread: {e}")
        raise e
    finally:
        logger().info("Start Cleanup")
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        time.sleep(10)

        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address1)
        time.sleep(10)

        state = ble_dut.interfaces.wifi.ble_get_device_state()
        logger().info(f"DUT state after disconnect to ref: {int(state)} ")

        logger().info("Removing services on dut")
        ble_dut.interfaces.wifi.ble_remove_service()
        remote_devices = [remote_wiseconnect3, remote_wiseconnect3s[0]]
        try:
            for remote_device in remote_devices:
                logger().info("\n\n Stopping Advertisement\n\n")
                remote_device.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0)
            time.sleep(10)
        except Exception as e:
            logger().info(f"Got Exception : {str(e)}")

@pytest.mark.parametrize(
    "test_case_id, pri_adv_phy, sec_adv_phy, data_size, notification_count, expected_pdu_length, service_uuid, char_uuid",
    [
        ("C768418", 1, 1, 20, 20, 23, 0xAABB, 0x1AA1),
        ("C768420", 3, 3, 20, 20, 23, 0xAABB, 0x1AA1),
        ("C768421", 1, 1, 230, 20, 233, 0xAABB, 0x1AA1),
        ("C768422", 1, 2, 230, 20, 233, 0xAABB, 0x1AA1),
        ("C768423", 3, 3, 230, 20, 233, 0xAABB, 0x1AA1),
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
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS_AE | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_ENABLE_ADV_EXTN | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_AE_MAX_ADV_SETS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS_AE | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV | Si91xBLEFeatureBitMap.BLECustomFeatureBitmapValid | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.Default | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 4, "stack_len": 2048, "priority": 8},
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
            "ble": {"count": 4, "stack_len": 2048, "priority": 8},
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
                "ble": {"count": 4, "stack_len": 2048, "priority": 8},
            }
        },
    }
)
@pytest.mark.ble_sniffer("frontline_sniffer")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bidirectional_tx_rx_notification(
        remote_wiseconnect3, remote_wiseconnect3s, ble_dut,
        ble_sniffer, sl_collections, pri_adv_phy, sec_adv_phy,
        test_case_id, data_size, notification_count, expected_pdu_length,
        service_uuid, char_uuid):
    try:
        logger().info("Initializing BLE sniffer...")
        ble_sniffer.interfaces.sniffer.init_sniffer()
        ble_sniffer.interfaces.sniffer.start_capture(capture_file=f"test_{test_case_id}_sniffer_capture")

        ble_dut_address = ble_dut.interfaces.bluetooth.ble_gatt_start(set_smp=1)
        ble_client_address = remote_wiseconnect3.interfaces.wifi.ble_gatt_start(set_smp=0)
        ble_client_address1 = remote_wiseconnect3s[0].interfaces.wifi.ble_gatt_start(set_smp=0)

        # Use parameterized notification counts for each thread
        notification_count_thread1 = notification_count
        notification_count_thread2 = notification_count

        dut_state = ble_dut.interfaces.wifi.ble_get_device_state()
        logger().info(f"dut state before test start:{dut_state}")

        logger().info(f"dut_ble_addr:{ble_dut_address}")
        logger().info(f"remote_device1_addr:{ble_client_address}")
        logger().info(f"remote_device2_addr:{ble_client_address1}")

        logger().info("Creating custom service in DUT for TX notifications")
        ble_dut.interfaces.wifi.ble_add_service(uid=service_uuid)
        ble_dut.interfaces.wifi.ble_add_char_serv_att(uid=char_uuid)
        ble_dut.interfaces.wifi.ble_add_char_val_att(uid=char_uuid)

        logger().info("Creating custom service service on remote_wiseconnect3 for RX notifications")
        remote_wiseconnect3.interfaces.wifi.ble_add_service(uid=service_uuid)  # Heart Rate Service
        remote_wiseconnect3.interfaces.wifi.ble_add_char_serv_att(uid=char_uuid)  # Heart Rate Measurement
        remote_wiseconnect3.interfaces.wifi.ble_add_char_val_att(uid=char_uuid)

        logger().info("Creating custom service  on remote_wiseconnect3s[0] for RX notifications")
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_service(uid=service_uuid)  # Heart Rate Service
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_serv_att(uid=char_uuid)  # Heart Rate Measurement
        remote_wiseconnect3s[0].interfaces.wifi.ble_add_char_val_att(uid=char_uuid)

        ble_thread = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3,
                               ble_sniffer=ble_sniffer, ble_client_address=ble_client_address,
                               ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                               notification_count=notification_count_thread1, data_size=data_size,
                               service_uuid=service_uuid, char_uuid=char_uuid,
                               operation_mode="notification", powersave_flag=True)

        ble_thread1 = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3s[0],
                                ble_sniffer=ble_sniffer, ble_client_address=ble_client_address1,
                                ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                                notification_count=notification_count_thread2, data_size=data_size,
                                service_uuid=service_uuid, char_uuid=char_uuid,
                                operation_mode="notification", powersave_flag=False)

        logger().info("Starting advertising and scanning for first TX connection...")
        ble_thread.start_advertising()
        ble_thread.start_scanning()
        link_key1 = ble_thread.connect_devices()

        ble_thread.perform_gatt_operations()

        logger().info("Starting advertising and scanning for second TX connection...")
        ble_thread1.start_advertising()
        ble_thread1.start_scanning()
        link_key2 = ble_thread1.connect_devices()
        ble_thread1.perform_gatt_operations()

        ble_thread_rx1 = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3,
                                   ble_sniffer=ble_sniffer, ble_client_address=ble_client_address,
                                   ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy, sec_adv_phy=sec_adv_phy,
                                   notification_count=notification_count_thread1, data_size=data_size,
                                   service_uuid=service_uuid, char_uuid=char_uuid,
                                   operation_mode="rx_notification", powersave_flag=False)

        ble_thread_rx2 = BLEThread(sl_collections, ble_dut=ble_dut, remote_device=remote_wiseconnect3s[0],
                                   ble_sniffer=ble_sniffer, ble_client_address=ble_client_address1,
                                   ble_dut_address=ble_dut_address, pri_adv_phy=pri_adv_phy,
                                   sec_adv_phy=sec_adv_phy,
                                   notification_count=notification_count_thread2, data_size=data_size,
                                   service_uuid=service_uuid, char_uuid=char_uuid,
                                   operation_mode="rx_notification", powersave_flag=False)

        logger().info("Setting up RX thread handles using existing connections...")
        ble_thread_rx1.write_handle = ble_thread.write_handle
        ble_thread_rx2.write_handle = ble_thread1.write_handle
        logger().info("Starting bidirectional notification threads...")
        # Start all threads in parallel for true bidirectional communication
        thread_tx1 = threading.Thread(target=ble_thread.run, name="TX-Thread-1")
        thread_tx2 = threading.Thread(target=ble_thread1.run, name="TX-Thread-2")
        thread_rx1 = threading.Thread(target=ble_thread_rx1.run, name="RX-Thread-1")
        thread_rx2 = threading.Thread(target=ble_thread_rx2.run, name="RX-Thread-2")
        logger().info("Starting all bidirectional threads simultaneously...")
        # Start all TX threads first to establish notification paths
        logger().info("Starting TX threads simultaneously...")
        thread_tx1.start()
        thread_tx2.start()
        time.sleep(3)

        # Start all RX threads simultaneously for true bidirectional communication
        logger().info("Starting RX threads simultaneously...")
        thread_rx1.start()
        thread_rx2.start()
        time.sleep(3)

        # Wait for all threads to complete
        completion_start = time.time()

        thread_tx1.join()

        thread_tx2.join()

        thread_rx1.join()

        thread_rx2.join()

        # Check for thread exceptions and re-raise them
        ble_thread.check_thread_exception()
        ble_thread1.check_thread_exception()
        ble_thread_rx1.check_thread_exception()
        ble_thread_rx2.check_thread_exception()
        logger().info("All bidirectional notification threads completed")

        ble_dut_address_hex = re.split(":", ble_dut_address)
        ble_client_address_hex1 = re.split(":", ble_client_address)
        ble_client_address_hex2 = re.split(":", ble_client_address1)
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

        # Set role and opcode based on expected PDU length
        if expected_pdu_length == 233:
            role = "* C"
            opcode = "* ATT_HANDLE_VALUE_NTF"
        else:
            role = "C"
            opcode = "ATT_HANDLE_VALUE_NTF"

        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == role) & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == opcode) & (
                               sniffer_data_df['+PDU Length (L2CAP)'] == expected_pdu_length)]) >= int(
            ble_thread.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")
        assert len(sniffer_data_df.loc[
                       (sniffer_data_df['Role'] == role) & (
                               sniffer_data_df['+BD Address (LE PKT)'] == f"0x{ble_dut_address.lower()}") & (
                               sniffer_data_df['Opcode'] == opcode) & (
                               sniffer_data_df['+PDU Length (L2CAP)'] == expected_pdu_length)]) >= int(
            ble_thread1.notification_count / 2), "No ATT_HANDLE_VALUE_NTF packets are present"
        logger().info("ATT_HANDLE_VALUE_NTF packets are sent successfully")

        logger().info("Bidirectional notification test completed successfully!")
    except Exception as e:
        logger().error(f"Error in bidirectional BLE notification test: {e}")
        raise e
    finally:
        logger().info("Starting cleanup for bidirectional notification test...")

        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        time.sleep(10)
        ble_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address1)
        time.sleep(10)

        state = ble_dut.interfaces.wifi.ble_get_device_state()
        logger().info(f"DUT state after disconnect to ref: {int(state)} ")

        logger().info("Removing services on dut")
        ble_dut.interfaces.wifi.ble_remove_service()
        remote_devices = [remote_wiseconnect3, remote_wiseconnect3s[0]]
        try:
            for remote_device in remote_devices:
                logger().info("\n\n Stopping Advertisement  \n\n")
                remote_device.interfaces.wifi.ble_start_ae_advertising(enable=0, no_of_sets=1, adv_handle=0)
            time.sleep(10)
        except Exception as e:
            logger().info(f"Got Exception : {str(e)}")