# Standard library imports for test framework, timing, and data manipulation
import pytest  # Testing framework for test case organization and execution
import time    # Time utilities for delays and timing operations
import string  # String manipulation utilities for generating random data

# Si91x device configuration imports - defines various operating modes and feature bitmaps
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,          # Device operating mode configurations
    Si91xCoexMode,               # WiFi/BLE coexistence mode settings
    Si91xFeatureBitMap,          # Main feature bitmap configurations
    Si91xTCPIPFeatureBitMap,     # TCP/IP stack feature configurations
    Si91xCustomFeatureBitMap,    # Custom feature bitmap settings
    Si91xExtCustomFeatureBitMap, # Extended custom feature configurations
    Si91xBTFeatureBitMap,        # Bluetooth feature bitmap settings
    Si91xExtTCPIPFeatureBitMap,  # Extended TCP/IP feature configurations
    Si91xBLEFeatureBitMap,       # BLE specific feature bitmap settings
    Si91xBLECustomFeatureBitMap, # Custom BLE feature configurations
    Si91xConfigFeatureBitMap,    # Device configuration feature settings
    Si91xRegion,                 # Regional configuration settings
    Si91xRegionCode,             # Region code definitions
    Si91xModuleType,             # Module type specifications
    Si91xPowerSaveModes,         # Power saving mode configurations
    Si91xPowerSaveProcedureTypes,# Power save procedure type settings
    Si91xMqttQos,                # MQTT Quality of Service settings
    Si91xMdnsParams              # mDNS (multicast DNS) parameter settings
)

# Test interface and utility imports for WiFi, BLE, and networking operations
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers   # Async event handling
from utf.interfaces.iperf.iperf_constants import IperfConstants                               # iPerf benchmarking constants
from utf.utils.logger import get_logger                                                       # Logging utility functions
from utf.utils.iperf.iperf_utils import ping                                                  # Network ping utilities
from utf_wiseconnect_3.tests.sl_status import SLStatus                                        # Status code definitions
from utf.utils.thread_base import ThreadBase                                                  # Base class for threading
from utf.utf_config import UtfConfig                                                          # UTF configuration management

# Bluetooth GATT service imports for BLE testing functionality
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import (
    HeartRateService,                    # Heart rate GATT service implementation
    BodySensorLocationCharacteristic,    # Body sensor location characteristic
    HeartRateMeasurementCharacterstic   # Heart rate measurement characteristic
)

# Timing and measurement utilities for performance testing
from utf.utils.stopwatch import Stopwatch           # Stopwatch for timing measurements
from utf.utils.time_measurer import TimeMeasurer    # Advanced time measurement utilities

# Additional standard library imports for pattern matching and network operations
import re         # Regular expression pattern matching utilities
import ipaddress  # IPv4/IPv6 address manipulation and validation
import random     # Random number and data generation utilities
import string     # Additional string manipulation utilities

"""The testcases added in this file run below test steps for SOC
        1. Configure the DUT in wlan coex mode for 2.4Ghz
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Do BLE Advertise/Scan/Connection/Tx/Rx
        6. Verify the MDNS feature
    setup requirement:
        1. SOC
        2. NUC
        3. Raspberry PI
        4. Access Point(Third Party AP's)

    Author: Hari Bhargav Nalla

"""

def logger():
    """
    Get logger instance for this module
    Returns: Logger object configured for this test module
    """
    return get_logger(__name__)


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr


def cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections):
    """
    Common cleanup function for BLE client connections and objects
    Provides robust cleanup of BLE resources to prevent connection leaks
    
    Args:
        ble_client: BLE client interface object (Raspberry Pi BLE)
        ble_obj: BLE thread functionality object containing connection details
        wifi_dut: WiFi DUT interface for BLE cleanup operations
        sl_collections: Collections object with cleanup utilities
    """
    logger().info("Finally - Cleaning up BLE client and objects")
    
    # Close the BLE interface of Raspberry Pi (remote BLE device)
    if ble_client:
        try:
            # Gracefully close the BLE client connection
            ble_client.interfaces.bluetooth.close()
        except Exception as e:
            # Log warning but continue cleanup if BLE client close fails
            logger().warning(f"Error closing BLE client: {e}")
    
    # Clean up BLE objects and device connections
    if ble_obj:
        try:
            # Clean up BLE device connections and remove paired devices
            if hasattr(ble_obj, 'ble_dut_address') and ble_obj.ble_dut_address:
                # Remove the DUT device from the BLE client's paired devices list
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            
            # Use the standardized BLE cleanup function to handle all cleanup operations
            sl_collections.cleanup_ble(
                ble_dut=wifi_dut,                                                    # WiFi DUT with BLE capabilities
                ble_client=ble_client,                                              # Remote BLE client device
                ble_client_address=getattr(ble_obj, 'ble_client_address', None),    # Client's BLE address
                ble_dut_address=getattr(ble_obj, 'ble_dut_address', None)          # DUT's BLE address
            )
        except Exception as e:
            # Log warning but continue if BLE cleanup fails to prevent test hanging
            logger().warning(f"Error during BLE cleanup: {e}")


# BLE Thread Functionality Class - Handles BLE operations in WiFi+BLE coexistence scenarios
# This thread is used for STA+BLE functionality where the DUT acts as a BLE slave device
class BleThreadFunctionality(ThreadBase):
    """
    Thread-based class for managing BLE functionality in WiFi/BLE coexistence tests
    Supports various BLE operations: advertising, scanning, connections, GATT operations
    """
    
    def __init__(
            self,
            wifi_dut=None,              # WiFi DUT device with BLE capabilities
            ble_client=None,            # Remote BLE client (typically Raspberry Pi)
            ble_test_type=None,         # Type of BLE test to perform (scan, advertise, connect, etc.)
            sl_collections=None,        # Test collections and utilities object
            ble_scan_type=1,            # BLE scan type (1=active, 0=passive)
            ble_pairing=0,              # Enable/disable BLE pairing (0=no pairing, 1=pairing)
            dev_state=8,                # Expected BLE device state after connection
            gatt=False,                 # Enable/disable GATT services
            service_class=None,         # BLE service class specifications
            conn_interval=200,          # BLE connection interval in milliseconds
            scan_interval=None,         # BLE scan interval in 0.625ms units
            scan_window=None,           # BLE scan window in 0.625ms units
            adv_int_min=1704,           # Minimum advertising interval in 0.625ms units
            adv_int_max=1704,           # Maximum advertising interval in 0.625ms units
            char_path=None,             # GATT characteristic path for operations
            char_uid=None,              # GATT characteristic UUID
            data=None,                  # Data payload for GATT operations
            data_length=20,             # Length of data for GATT operations
            data_duration=60,           # Duration for data transfer operations
            periodic_delay=1,           # Delay between periodic operations
            service_uid=None,           # GATT service UUID
            address=None,               # Memory address for data operations
            service_uuid=None,          # Service UUID for GATT operations
            char_uuid=None,             # Characteristic UUID for GATT operations
            characteristic=None,        # Characteristic object for GATT operations
            bond_info=0                 # Bonding information for secure connections
    ):
        # Initialize the parent ThreadBase class
        super().__init__()
        
        # Core device and test configuration
        self.wifi_dut = wifi_dut                    # WiFi DUT with BLE coexistence capability
        self.ble_client = ble_client                # Remote BLE client device interface
        self.ble_test_type = ble_test_type          # Specific BLE test operation to perform
        self.sl_collections = sl_collections        # Test utility collections object
        
        # BLE scanning and connection parameters
        self.ble_scan_type = ble_scan_type          # Active (1) or passive (0) scanning
        self.ble_pairing = ble_pairing              # Pairing enabled (1) or disabled (0)
        self.dev_state = dev_state                  # Expected device state after connection
        self.gatt = gatt                            # GATT services enabled flag
        self.conn_interval = conn_interval          # Connection interval for stable connection
        self.service_class = service_class          # BLE service class definitions
        
        # BLE timing parameters (all in 0.625ms units per BLE specification)
        self.scan_interval = scan_interval          # Time between scan attempts
        self.scan_window = scan_window              # Active scanning duration per interval
        self.adv_int_min = adv_int_min             # Minimum advertising interval
        self.adv_int_max = adv_int_max             # Maximum advertising interval
        
        # GATT service and characteristic parameters
        self.service_uid = service_uid              # Service UUID for GATT operations
        self.char_path = char_path                  # D-Bus path to characteristic
        self.char_uid = char_uid                    # Characteristic UUID
        self.data = data                            # Data payload for read/write operations
        self.data_length = data_length              # Expected data length
        self.data_duration = data_duration          # Duration for data transfer tests
        self.periodic_delay = periodic_delay        # Delay between periodic operations
        self.address = address                      # Memory address for data storage
        self.service_uuid = service_uuid            # Service UUID for discovery
        self.char_uuid = char_uuid                  # Characteristic UUID for operations
        self.characteristic = characteristic        # Characteristic class object
        self.bond_info = bond_info                  # Bonding information for security
        
        # Initialize connection addresses to None - will be populated during execution
        self.ble_dut_address = None                 # DUT's BLE MAC address
        self.ble_client_address = None              # Client's BLE MAC address  
        self.write_handle = None                    # GATT write handle for operations

        # Set up DUT for BLE advertising and get its Bluetooth address
        logger().info("Starting BLE GATT service initialization on DUT")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=self.ble_pairing,      # Set Security Manager Protocol for pairing
            bond_info=self.bond_info       # Configure bonding information
        )
        # Verify that we successfully obtained the DUT's Bluetooth address
        assert self.ble_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f"DUT Bluetooth address obtained: {self.ble_dut_address}")
        
        # Allow time for BLE initialization to complete
        time.sleep(5)

    def stop_adv_scan(self):
        """
        Stop advertising on DUT and scanning on remote device
        Used when DUT is advertising and remote device is scanning
        """
        logger().info("Initiating stop advertise from DUT")
        # Stop BLE advertising on the WiFi DUT
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        
        logger().info("Initiating stop scan from Remote device")
        # Stop BLE scanning on the remote client device
        self.ble_client.interfaces.bluetooth.stop_scanning()
        # Close the BLE interface on the remote client
        self.ble_client.interfaces.bluetooth.close()

    def stop_scan_adv(self):
        """
        Stop scanning on DUT and advertising on remote device
        Used when DUT is scanning and remote device is advertising
        """
        logger().info("Initiating stop scan from DUT")
        # Stop BLE scanning on the WiFi DUT
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        
        logger().info("Initiating stop advertise from Remote device")
        # Stop BLE advertising on the remote client device
        self.ble_client.interfaces.bluetooth.stop_advertising()
        # Close the BLE interface on the remote client
        self.ble_client.interfaces.bluetooth.close()

    def check_scan_functionality_dut(self):
        """
        Check BLE scan functionality where DUT scans for remote devices
        Verifies that the DUT can successfully scan and detect BLE devices
        
        Returns:
            Updates self.ble_client_address with the discovered client's BLE address
        """
        # Use collections utility to perform comprehensive BLE scan test
        self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut,                 # WiFi DUT performing the scan
            ble_client=self.ble_client,             # Remote BLE client to be discovered
            ble_address=self.ble_dut_address,       # DUT's own BLE address
            ble_scan_type=self.ble_scan_type,       # Active (1) or passive (0) scanning
            timeout=60,                             # Scan timeout in seconds
            services=self.service_class             # Expected service classes to discover
        )

    def add_service(self, service_uuid):
        """
        Add a custom GATT service to the DUT
        
        Args:
            service_uuid (int): UUID of the service to add (as integer)
        """
        logger().info(f"***** Configuring BLE GATT service {hex(service_uuid)} in DUT *****")
        # Add the specified service UUID to the DUT's GATT service table
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=hex(service_uuid))

    def ble_disconnect(self, disconnect_from="remote"):
        """
        Disconnect BLE connection from either remote device or DUT
        
        Args:
            disconnect_from (str): "remote" to disconnect from client side, "dut" from DUT side
        """
        logger().info("Checking connection status of BLE")
        # Get current BLE device state from the DUT
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        # Convert state to integer for comparison (handle non-numeric states gracefully)
        state_int = int(state) if state.isdigit() else -1
        # Verify that the device is in the expected connected state
        assert state_int == self.dev_state, "DUT BLE device is not in connected state"

        # Initiate disconnection from the specified side
        if disconnect_from == "remote":
            logger().info("Initiating BLE disconnection from Raspberry Pi (remote)")
            # Disconnect from the remote client side
            self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)
        else:
            logger().info("Initiating BLE disconnection from DUT side")
            # Disconnect from the DUT side
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.ble_client_address)
        
        # Close the BLE interface on the remote client
        self.ble_client.interfaces.bluetooth.close()

    def connect_from_dut(self):
        """
        Establish BLE connection from DUT to remote client (DUT as master)
        Uses the collections utility for robust connection establishment
        """
        # Use standardized BLE connection function with retry mechanism
        self.sl_collections.connect_ble(
            wifi_dut=self.wifi_dut,                     # WiFi DUT with BLE capability
            ble_client=self.ble_client,                 # Remote BLE client device
            ble_client_address=self.ble_client_address, # Client's BLE address
            mode="master",                              # DUT acts as BLE master
            retries=3,                                  # Number of connection retry attempts
            ble_pairing=self.ble_pairing,               # Pairing configuration
            dev_state=self.dev_state,                   # Expected connected state
            max_conn_interval=self.conn_interval,       # Maximum connection interval
            min_conn_interval=self.conn_interval,       # Minimum connection interval
            timeout=30                                  # Connection timeout in seconds
        )

    def ble_connect(self, role="master"):
        """
        Establish BLE connection with specified role (master or slave)
        
        Args:
            role (str): "master" for DUT as master, "slave" for DUT as slave
        """
        if role == "master":
            # DUT acts as BLE master - scan for and connect to remote device
            self.check_scan_functionality()                        # Scan for remote devices
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()      # Stop scanning once found
            self.wifi_dut.interfaces.wifi.ble_advertising = False  # Disable advertising
            self.connect_from_dut()                                # Connect as master

        else:
            # DUT acts as BLE slave - advertise and wait for remote connection
            logger().info("Starting DUT BLE advertising for slave role")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()  # Start advertising
            time.sleep(5)                                          # Wait for advertising to stabilize
            self.scan_and_connect_from_remote()                    # Remote scans and connects

    def fetch_profiles(self):
        """
        Discover and fetch GATT profiles from the remote BLE device
        Specifically looks for HeartRateService and gets write handles for characteristics
        """
        # Get all available service UUIDs from the remote device
        uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=self.ble_client_address)
        # Verify that the Heart Rate Service is available on the remote device
        assert HeartRateService.UUID.lower() in uuids, "Unable to get HeartRateService profile of Remote Device from DUT"

        logger().info(" ******************** Resolving Profile ********************")
        # Get the start and end handles for the Heart Rate Service
        start_handle, end_handle, data = self.wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=self.ble_client_address,     # Remote device address
            uuid=int(HeartRateService.UUID, 16)                 # Heart Rate Service UUID as integer
        )
        # Verify that we successfully got the service handle range
        assert start_handle is not None, "Failed to fetch the start handle for Heart Rate Service"
        assert end_handle is not None, "Failed to fetch the end handle for Heart Rate Service"

        # Discover all characteristics within the Heart Rate Service handle range
        char_uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(
            ble_remote_dev_address=self.ble_client_address,     # Remote device address
            start_handle=int(start_handle, 16),                 # Service start handle
            end_handle=int(end_handle, 16),                     # Service end handle
            async_timeout=60                                    # Discovery timeout
        )
        # Log discovered characteristics information for debugging
        logger().info(
            f"Discovered characteristics - UUIDs: {char_uuids}, "
            f"Write handles: {write_handles}, Properties: {char_properties}"
        )

        # Find the Heart Rate Measurement characteristic specifically
        assert HeartRateMeasurementCharacterstic.HR_Measure_UUID in char_uuids, \
            f"Unable to find {HeartRateMeasurementCharacterstic.HR_Measure_UUID} UUID in discovered characteristics"
        
        # Get the index of the Heart Rate Measurement characteristic
        index = char_uuids.index(HeartRateMeasurementCharacterstic.HR_Measure_UUID)
        logger().info(f"Heart Rate Measurement characteristic found at index: {index}")
        logger().info(f"All discovered UUIDs: {char_uuids}")
        logger().info(f"All write handles: {write_handles}")
        
        # Verify that the characteristic property is valid
        assert char_properties[index].isdigit(), "Characteristic property found is not a valid integer"
        
        # Store the write handle for the Heart Rate Measurement characteristic
        self.write_handle = int(write_handles[index], 16)
        logger().info(f"Heart Rate Measurement write handle: {self.write_handle}")
        assert self.write_handle > 0, "Unable to get valid write handle for Heart Rate Service"

    def enable_notifications(self):
        """
        Enable BLE notifications on the DUT and receive data from remote device
        Monitors for GATT write events and collects notification data
        """
        # Only proceed if we have a valid write handle from service discovery
        if self.write_handle:
            logger().info("Enabling notifications on DUT for Heart Rate Measurement")
            # Enable notifications by writing to the Client Characteristic Configuration Descriptor
            # (write_handle + 1) is the standard location for CCCD
            self.wifi_dut.interfaces.wifi.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address,     # Remote device sending notifications
                handle=(self.write_handle + 1),                     # CCCD handle
                enable_notify=1                                     # Enable notifications
            )
            # Wait for notification setup to complete
            time.sleep(10)

            # Start monitoring for incoming notifications
            tw = Stopwatch()                    # Timer for monitoring duration
            Data_received_on_dut = []          # List to store received notification data
            
            # Monitor for notifications for 60 seconds
            while tw.elapsed_sec < 60:
                # Get any pending asynchronous events from the DUT
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                
                # Process each event looking for GATT write events (notifications)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        # Check if this is a GATT write event containing notification data
                        if "rsi_ble_on_gatt_write_event_gatt" in event.event_data:
                            # Extract the notification data using regex
                            received_data = re.findall(r"att_length: 1, att_value: (.*)", event.event_data)
                            # Accumulate all received notification data
                            Data_received_on_dut = received_data + Data_received_on_dut
                            # Convert the first byte to its ASCII value for logging
                            received_data = ord(received_data[0])
                            logger().info(f"Notification data received: {received_data}")
            
            # Verify that we actually received notification data
            assert len(Data_received_on_dut) > 0, "No notifications received on DUT during monitoring period"
            
            # Disable notifications after testing is complete
            self.wifi_dut.interfaces.wifi.ble_set_att_value(
                ble_remote_dev_address=self.ble_client_address,
                handle=(self.write_handle + 1), 
                enable_notify=0  # Disable notifications
            )

    def configure_buffer_mode(self, mode=None, count=None):
        """
        Configure BLE response and notification buffer settings on the DUT
        
        Args:
            mode (int): Buffer mode configuration
            count (int): Number of buffers to allocate
        """
        logger().info(f"******* Configuring Buffer Mode: {mode} and Buffer count: {count} *******")
        # Set the buffer configuration for BLE responses and notifications
        self.wifi_dut.interfaces.wifi.ble_set_resp_notify_buffer(
            ble_remote_dev_address=self.ble_client_address,     # Target remote device
            buffer_mode=mode,                                   # Buffer mode setting
            buffer_count=count                                  # Number of buffers
        )
        logger().info(f"******* Buffer Mode: {mode} and Buffer count: {count} configured successfully *******")

    def service_discovery_on_remote(self):
        """
        Perform GATT service discovery on the remote device to find characteristic paths
        Updates self.char_path with the discovered characteristic path
        """
        # Use collections utility to discover services on the remote BLE client
        self.char_path = self.sl_collections.service_discovery_on_remote(
            self.ble_client,                # Remote BLE client device
            service_uid=self.service_uid,   # Target service UUID
            char_uid=self.char_uid         # Target characteristic UUID
        )
        logger().info(f"Discovered characteristic path on remote device: {self.char_path}")

    def service_discovery_on_dut(self):
        """
        Perform GATT service discovery on the DUT to find characteristic handles
        Updates self.write_handle with the discovered characteristic handle
        """
        # Use collections utility to discover services and get write handle from DUT
        self.write_handle = self.sl_collections.service_discovery_on_dut(
            ble_dut=self.wifi_dut,                      # WiFi DUT with BLE capability
            ble_client_address=self.ble_client_address, # Remote client address
            service_uuid=self.service_uuid,             # Target service UUID
            char_uuid=self.char_uuid,                   # Target characteristic UUID
            characteristic=self.characteristic          # Characteristic class object
        )

    def enable_notifications_on_dut(self):
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

    def enable_notifications_remote(self):

        if self.write_handle:
            logger().info(f"Enabling notification on dut")
            self.wifi_dut.interfaces.wifi.ble_set_att_value(ble_remote_dev_address=self.ble_client_address,
                                                            handle=(self.write_handle + 1), enable_notify=1)

            tw = Stopwatch()
            Data_received_on_dut = []
            while tw.elapsed_sec < self.data_duration:
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

    def advertise_remote_device(self):
        self.ble_client_address = self.sl_collections.advertise_remote_device(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
        )

    def advertise_dut(self):
        logger().info(f"Advertising the DUT")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

    def scan_and_connect_from_remote(self):
        self.ble_client_address = self.sl_collections.scan_and_connect_from_remote(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            ble_pairing=self.ble_pairing,
            dev_state=self.dev_state,
            services=self.service_class,
            max_conn_interval=self.conn_interval,
            min_conn_interval=self.conn_interval
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

    def check_scan_functionality(self):
        self.ble_client_address = self.sl_collections.check_ble_scan_functionality(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_address=self.ble_dut_address,
            ble_scan_type=1,
            ble_scan_interval=self.scan_interval,
            ble_scan_window=self.scan_window,
            timeout=60,
            services=self.service_class,
            remote_adv_int_min="0x40 0x01", remote_adv_int_max="0x40 0x01"
        )

    def run(self):
        """
        Main execution method for BLE thread functionality
        Executes different BLE operations based on the configured test type
        """
        # BLE Advertising Test - DUT advertises and remote device scans
        if self.ble_test_type == "advertise":
            # Test BLE advertising functionality with specified intervals
            self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(
                wifi_dut=self.wifi_dut,                         # WiFi DUT with BLE capability
                ble_client=self.ble_client,                     # Remote BLE client device
                ble_dut_address=self.ble_dut_address,           # DUT's BLE address
                ble_adv_int_min=self.adv_int_min,              # Minimum advertising interval
                ble_adv_int_max=self.adv_int_max,              # Maximum advertising interval
                timeout=20,                                     # Advertising test timeout
            )

        # BLE Scanning Test - DUT scans for remote devices
        if self.ble_test_type == "scan":
            # Execute BLE scanning functionality test
            self.check_scan_functionality()

        # BLE Start/Stop Scan Test - Test scan control operations
        if self.ble_test_type == "start_scan_stop_scan":
            # Start BLE scanning on the DUT
            self.wifi_dut.interfaces.wifi.ble_start_scanning(
                ble_client_address=self.ble_client_address,     # Client address to scan for
                timeout=60                                      # Scan timeout in seconds
            )
            logger().info("Remote device found in scan results - BLE scanning is successful")
            
            # Stop BLE scanning on the DUT
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        # BLE Slave Connection Test - DUT acts as BLE slave
        if self.ble_test_type == "slave":
            # Establish BLE connection with DUT as slave device
            self.ble_connect(role="slave")

        # BLE Master Connection Test - DUT acts as BLE master
        if self.ble_test_type == "master":
            # Establish BLE connection with DUT as master device
            self.ble_connect(role="master")

        # BLE Notifications Test - Basic notification functionality
        if self.ble_test_type == "notifications":
            # Test basic BLE notification reception on DUT
            self.enable_notifications()

        # BLE Notification TX Test - DUT sends notifications to remote
        if self.ble_test_type == "notify_tx":
            # Test BLE notification transmission from DUT to remote device
            self.enable_notifications_on_dut()

        # BLE Notification RX Test - DUT receives notifications from remote
        if self.ble_test_type == "notify_rx":
            # Test BLE notification reception from remote device to DUT
            self.enable_notifications_remote()

        # Remote Device Scan Test - Remote device scans for DUT
        if self.ble_test_type == "scan_from_remote_device":
            # Test scanning functionality from the remote device perspective
            self.ble_client_address = self.sl_collections.scan_from_remote_device(
                wifi_dut=self.wifi_dut,                         # WiFi DUT to be discovered
                ble_client=self.ble_client,                     # Remote BLE client performing scan
                ble_dut_address=self.ble_dut_address,           # DUT's BLE address to find
            )

        # Scan and Connect from DUT Test - DUT scans and connects
        if self.ble_test_type == "scan_and_connect_from_dut":
            # Test complete scan and connection process initiated from DUT
            self.scan_and_connect_from_dut()

        # Scan and Connect from Remote Test - Remote scans and connects
        if self.ble_test_type == "scan_and_connect_from_remote":
            # Test complete scan and connection process initiated from remote device
            self.scan_and_connect_from_remote()


class WifiThreadFunctionality(ThreadBase):
    """
    Thread-based class for managing WiFi functionality in WiFi/BLE coexistence tests
    Handles WiFi operations including mDNS service management and network connectivity
    """
    # Class-level dictionaries to store connection information
    client_info = {"mac_address": None, "ip_address": None}    # Remote client connection info
    dut_info = {"mac_address": None, "ip_address": None}       # DUT connection info

    def __init__(self, 
                 wifi_sniffer=None,         # WiFi packet sniffer for traffic analysis
                 wifi_dut=None,             # WiFi DUT device interface
                 wifi_access_point=None,    # WiFi Access Point for connectivity
                 wifi_client=None,          # WiFi client device interface
                 sl_collections=None,       # Test collections and utilities
                 addr_type="global",        # IPv6 address type (global/link-local)
                 sniffer_filter=None,       # Packet filter for sniffer
                 test_case=None,            # Specific test case ID to execute
                 capture_filename=None,     # Filename for packet capture
                 utf_constants=None,        # UTF test constants
                 power_save=None,           # Power save mode configuration
                 iteration_count=5          # Number of iterations for loop tests
                ):
        # Initialize the parent ThreadBase class
        super().__init__()
        
        # Store all configuration parameters for WiFi testing
        self.wifi_sniffer = wifi_sniffer                # Network packet sniffer interface
        self.wifi_dut = wifi_dut                        # Device Under Test (DUT) interface  
        self.wifi_access_point = wifi_access_point      # Access Point for network connectivity
        self.wifi_client = wifi_client                  # Remote WiFi client device
        self.sl_collections = sl_collections            # Test utility collections object
        self.addr_type = addr_type                      # IPv6 address type configuration
        self.sniffer_filter = sniffer_filter            # Packet filtering rules for sniffer
        
        # Test execution parameters
        self.test_case = test_case                      # Specific test case ID to execute
        self.capture_filename = capture_filename        # Filename for packet capture files
        self.utf_constants = utf_constants              # UTF framework constants
        self.power_save = power_save                    # Power save mode configuration
        self.iteration_count = iteration_count          # Number of test iterations
        
        # Runtime variables initialized during test execution
        self.device_ip = None                           # DUT's assigned IP address
        self.dut_addr = None                            # DUT's address information
        self.iperf_throughput = None                    # iPerf throughput measurements
        self.dut_add_dict = None                        # Dictionary containing DUT address info
        self.remote_ip = None                           # Remote device IP address
        self.ping_count = 5                            # Number of ping attempts for connectivity checks

    def join_to_ap(self):
        """
        Connect the DUT to the WiFi Access Point and configure IPv6 addressing
        Retrieves both DUT and remote client IP addresses for testing
        """
        # Join the DUT to the WiFi network with comprehensive configuration
        self.dut_add_dict = self.sl_collections.join_to_wifi_network(
            wifi_dut=self.wifi_dut,                                 # WiFi DUT to connect
            wifi_access_point=self.wifi_access_point,               # Target Access Point
            associated=self.wifi_dut.interfaces.wifi.associated,    # Current association status
            ip_version='ipv6',                                      # Use IPv6 addressing
            ping_after_power_save=True,                            # Verify connectivity after power save
            ping_before_power_save=True,                           # Verify connectivity before power save
            power_save=self.power_save,                            # Power save mode configuration
            ipv6_type=self.addr_type,                              # IPv6 address type (global/link-local)
            retry_count=3                                          # Number of connection retry attempts
        )
        
        # Log the DUT's network configuration information
        logger().info(
            f"DUT Network Configuration - MAC: {self.dut_add_dict['dut_mac_address']}, "
            f"IPv6: {self.dut_add_dict['device_ip']}"
        )

        # Get the remote WiFi client's IPv6 address for comparison testing
        self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(
            version=6,                      # IPv6 addressing
            addr_type=self.addr_type       # Address type (global/link-local)
        )
        # Convert string IP to IPv6Address object for easier manipulation
        self.remote_ip = ipaddress.ip_address(self.remote_ip)
        logger().info(f"Remote WiFi client IPv6 address: {self.remote_ip}")

        # Store the Access Point's BSSID (MAC address) for reference
        self.dut_add_dict['ap_mac_address'] = self.wifi_access_point.interfaces.wifi.bssid

        # for count in range(0, 2):
        #     logger().info(f"=======>>>>>Pinging the DUT from remote side....")
        #     status = ping(self.dut_add_dict['device_ip'], self.ping_count)
        #     if status:
        #         break
        #     else:
        #         client_interface = self.wifi_client.interfaces.wifi.config["interface"]
        #         logger().info(f"=======>>>>>DUT NOT RESPONDING FOR PING REQUEST......")
        #         logger().info(f"=======>>>>>Disabling the ethernet adaptor at remote side....")
        #         self.wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {client_interface} down")
        #         time.sleep(10)
        #         logger().info(f"=======>>>>>Enabling the ethernet adaptor at remote side....")
        #         self.wifi_client.interfaces.wifi.shell.execute(f"sudo ifconfig {client_interface} up")
        #         self.wifi_client.interfaces.wifi.shell.execute(f"sudo ip6tables -F")
        #         time.sleep(20)
        #
        # assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

    def _execute_mdns_cycle(self, enable_ping_test=False):
        """
        Execute a single mDNS initialization, registration, and deinitialization cycle
        
        Args:
            enable_ping_test (bool): Whether to perform ping test after service registration
        """
        # Initialize mDNS service with IPv6 support on the DUT
        self.wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)
        # Add the network interface to mDNS for service discovery
        self.wifi_dut.interfaces.wifi.mdns_add_interface()
        # Register the mDNS service to make it discoverable on the network
        self.wifi_dut.interfaces.wifi.mdns_register_service()
        # Wait for 5 seconds to allow service registration to complete
        time.sleep(10)
        
        # Perform ping test if requested (for test cases 768355 and 768347)
        if enable_ping_test:
            # Log information about the ping test that's about to start
            logger().info("....Pinging DUT ....")
            # Ping the DUT using its mDNS hostname to verify service discovery works
            status = self.sl_collections.ping("wiseconnect.local", ping_count=10)
            # Assert that the ping was successful, otherwise fail the test
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        
        # Deinitialize mDNS service to clean up resources
        self.wifi_dut.interfaces.wifi.mdns_deinit()
        time.sleep(2)

    def run(self):
        # Main execution method for WiFi thread functionality testing
        try:
            # Define test case groups for different mDNS operation patterns
            iterative_test_cases = {768351, 768342, 768343, 768352}  # Loop-based mDNS testing
            single_shot_test_cases = {768353, 768344}                # Single-shot mDNS testing
            ping_test_cases = {768355, 768347}                       # mDNS testing with ping validation
            
            # Execute iterative mDNS testing for stress testing scenarios
            if self.test_case in iterative_test_cases:
                # Loop through the specified number of iterations for stress testing
                for count in range(self.iteration_count):
                    logger().info(f"Executing mDNS cycle {count + 1} of {self.iteration_count}")
                    self._execute_mdns_cycle(enable_ping_test=False)

            # Execute single-shot mDNS testing for basic functionality validation
            elif self.test_case in single_shot_test_cases:
                logger().info("Executing single mDNS cycle")
                self._execute_mdns_cycle(enable_ping_test=False)

            # Execute mDNS testing with ping validation for connectivity verification
            elif self.test_case in ping_test_cases:
                logger().info("Executing mDNS cycle with ping validation")
                self._execute_mdns_cycle(enable_ping_test=True)

        # Catch any exceptions that occur during test execution
        except Exception as Ex:
            # Handle the exception using the standard exception handling mechanism
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

# Global pytest configuration for WiFi DUT device setup
# This configuration applies to all test cases in this module
pytestmark = [
    pytest.mark.config(
        "wifi_dut",                                     # Target device identifier
        wifi={
            "oper_mode": 0,                             # Operation mode: 0 = Client mode
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,  # Enable WiFi+BLE coexistence
            "features": Si91xFeatureBitMap.Default      # Default feature set
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,  # ULP GPIO1 for device-to-host signaling
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default           # Default TCP/IP features
                          | Si91xTCPIPFeatureBitMap.DHCPv6Client        # DHCPv6 client for IPv6 address assignment
                          | Si91xTCPIPFeatureBitMap.IPv6Mode            # IPv6 protocol support
                          | Si91xTCPIPFeatureBitMap.mDNS,               # Multicast DNS (mDNS) service discovery
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid   # Enable config feature bitmap
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose           # Wait for socket close confirmation
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,     # Dynamic memory allocation for coexistence
            "custom_features": Si91xCustomFeatureBitMap.NWP120MHz                       # Network processor at 120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,      # Enable extended custom features
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default                  # Default extended custom features
                               # | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode    # 256KB memory mode (commented out)
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,      # Enable BT feature bitmap
            "ble_features": Si91xBLEFeatureBitMap.Default                               # Default BLE features
                        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,        # Enable asynchronous GATT operations
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default              # Default BLE custom features
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST  # Indication confirmation from host
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,           # MTU exchange from host
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0      # Wakeup indication via UULP GPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,                   # Enhanced maximum power save
            "thread_config": {
                "wifi": {"count": 1, "stack_len": 3072, "priority": 8},                # WiFi thread: 1 thread, 3KB stack, priority 8
                "ble": {"count": 1, "stack_len": 2048, "priority": 8},                 # BLE thread: 1 thread, 2KB stack, priority 8
            },
        },
    )
]
wan_ipv6_addr = random_ipv6_addr("2001:db8:abcd:0012::")
wan_gateway = "2001:db8:abcd:0012::1"

# Test-specific Access Point configuration
@pytest.mark.config(
    "wifi_access_point", 
    wifi={
        "ipv6_state": "0",                                          # IPv6 state configuration   # Random IPv6 address in specified range
        "security": "WPA2",                                          # WPA2 security configuration
        "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
    }
)

# Test state management markers - define initial and final states for devices
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")   # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                # Start with DUT initialized
@pytest.mark.end_state(                                            # End state configuration
    "wifi_dut", 
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_mdns_init_reg_service_deinit_stateless_loop_ble_scan_ps_C768342(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants, service_discovery, wifi_client, sniffer_filter):
    """
    Test Case C768342: Verify mDNS Init/Register/Deinit in a loop with BLE scanning in power save mode
    
    Test Objective:
    - Validate mDNS service initialization, registration, and deinitialization in multiple iterations
    - Verify WiFi/BLE coexistence during BLE scanning operations
    - Test power save functionality during mDNS operations
    - Ensure service discovery works correctly with mDNS
    
    Test Flow:
    1. Configure BLE scanning with specific intervals
    2. Start packet capture for traffic analysis
    3. Execute BLE scanning operations
    4. Configure WiFi advanced client settings
    5. Connect DUT to WiFi access point
    6. Start service discovery on remote client
    7. Execute mDNS operations in a loop
    8. Validate packet capture and cleanup
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test execution parameters
        capture_filename = request.node.name           # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")   # Get iteration count from test constants
        
        # Ensure minimum iteration count for meaningful testing
        if iter_count <= 5:
            iter_count = 5

        # Configure BLE thread for scanning functionality with power save
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,              # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,      # Test utility collections
            ble_test_type="scan",               # Configure for BLE scanning test
            scan_interval=480,                  # BLE scan interval: 480 * 0.625ms = 300ms
            scan_window=160                     # BLE scan window: 160 * 0.625ms = 100ms
        )
        
        # Configure WiFi thread for mDNS operations with specific test case
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT interface
            wifi_access_point=wifi_access_point, # Target access point
            wifi_client=wifi_client,            # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,          # Packet capture interface
            test_case=768342,                   # Specific test case ID for mDNS loop testing
            sl_collections=sl_collections,      # Test utility collections
            sniffer_filter=sniffer_filter,      # Packet filtering configuration
            power_save=True,                    # Enable power save mode
            iteration_count=iter_count          # Number of mDNS test iterations
        )

        # Start packet capture for traffic analysis and validation
        logger().info(f"Starting packet capture on WiFi channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")

        # Execute BLE scanning operations in background thread
        ble_obj.check_scan_functionality()                       # Start BLE scanning thread
        
        # Configure advanced WiFi client settings for optimal coexistence
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,               # Disable connection retries for faster testing
            scan_interval=4,                    # WiFi scan interval in seconds
            beacon_missed_count=40,             # Number of missed beacons before disconnection
            first_time_retry_enable=0           # Disable first-time retry mechanism
        )

        # Establish WiFi connection and configure IPv6 addressing
        wifi_obj.join_to_ap()
        
        # Initialize and start service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()
        logger().info(f"Service discovery initial status: {status}")
        service_discovery.interfaces.sd.start_discovering_services()
        logger().info("Started Avahi-daemon browser services from the remote side")
        time.sleep(1)  # Allow service discovery to stabilize
        
        # Execute WiFi mDNS operations (init/register/deinit loop)
        wifi_obj.start()                        # Start mDNS operations thread
        wifi_obj.wait_for_exit()                # Wait for all mDNS iterations to complete
        
        # Stop service discovery and packet capture
        service_discovery.interfaces.sd.stop_discovering_services()
        logger().info("Stopping packet sniffer and saving capture file")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Clean up BLE and WiFi connections
        wifi_dut.interfaces.wifi.ble_stop_scanning()   # Stop any remaining BLE scanning
        wifi_dut.interfaces.wifi.leave()               # Disconnect from WiFi access point

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        # Cleanup section - always executed regardless of test outcome
        logger().info("Executing test cleanup procedures")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)

@pytest.mark.skip()
# Test configuration: Disable IPv6, use Open security for simplified testing
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",                                      # Disable IPv6 support (IPv4 only)
                               "security": "Open",                                      # Use Open security (no authentication)
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
                               }
)
# Pytest state management markers - define initial and final states
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")                      # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                                   # Initialize WiFi DUT
@pytest.mark.end_state(                                            # End state configuration
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_mdns_init_reg_service_deinit_stateless_loop_ble_scan_C768351(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants,
        service_discovery, wifi_client, sniffer_filter):
    """
    Test Case C768342: Verify mDNS Init/Register/Deinit in a loop with BLE scanning in power save mode

    Test Objective:
    - Validate mDNS service initialization, registration, and deinitialization in multiple iterations
    - Verify WiFi/BLE coexistence during BLE scanning operations
    - Test power save functionality during mDNS operations
    - Ensure service discovery works correctly with mDNS

    Test Flow:
    1. Configure BLE scanning with specific intervals
    2. Start packet capture for traffic analysis
    3. Execute BLE scanning operations
    4. Configure WiFi advanced client settings
    5. Connect DUT to WiFi access point
    6. Start service discovery on remote client
    7. Execute mDNS operations in a loop
    8. Validate packet capture and cleanup
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test execution parameters
        capture_filename = request.node.name  # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")  # Get iteration count from test constants

        # Ensure minimum iteration count for meaningful testing
        if iter_count <= 5:
            iter_count = 5

        # Configure BLE thread for scanning functionality with power save
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,  # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,  # Test utility collections
            ble_test_type="scan",  # Configure for BLE scanning test
            scan_interval=480,  # BLE scan interval: 480 * 0.625ms = 300ms
            scan_window=160  # BLE scan window: 160 * 0.625ms = 100ms
        )

        # Configure WiFi thread for mDNS operations with specific test case
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT interface
            wifi_access_point=wifi_access_point,  # Target access point
            wifi_client=wifi_client,  # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,  # Packet capture interface
            test_case=768342,  # Specific test case ID for mDNS loop testing
            sl_collections=sl_collections,  # Test utility collections
            sniffer_filter=sniffer_filter,  # Packet filtering configuration
            power_save=False,  # Enable power save mode
            iteration_count=iter_count  # Number of mDNS test iterations
        )

        # Start packet capture for traffic analysis and validation
        logger().info(f"Starting packet capture on WiFi channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")

        # Execute BLE scanning operations in background thread
        ble_obj.check_scan_functionality()  # Start BLE scanning thread

        # Configure advanced WiFi client settings for optimal coexistence
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,  # Disable connection retries for faster testing
            scan_interval=4,  # WiFi scan interval in seconds
            beacon_missed_count=40,  # Number of missed beacons before disconnection
            first_time_retry_enable=0  # Disable first-time retry mechanism
        )

        # Establish WiFi connection and configure IPv6 addressing
        wifi_obj.join_to_ap()

        # Initialize and start service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()
        logger().info(f"Service discovery initial status: {status}")
        service_discovery.interfaces.sd.start_discovering_services()
        logger().info("Started Avahi-daemon browser services from the remote side")
        time.sleep(1)  # Allow service discovery to stabilize

        # Execute WiFi mDNS operations (init/register/deinit loop)
        wifi_obj.start()  # Start mDNS operations thread
        wifi_obj.wait_for_exit()  # Wait for all mDNS iterations to complete

        # Stop service discovery and packet capture
        service_discovery.interfaces.sd.stop_discovering_services()
        logger().info("Stopping packet sniffer and saving capture file")
        wifi_sniffer.interfaces.capture.stop_capture()

        # Clean up BLE and WiFi connections
        wifi_dut.interfaces.wifi.ble_stop_scanning()  # Stop any remaining BLE scanning
        wifi_dut.interfaces.wifi.leave()  # Disconnect from WiFi access point

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        # Cleanup section - always executed regardless of test outcome
        logger().info("Executing test cleanup procedures")

        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)


# Test-specific Access Point configuration with WPA2 security
@pytest.mark.config(
    "wifi_access_point", 
    wifi={
        "ipv6_state": "0",                                          # IPv6 state: disabled
        "security": "WPA2",                                          # WPA2 security configuration
        "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
    }
)
# Test state management - same pattern as previous tests
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")   # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                # Start with DUT initialized
@pytest.mark.end_state(                                            # End state cleanup
    "wifi_dut", 
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_wlan_conn_mdns_init_reg_service_deinit_stateless_disconn_loop_ble_adv_ps_C768344(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants, service_discovery, wifi_client, sniffer_filter,):
    """
    Test Case C768344: Verify mDNS operations with WiFi connection/disconnection loop and BLE advertising
    
    Test Objective:
    - Test mDNS service lifecycle during WiFi connect/disconnect cycles
    - Verify WiFi/BLE coexistence during BLE advertising operations
    - Validate power save functionality during repetitive connection cycles
    - Test service discovery during network reconnection scenarios
    
    Test Flow:
    1. Configure BLE advertising with 20ms intervals
    2. Start packet capture for traffic analysis
    3. Execute BLE advertising operations
    4. Perform multiple WiFi connect/mDNS/disconnect cycles
    5. Validate operations and cleanup connections
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test execution parameters
        capture_filename = request.node.name           # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")   # Get iteration count from test constants
        
        # Ensure minimum iteration count for testing
        if iter_count <= 5:
            iter_count = 5

        # Start packet capture for WiFi traffic analysis
        logger().info(f"Starting packet capture on WiFi channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")
        
        # Configure BLE thread for advertising functionality
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,              # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,      # Test utility collections
            ble_test_type="advertise",          # Configure for BLE advertising test
            adv_int_min=32,                     # Minimum advertising interval: 32 * 0.625ms = 20ms
            adv_int_max=32,                     # Maximum advertising interval: 32 * 0.625ms = 20ms
        )
        
        # Configure WiFi thread for mDNS operations with specific test case
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT interface
            wifi_access_point=wifi_access_point, # Target access point
            wifi_client=wifi_client,            # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,          # Packet capture interface
            test_case=768344,                   # Specific test case ID for connect/disconnect loops
            sl_collections=sl_collections,      # Test utility collections
            sniffer_filter=sniffer_filter,      # Packet filtering configuration
            power_save=True,                    # Enable power save mode
            iteration_count=iter_count          # Number of connect/disconnect iterations
        )
        
        # Execute BLE advertising operations
        ble_obj.start()                         # Start BLE advertising thread
        ble_obj.wait_for_exit()                    # Wait for BLE advertising to complete
        
        # Configure WiFi advanced client settings for optimal performance
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,               # Disable connection retries for faster testing
            scan_interval=4,                    # WiFi scan interval in seconds
            beacon_missed_count=40,             # Number of missed beacons before disconnection
            first_time_retry_enable=0           # Disable first-time retry mechanism
        )

        # Initialize and start service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()
        logger().info(f"Service discovery initial status: {status}")
        
        # Start Avahi-daemon service discovery
        service_discovery.interfaces.sd.start_discovering_services()
        logger().info("Started Avahi-daemon browser services from the remote side")
        time.sleep(1)  # Allow service discovery to initialize
        
        # Execute multiple WiFi connection/mDNS/disconnection cycles
        for count in range(iter_count):
            logger().info(f"Starting WiFi connect/mDNS/disconnect cycle {count + 1} of {iter_count}")
            wifi_obj.join_to_ap()               # Connect to WiFi access point
            wifi_obj.start()                    # Execute mDNS operations
            wifi_obj.wait_for_exit()            # Wait for mDNS operations to complete
            wifi_dut.interfaces.wifi.leave()    # Disconnect from WiFi access point
            time.sleep(2)                       # Allow time between cycles for stability
        
        # Stop service discovery and BLE advertising
        service_discovery.interfaces.sd.stop_discovering_services()
        time.sleep(1)  # Allow service discovery to stop cleanly
        wifi_dut.interfaces.wifi.ble_stop_advertising()  # Stop BLE advertising

        # Stop packet capture and save results
        logger().info("Stopping packet sniffer and saving capture file")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)

@pytest.mark.skip()
# Test configuration: Disable IPv6, use WPA2 security for enhanced security testing
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",                                      # Disable IPv6 support (IPv4 only)
                               "security": "WPA2",                                      # Use WPA2 security
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
                               }
)
# Pytest state management markers - define initial and final states
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")                      # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                                   # Initialize WiFi DUT
@pytest.mark.end_state(                                                               # End state configuration
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_wlan_conn_mdns_init_reg_service_deinit_stateless_disconn_loop_ble_adv_C768353(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants,
        service_discovery, wifi_client, sniffer_filter, ):
    """
    Test Case C768344: Verify mDNS operations with WiFi connection/disconnection loop and BLE advertising

    Test Objective:
    - Test mDNS service lifecycle during WiFi connect/disconnect cycles
    - Verify WiFi/BLE coexistence during BLE advertising operations
    - Validate power save functionality during repetitive connection cycles
    - Test service discovery during network reconnection scenarios

    Test Flow:
    1. Configure BLE advertising with 20ms intervals
    2. Start packet capture for traffic analysis
    3. Execute BLE advertising operations
    4. Perform multiple WiFi connect/mDNS/disconnect cycles
    5. Validate operations and cleanup connections
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test execution parameters
        capture_filename = request.node.name  # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")  # Get iteration count from test constants

        # Ensure minimum iteration count for testing
        if iter_count <= 5:
            iter_count = 5

        # Start packet capture for WiFi traffic analysis
        logger().info(f"Starting packet capture on WiFi channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")

        # Configure BLE thread for advertising functionality
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,  # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,  # Test utility collections
            ble_test_type="advertise",  # Configure for BLE advertising test
            adv_int_min=32,  # Minimum advertising interval: 32 * 0.625ms = 20ms
            adv_int_max=32,  # Maximum advertising interval: 32 * 0.625ms = 20ms
        )

        # Configure WiFi thread for mDNS operations with specific test case
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT interface
            wifi_access_point=wifi_access_point,  # Target access point
            wifi_client=wifi_client,  # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,  # Packet capture interface
            test_case=768344,  # Specific test case ID for connect/disconnect loops
            sl_collections=sl_collections,  # Test utility collections
            sniffer_filter=sniffer_filter,  # Packet filtering configuration
            power_save=False,  # Enable power save mode
            iteration_count=iter_count  # Number of connect/disconnect iterations
        )

        # Execute BLE advertising operations
        ble_obj.start()  # Start BLE advertising thread
        ble_obj.wait_for_exit()  # Wait for BLE advertising to complete

        # Configure WiFi advanced client settings for optimal performance
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,  # Disable connection retries for faster testing
            scan_interval=4,  # WiFi scan interval in seconds
            beacon_missed_count=40,  # Number of missed beacons before disconnection
            first_time_retry_enable=0  # Disable first-time retry mechanism
        )

        # Initialize and start service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()
        logger().info(f"Service discovery initial status: {status}")

        # Start Avahi-daemon service discovery
        service_discovery.interfaces.sd.start_discovering_services()
        logger().info("Started Avahi-daemon browser services from the remote side")
        time.sleep(1)  # Allow service discovery to initialize

        # Execute multiple WiFi connection/mDNS/disconnection cycles
        for count in range(iter_count):
            logger().info(f"Starting WiFi connect/mDNS/disconnect cycle {count + 1} of {iter_count}")
            wifi_obj.join_to_ap()  # Connect to WiFi access point
            wifi_obj.start()  # Execute mDNS operations
            wifi_obj.wait_for_exit()  # Wait for mDNS operations to complete
            wifi_dut.interfaces.wifi.leave()  # Disconnect from WiFi access point
            time.sleep(2)  # Allow time between cycles for stability

        # Stop service discovery and BLE advertising
        service_discovery.interfaces.sd.stop_discovering_services()
        time.sleep(1)  # Allow service discovery to stop cleanly
        wifi_dut.interfaces.wifi.ble_stop_advertising()  # Stop BLE advertising

        # Stop packet capture and save results
        logger().info("Stopping packet sniffer and saving capture file")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")

        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)


@pytest.mark.skip()
# Test-specific Access Point configuration for Open security
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ipv6_state": "0",  # IPv6 state: disabled for this test
        "security": "Open",  # Open WiFi security (no encryption)
        "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
    }
)
# Test state management - same as previous test
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")  # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])  # Start with DUT initialized
@pytest.mark.end_state(  # End state cleanup
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "unassociated"]
    # Disable power save and disassociate
)
def test_wifi_sdk_mdns_init_reg_service_deinit_stateless_loop_ble_central_rx_ps_C768343(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants,
        service_discovery, wifi_client, sniffer_filter, ):
    """
    Test Case C768343: Verify mDNS operations with BLE Central RX notifications in power save mode

    Test Objective:
    - Test mDNS service lifecycle with BLE notification reception
    - Verify WiFi/BLE coexistence during GATT notification operations
    - Validate Heart Rate Service notification functionality
    - Test power save mode during concurrent WiFi and BLE operations

    Test Flow:
    1. Configure BLE for notification reception from Heart Rate Service
    2. Start packet capture for analysis
    3. Establish BLE connection and perform service discovery
    4. Configure WiFi client settings and connect to AP
    5. Execute mDNS operations while receiving BLE notifications
    6. Validate operations and cleanup connections
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test execution parameters
        capture_filename = request.node.name  # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")  # Get iteration count from test constants

        # Ensure minimum iteration count for meaningful testing
        if iter_count <= 5:
            iter_count = 5

        # Start packet capture for WiFi traffic analysis
        logger().info(f"Starting packet capture on WiFi channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")

        # Configure BLE thread for notification reception from Heart Rate Service
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT with BLE coexistence
            ble_client=ble_client,  # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,  # Test utility collections
            ble_test_type="notify_rx",  # Configure for notification reception
            dev_state=8,  # Expected connected device state
            data_duration=30,  # Notification monitoring duration (30 seconds)
            service_class=["HeartRateService"],  # Expected BLE service class
            ble_pairing=1,  # Enable BLE pairing/bonding
            bond_info=1,  # Store bonding information
            service_uuid=HeartRateService.UUID,  # Heart Rate Service UUID
            char_uuid=HeartRateMeasurementCharacterstic.HR_Measure_UUID,  # Heart Rate Measurement characteristic UUID
            characteristic=HeartRateMeasurementCharacterstic  # Heart Rate characteristic class
        )

        # Configure WiFi thread for mDNS operations with specific test case
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT interface
            wifi_access_point=wifi_access_point,  # Target access point
            wifi_client=wifi_client,  # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,  # Packet capture interface
            test_case=768343,  # Specific test case ID for mDNS with BLE notifications
            sl_collections=sl_collections,  # Test utility collections
            sniffer_filter=sniffer_filter,  # Packet filtering configuration
            power_save=True,  # Enable power save mode
            iteration_count=iter_count  # Number of mDNS test iterations
        )

        # Establish BLE connection and prepare for notification reception
        ble_obj.check_scan_functionality_dut()  # Verify DUT can scan for remote BLE devices
        ble_obj.connect_from_dut()  # Establish BLE connection with DUT as master
        ble_obj.service_discovery_on_dut()  # Discover Heart Rate Service on remote device
        ble_obj.start()  # Start BLE notification reception thread

        # Configure WiFi advanced client settings for optimal coexistence
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,  # Disable connection retries for faster testing
            scan_interval=4,  # WiFi scan interval in seconds
            beacon_missed_count=40,  # Number of missed beacons before disconnection
            first_time_retry_enable=0  # Disable first-time retry mechanism
        )
        time.sleep(5)  # Allow BLE connection to stabilize before WiFi operations

        # Establish WiFi connection to access point
        wifi_obj.join_to_ap()

        # Initialize and start service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()
        logger().info(f"Service discovery initial status: {status}")

        # Start Avahi-daemon service discovery on remote device
        service_discovery.interfaces.sd.start_discovering_services()
        logger().info("Started Avahi-daemon browser services from the remote side")
        time.sleep(1)  # Allow service discovery to initialize

        # Execute concurrent WiFi mDNS operations and BLE notification reception
        wifi_obj.start()  # Start mDNS operations thread
        wifi_obj.wait_for_exit()  # Wait for mDNS operations to complete
        ble_obj.wait_for_exit()  # Wait for BLE notification reception to complete

        # Stop service discovery and allow cleanup time
        service_discovery.interfaces.sd.stop_discovering_services()
        time.sleep(1)  # Allow service discovery to stop cleanly

        # Disconnect BLE connection from DUT side and leave WiFi network
        ble_obj.ble_disconnect(disconnect_from="dut")  # Initiate BLE disconnection from DUT
        wifi_dut.interfaces.wifi.leave()  # Disconnect from WiFi access point

        # Stop packet capture and save results
        logger().info("Stopping packet sniffer and saving capture file")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        # Cleanup section - always executed regardless of test outcome
        logger().info("Executing test cleanup procedures")

        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)


@pytest.mark.skip()
# Test configuration: Enable IPv6 support on WiFi access point
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",                                      # Enable IPv6 support
                               "security": "WPA2",                                      # Use WPA2 security
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
                               }
)
# Pytest state management markers - define initial and final states
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")                      # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                                   # Initialize WiFi DUT
@pytest.mark.end_state(                                                               # End state configuration
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_wlan_conn_mdns_init_reg_service_deinit_stateful_disconn_loop_ble_tx_240_ps_C768345(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants, service_discovery, wifi_client, sniffer_filter,):
    """
    Test Case C768345: WiFi SDK WLAN connection with mDNS init/register/deinit in stateful disconnection loop
    
    Test Objective:
    - Verify mDNS functionality during repeated WiFi connect/disconnect cycles
    - Test BLE data transmission (240 bytes) with power save mode
    - Validate coexistence between WiFi mDNS operations and BLE data transfer
    
    Test Flow:
    1. Configure BLE for 240-byte data transmission with notifications
    2. Setup WiFi for repeated connect/disconnect with mDNS operations
    3. Execute test cycles with BLE data transfer and WiFi mDNS operations
    4. Verify successful coexistence and performance
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test parameters from pytest request and configuration
        capture_filename = request.node.name                   # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")           # Get iteration count from test constants
        if iter_count <= 5:                                    # Ensure minimum iteration count for thorough testing
            iter_count = 5

        # BLE service and characteristic configuration for GATT operations
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"   # Custom BLE service UUID
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"     # Custom characteristic UUID for data transfer
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))  # Generate 240 bytes of random data
        index = 1                                              # Service index for GATT attribute handling
        
        # Allocate and load data into DUT memory for BLE operations
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)       # Allocate memory for data + null terminator
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)  # Load data into allocated memory

        # Start packet capture on WiFi sniffer for debugging and analysis
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)  # Configure sniffer channel
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")  # Start packet capture

        # Configure BLE thread for high-volume data transmission with notifications
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,              # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,      # Test utility collections
            ble_test_type="notify_tx",          # Configure for BLE notification transmission
            dev_state=8,                        # Device state for connected mode
            char_path=None,                     # No specific characteristic path
            char_uid=char_uid1,                 # Custom characteristic UUID
            data=data,                          # 240 bytes of test data
            service_uid=service_uid,            # Custom service UUID
            data_length=240,                    # Data length for transmission
            data_duration=120,                  # Duration of data transmission in seconds
            periodic_delay=1,                   # Delay between transmissions
            ble_pairing=1,                      # Enable BLE pairing
            gatt=True,                          # Enable GATT operations
            address=address2,                   # Memory address of loaded data
            adv_int_min=256,                    # Minimum advertising interval: 256 * 0.625ms = 160ms
            adv_int_max=256,                    # Maximum advertising interval: 256 * 0.625ms = 160ms
            conn_interval=30,                   # Connection interval: 30 * 1.25ms = 37.5ms
        )
        
        # Configure WiFi thread for mDNS operations during connect/disconnect cycles
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT interface
            wifi_access_point=wifi_access_point, # Target access point
            wifi_client=wifi_client,            # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,          # Packet capture interface
            test_case=768354,                   # Specific test case ID for mDNS init/register/deinit
            sl_collections=sl_collections,      # Test utility collections
            sniffer_filter=sniffer_filter,      # Packet filtering configuration
            power_save=True,                    # Enable power save mode
            iteration_count=iter_count          # Number of connect/disconnect iterations
        )
        
        # Create custom GATT services on DUT for BLE functionality
        # Create Custom services, attributes, values
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)                # Add custom service with UUID 0xAABB
        
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(        # Add characteristic declaration attribute
            uid=0x1AA1,                                         # Characteristic UUID
            service_handler_num=index,                          # Service handler number
            value_handler_num=index + 1                         # Value handler number (next index)
        )
        
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(         # Add characteristic value attribute
            uid=0x1AA1,                                         # Characteristic UUID
            value_handler_num=index + 1                         # Value handler number
        )

        # Establish BLE connection and perform service discovery
        ble_obj.ble_connect(role="slave")                       # Connect BLE as slave device
        ble_obj.service_discovery_on_remote()                  # Perform service discovery on remote device
        
        # Configure WiFi advanced client settings for optimal performance
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,                               # Disable connection retries for faster testing
            scan_interval=4,                                    # WiFi scan interval in seconds
            beacon_missed_count=40,                             # Number of missed beacons before disconnection
            first_time_retry_enable=0                           # Disable first-time retry mechanism
        )

        # Initialize and start service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()  # Get current service discovery status
        logger().info(f"Service discovery status: {status}")
        time.sleep(1)
        
        # Start Avahi-daemon service discovery
        service_discovery.interfaces.sd.start_discovering_services()  # Start service discovery
        logger().info("starting the avahi-daemon browser services from the remote side")
        time.sleep(1)                                           # Allow service discovery to initialize
        
        # Start BLE data transmission operations
        ble_obj.start()                                         # Start BLE thread for data transmission
        
        # Execute multiple WiFi connection/mDNS/disconnection cycles
        iter_count = utf_constants.get("iter_count")            # Get iteration count from constants
        for count in range(iter_count):
            logger().info(f"Starting WiFi connect/mDNS/disconnect cycle {count + 1} of {iter_count}")
            time.sleep(5)                                       # Initial delay for stability
            wifi_obj.join_to_ap()                               # Connect to WiFi access point
            wifi_obj.start()                                    # Execute mDNS operations
            wifi_obj.wait_for_exit()                            # Wait for mDNS operations to complete
            wifi_dut.interfaces.wifi.leave()                    # Disconnect from WiFi access point
        
        # Stop service discovery and wait for BLE operations to complete
        service_discovery.interfaces.sd.stop_discovering_services()  # Stop Avahi-daemon service discovery
        time.sleep(1)                                           # Allow service discovery to stop cleanly
        ble_obj.wait_for_exit()                                 # Wait for BLE operations to complete

        # Stop packet capture and save results
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()         # Stop packet capture

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)

@pytest.mark.skip()
# Test configuration: Disable IPv6 support on WiFi access point for IPv4 testing
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",                                      # Disable IPv6 support (IPv4 only)
                               "security": "WPA2",                                        # Use WPA2 security
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
                               }
)
# Pytest state management markers - define initial and final states
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")                      # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                                   # Initialize WiFi DUT
@pytest.mark.end_state(                                                               # End state configuration
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_mdns_ping_hostname_ble_scan_ps_C768347(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants, service_discovery, wifi_client, sniffer_filter):
    """
    Test Case C768347: WiFi SDK mDNS ping hostname with BLE scan and power save
    
    Test Objective:
    - Verify mDNS hostname resolution and ping functionality
    - Test BLE scanning operations with power save mode
    - Validate coexistence between WiFi mDNS operations and BLE scanning
    
    Test Flow:
    1. Configure BLE for scanning operations
    2. Setup WiFi for mDNS hostname resolution and ping operations
    3. Execute test with concurrent BLE scanning and WiFi mDNS operations
    4. Verify successful coexistence and functionality
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test parameters from pytest request and configuration
        capture_filename = request.node.name                   # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")           # Get iteration count from test constants
        if iter_count <= 5:                                    # Ensure minimum iteration count for thorough testing
            iter_count = 5

        # Configure BLE thread for scanning operations
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,              # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,      # Test utility collections
            ble_test_type="scan",               # Configure for BLE scanning operations
            scan_interval=1600,                 # Scan interval: 1600 * 0.625ms = 1000ms
            scan_window=480                     # Scan window: 480 * 0.625ms = 300ms
        )
        
        # Configure WiFi thread for mDNS hostname ping operations
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT interface
            wifi_access_point=wifi_access_point, # Target access point
            wifi_client=wifi_client,            # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,          # Packet capture interface
            test_case=768347,                   # Specific test case ID for mDNS ping hostname
            sl_collections=sl_collections,      # Test utility collections
            sniffer_filter=sniffer_filter,      # Packet filtering configuration
            power_save=True,                    # Enable power save mode
            iteration_count=iter_count          # Number of iterations
        )

        # Start packet capture on WiFi sniffer for debugging and analysis
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)  # Configure sniffer channel
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")  # Start packet capture

        # Execute BLE scanning operations
        ble_obj.start()                         # Start BLE scanning thread
        ble_obj.wait_for_exit()                 # Wait for BLE scanning to complete
        
        # Configure WiFi advanced client settings for optimal performance
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,               # Disable connection retries for faster testing
            scan_interval=4,                    # WiFi scan interval in seconds
            beacon_missed_count=40,             # Number of missed beacons before disconnection
            first_time_retry_enable=0           # Disable first-time retry mechanism
        )

        # Connect to WiFi access point
        wifi_obj.join_to_ap()                   # Connect to WiFi access point
        
        # Initialize and start service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()  # Get current service discovery status
        logger().info(f"Service discovery status: {status}")
        time.sleep(1)
        
        # Start Avahi-daemon service discovery
        service_discovery.interfaces.sd.start_discovering_services()  # Start service discovery
        logger().info("starting the avahi-daemon browser services from the remote side")
        time.sleep(1)                           # Allow service discovery to initialize
        
        # Execute mDNS hostname ping operations
        wifi_obj.start()                        # Start WiFi thread for mDNS ping operations
        wifi_obj.wait_for_exit()                # Wait for mDNS operations to complete
        
        # Stop service discovery and cleanup
        service_discovery.interfaces.sd.stop_discovering_services()  # Stop Avahi-daemon service discovery
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()  # Stop packet capture

        # Stop BLE scanning and disconnect from WiFi
        wifi_dut.interfaces.wifi.ble_stop_scanning()  # Stop BLE scanning operations
        wifi_dut.interfaces.wifi.leave()              # Disconnect from WiFi access point

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)

@pytest.mark.skip()
# Test configuration: Disable IPv6 support on WiFi access point for IPv4 testing
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",                                      # Disable IPv6 support (IPv4 only)
                               "security": "WPA2"}                                     # Use WPA2 security
)
# Pytest state management markers - define initial and final states
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")                      # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                                   # Initialize WiFi DUT
@pytest.mark.end_state(                                                               # End state configuration
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_verify_mdns_functionality_restart_avahi_ble_connection_30ms_ps_C768348(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants, service_discovery, wifi_client, sniffer_filter):
    """
    Test Case C768348: WiFi SDK verify mDNS functionality with Avahi restart and BLE connection (30ms, power save)
    
    Test Objective:
    - Verify mDNS functionality during Avahi-daemon kill and restart operations
    - Test BLE connection establishment with 30ms connection interval
    - Validate robustness of mDNS operations during service disruption
    - Test coexistence with power save mode enabled
    
    Test Flow:
    1. Establish BLE connection with 30ms interval
    2. Setup WiFi connection and mDNS services
    3. Kill and restart Avahi-daemon service during operations
    4. Verify mDNS functionality recovery and BLE connection stability
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test parameters from pytest request and configuration
        capture_filename = request.node.name                   # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")           # Get iteration count from test constants
        if iter_count <= 5:                                    # Ensure minimum iteration count for thorough testing
            iter_count = 5

        # Configure BLE thread for connection operations (slave role)
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,              # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,      # Test utility collections
            ble_test_type="slave",              # Configure for BLE slave connection
            adv_int_min=32,                     # Minimum advertising interval: 32 * 0.625ms = 20ms
            adv_int_max=32,                     # Maximum advertising interval: 32 * 0.625ms = 20ms
            conn_interval=30                    # Connection interval: 30 * 1.25ms = 37.5ms (close to 30ms)
        )
        
        # Configure WiFi thread for mDNS operations without specific test case
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,                  # WiFi DUT interface
            wifi_access_point=wifi_access_point, # Target access point
            wifi_client=wifi_client,            # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,          # Packet capture interface
            sl_collections=sl_collections,      # Test utility collections
            sniffer_filter=sniffer_filter,      # Packet filtering configuration
            power_save=True,                    # Enable power save mode
            iteration_count=iter_count          # Number of iterations for stress testing
        )

        # Start packet capture on WiFi sniffer for debugging and analysis
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)  # Configure sniffer channel
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")  # Start packet capture

        # Execute BLE connection establishment
        ble_obj.start()                         # Start BLE connection thread
        ble_obj.wait_for_exit()                 # Wait for BLE connection to establish
        
        # Execute multiple cycles of WiFi connect with mDNS init/register/deinit and Avahi restart
        for count in range(iter_count):
            logger().info(f"Starting WiFi/mDNS/Avahi restart cycle {count + 1} of {iter_count}")
            
            # Connect to WiFi and initialize mDNS services
            wifi_obj.join_to_ap()               # Connect to WiFi access point
            wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)  # Initialize mDNS with IPv6 support
            wifi_dut.interfaces.wifi.mdns_add_interface()    # Add network interface to mDNS
            wifi_dut.interfaces.wifi.mdns_register_service() # Register mDNS service for discovery
            
            # Test Avahi-daemon restart functionality
            service_discovery.interfaces.sd.stop_discovering_services()  # Stop Avahi service discovery
            status = service_discovery.interfaces.sd.get_status()        # Check service status
            logger().info(f"Service discovery status after stop: {status}")
            service_discovery.interfaces.sd.start_discovering_services() # Restart Avahi service discovery
            time.sleep(20)                      # Allow time for service discovery to stabilize
            service_discovery.interfaces.sd.stop_discovering_services()  # Stop service discovery again
            time.sleep(5)
            
            # Clean up mDNS and WiFi connection
            wifi_dut.interfaces.wifi.mdns_deinit()  # Deinitialize mDNS services
            wifi_dut.interfaces.wifi.leave()        # Disconnect from WiFi access point
            time.sleep(5)                           # Allow time between cycles for stability

        # Stop packet capture and disconnect BLE
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()  # Stop packet capture
        ble_obj.ble_disconnect(disconnect_from="remote") # Disconnect BLE from remote side

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)

@pytest.mark.skip()
# Test configuration: Disable IPv6, use Open security for simplified testing
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",                                      # Disable IPv6 support (IPv4 only)
                               "security": "WPA2",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
                               }
)
# Pytest state management markers - define initial and final states
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")                      # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                                   # Initialize WiFi DUT
@pytest.mark.end_state(                                                               # End state configuration
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_mdns_init_reg_service_deinit_stateless_loop_ble_central_rx_C768352(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants, service_discovery, wifi_client, sniffer_filter,):
    """
    Test Case C768352: WiFi SDK mDNS init/register/deinit in stateless loop with BLE Central RX
    
    Test Objective:
    - Verify mDNS initialization, service registration, and deinitialization in stateless mode
    - Test BLE central role with notification reception from Heart Rate Service
    - Validate coexistence between WiFi mDNS operations and BLE data reception
    - Test notification handling during mDNS service lifecycle
    
    Test Flow:
    1. Configure BLE for Heart Rate Service notification reception
    2. Establish BLE connection and perform service discovery
    3. Setup WiFi for mDNS operations in stateless mode
    4. Execute concurrent BLE notifications and WiFi mDNS operations
    5. Validate successful coexistence and cleanup
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test parameters from pytest request and configuration
        capture_filename = request.node.name                   # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")
        if iter_count <= 5:
            iter_count = 5

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=60,
            service_class=["HeartRateService"],
            ble_pairing=1,
            bond_info=1,
            service_uuid=HeartRateService.UUID,
            char_uuid=HeartRateMeasurementCharacterstic.HR_Measure_UUID,
            characteristic=HeartRateMeasurementCharacterstic
        )
        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_client=wifi_client, wifi_sniffer=wifi_sniffer, test_case=768352,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                                           power_save=False, iteration_count=iter_count)

        ble_obj.check_scan_functionality_dut()
        ble_obj.connect_from_dut()
        ble_obj.service_discovery_on_dut()
        ble_obj.start()
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0, scan_interval=4, beacon_missed_count=40, first_time_retry_enable=0)
        time.sleep(5)
        wifi_obj.join_to_ap()
        status = service_discovery.interfaces.sd.get_status()
        logger().info(f"Status {status}")
        #time.sleep(5)
        service_discovery.interfaces.sd.start_discovering_services()
        logger().info("starting the avahi-daemon browser services from the remote side")
        time.sleep(1)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        service_discovery.interfaces.sd.stop_discovering_services()
        time.sleep(1)

        # ble_obj.wait_for_exit()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_dut.interfaces.wifi.leave()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)



@pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "security": "WPA2",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
                                }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_wlan_conn_mdns_init_reg_service_deinit_stateful_disconn_loop_ble_tx_240_C768354(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants, service_discovery, wifi_client, sniffer_filter,):
    """
    Test Case C768354: WiFi SDK WLAN connection with mDNS init/register/deinit in stateful disconnect loop with BLE TX 240 bytes

    Test Objective:
    - Verify mDNS initialization, service registration, and deinitialization in iterative stateful disconnect/reconnect cycles
    - Test BLE GATT notification transmission of 240-byte payloads during WiFi/mDNS operations
    - Validate coexistence stability with large BLE data transfers and dynamic WiFi connection cycling

    Test Flow:
    1. Setup custom BLE GATT service with 240-byte characteristic for notifications
    2. Establish BLE connection with GATT service discovery and pairing
    3. For each iteration:
       - Connect to WiFi and perform full mDNS lifecycle (init → register → deinit)
       - Maintain BLE GATT notifications with 240-byte data payload
       - Disconnect WiFi and repeat cycle
    4. Verify stability and performance across all iterations
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test parameters from pytest request and configuration
        capture_filename = request.node.name  # Use test function name for packet capture file
        iter_count = utf_constants.get("iter_count")  # Get iteration count from test constants
        if iter_count <= 5:  # Ensure minimum iteration count for stress testing
            iter_count = 5

        # Define BLE GATT service and characteristic UUIDs for large data transfer test
        service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"  # Custom service UUID
        char_uid1 = "00001aa1-0000-1000-8000-00805f9b34fb"  # Custom characteristic UUID for notifications
        # Generate random 240-byte data payload for BLE transmission stress test
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=240))
        index = 1  # Service index for GATT attribute management
        
        # Allocate memory on DUT for large data payload storage
        address2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)  # Allocate 241 bytes (240 + null terminator)
        wifi_dut.interfaces.wifi.load_memory(address=address2, size=len(data), write_content=data)  # Load data into allocated memory

        # Start packet capture for WiFi traffic analysis and debugging
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)  # Configure sniffer channel
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")  # Start packet capture with test name

        # Configure BLE thread for GATT notification transmission with large payload
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,  # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,  # Test utility collections
            ble_test_type="notify_tx",  # Configure for GATT notification transmission
            dev_state=8,  # Device state for GATT operations
            char_path=None,  # Character path (not used for notifications)
            char_uid=char_uid1,  # Characteristic UUID for notifications
            data=data,  # 240-byte data payload
            service_uid=service_uid,  # Custom service UUID
            data_length=240,  # Exact length of data payload
            data_duration=120,  # Duration for data transmission operations (seconds)
            periodic_delay=1,  # Delay between periodic operations
            ble_pairing=1,  # Enable BLE pairing for secure connection
            gatt=True,  # Enable GATT operations
            address=address2,  # Memory address containing the data payload
            adv_int_min=256,  # Minimum advertising interval: 256 * 0.625ms = 160ms
            adv_int_max=256,  # Maximum advertising interval: 256 * 0.625ms = 160ms
            conn_interval=30,  # Connection interval: 30 * 1.25ms = 37.5ms
        )
        
        # Configure WiFi thread for mDNS operations with iterative connect/disconnect cycles
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT interface
            wifi_access_point=wifi_access_point,  # Target access point
            wifi_client=wifi_client,  # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,  # Packet capture interface
            test_case=768354,  # Specific test case identifier for mDNS operations
            sl_collections=sl_collections,  # Test utility collections
            sniffer_filter=sniffer_filter,  # Packet filtering configuration
            power_save=False,  # Disable power save mode for consistent performance
            iteration_count=iter_count  # Number of WiFi connect/disconnect iterations
        )
        # Create custom GATT service and characteristics on DUT for large data transfer
        logger().info("Creating new custom gatt service in DUT")
        ble_obj.add_service(service_uuid=0xAABB)  # Add custom service with 16-bit UUID
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(  # Add characteristic declaration attribute
            uid=0x1AA1,  # Characteristic UUID (16-bit)
            service_handler_num=index,  # Service handler number
            value_handler_num=index + 1  # Value handler number (next sequential index)
        )
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(  # Add characteristic value attribute
            uid=0x1AA1,  # Characteristic UUID matching declaration
            value_handler_num=index + 1  # Value handler number for data storage
        )

        # Establish BLE connection with client and perform service discovery
        ble_obj.ble_connect(role="slave")  # Connect as BLE slave (server role)
        ble_obj.service_discovery_on_remote()  # Perform GATT service discovery from client side
        
        # Configure WiFi client parameters for optimal connectivity
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,  # Disable automatic retry attempts
            scan_interval=4,  # Scan interval for AP discovery
            beacon_missed_count=40,  # Threshold for considering AP lost
            first_time_retry_enable=0  # Disable first-time connection retry
        )

        # Start mDNS service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()  # Check current service discovery status
        logger().info(f"Status {status}")
        #time.sleep(5)  # Optional delay for system stabilization
        service_discovery.interfaces.sd.start_discovering_services()  # Start Avahi-daemon service discovery
        logger().info("starting the avahi-daemon browser services from the remote side")
        time.sleep(1)  # Brief delay for service discovery initialization
        
        # Start BLE GATT notification transmission in background thread
        ble_obj.start()  # Begin BLE notification operations
        
        # Execute iterative WiFi connection and mDNS lifecycle cycles
        iter_count = utf_constants.get("iter_count")  # Re-fetch iteration count for loop
        for count in range(iter_count):
            logger().info(f"Starting WiFi/mDNS cycle {count + 1} of {iter_count}")
            time.sleep(5)  # Delay between cycles for stability
            wifi_obj.join_to_ap()  # Connect to WiFi access point
            wifi_obj.start()  # Start WiFi thread operations (mDNS init/register/deinit)
            wifi_obj.wait_for_exit()  # Wait for WiFi operations to complete
            wifi_dut.interfaces.wifi.leave()  # Disconnect from WiFi access point
            
        # Stop service discovery and wait for BLE operations to complete
        service_discovery.interfaces.sd.stop_discovering_services()  # Stop Avahi-daemon service discovery
        time.sleep(1)  # Brief delay for cleanup
        ble_obj.wait_for_exit()  # Wait for BLE notification thread to finish

        # Stop packet capture for analysis
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()  # Stop packet capture

    except Exception as Ex:
        # Handle any exceptions during test execution with comprehensive error reporting
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)

@pytest.mark.skip()
# Test-specific Access Point configuration
@pytest.mark.config("wifi_access_point",
    wifi={
        "ipv6_state": "0",                                          # IPv6 state configuration
        "security": "WPA2",                                          # WPA2 security configuration
        "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
    }
)

# Test state management markers - define initial and final states for devices
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")   # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])                # Start with DUT initialized
@pytest.mark.end_state(                                            # End state configuration
    "wifi_dut",
    wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_mdns_ping_hostname_ble_scan_C768355(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants, service_discovery, wifi_client, sniffer_filter):
    """
    Test Case C768355: WiFi SDK mDNS ping hostname functionality with BLE scan operations

    Test Objective:
    - Verify mDNS hostname resolution and ping functionality while BLE scanning is active
    - Test coexistence between WiFi mDNS operations and BLE scan activities
    - Validate network hostname discovery and connectivity during concurrent BLE scan operations

    Test Flow:
    1. Start BLE scanning with specified scan interval and window parameters
    2. Connect to WiFi and initiate mDNS service discovery
    3. Perform mDNS hostname ping operations while maintaining BLE scan
    4. Verify successful hostname resolution and ping responses with BLE scan active
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test parameters from pytest request and configuration
        capture_filename = request.node.name  # Use test function name for packet capture file
        iter_count = utf_constants.get("iter_count")  # Get iteration count from test constants
        if iter_count <= 5:  # Ensure minimum iteration count for thorough testing
            iter_count = 5

        # Configure BLE thread for scan operations during mDNS testing
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,  # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,  # Test utility collections
            ble_test_type="scan",  # Configure for BLE scanning operations
            scan_interval=1600,  # Scan interval: 1600 * 0.625ms = 1000ms
            scan_window=480  # Scan window: 480 * 0.625ms = 300ms
        )
        
        # Configure WiFi thread for mDNS ping hostname operations
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT interface
            wifi_access_point=wifi_access_point,  # Target access point
            wifi_client=wifi_client,  # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,  # Packet capture interface
            test_case=768355,  # Specific test case identifier for mDNS ping operations
            sl_collections=sl_collections,  # Test utility collections
            sniffer_filter=sniffer_filter,  # Packet filtering configuration
            power_save=False,  # Disable power save mode for consistent performance
            iteration_count=iter_count  # Number of mDNS operations iterations
        )

        # Start packet capture for WiFi and mDNS traffic analysis
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)  # Configure sniffer channel
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")  # Start packet capture

        # Execute BLE scanning operations first
        ble_obj.start()  # Start BLE scanning thread
        ble_obj.wait_for_exit()  # Wait for BLE scanning operations to complete
        
        # Configure WiFi client parameters for optimal connectivity
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
            max_retry_attempts=0,  # Disable automatic retry attempts
            scan_interval=4,  # Scan interval for AP discovery
            beacon_missed_count=40,  # Threshold for considering AP lost
            first_time_retry_enable=0  # Disable first-time connection retry
        )

        # Connect to WiFi access point for mDNS operations
        wifi_obj.join_to_ap()  # Establish WiFi connection
        
        # Start mDNS service discovery on remote device
        status = service_discovery.interfaces.sd.get_status()  # Check current service discovery status
        logger().info(f"Status {status}")
        #time.sleep(3)  # Optional delay for system stabilization
        service_discovery.interfaces.sd.start_discovering_services()  # Start Avahi-daemon service discovery
        logger().info("starting the avahi-daemon browser services from the remote side")
        time.sleep(1)  # Brief delay for service discovery initialization
        
        # Execute WiFi mDNS ping hostname operations
        wifi_obj.start()  # Start WiFi thread operations (mDNS ping hostname functionality)
        wifi_obj.wait_for_exit()  # Wait for WiFi operations to complete
        
        # Stop service discovery and cleanup
        service_discovery.interfaces.sd.stop_discovering_services()  # Stop Avahi-daemon service discovery
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()  # Stop packet capture

        # Clean up BLE and WiFi connections
        wifi_dut.interfaces.wifi.ble_stop_scanning()  # Stop BLE scanning operations
        wifi_dut.interfaces.wifi.leave()  # Disconnect from WiFi access point

    except Exception as Ex:
        # Handle any exceptions during test execution with comprehensive error reporting
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)

@pytest.mark.skip()
# Test configuration: Disable IPv6 support on WiFi access point for IPv4 testing
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",  # Disable IPv6 support (IPv4 only)
                               "security": "WPA2", # Use WPA2 security
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")
                               }
)
# Pytest state management markers - define initial and final states
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")  # Start with AP enabled
@pytest.mark.start_state("wifi_dut", wifi=["init"])  # Initialize WiFi DUT
@pytest.mark.end_state(  # End state configuration
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated","unassociated"]  # Disable power save and disassociate
)
def test_wifi_sdk_verify_mdns_functionality_restart_avahi_ble_connection_30ms_C768356(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, sl_collections, request, utf_constants,
        service_discovery, wifi_client, sniffer_filter):
    """
    Test Case C768348: WiFi SDK verify mDNS functionality with Avahi restart and BLE connection (30ms, power save)

    Test Objective:
    - Verify mDNS functionality during Avahi-daemon kill and restart operations
    - Test BLE connection establishment with 30ms connection interval
    - Validate robustness of mDNS operations during service disruption

    Test Flow:
    1. Establish BLE connection with 30ms interval
    2. Setup WiFi connection and mDNS services
    3. Kill and restart Avahi-daemon service during operations
    4. Verify mDNS functionality recovery and BLE connection stability
    """
    ble_obj = None  # Initialize BLE object reference for cleanup
    try:
        # Extract test parameters from pytest request and configuration
        capture_filename = request.node.name  # Use test function name for capture file
        iter_count = utf_constants.get("iter_count")  # Get iteration count from test constants
        if iter_count <= 5:  # Ensure minimum iteration count for thorough testing
            iter_count = 5

        # Configure BLE thread for connection operations (slave role)
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT with BLE coexistence capability
            ble_client=ble_client,  # Remote BLE client (Raspberry Pi)
            sl_collections=sl_collections,  # Test utility collections
            ble_test_type="slave",  # Configure for BLE slave connection
            adv_int_min=32,  # Minimum advertising interval: 32 * 0.625ms = 20ms
            adv_int_max=32,  # Maximum advertising interval: 32 * 0.625ms = 20ms
            conn_interval=30  # Connection interval: 30 * 1.25ms = 37.5ms (close to 30ms)
        )

        # Configure WiFi thread for mDNS operations without specific test case
        wifi_obj = WifiThreadFunctionality(
            wifi_dut=wifi_dut,  # WiFi DUT interface
            wifi_access_point=wifi_access_point,  # Target access point
            wifi_client=wifi_client,  # Remote WiFi client device
            wifi_sniffer=wifi_sniffer,  # Packet capture interface
            sl_collections=sl_collections,  # Test utility collections
            sniffer_filter=sniffer_filter,  # Packet filtering configuration
            power_save=False,  # Disable power save mode
            iteration_count=iter_count  # Number of iterations for stress testing
        )

        # Start packet capture on WiFi sniffer for debugging and analysis
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)  # Configure sniffer channel
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")  # Start packet capture

        # Execute BLE connection establishment
        ble_obj.start()  # Start BLE connection thread
        ble_obj.wait_for_exit()  # Wait for BLE connection to establish

        # Execute multiple cycles of WiFi connect with mDNS init/register/deinit and Avahi restart
        for count in range(iter_count):
            logger().info(f"Starting WiFi/mDNS/Avahi restart cycle {count + 1} of {iter_count}")

            # Connect to WiFi and initialize mDNS services
            wifi_obj.join_to_ap()  # Connect to WiFi access point
            wifi_dut.interfaces.wifi.mdns_init(ip_version=Si91xMdnsParams.IPV6)  # Initialize mDNS with IPv6 support
            wifi_dut.interfaces.wifi.mdns_add_interface()  # Add network interface to mDNS
            wifi_dut.interfaces.wifi.mdns_register_service()  # Register mDNS service for discovery

            # Test Avahi-daemon restart functionality
            service_discovery.interfaces.sd.stop_discovering_services()  # Stop Avahi service discovery
            status = service_discovery.interfaces.sd.get_status()  # Check service status
            logger().info(f"Service discovery status after stop: {status}")
            service_discovery.interfaces.sd.start_discovering_services()  # Restart Avahi service discovery
            time.sleep(20)  # Allow time for service discovery to stabilize
            service_discovery.interfaces.sd.stop_discovering_services()  # Stop service discovery again
            time.sleep(5)

            # Clean up mDNS and WiFi connection
            wifi_dut.interfaces.wifi.mdns_deinit()  # Deinitialize mDNS services
            wifi_dut.interfaces.wifi.leave()  # Disconnect from WiFi access point
            time.sleep(5)  # Allow time between cycles for stability

        # Stop packet capture and disconnect BLE
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()  # Stop packet capture
        ble_obj.ble_disconnect(disconnect_from="remote")  # Disconnect BLE from remote side

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        logger().info("Finally")
        
        # Use the standardized BLE cleanup function
        cleanup_ble_and_client(ble_client, ble_obj, wifi_dut, sl_collections)