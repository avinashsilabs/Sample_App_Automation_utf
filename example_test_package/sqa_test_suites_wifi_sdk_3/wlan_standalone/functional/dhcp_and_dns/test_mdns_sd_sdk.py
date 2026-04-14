import pytest
import time
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xJoinFeatureBitMap
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from threading import Thread
import threading

"""The testcases added in this file run below test steps for SOC
        1. Configure the DUT in wlan coex mode for 2.4Ghz
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Verify the MDNS service discovery feature
        
    setup requirement:
        1. SOC
        2. NUC
        3. Raspberry PI (with Avahi-daemon installed)
        4. Access Point(Third Party AP's)

    Author: Shailesh Kharecha

"""

def logger():
    return get_logger(__name__)

class WifiThreadFunctionality(ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None, sl_collections=None,
                 sniffer_filter=None, test_case=None, capture_filename=None, utf_constants=None):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.dut_addr = None
        self.iperf_throughput = None
        self.test_case = test_case
        self.capture_filename = capture_filename
        self.utf_constants = utf_constants

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}")

            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)

            # self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
            #                                                          associated=self.wifi_dut.interfaces.wifi.associated)
            iter_count = self.utf_constants.get("iter_count")
            for count in range(iter_count):
                self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                         associated=self.wifi_dut.interfaces.wifi.associated, ip_config_disable=True
                                                       )

                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = False
                ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30, ip_version='ipv4')
                device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                logger().info(f"*************device ip : {device_ip}*****************")
                self.wifi_dut.interfaces.wifi.is_external_stack_enabled = True

        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880516')
def test_wifi_sdk_verify_mdns_sd_functionality_with_hostname_c880516(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                     service_advertisement,
                                                                     sl_collections, request, utf_constants):
    """
    Test Case: Verify MDNS service discovery functionality with hostname.

    This test verifies:
    - MDNS initialization and service registration
    - Service discovery with hostname query
    - A Record and IPv4 address resolution in discovered services
    """
    try:
        # Step 1: Initialize test environment
        capture_filename = request.node.name
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Step 2: Configure WiFi DUT join parameters
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Step 3: Initialize WiFi connection thread with sniffer capture
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )

        # Step 4: Start WiFi connection and wait for completion
        obj.start()
        obj.wait_for_exit()

        # Step 5: Start advertising mDNS services on the service advertisement device
        logger().info("Starting mDNS service advertisement")
        # Publish HTTP service
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)


        # # Step 6: Run mDNS discovery iterations
        max_iterations = 2
        for iteration in range(1, max_iterations + 1):
            # logger().info(f"Starting mDNS discovery iteration {iteration}/{max_iterations}")

            # Initialize mDNS stack
            wifi_dut.interfaces.wifi.mdns_init()
            time.sleep(1)

            # Add network interface to mDNS
            wifi_dut.interfaces.wifi.mdns_add_interface()
            time.sleep(1)

            # Register mDNS service
            wifi_dut.interfaces.wifi.mdns_register_service()
            time.sleep(3)

            # Start service discovery with hostname query
            wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                service_type="rs9116test1.local.",
                query_type=1,
                timeout_ms=5000
            )
            time.sleep(3)

            # Step 7: Collect mDNS discovery events
            mdns_sd_list = []
            for events in range(0, 3):
                events = wifi_dut.interfaces.wifi.get_async_events()
                time.sleep(1)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"mDNS data received: {mdns_data}")
                        break

            time.sleep(3)

            # Step 8: Validate mDNS discovery results (only after first iteration)
            # if iteration > 1:
            logger().info("Validating mDNS discovery results")
            a_record_found = False
            ipv4_address_found = False

            # Check if A Record and IPv4 Address are present in discovered services
            for element in mdns_sd_list:
                if "=== A Record ===" in element:
                    logger().info("A Record found in mDNS discovery")
                    a_record_found = True
                if "IPv4 Address" in element:
                    logger().info("IPv4 Address found in mDNS discovery")
                    ipv4_address_found = True

            time.sleep(2)

            # Verify that both A Record and IPv4 Address were discovered
            if a_record_found and ipv4_address_found:
                logger().info("SUCCESS: A Record and IPv4 Address found in mDNS discovery")
            else:
                error_msg = "FAILURE: A Record and/or IPv4 Address not found in mDNS discovery"
                logger().error(error_msg)
                raise Exception(error_msg)

            # Clean up mDNS resources
            wifi_dut.interfaces.wifi.mdns_deinit()
            time.sleep(3)

        # Step 9: Stop packet capture
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Step 10: Cleanup - Stop all advertising services
        service_advertisement.interfaces.sa.stop_advertising_services()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880517')
def test_wifi_sdk_verify_mdns_functionality_with_mdns_service_query_type_c880517(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        service_advertisement,
        sl_collections,
        request,
        utf_constants
):
    """
    Test Case: Verify mDNS TXT record discovery functionality.

    This test validates:
    - mDNS initialization and service registration
    - TXT record query (query_type=16) for HTTP services
    - Proper parsing and validation of TXT records in mDNS responses

    """
    try:
        # Generate unique capture filename from test case name
        capture_filename = request.node.name

        # Stop any existing service advertisements to ensure clean test state
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi DUT with default join feature bitmap
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize WiFi connection thread with packet capture
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )

        # Start WiFi connection and wait for completion
        obj.start()
        obj.wait_for_exit()

        # Start HTTP service advertisement with hostname and path TXT record
        logger().info("Starting HTTP service advertisement with TXT records")
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Run mDNS discovery for specified iterations
        max_iterations = 2
        for iteration in range(1, max_iterations + 1):
            logger().info(f"Starting mDNS TXT record discovery iteration {iteration}/{max_iterations}")

            # Initialize mDNS stack
            wifi_dut.interfaces.wifi.mdns_init()
            time.sleep(1)

            # Add network interface to mDNS service
            wifi_dut.interfaces.wifi.mdns_add_interface()
            time.sleep(1)

            # Register mDNS service on the DUT
            wifi_dut.interfaces.wifi.mdns_register_service()
            time.sleep(3)

            # Start service discovery with TXT record query type
            # query_type=16 corresponds to DNS TXT record queries
            wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                service_type="_http._tcp.local.",
                query_type=16,
                timeout_ms=5000
            )
            time.sleep(3)

            # Collect mDNS discovery events from DUT
            mdns_sd_list = []
            for _ in range(3):
                events = wifi_dut.interfaces.wifi.get_async_events()
                time.sleep(1)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"mDNS TXT record data received: {mdns_data}")
                        break

            time.sleep(3)

            # Validate that TXT records were discovered
            logger().info("Validating mDNS TXT record discovery results")
            txt_record_found = False

            # Search for TXT record marker in discovered service data
            for element in mdns_sd_list:
                if "=== TXT Record ===" in element:
                    logger().info("TXT Record found in mDNS discovery response")
                    txt_record_found = True

            time.sleep(2)

            # Verify TXT record discovery success
            if txt_record_found:
                logger().info("SUCCESS: TXT Record successfully discovered via mDNS")
            else:
                error_msg = "FAILURE: TXT Record not found in mDNS discovery response"
                logger().error(error_msg)
                raise Exception(error_msg)

            # Clean up mDNS resources before next iteration
            wifi_dut.interfaces.wifi.mdns_deinit()
            time.sleep(3)

        # Stop packet capture after test completion
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle test execution errors
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880518')
def test_wifi_sdk_verify_mdns_functionality_with_mdns_service_query_name_C880518(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        service_advertisement,
        sl_collections,
        request,
        utf_constants
):
    """
    Test Case: Verify mDNS functionality with service query by name.

    This test verifies mDNS discovery functionality by:
    1. Setting up Avahi service advertisements on the remote side
    2. Performing mDNS service discovery from the DUT
    3. Validating PTR records are discovered correctly
    """

    try:
        # Initialize test parameters
        capture_filename = request.node.name

        # Stop any existing service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi DUT join feature bitmap
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize WiFi thread functionality and wait for connection
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )
        obj.start()
        obj.wait_for_exit()

        # Start HTTP service advertisement
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Start UDP service advertisement
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        logger().info("Service advertisements started successfully")
        ptr_record_found = False
        service_type_found = False
        # Perform mDNS discovery test iterations
        for iteration in range(1, 3):
            logger().info(f"Starting iteration {iteration}")

            # Initialize mDNS on the DUT
            wifi_dut.interfaces.wifi.mdns_init()
            time.sleep(1)

            # Add network interface for mDNS
            wifi_dut.interfaces.wifi.mdns_add_interface()
            time.sleep(1)

            # Register mDNS service
            wifi_dut.interfaces.wifi.mdns_register_service()
            time.sleep(3)

            # Start mDNS service discovery
            wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                service_type="_http._tcp.local.",
                query_type=12,
                timeout_ms=50000
            )
            time.sleep(3)

            # Collect mDNS events
            mdns_sd_list = []
            for events in range(0, 3):
                events = wifi_dut.interfaces.wifi.get_async_events()
                time.sleep(1)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"mDNS data received: {mdns_data}")
                        break

            time.sleep(3)

            for element in mdns_sd_list:
                if "=== PTR Record ===" in element:
                    logger().info("PTR Record found in mDNS response")
                    ptr_record_found = True
                if "_http._tcp.local." in element:
                    logger().info("Service type _http._tcp.local. found in mDNS response")
                    service_type_found = True


            # Deinitialize mDNS after each iteration
            wifi_dut.interfaces.wifi.mdns_deinit()
            time.sleep(3)
            # time.sleep(2)

        # Assert both PTR record and service type are discovered
        if ptr_record_found and service_type_found:
            logger().info("mDNS discovery successful: PTR Record and service type found")
        else:
            error_msg = "mDNS discovery failed: PTR Record or service type not found"
            logger().error(error_msg)
            raise Exception(error_msg)

        # Stop packet capture
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle exceptions and perform cleanup
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880519')
def test_wifi_sdk_verify_mdns_functionality_with_mdns_service_srv_query_type_c880519(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        service_advertisement,
        sl_collections,
        request,
        utf_constants
):
    """
    Test Case: Verify mDNS SRV record discovery functionality.

    This test validates:
    - mDNS initialization and service registration
    - SRV record query (query_type=33) for HTTP services
    - Proper parsing and validation of SRV records in mDNS responses

    """
    try:
        # Generate unique capture filename from test case name
        capture_filename = request.node.name

        # Stop any existing service advertisements to ensure clean test state
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi DUT with default join feature bitmap
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize WiFi connection thread with packet capture
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )

        # Start WiFi connection and wait for completion
        obj.start()
        obj.wait_for_exit()

        # Start HTTP service advertisement with hostname and path SRV record
        logger().info("Starting HTTP service advertisement with SRV records")
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Run mDNS discovery for specified iterations
        max_iterations = 2
        for iteration in range(1, max_iterations + 1):
            logger().info(f"Starting mDNS SRV record discovery iteration {iteration}/{max_iterations}")

            # Initialize mDNS stack
            wifi_dut.interfaces.wifi.mdns_init()
            time.sleep(1)

            # Add network interface to mDNS service
            wifi_dut.interfaces.wifi.mdns_add_interface()
            time.sleep(1)

            # Register mDNS service on the DUT
            wifi_dut.interfaces.wifi.mdns_register_service()
            time.sleep(3)

            # Start service discovery with SRV record query type
            # query_type=33 corresponds to DNS SRV record queries
            wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                service_type="_http._tcp.local.",
                query_type=33,
                timeout_ms=5000
            )
            time.sleep(3)

            # Collect mDNS discovery events from DUT
            mdns_sd_list = []
            for _ in range(3):
                events = wifi_dut.interfaces.wifi.get_async_events()
                time.sleep(1)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"mDNS SRV record data received: {mdns_data}")
                        break

            time.sleep(3)

            # Validate that SRV records were discovered
            logger().info("Validating mDNS SRV record discovery results")
            txt_record_found = False

            # Search for SRV record marker in discovered service data
            for element in mdns_sd_list:
                if "=== SRV Record ===" in element:
                    logger().info("SRV Record found in mDNS discovery response")
                    txt_record_found = True

            time.sleep(2)

            # Verify SRV record discovery success
            if txt_record_found:
                logger().info("SUCCESS: SRV Record successfully discovered via mDNS")
            else:
                error_msg = "FAILURE: SRV Record not found in mDNS discovery response"
                logger().error(error_msg)
                raise Exception(error_msg)

            # Clean up mDNS resources before next iteration
            wifi_dut.interfaces.wifi.mdns_deinit()
            time.sleep(3)

        # Stop packet capture after test completion
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle test execution errors
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880521')
def test_wifi_sdk_discover_mdns_service_with_ipv6_records_C880521(
        wifi_sniffer, wifi_access_point, wifi_dut,
        service_advertisement, sl_collections, request, utf_constants
):
    """
    Test Case: Verify mDNS functionality with IPv6 records (AAAA records).

    This test verifies that the DUT can discover mDNS services advertising IPv6 records
    by starting Avahi services and querying for AAAA records through the mDNS service discovery.

    Steps:
    1. Stop any existing advertising services
    2. Configure WiFi DUT with default join feature bitmap
    3. Initialize WiFi thread functionality and start packet capture
    4. Start advertising two test services via Avahi
    5. mDNS discovery with IPv6 query
    6. Validate AAAA records and IPv6 addresses are discovered
    """

    try:
        # Set up the capture filename from test node name
        capture_filename = request.node.name

        # Stop any previously running advertising services
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure the WiFi DUT's join feature bitmap to default settings
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize WiFi thread functionality for connection and packet capture
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )

        # Start the WiFi functionality and wait for initialization to complete
        obj.start()
        obj.wait_for_exit()

        logger().info("Starting Avahi service advertisements")

        # Start advertising HTTP service on port 80
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Start advertising UDP service on port 12345
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        # Perform mDNS discovery in 2 iterations
        # First iteration: Initialize and discover services
        # Second iteration: Validate IPv6 records are present
        iteration = 1
        # Flags to track if required records are found
        aaaa_record_found = False
        ipv6_address_found = False
        while iteration <= 2:
            logger().info(f"Starting iteration {iteration} of mDNS discovery")

            # Initialize mDNS on the device
            wifi_dut.interfaces.wifi.mdns_init()
            time.sleep(1)

            # Add network interface to mDNS
            wifi_dut.interfaces.wifi.mdns_add_interface()
            time.sleep(1)

            # Register the mDNS service
            wifi_dut.interfaces.wifi.mdns_register_service()
            time.sleep(3)

            # Start mDNS service discovery for IPv6 records (query_type=28 is for AAAA records)
            wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                service_type="rs9116test1.local.",
                query_type=28,  # AAAA record query type for IPv6
                timeout_ms=5000
            )
            time.sleep(3)

            # Initialize variables for collecting mDNS events
            mdns_data = ""
            events = []
            mdns_sd_list = []

            # Retrieve async events from the WiFi interface
            for events in range(0, 3):
                events = wifi_dut.interfaces.wifi.get_async_events()
                time.sleep(1)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"mDNS data received: {mdns_data}")
                        break

            time.sleep(3)
            # Validate IPv6 records only in the second iteration
            if iteration > 1:
                logger().info(f"MDNS discovered services: {mdns_sd_list}")

                # Check for AAAA record and IPv6 address in discovered services
                for element in mdns_sd_list:
                    if "=== AAAA Record ===" in element:
                        logger().info("AAAA Record found in mDNS discovery")
                        aaaa_record_found = True

                    if "IPv6 Address" in element:
                        logger().info("IPv6 Address found in mDNS discovery")
                        ipv6_address_found = True

                time.sleep(2)
            iteration += 1

            # Deinitialize mDNS after each iteration
            wifi_dut.interfaces.wifi.mdns_deinit()
            # Validate that both AAAA record and IPv6 address were discoveredS
        if aaaa_record_found and ipv6_address_found:
            logger().info('SUCCESS: AAAA Record and IPv6 Address found in mDNS discovery')
        else:
            error_msg = "FAILURE: AAAA Record and IPv6 Address not found in mDNS discovery"
            logger().error(error_msg)
            raise Exception(error_msg)
            time.sleep(3)
            # Stop packet capture after completing all iterations
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle any exceptions that occur during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Ensure advertising services are stopped in cleanup
        service_advertisement.interfaces.sa.stop_advertising_services()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880522')
def test_verify_the_MDNS_service_discovery_when_announce_2_or_more_services_c880522(
        wifi_sniffer, wifi_access_point, wifi_dut, service_advertisement,
        sl_collections, request, utf_constants):
    """
    Verify MDNS service discovery functionality when multiple services are announced.

    Test validates that the DUT can discover both HTTP and UDP services advertised
    by the service_advertisement interface using mDNS-SD protocol.
    """


    HTTP_SERVICE_TYPE = "_http._tcp.local."
    ALEXA_SERVICE_TYPE = "_alexa._tcp.local."
    UDP_SERVICE_TYPE = "_myservice._udp.local."
    DISCOVERY_SERVICE_TYPE = "_services._dns-sd._udp.local."

    try:
        # Initialize test setup
        capture_filename = request.node.name

        # Stop any existing service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi join feature bitmap
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize and start WiFi thread functionality
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )
        obj.start()
        obj.wait_for_exit()

        # Start advertising HTTP service
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Start advertising UDP service
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        logger().info("Service advertisement started successfully")


        # Initialize mDNS
        wifi_dut.interfaces.wifi.mdns_init()
        time.sleep(1)

        # Add network interface for mDNS
        wifi_dut.interfaces.wifi.mdns_add_interface()
        time.sleep(1)

        # Register mDNS service
        wifi_dut.interfaces.wifi.mdns_register_service()
        time.sleep(5)

        # Start mDNS service discovery
        wifi_dut.interfaces.wifi.mdns_service_discovery_start(
            service_type=DISCOVERY_SERVICE_TYPE,
            query_type=255,
            timeout_ms=5000
        )

        # Collect async events
        mdns_sd_list = []
        events = wifi_dut.interfaces.wifi.get_async_events()
        time.sleep(3)

        # Process mDNS service discovery events
        for events in range(0, 3):
            events = wifi_dut.interfaces.wifi.get_async_events()
            time.sleep(1)
            for event in events:
                if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                    mdns_data = event.event_data
                    mdns_sd_list.append(mdns_data)
                    logger().info(f"mDNS data received: {mdns_data}")
                    break

        time.sleep(3)

        # Validate discovered services (skip first iteration)

        http_service_found = False
        udp_service_found = False

            # Check for both service types in discovered services
        for service_data in mdns_sd_list:
            if HTTP_SERVICE_TYPE in service_data or ALEXA_SERVICE_TYPE in service_data:
                logger().info(f"HTTP/Alexa service discovered: {service_data}")
                http_service_found = True

            if UDP_SERVICE_TYPE in service_data:
                logger().info(f"UDP service discovered: {service_data}")
                udp_service_found = True

            time.sleep(1)

        # Verify both services were discovered
        if http_service_found and udp_service_found:
            logger().info("Both services successfully discovered in mDNS")
        else:
            error_msg = "Service discovery failed - "
            if not http_service_found:
                error_msg += "HTTP service not found. "
            if not udp_service_found:
                error_msg += "UDP service not found."
            logger().error(error_msg)
            raise Exception(error_msg)

        # Cleanup mDNS for this iteration
        wifi_dut.interfaces.wifi.mdns_deinit()
        time.sleep(3)

        # Stop packet capture
        logger().info("Stopping WiFi sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880524')
def test_verify_the_continue_mdns_sd_when_host_starts_and_stops_the_service_advertisement_c880524(
        wifi_sniffer, wifi_access_point, wifi_dut, service_advertisement, sl_collections, request, utf_constants
):
    """
    Verify MDNS functionality when host starts and stops service advertisement.

    Test flow:
    1. Stop any existing service advertisements
    2. Initialize WiFi DUT and start sniffer
    3. Run two iterations:
       - First: Start service, discover it via mDNS
       - Second: Verify service discovery, then verify service disappears after stopping advertisement
    """

    try:
        # Initialize test parameters
        capture_filename = request.node.name

        # Ensure no services are running before starting test
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi DUT join feature bitmap
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Start WiFi thread functionality with sniffer
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )
        obj.start()
        obj.wait_for_exit()

        # Run test for 2 iterations
        for iteration in range(1, 3):
            logger().info(f"-------------------Iteration = {iteration}---------------------")

            # Start advertising mDNS service
            service_advertisement.interfaces.sa.start_advertising_services(
                command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
            )
            time.sleep(5)

            # Initialize mDNS on DUT
            wifi_dut.interfaces.wifi.mdns_init()
            time.sleep(1)

            # Add network interface for mDNS
            wifi_dut.interfaces.wifi.mdns_add_interface()
            time.sleep(1)

            # Register mDNS service
            wifi_dut.interfaces.wifi.mdns_register_service()
            time.sleep(5)

            # Start mDNS service discovery
            wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                service_type='_services._dns-sd._udp.local.',
                query_type=255,
                timeout_ms=5000
            )

            # Collect mDNS discovery events
            mdns_sd_list = []
            events = wifi_dut.interfaces.wifi.get_async_events()
            time.sleep(3)

            # Parse events and collect mDNS service discovery data
            for events in range(0, 3):
                events = wifi_dut.interfaces.wifi.get_async_events()
                time.sleep(1)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"mDNS data received: {mdns_data}")
                        break

            time.sleep(3)

            # On second iteration, verify service discovery and test stopping advertisement
            if iteration > 1:
                # Verify service is discovered
                service_found = any("_myservice._udp.local." in element for element in mdns_sd_list)

                if service_found:
                    logger().info("Services found in mDNS discovery")
                else:
                    logger().error("Services not found in mDNS discovery")
                    raise Exception("Services not found in mDNS discovery")

                time.sleep(5)

                # Stop service discovery
                wifi_dut.interfaces.wifi.mdns_service_discovery_stop()
                time.sleep(5)

                # Stop the service advertisement
                service_advertisement.interfaces.sa.stop_advertising_services()
                time.sleep(2)

                # Verify service is no longer discoverable after stopping advertisement
                logger().info("Checking mDNS discovery after stopping service advertisement")
                since_time = time.perf_counter_ns()

                # Restart service discovery
                wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                    service_type='_services._dns-sd._udp.local.',
                    query_type=255,
                    timeout_ms=5000
                )

                # Collect new events
                mdns_sd_list = []
                events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                time.sleep(3)

                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"MDNS DATA FROM EVENT: {mdns_data}")

                time.sleep(3)

                # Verify service is NOT found after stopping advertisement
                service_found_after_stop = any("_myservice._udp.local." in element for element in mdns_sd_list)

                if not service_found_after_stop:
                    logger().info("Service not found in mDNS discovery, which is expected")
                else:
                    logger().error("Service found in mDNS discovery, which is not expected")
                    raise Exception("Service found in mDNS discovery after stopping advertisement")

                time.sleep(5)
            # Cleanup mDNS
            wifi_dut.interfaces.wifi.mdns_deinit()
            time.sleep(3)

        # Stop packet capture
        logger().info("Stopping the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Ensure service advertisement is stopped
        service_advertisement.interfaces.sa.stop_advertising_services()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880525')
def test_start_mdns_sd_with_tcp_udp_services_c880525(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        service_advertisement,
        sl_collections,
        request,
        utf_constants
):
    """
    Test Case: Verify mDNS service discovery functionality for both TCP and UDP services.

    This test validates:
    1. Discovery of TCP-based HTTP services via mDNS
    2. Discovery of UDP-based custom services via mDNS
    3. Proper handling of mDNS initialization, registration, and deinitialization

    Test Flow:
    - Phase 1: Advertise and discover HTTP TCP service
    - Phase 2: Advertise and discover UDP service
    """

    # Service type constants
    HTTP_SERVICE_TYPE = "_http._tcp.local."
    ALEXA_SERVICE_TYPE = "_alexa._tcp.local."
    UDP_SERVICE_TYPE = "_myservice._udp.local."
    DNS_SD_SERVICE_TYPE = "_services._dns-sd._udp.local."

    try:
        # Step 1: Initialize test environment
        capture_filename = request.node.name

        # Stop any existing service advertisements to ensure clean state
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Step 2: Configure WiFi DUT with default join parameters
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Step 3: Initialize WiFi connection thread with packet capture
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )

        # Step 4: Start WiFi connection and wait for completion
        obj.start()
        obj.wait_for_exit()

        # ========== PHASE 1: TCP Service Discovery ==========
        logger().info("========== Starting TCP Service Discovery Phase ==========")

        # Step 5: Advertise HTTP TCP service on port 880
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "MyHTTPSServer" _http._tcp 880 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Step 6: Initialize mDNS on DUT
        logger().info("Initializing mDNS module")
        wifi_dut.interfaces.wifi.mdns_init()
        time.sleep(1)

        # Step 7: Add network interface for mDNS
        wifi_dut.interfaces.wifi.mdns_add_interface()
        time.sleep(1)

        # Step 8: Register mDNS service on DUT
        wifi_dut.interfaces.wifi.mdns_register_service()
        time.sleep(5)

        # Step 9: Start mDNS service discovery for HTTP TCP service
        logger().info(f"Starting mDNS discovery for {HTTP_SERVICE_TYPE}")
        data = wifi_dut.interfaces.wifi.mdns_service_discovery_start(
            service_type=HTTP_SERVICE_TYPE,
            query_type=12,  # PTR query type
            timeout_ms=5000
        )
        logger().info(f"mDNS service discovery start response: {data}")

        # Step 10: Collect mDNS async events for TCP service
        mdns_sd_list = []
        for _ in range(3):
            events = wifi_dut.interfaces.wifi.get_async_events()
            time.sleep(1)
            for event in events:
                if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                    mdns_data = event.event_data
                    mdns_sd_list.append(mdns_data)
                    logger().info(f"mDNS TCP service data received: {mdns_data}")
                    break

        time.sleep(3)

        # Step 11: Validate TCP service was discovered
        tcp_service_found = False
        for element in mdns_sd_list:
            if HTTP_SERVICE_TYPE in element or ALEXA_SERVICE_TYPE in element:
                logger().info(f"TCP service discovered: {element}")
                tcp_service_found = True
                break

        time.sleep(1)

        # Verify TCP service discovery result
        if tcp_service_found:
            logger().info("✓ TCP service successfully found in mDNS discovery")
        else:
            logger().error("✗ TCP service NOT found in mDNS discovery")
            raise Exception("TCP service not found in mDNS discovery")

        # Step 12: Cleanup TCP discovery phase
        time.sleep(2)
        wifi_dut.interfaces.wifi.mdns_deinit()
        time.sleep(3)
        wifi_dut.interfaces.wifi.mdns_service_discovery_stop()
        time.sleep(5)

        # ========== PHASE 2: UDP Service Discovery ==========
        logger().info("========== Starting UDP Service Discovery Phase ==========")

        # Step 13: Advertise UDP service on port 12345
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        # Step 14: Reinitialize mDNS for UDP discovery
        logger().info("Reinitializing mDNS module for UDP service")
        wifi_dut.interfaces.wifi.mdns_init()
        time.sleep(1)
        wifi_dut.interfaces.wifi.mdns_add_interface()
        time.sleep(1)
        wifi_dut.interfaces.wifi.mdns_register_service()
        time.sleep(5)

        # Step 15: Start mDNS service discovery for all DNS-SD services
        logger().info(f"Starting mDNS discovery for {DNS_SD_SERVICE_TYPE}")
        data = wifi_dut.interfaces.wifi.mdns_service_discovery_start(
            service_type=DNS_SD_SERVICE_TYPE,
            query_type=255,  # ANY query type
            timeout_ms=5000
        )
        logger().info(f"mDNS service discovery start response: {data}")

        # Step 16: Collect mDNS async events for UDP service
        mdns_sd_list = []
        time.sleep(2)
        for _ in range(3):
            events = wifi_dut.interfaces.wifi.get_async_events()
            time.sleep(1)
            for event in events:
                if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                    mdns_data = event.event_data
                    mdns_sd_list.append(mdns_data)
                    logger().info(f"mDNS UDP service data received: {mdns_data}")
                    break

            time.sleep(3)

        # Step 17: Validate UDP service was discovered
        udp_service_found = False
        for element in mdns_sd_list:
            if UDP_SERVICE_TYPE in element:
                logger().info(f"UDP service discovered: {element}")
                udp_service_found = True
                break

        time.sleep(1)

        # Verify UDP service discovery result
        if udp_service_found:
            logger().info("✓ UDP service successfully found in mDNS discovery")
        else:
            logger().error("✗ UDP service NOT found in mDNS discovery")
            raise Exception("UDP service not found in mDNS discovery")

        # Step 18: Final cleanup
        time.sleep(5)
        wifi_dut.interfaces.wifi.mdns_deinit()
        time.sleep(3)

        # Step 19: Stop packet capture
        logger().info("Stopping WiFi sniffer packet capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle any exceptions during test execution
        logger().error(f"Test failed with exception: {ex}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)
        raise

    finally:
        # Step 20: Cleanup - Stop all service advertisements
        logger().info("Cleanup: Stopping all service advertisements")
        service_advertisement.interfaces.sa.stop_advertising_services()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880526')
def test_wifi_sdk_verify_mdns_sd_functionality_start_stop_in_loop_c880526(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        service_advertisement,
        sl_collections,
        request,
        utf_constants
):
    """
    Test Case: Verify mDNS functionality with service query by name.

    This test verifies mDNS discovery functionality by:
    1. Setting up Avahi service advertisements on the remote side
    2. Performing mDNS service discovery start and stop from the DUT

    """

    try:
        # Initialize test parameters
        capture_filename = request.node.name

        # Stop any existing service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi DUT join feature bitmap
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize WiFi thread functionality and wait for connection
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )
        obj.start()
        obj.wait_for_exit()

        # Start HTTP service advertisement
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Start UDP service advertisement
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        logger().info("Service advertisements started successfully")
        ptr_record_found = False
        service_type_found = False

        # Initialize mDNS on the DUT
        wifi_dut.interfaces.wifi.mdns_init()
        time.sleep(1)

        # Add network interface for mDNS
        wifi_dut.interfaces.wifi.mdns_add_interface()
        time.sleep(1)

        # Register mDNS service
        wifi_dut.interfaces.wifi.mdns_register_service()
        time.sleep(3)
        iterations=1
        while(iterations <= 3):
            # Start mDNS service discovery
            wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                service_type="_http._tcp.local.",
                query_type=12,
                timeout_ms=50000
            )
            time.sleep(3)

            # Collect mDNS events
            mdns_sd_list = []
            # events = wifi_dut.interfaces.wifi.get_async_events()
            time.sleep(3)

            # Parse mDNS discovery events
            for events in range(0, 3):
                events = wifi_dut.interfaces.wifi.get_async_events()
                time.sleep(1)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"mDNS data received: {mdns_data}")
                        break

            time.sleep(3)

            for element in mdns_sd_list:
                if "=== PTR Record ===" in element:
                    logger().info("PTR Record found in mDNS response")
                    ptr_record_found = True
                if "_http._tcp.local." in element:
                    logger().info("Service type _http._tcp.local. found in mDNS response")
                    service_type_found = True
                    # Assert both PTR record and service type are discovered
            if ptr_record_found and service_type_found:
                logger().info("mDNS discovery successful: PTR Record and service type found")
            else:
                error_msg = "mDNS discovery failed: PTR Record or service type not found"
                logger().error(error_msg)
                raise Exception(error_msg)
            time.sleep(3)
            wifi_dut.interfaces.wifi.mdns_service_discovery_stop()
            time.sleep(3)
            iterations=iterations+1

        # Stop packet capture
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle exceptions and perform cleanup
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)

@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880528')
def test_verify_the_mdns_sd_with_timeout_less_than_5_sec_c880528(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        service_advertisement,
        sl_collections,
        request,
        utf_constants
):
    """
    Test Case: Verify mDNS functionality with service query by name.

    This test verifies mDNS discovery functionality by:
    1. Setting up Avahi service advertisements on the remote side
    2. Performing mDNS service discovery from the DUT
    3. Validating PTR records are discovered correctly
    """

    try:
        # Initialize test parameters
        capture_filename = request.node.name

        # Stop any existing service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi DUT join feature bitmap
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize WiFi thread functionality and wait for connection
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )
        obj.start()
        obj.wait_for_exit()

        # Start HTTP service advertisement
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Start UDP service advertisement
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        logger().info("Service advertisements started successfully")
        ptr_record_found = False
        service_type_found = False
        # Perform mDNS discovery test iterations
        for iteration in range(1, 3):
            logger().info(f"Starting iteration {iteration}")

            # Initialize mDNS on the DUT
            wifi_dut.interfaces.wifi.mdns_init()
            time.sleep(1)

            # Add network interface for mDNS
            wifi_dut.interfaces.wifi.mdns_add_interface()
            time.sleep(1)

            # Register mDNS service
            wifi_dut.interfaces.wifi.mdns_register_service()
            time.sleep(3)

            # Start mDNS service discovery
            wifi_dut.interfaces.wifi.mdns_service_discovery_start(
                service_type="_http._tcp.local.",
                query_type=12,
                timeout_ms=3000
            )
            time.sleep(3)

            # Collect mDNS events
            mdns_sd_list = []
            # events = wifi_dut.interfaces.wifi.get_async_events()
            # time.sleep(3)
            #
            # # Parse mDNS discovery events
            # for event in events:
            #     if event.event_type == AsyncEventIdentifiers.MDNS_SD:
            #         mdns_data = event.event_data
            #         mdns_sd_list.append(mdns_data)
            #         logger().info(f"mDNS data received: {mdns_data}")

            for events in range(0, 3):
                events = wifi_dut.interfaces.wifi.get_async_events()
                time.sleep(1)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.MDNS_SD:
                        mdns_data = event.event_data
                        mdns_sd_list.append(mdns_data)
                        logger().info(f"mDNS data received: {mdns_data}")
                        break

            time.sleep(3)

            for element in mdns_sd_list:
                if "=== PTR Record ===" in element:
                    logger().info("PTR Record found in mDNS response")
                    ptr_record_found = True
                if "_http._tcp.local." in element:
                    logger().info("Service type _http._tcp.local. found in mDNS response")
                    service_type_found = True


            # Deinitialize mDNS after each iteration
            wifi_dut.interfaces.wifi.mdns_deinit()
            time.sleep(3)
            # time.sleep(2)

        # Assert both PTR record and service type are discovered
        if ptr_record_found and service_type_found:
            logger().info("mDNS discovery successful: PTR Record and service type found")
        else:
            error_msg = "mDNS discovery failed: PTR Record or service type not found"
            logger().error(error_msg)
            raise Exception(error_msg)

        # Stop packet capture
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle exceptions and perform cleanup
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880529')
def test_verify_mdns_sd_using_wrong_service_name_c880529(
        wifi_sniffer, wifi_access_point, wifi_dut, service_advertisement,
        sl_collections, request, utf_constants
):
    """
    Verify mDNS functionality using a non-existent service name.

    This test verifies that the device correctly handles mDNS service discovery
    requests for non-existent services by returning the appropriate error code.
    """

    try:
        # Generate capture filename based on test name
        capture_filename = request.node.name
        # Stop any existing service advertisements to ensure clean test state
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)
        # Configure join feature bitmap with default settings for client interface
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )
        # Initialize WiFi thread functionality for connection and network setup
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )

        # Start WiFi connection thread and wait for completion
        obj.start()
        obj.wait_for_exit()

        # Advertise HTTP service on port 80
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Advertise UDP service on port 12345
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        # Initialize mDNS module on the DUT
        wifi_dut.interfaces.wifi.mdns_init()
        time.sleep(1)

        # Add network interface for mDNS
        wifi_dut.interfaces.wifi.mdns_add_interface()
        time.sleep(1)

        # Register mDNS service on the DUT
        wifi_dut.interfaces.wifi.mdns_register_service()
        time.sleep(5)

        # Attempt to discover a non-existent service
        # This should return SL_STATUS_IN_PROGRESS (error code 0x00005)
        wifi_dut.interfaces.wifi.mdns_service_discovery_start(
            service_type='_nonexistent._tcp.local.',
            query_type=12,
            timeout_ms=5000,
            expected_status=SLStatus.SL_STATUS_IN_PROGRESS
        )
        # Log successful error handling
        logger().info(
            "******* DUT sent error code 0x00005 when non-existent service is called "
            "which is expected *******"
        )
        # Stop packet capture
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880531')
def test_mdns_feature_not_enabled_in_opermode_c880531(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        service_advertisement,
        sl_collections,
        request,
        utf_constants
):
    """
    Test Case: Verify mDNS functionality when feature is not enabled in opermode.

    This test verifies that the DUT returns the correct error code (SL_STATUS_SI91X_FEATURE_NOT_ENABLED)
    when attempting to initialize mDNS without enabling the mDNS feature in the TCP/IP feature bitmap.

    Expected behavior:
    - mDNS init should fail with error code 0x1ff74 (SL_STATUS_SI91X_FEATURE_NOT_ENABLED)
    """

    try:
        # Generate capture filename from test node name
        capture_filename = request.node.name

        # Stop any existing service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi join feature bitmap with default settings
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize WiFi thread functionality for connection and packet capture
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )

        # Start WiFi connection and wait for completion
        obj.start()
        obj.wait_for_exit()

        # Start HTTP service advertisement on port 80
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Start UDP service advertisement on port 12345
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        logger().info("Service advertisements started successfully")

        # Attempt to initialize mDNS when feature is not enabled
        # This should return SL_STATUS_SI91X_FEATURE_NOT_ENABLED (0x1ff74)
        wifi_dut.interfaces.wifi.mdns_init(
            expected_status=SLStatus.SL_STATUS_SI91X_FEATURE_NOT_ENABLED
        )

        # Log successful error handling
        logger().info(
            "DUT sent error code 0x1ff74 when mDNS feature is not enabled which is expected"
        )

        # Stop packet capture
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle any exceptions during test execution
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.mDNSSD |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C880532')
def test_verify_dut_allows_configuration_of_invalid_parameters_or_not_c880532(
        wifi_sniffer,
        wifi_access_point,
        wifi_dut,
        service_advertisement,
        sl_collections,
        request,
        utf_constants
):
    """
    Test Case: Verify DUT correctly rejects mDNS service discovery with invalid query type.

    This test validates that the device properly handles mDNS service discovery requests
    with invalid query_type parameter (query_type=1 is invalid for service discovery).
    The expected behavior is to return SL_STATUS_IN_PROGRESS error code.

    """
    try:
        # Generate unique capture filename from test case name
        capture_filename = request.node.name

        # Stop any existing service advertisements to ensure clean test state
        service_advertisement.interfaces.sa.stop_advertising_services()
        time.sleep(2)

        # Configure WiFi DUT with default join feature bitmap
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            interface='client',
            join_feature_bitmap=Si91xJoinFeatureBitMap.Default
        )

        # Initialize WiFi connection thread with packet capture
        obj = WifiThreadFunctionality(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            sl_collections=sl_collections,
            test_case=request.node.name,
            capture_filename=capture_filename,
            utf_constants=utf_constants
        )

        # Start WiFi connection and wait for completion
        obj.start()
        obj.wait_for_exit()

        # Start HTTP service advertisement on port 80 with hostname
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "TestService" _http._tcp 80 -H rs9116test-alt.local2 /index.html -v'
        )
        time.sleep(5)

        # Start UDP service advertisement on port 12345 with hostname
        service_advertisement.interfaces.sa.start_advertising_services(
            command_args='avahi-publish-service "My UDP Service" _myservice._udp 12345 -H rs9116test-alt.local2 -v'
        )
        time.sleep(5)

        # Initialize mDNS stack
        wifi_dut.interfaces.wifi.mdns_init()
        time.sleep(1)

        # Add network interface to mDNS service
        wifi_dut.interfaces.wifi.mdns_add_interface()
        time.sleep(1)

        # Register mDNS service on the DUT
        wifi_dut.interfaces.wifi.mdns_register_service()
        time.sleep(5)

        # Attempt service discovery with invalid query_type parameter
        # query_type=1 (A record) is invalid for service discovery
        # Expected status: SL_STATUS_IN_PROGRESS (0x00005)
        wifi_dut.interfaces.wifi.mdns_service_discovery_start(
            service_type='_http._tcp.local.',
            query_type=1,
            timeout_ms=5000,
            expected_status=SLStatus.SL_STATUS_IN_PROGRESS
        )

        # Log successful error handling validation
        logger().info(
            "******* DUT correctly returned error code 0x00005 (SL_STATUS_IN_PROGRESS) "
            "when invalid query_type=1 was used for service discovery *******"
        )

        # Stop packet capture
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as ex:
        # Handle test execution errors
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=ex)

    finally:
        # Cleanup: Stop all service advertisements
        service_advertisement.interfaces.sa.stop_advertising_services()


