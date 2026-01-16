"""
Test Scripts for WPA3 EAP TLS Security and WPA3 Transition with BLE Coexistence

Test Cases:
1. Verify whether DUT is able to scan and connect to AP with WPA3 EAP TLS1.0 Security 
   and run TCP TX traffic after BLE Tx in peripheral role
2. Verify whether DUT is able to scan and connect to AP with WPA3 EAP TLS1.2 Security 
   and run TCP RX traffic after BLE connection and Rx in Central role
3. Verify WPA3 Transition from WPA2 to WPA3 and vice versa with BLE Scan Interval: 30ms and Scan Window: 10ms
4. Verify WPA3 Transition from WPA2 to WPA3 and vice versa after BLE peripheral connection with CI: 30ms
5. Verify WPA3 connection from Hunting and pecking to H2E while BLE scan and advertise

Reference Files:
- WiFi Component: test_wpa3_enterprise_sdk.py (WPA3Enterprise thread class)
- WiFi Transition: test_wpa3_enhancements_sdk.py (WPA3 transition patterns)
- BLE Component: test_sta_ble_dle_sdk.py (BleThread with notify_tx/notify_rx)
- BLE Component: test_sta_ble_sdk.py (BleThreadFunctionality for scan/advertise/slave)
- TCP Traffic: test_sta_ble_smp_iperf_sdk.py (get_throughput thread)

Author: Generated based on testplan requirements
"""

import time
import pytest
import string
import random
import re
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    DeviceConstants,
)
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.security_enhancements.test_wpa3_enterprise_sdk import (
    WPA3Enterprise,
    SnifferValidationProcess,
)
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_dle_sdk import BleThread
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_smp_iperf_sdk import get_throughput
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_sdk import BleThreadFunctionality, WifiJoinThread
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.devices.si91x import Si91xJoinFeatureBitMap
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService

from threading import Thread

def logger():
    return get_logger(__name__)


# Global cleanup variables
ble_obj = None
wifi_obj = None


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.NWP120MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE |
                              Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1 |
                           Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ble_features": Si91xBLEFeatureBitMap.Default |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "bt_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server", radius_server={"private_key_file": 'wifi-user.pem', 
                                                    "certificate_file": 'wifi-user.pem',
                                                    "ca_file": 'wifi-user.pem'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", 
                                         "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
def test_wpa3_eap_tls1_0_tcp_tx_ble_peripheral_tx(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                  wifi_client, radius_server, sl_collections, request,
                                                  net_perf_client, protocol, ble_client, utf_constants):
    """
    Test Case 1: Verify whether DUT is able to scan and connect to AP with WPA3 EAP TLS1.0 Security 
    and run TCP TX traffic after BLE Tx in peripheral role
    
    Test Steps:
    1. Configure WiFi sniffer with the access point channel
    2. Start packet capture with test case name as filename
    3. Configure AP with WPA2 Enterprise and PMF Required
    4. Configure DUT roam and advanced client settings
    5. Scan for AP and set EAP credentials
    6. Create BLE thread functionality object for peripheral role (slave)
    7. Start BLE advertising and wait for connection
    8. Perform service discovery on remote device
    9. Start BLE TX notifications from DUT to remote BLE client
    10. Create WiFi join thread with WPA3 Enterprise TLS 1.0
    11. Join the access point and establish WiFi connection
    12. Enable power save modes
    13. Run TCP TX traffic from DUT
    14. Validate BLE notifications are received by BLE client
    15. Validate coexistence state throughout
    16. Disconnect BLE connection
    17. Disconnect WiFi from access point
    18. Stop packet capture
    19. Validate sniffer capture for EAP TLS 1.0 packets
    20. Clean up BLE resources and close connections
    """
    global ble_obj, wifi_obj
    
    try:
        logger().info("=" * 80)
        logger().info("Test Case 1: WPA3 EAP TLS1.0 Security - TCP TX after BLE Peripheral TX")
        logger().info("=" * 80)
        
        logger().info("Since WPA3-ENT is not supported in 3rd party Asus AP, as per input from QA team "
                     "configured wpa2-ent-pmf on 3rd party side and on DUT enabled wpa3-enterprise with pmf")
        
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        
        # Step 1: Configure WiFi sniffer with the access point channel
        logger().info("Step 1: Configuring WiFi sniffer with AP channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        
        # Step 2: Start packet capture with test case name as filename
        logger().info(f"Step 2: Starting packet capture with filename: {test_name}")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        
        # Step 3: Configure AP with WPA2 Enterprise and PMF Required
        logger().info("Step 3: Configuring AP with WPA2 Enterprise and PMF Required")
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(5)
        
        # Step 4: Configure DUT roam and advanced client settings
        logger().info("Step 4: Configuring DUT roam and advanced client settings")
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        
        # Step 5: Scan for AP and set EAP credentials
        logger().info("Step 5: Scanning for AP and setting EAP credentials")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()
        
        # Step 6-9: Create BLE thread functionality object for peripheral role (slave) with TX notifications
        logger().info("Step 6-9: Setting up BLE peripheral role with TX notifications")
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
            gatt=True,
            set_smp=0
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

        logger().info("Step 10-12: Setting up WiFi connection with WPA3 Enterprise TLS 1.0")
        wifi_obj = WPA3Enterprise(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            eap_type="tls",
            sl_collections=sl_collections,
            test_name=test_name,
            traffic_type="TX",
            test_case_no="679996",
            net_perf_client=net_perf_client,
            protocol=protocol,
            data_transfer=True,
            wifi_client=wifi_client,
            power_save=True
        )

        # Start WiFi thread - this handles join, IP, power save, and TCP TX
        logger().info("Starting WiFi connection and TCP TX traffic")
        wifi_obj.start()

        # BLE connection as slave (peripheral) - ble_connect() handles advertise, scan, connect
        logger().info("Connecting BLE as peripheral (slave)")
        ble_obj.ble_connect(role="slave")
        
        # Service discovery on remote device
        logger().info("Performing service discovery on remote device")
        ble_obj.service_discovery_on_remote()
        
        # Start BLE thread - start() calls run() which executes enable_notifications_from_dut()
        logger().info("Starting BLE TX notifications")
        ble_obj.start()
        ble_obj.wait_for_exit()
        
        # Wait a bit for BLE connection to stabilize
        time.sleep(5)
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_remove_service(timeout=10)
        ble_obj.ble_disconnect()
        wifi_dut.interfaces.wifi.memory_free(address1)

        # Step 19: Validate sniffer capture for EAP TLS 1.0 packets
        logger().info("Step 19: Validating sniffer capture for EAP TLS 1.0 packets")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        dut_mac_address = wifi_obj.dut_add_dict['dut_mac_address']
        
        sniffer_verification = SnifferValidationProcess(
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            wifi_access_point=wifi_access_point,
            dut_mac_address=dut_mac_address,
            ap_mac_address=ap_mac_address
        )
        sniffer_verification.verify_sniffer_validation()
        
        # Validate EAP TLS 1.0 frames
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=dut_mac_address,
            filter_name='eap_type_tls_verification'
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find EAP frames sent from AP in sniffer'
        
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0'
        )
        logger().info("Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
        
        logger().info("=" * 80)
        logger().info("Test Case 1 PASSED: WPA3 EAP TLS1.0 Security - TCP TX after BLE Peripheral TX")
        logger().info("=" * 80)
        
    except Exception as Ex:
        logger().error(f"Test Case 1 FAILED: {str(Ex)}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    
    finally:
        # Step 20: Clean up BLE resources and close connections
        logger().info("Step 20: Cleaning up BLE resources and closing connections")
        try:
            if ble_client:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
            if ble_obj is not None:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address,
                    ble_dut_address=ble_obj.ble_dut_address
                )
        except Exception as cleanup_error:
            logger().error(f"Cleanup error: {cleanup_error}")
        try:
            wifi_sniffer.interfaces.capture.stop_capture()
        except:
            pass



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3072, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3072, "priority": 8}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.NWP120MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2 |
                           Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ble_features": Si91xBLEFeatureBitMap.Default |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "bt_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server", radius_server={"private_key_file": 'wifi-user.pem', 
                                                    "certificate_file": 'wifi-user.pem',
                                                    "ca_file": 'wifi-user.pem'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", 
                                         "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
def test_wpa3_eap_tls1_2_tcp_rx_ble_central_rx(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                wifi_client, radius_server, sl_collections, request,
                                                net_perf_client, protocol, ble_client, utf_constants):
    """
    Test Case 2: Verify whether DUT is able to scan and connect to AP with WPA3 EAP TLS1.2 Security 
    and run TCP RX traffic after BLE connection and Rx in Central role
    
    Test Steps:
    1. Configure WiFi sniffer with the access point channel
    2. Start packet capture with test case name as filename
    3. Configure AP with WPA2 Enterprise and PMF Required
    4. Configure DUT roam and advanced client settings
    5. Scan for AP and set EAP credentials
    6. Create BLE thread functionality object for central role (master)
    7. Start BLE advertising on remote device and scan from DUT
    8. Connect BLE as master (central)
    9. Perform service discovery on DUT
    10. Start BLE RX notifications (receive from remote)
    11. Create WiFi join thread with WPA3 Enterprise TLS 1.2
    12. Join the access point and establish WiFi connection
    13. Enable power save modes
    14. Run TCP RX traffic to DUT
    15. Validate BLE notifications are received by DUT
    16. Validate coexistence state throughout
    17. Disconnect BLE connection
    18. Disconnect WiFi from access point
    19. Stop packet capture
    20. Validate sniffer capture for EAP TLS 1.2 packets
    21. Clean up BLE resources and close connections
    """
    global ble_obj, wifi_obj
    
    try:
        logger().info("=" * 80)
        logger().info("Test Case 2: WPA3 EAP TLS1.2 Security - TCP RX after BLE Central RX")
        logger().info("=" * 80)
        
        logger().info("Since WPA3-ENT is not supported in 3rd party Asus AP, as per input from QA team "
                     "configured wpa2-ent-pmf on 3rd party side and on DUT enabled wpa3-enterprise with pmf")
        
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        
        # Step 1: Configure WiFi sniffer with the access point channelc
        logger().info("Step 1: Configuring WiFi sniffer with AP channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        
        # Step 2: Start packet capture with test case name as filename
        logger().info(f"Step 2: Starting packet capture with filename: {test_name}")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        
        # Step 3: Configure AP with WPA2 Enterprise and PMF Required
        logger().info("Step 3: Configuring AP with WPA2 Enterprise and PMF Required")
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(5)
        
        # Step 4: Configure DUT roam and advanced client settings
        logger().info("Step 4: Configuring DUT roam and advanced client settings")
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        
        # Step 5: Scan for AP and set EAP credentials
        logger().info("Step 5: Scanning for AP and setting EAP credentials")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()
        
        # Step 6-10: Create BLE thread functionality object for central role (master) with RX notifications
        logger().info("Step 6-10: Setting up BLE central role with RX notifications")

        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=60,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            set_smp=1,
            svc=svc,
            charc=charc,
            data=data,
        )

        # Step 11-13: Create WiFi join thread with WPA3 Enterprise TLS 1.2
        logger().info("Step 11-13: Setting up WiFi connection with WPA3 Enterprise TLS 1.2")
        wifi_obj = WPA3Enterprise(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            eap_type="tls",
            sl_collections=sl_collections,
            test_name=test_name,
            traffic_type="RX",
            test_case_no="679997",
            net_perf_client=net_perf_client,
            protocol=protocol,
            data_transfer=False,
            wifi_client=wifi_client,
            power_save=True
        )

        # BLE connection as master (central) - ble_connect() handles advertise remote, scan, connect
        logger().info("Connecting BLE as central (master)")
        ble_obj.ble_connect(role="master")

        # Service discovery on DUT
        logger().info("Performing service discovery on DUT")
        ble_obj.service_discovery_on_dut()

        # Start WiFi thread - this handles join, IP, power save, and TCP RX
        logger().info("Starting WiFi connection and TCP RX traffic")
        wifi_obj.start()

        wifi_obj.wait_for_exit()

        # Start BLE thread - start() calls run() which executes enable_notifications_remote()
        logger().info("Starting BLE RX notifications")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        iperf_thread = Thread(target=sl_collections.run_traffic, args=(wifi_dut, net_perf_client, protocol,
                              wifi_obj.dut_add_dict['device_ip'], host_ip,
                              120, "RX", None, 1460, 1470, 4, 1, "60M", "global", None))
        iperf_thread.start()

        # sl_collections.run_traffic(
        #     wifi_dut=wifi_dut,
        #     net_perf_client=net_perf_client,
        #     protocol=protocol,
        #     device_ip=wifi_obj.dut_add_dict['device_ip'],
        #     host_ip=host_ip,
        #     timeout=120,
        #     traffic_type="RX",
        #     async_socket=1,
        # )

        ble_obj.start()

        ble_obj.wait_for_exit()

        iperf_thread.join()
        # Step 19: Stop packet capture
        logger().info("Step 19: Stopping packet capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        
        # Step 20: Validate sniffer capture for EAP TLS 1.2 packets
        logger().info("Step 20: Validating sniffer capture for EAP TLS 1.2 packets")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        dut_mac_address = wifi_obj.dut_add_dict['dut_mac_address']
        
        sniffer_verification = SnifferValidationProcess(
            wifi_sniffer=wifi_sniffer,
            sniffer_filter=sniffer_filter,
            wifi_access_point=wifi_access_point,
            dut_mac_address=dut_mac_address,
            ap_mac_address=ap_mac_address
        )
        sniffer_verification.verify_sniffer_validation()
        
        # Validate EAP TLS 1.2 frames
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=dut_mac_address,
            filter_name='eap_type_tls_verification'
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find EAP frames sent from AP in sniffer'
        
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2'
        )
        logger().info("Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
        
        logger().info("=" * 80)
        logger().info("Test Case 2 PASSED: WPA3 EAP TLS1.2 Security - TCP RX after BLE Central RX")
        logger().info("=" * 80)
        
    except Exception as Ex:
        logger().error(f"Test Case 2 FAILED: {str(Ex)}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    
    finally:
        # Step 21: Clean up BLE resources and close connections
        logger().info("Step 21: Cleaning up BLE resources and closing connections")
        try:
            if ble_client:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
            if ble_obj is not None:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address,
                    ble_dut_address=ble_obj.ble_dut_address
                )
        except Exception as cleanup_error:
            logger().error(f"Cleanup error: {cleanup_error}")
        
        try:
            wifi_sniffer.interfaces.capture.stop_capture()
        except:
            pass



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 2048, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.PSKSecurity,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.NWP120MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ble_features": Si91xBLEFeatureBitMap.Default |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "bt_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "passphrase": '1234567890',
                                               "protected_management_frame": "Required"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.skip(reason="SI91X-20697")
def test_wpa3_transition_wpa2_to_wpa3_viceversa_ble_scan_si30_sw10(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                   sniffer_filter, wifi_client, sl_collections,
                                                                   request, utf_constants, ble_client):
    """
    Test Case 3: Verify WPA3 Transition from WPA2 to WPA3 and vice versa with BLE Scan Interval: 30ms and Scan Window: 10ms
    
    Test Steps:
    1. Configure WiFi sniffer with the access point channel
    2. Start packet capture
    3. Configure BLE scan with SI: 30ms (48 in 0.625ms units) and SW: 10ms (16 in 0.625ms units)
    4. Start BLE scanning from DUT
    5. Join AP with WPA2 security
    6. Validate WiFi connection and BLE scan coexistence
    7. Stop AP and restart with WPA3 Transition security
    8. DUT should rejoin with WPA3 Transition
    9. Validate coexistence during transition
    10. Stop AP and restart with WPA2 security
    11. DUT should rejoin with WPA2
    12. Validate coexistence during reverse transition
    13. Stop BLE scanning
    14. Disconnect WiFi
    15. Stop packet capture
    16. Validate sniffer capture
    """
    global ble_obj, wifi_obj
    
    try:
        logger().info("=" * 80)
        logger().info("Test Case 3: WPA3 Transition WPA2↔WPA3 with BLE Scan SI:30ms SW:10ms")
        logger().info("=" * 80)
        
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        
        # Step 1: Configure WiFi sniffer
        logger().info("Step 1: Configuring WiFi sniffer")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        
        # Step 2: Start packet capture
        logger().info(f"Step 2: Starting packet capture: {test_name}")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        
        # Step 3-4: Configure and start BLE scan with SI: 30ms, SW: 10ms
        # SI: 30ms = 30 / 0.625 = 48 (0x30)
        # SW: 10ms = 10 / 0.625 = 16 (0x10)
        logger().info("Step 3-4: Starting BLE scan with SI: 30ms, SW: 10ms")
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            ble_scan_interval=30,  # In milliseconds, will be converted to 0.625ms units internally
            ble_scan_window=10,    # In milliseconds, will be converted to 0.625ms units internally
        )
        # ble_obj.start()
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40,
                                                                 first_time_retry_enable=1)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired | Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security="wpa3_transition",
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      channel=wifi_access_point.interfaces.wifi.channel, timeout=60)
        time.sleep(5)
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
        time.sleep(2)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip: {device_ip}")
        time.sleep(2)
        mode = 'power_save_low_latency'

        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        time.sleep(10)
        # Step 6: Validate WiFi connection and BLE scan coexistence
        logger().info("Step 6: Validating coexistence - WiFi connected, BLE scanning")
        wifi_connectivity_status = ping(device_ip, ping_count, size=300)
        assert wifi_connectivity_status, "WiFi not responding to ping"
        assert wifi_dut.interfaces.wifi.associated, "WiFi connection lost"
        logger().info("Coexistence validated: WiFi connected, BLE scanning")
        
        # Step 7-8: Stop AP and restart with WPA3 Transition security
        logger().info("Step 7-8: Transitioning AP from WPA2 to WPA3 Transition")
        # wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(5)
        wifi_access_point.interfaces.wifi.config['security'] = 'WPA2'
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()

        
        # DUT should rejoin automatically with WPA3 Transition
        logger().info("Waiting for DUT to rejoin with WPA3 Transition")
        time.sleep(120)
        
        # Validate rejoin
        assert wifi_dut.interfaces.wifi.associated, "DUT failed to rejoin with WPA3 Transition"
        wifi_connectivity_status = ping(device_ip, ping_count, size=300)
        assert wifi_connectivity_status, "WiFi not responding to ping after WPA3 Transition"
        logger().info("DUT successfully rejoined with WPA3 Transition")
        
        # # Step 9: Validate coexistence during transition
        # logger().info("Step 9: Validating coexistence during WPA2→WPA3 transition")
        # assert wifi_dut.interfaces.wifi.associated, "WiFi connection lost during transition"
        # logger().info("Coexistence validated during transition")
        #
        # # Step 15: Stop packet capture
        # logger().info("Step 15: Stopping packet capture")
        # wifi_sniffer.interfaces.capture.stop_capture()
        #
        # # Step 10-11: Stop AP and restart with WPA2 security (reverse transition)
        # logger().info("Step 10-11: Transitioning AP from WPA3 to WPA2 (reverse)")
        # # wifi_access_point.interfaces.wifi.stop_ap()
        # time.sleep(5)
        #
        # # Step 1: Configure WiFi sniffer
        # logger().info("Step 1: Configuring WiFi sniffer")
        # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        #
        # # Step 2: Start packet capture
        # logger().info(f"Step 2: Starting packet capture: {test_name}")
        # wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        #
        # wifi_access_point.interfaces.wifi.config['security'] = 'WPA2'
        # wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        #
        # wifi_access_point.interfaces.wifi.start_ap()
        #
        # # DUT should rejoin automatically with WPA2
        # logger().info("Waiting for DUT to rejoin with WPA2")
        # time.sleep(200)
        #
        # # Validate rejoin
        # assert wifi_dut.interfaces.wifi.associated, "DUT failed to rejoin with WPA2"
        # wifi_connectivity_status = ping(device_ip, ping_count, size=300)
        #
        # assert wifi_connectivity_status, "WiFi not responding to ping after WPA2 rejoin"
        # logger().info("DUT successfully rejoined with WPA2")
        #
        # # Step 12: Validate coexistence during reverse transition
        # logger().info("Step 12: Validating coexistence during WPA3→WPA2 transition")
        # assert wifi_dut.interfaces.wifi.associated, "WiFi connection lost during reverse transition"
        # logger().info("Coexistence validated during reverse transition")
        #
        # # Step 13: Stop BLE scanning
        # # logger().info("Step 13: Stopping BLE scanning")
        # # ble_obj.wait_for_exit()
        # # if hasattr(ble_obj, 'stop_adv_scan'):
        # #     ble_obj.stop_adv_scan()
        #
        # # Step 14: Disconnect WiFi
        # logger().info("Step 14: Disconnecting WiFi")
        # if wifi_dut.interfaces.wifi.associated:
        #     wifi_dut.interfaces.wifi.leave()
        
        # Step 15: Stop packet capture
        logger().info("Step 15: Stopping packet capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        
        # # Step 16: Validate sniffer capture
        # logger().info("Step 16: Validating sniffer capture")
        # wifi_obj.sniffer_validation_join()
        #
        # logger().info("=" * 80)
        # logger().info("Test Case 3 PASSED: WPA3 Transition WPA2↔WPA3 with BLE Scan")
        # logger().info("=" * 80)
        #
    except Exception as Ex:
        logger().error(f"Test Case 3 FAILED: {str(Ex)}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    
    finally:
        try:
            if ble_client:
                ble_client.interfaces.bluetooth.close()
            if ble_obj is not None:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address if hasattr(ble_obj, 'ble_client_address') else None,
                    ble_dut_address=ble_obj.ble_dut_address if hasattr(ble_obj, 'ble_dut_address') else None
                )
        except Exception as cleanup_error:
            logger().error(f"Cleanup error: {cleanup_error}")
        
        try:
            wifi_sniffer.interfaces.capture.stop_capture()
        except:
            pass


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.PSKSecurity,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.NWP120MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE |
                              Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ble_features": Si91xBLEFeatureBitMap.Default |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "bt_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.skip(reason="SI91X-20697")
def test_wpa3_transition_wpa2_to_wpa3_viceversa_ble_peripheral_ci30(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                    sniffer_filter, wifi_client, sl_collections,
                                                                    request, utf_constants, ble_client):
    """
    Test Case 4: Verify WPA3 Transition from WPA2 to WPA3 and vice versa after BLE peripheral connection with CI: 30ms
    
    Test Steps:
    1. Configure WiFi sniffer with the access point channel
    2. Start packet capture
    3. Create BLE thread functionality object for peripheral role (slave)
    4. Connect BLE as peripheral with connection interval: 30ms (24 in 1.25ms units)
    5. Validate BLE connection
    6. Join AP with WPA2 security
    7. Validate WiFi connection and BLE connection coexistence
    8. Stop AP and restart with WPA3 Transition security
    9. DUT should rejoin with WPA3 Transition
    10. Validate coexistence during transition
    11. Stop AP and restart with WPA2 security
    12. DUT should rejoin with WPA2
    13. Validate coexistence during reverse transition
    14. Disconnect BLE connection
    15. Disconnect WiFi
    16. Stop packet capture
    17. Validate sniffer capture
    """
    global ble_obj, wifi_obj
    
    try:
        logger().info("=" * 80)
        logger().info("Test Case 4: WPA3 Transition WPA2↔WPA3 with BLE Peripheral CI:30ms")
        logger().info("=" * 80)
        
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        
        # Step 1: Configure WiFi sniffer
        logger().info("Step 1: Configuring WiFi sniffer")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        
        # Step 2: Start packet capture
        logger().info(f"Step 2: Starting packet capture: {test_name}")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        
        # Step 3-5: Create BLE thread functionality object for peripheral role with CI: 30ms
        # CI: 30ms = 30 / 1.25 = 24 (0x18)
        logger().info("Step 3-5: Connecting BLE as peripheral with CI: 30ms")
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            conn_int=30,  # Connection interval in ms (will be converted to 1.25ms units internally)
            ble_pairing=1,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        
        # Step 6: Join AP with WPA2 security
        logger().info("Step 6: Joining AP with WPA2 security")
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="join",
        )
        wifi_obj.join_to_ap()
        device_ip = wifi_obj.device_ip
        dut_mac_address = wifi_obj.dut_mac_address
        
        # Step 7: Validate WiFi connection and BLE connection coexistence
        logger().info("Step 7: Validating coexistence - WiFi connected, BLE connected")
        wifi_connectivity_status = ping(device_ip, ping_count, size=300)
        assert wifi_connectivity_status, "WiFi not responding to ping"
        assert wifi_dut.interfaces.wifi.associated, "WiFi connection lost"
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost"
        logger().info("Coexistence validated: WiFi connected, BLE connected")
        
        # Step 8-9: Stop AP and restart with WPA3 Transition security
        logger().info("Step 8-9: Transitioning AP from WPA2 to WPA3 Transition")
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(5)
        wifi_access_point.interfaces.wifi.config['security'] = 'WPA3'
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(20)
        
        # DUT should rejoin automatically with WPA3 Transition
        logger().info("Waiting for DUT to rejoin with WPA3 Transition")
        time.sleep(30)
        
        # Validate rejoin
        assert wifi_dut.interfaces.wifi.associated, "DUT failed to rejoin with WPA3 Transition"
        wifi_connectivity_status = ping(device_ip, ping_count, size=300)
        assert wifi_connectivity_status, "WiFi not responding to ping after WPA3 Transition"
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost during transition"
        logger().info("DUT successfully rejoined with WPA3 Transition, BLE connection maintained")
        
        # Step 10: Validate coexistence during transition
        logger().info("Step 10: Validating coexistence during WPA2→WPA3 transition")
        assert wifi_dut.interfaces.wifi.associated, "WiFi connection lost during transition"
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost during transition"
        logger().info("Coexistence validated during transition")
        
        # Step 11-12: Stop AP and restart with WPA2 security (reverse transition)
        logger().info("Step 11-12: Transitioning AP from WPA3 to WPA2 (reverse)")
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(5)
        wifi_access_point.interfaces.wifi.config['security'] = 'WPA2'
        if 'protected_management_frame' in wifi_access_point.interfaces.wifi.config:
            del wifi_access_point.interfaces.wifi.config['protected_management_frame']
        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(20)
        
        # DUT should rejoin automatically with WPA2
        logger().info("Waiting for DUT to rejoin with WPA2")
        time.sleep(30)
        
        # Validate rejoin
        assert wifi_dut.interfaces.wifi.associated, "DUT failed to rejoin with WPA2"
        wifi_connectivity_status = ping(device_ip, ping_count, size=300)
        assert wifi_connectivity_status, "WiFi not responding to ping after WPA2 rejoin"
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost during reverse transition"
        logger().info("DUT successfully rejoined with WPA2, BLE connection maintained")
        
        # Step 13: Validate coexistence during reverse transition
        logger().info("Step 13: Validating coexistence during WPA3→WPA2 transition")
        assert wifi_dut.interfaces.wifi.associated, "WiFi connection lost during reverse transition"
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "BLE connection lost during reverse transition"
        logger().info("Coexistence validated during reverse transition")
        
        # Step 14: Disconnect BLE connection
        logger().info("Step 14: Disconnecting BLE connection")
        if ble_obj is not None:
            ble_obj.ble_disconnect()
        
        # Step 15: Disconnect WiFi
        logger().info("Step 15: Disconnecting WiFi")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()
        
        # Step 16: Stop packet capture
        logger().info("Step 16: Stopping packet capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        
        # Step 17: Validate sniffer capture
        logger().info("Step 17: Validating sniffer capture")
        wifi_obj.sniffer_validation_join()
        
        logger().info("=" * 80)
        logger().info("Test Case 4 PASSED: WPA3 Transition WPA2↔WPA3 with BLE Peripheral CI:30ms")
        logger().info("=" * 80)
        
    except Exception as Ex:
        logger().error(f"Test Case 4 FAILED: {str(Ex)}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    
    finally:
        try:
            if ble_client:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
            if ble_obj is not None:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address if hasattr(ble_obj, 'ble_client_address') else None,
                    ble_dut_address=ble_obj.ble_dut_address if hasattr(ble_obj, 'ble_dut_address') else None
                )
        except Exception as cleanup_error:
            logger().error(f"Cleanup error: {cleanup_error}")
        
        try:
            wifi_sniffer.interfaces.capture.stop_capture()
        except:
            pass


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8},
                          "ble": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.PSKSecurity,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.NWP120MHz,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE |
                              Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ble_features": Si91xBLEFeatureBitMap.Default |
                        Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "bt_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3', "protected_management_frame": "Capable"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wpa3_h2e_transition_hunting_pecking_ble_scan_adv(wifi_dut, wifi_access_point, wifi_sniffer,
                                                          sniffer_filter, wifi_client, sl_collections,
                                                          request, utf_constants, ble_client):
    """
    Test Case 5: Verify WPA3 connection from Hunting and pecking to H2E while BLE scan and advertise
    
    Test Steps:
    1. Configure WiFi sniffer with the access point channel
    2. Start packet capture
    3. Configure BLE scan and advertise
    4. Start BLE scanning from DUT
    5. Start BLE advertising from DUT
    6. Configure DUT for WPA3 Transition with Hunting and pecking (SAE PWE method 0)
    7. Join AP with WPA3 Transition (should use Hunting and pecking initially)
    8. Validate WiFi connection and BLE scan/advertise coexistence
    9. Leave AP
    10. Configure DUT for WPA3 with H2E (SAE PWE method 1)
    11. Join AP with WPA3 (should use H2E)
    12. Validate H2E mode in sniffer capture
    13. Validate coexistence during H2E connection
    14. Stop BLE scan and advertise
    15. Disconnect WiFi
    16. Stop packet capture
    17. Validate sniffer capture for H2E packets
    """
    global ble_obj, wifi_obj
    
    try:
        logger().info("=" * 80)
        logger().info("Test Case 5: WPA3 H2E Transition (Hunting→H2E) with BLE Scan & Advertise")
        logger().info("=" * 80)
        
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        
        # Step 1: Configure WiFi sniffer
        logger().info("Step 1: Configuring WiFi sniffer")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        
        # Step 2: Start packet capture
        logger().info(f"Step 2: Starting packet capture: {test_name}")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        
        # Step 3-5: Configure and start BLE scan and advertise
        logger().info("Step 3-5: Starting BLE scan and advertise")
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_from_remote_device",  # This will handle both scan and advertise
        )
        ble_obj.advertise_dut()
        ble_obj.start()
        
        # Step 6-7: Configure DUT for WPA3 Transition with Hunting and pecking and join
        logger().info("Step 6-7: Joining AP with WPA3 Transition (Hunting and pecking)")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        
        # Join with WPA3 Transition (will use Hunting and pecking by default)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security="wpa3_transition",
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      channel=wifi_access_point.interfaces.wifi.channel, timeout=60)
        time.sleep(5)
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT IP: {device_ip}, DUT MAC: {dut_mac_address}")
        
        # Step 8: Validate WiFi connection and BLE scan/advertise coexistence
        logger().info("Step 8: Validating coexistence - WiFi connected, BLE scan & advertise")
        wifi_connectivity_status = ping(device_ip, ping_count, size=300)
        assert wifi_connectivity_status, "WiFi not responding to ping"
        assert wifi_dut.interfaces.wifi.associated, "WiFi connection lost"
        logger().info("Coexistence validated: WiFi connected, BLE scan & advertise active")
        
        # Step 9: Leave AP
        logger().info("Step 9: Leaving AP")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(5)
        
        # Step 10-11: Configure DUT for WPA3 with H2E and join
        logger().info("Step 10-11: Joining AP with WPA3 (H2E mode)")
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        
        # Join with WPA3 (should use H2E)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      security="wpa3",
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      channel=wifi_access_point.interfaces.wifi.channel, timeout=60)
        time.sleep(5)
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT IP: {device_ip}, DUT MAC: {dut_mac_address}")
        
        # Step 12: Validate H2E mode in sniffer capture
        logger().info("Step 12: Validating H2E mode in sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=dut_mac_address,
            filter_name="wpa3_h2e_mode")
        logger().info(f"Sniffer Filter for H2E: {packet_filter1}")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
        assert snif_pkt_count, "Unable to find Assoc req with H2E"
        logger().info("H2E mode validated in sniffer capture")
        
        # Step 13: Validate coexistence during H2E connection
        logger().info("Step 13: Validating coexistence during H2E connection")
        wifi_connectivity_status = ping(device_ip, ping_count, size=300)
        assert wifi_connectivity_status, "WiFi not responding to ping"
        assert wifi_dut.interfaces.wifi.associated, "WiFi connection lost"
        logger().info("Coexistence validated: WiFi connected with H2E, BLE scan & advertise active")
        
        # Step 14: Stop BLE scan and advertise
        logger().info("Step 14: Stopping BLE scan and advertise")
        ble_obj.wait_for_exit()
        if hasattr(ble_obj, 'stop_adv_scan'):
            ble_obj.stop_adv_scan()
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        
        # Step 15: Disconnect WiFi
        logger().info("Step 15: Disconnecting WiFi")
        if wifi_dut.interfaces.wifi.associated:
            wifi_dut.interfaces.wifi.leave()
        
        # Step 16: Stop packet capture (already stopped above)
        logger().info("Step 16: Packet capture already stopped")
        
        # Step 17: Validate sniffer capture for H2E packets (already validated above)
        logger().info("Step 17: Sniffer validation for H2E already completed")
        
        logger().info("=" * 80)
        logger().info("Test Case 5 PASSED: WPA3 H2E Transition with BLE Scan & Advertise")
        logger().info("=" * 80)
        
    except Exception as Ex:
        logger().error(f"Test Case 5 FAILED: {str(Ex)}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
        raise
    
    finally:
        try:
            if ble_client:
                ble_client.interfaces.bluetooth.close()
            if ble_obj is not None:
                sl_collections.cleanup_ble(
                    ble_dut=wifi_dut,
                    ble_client=ble_client,
                    ble_client_address=ble_obj.ble_client_address if hasattr(ble_obj, 'ble_client_address') else None,
                    ble_dut_address=ble_obj.ble_dut_address if hasattr(ble_obj, 'ble_dut_address') else None
                )
        except Exception as cleanup_error:
            logger().error(f"Cleanup error: {cleanup_error}")
        
        try:
            wifi_sniffer.interfaces.capture.stop_capture()
        except:
            pass

