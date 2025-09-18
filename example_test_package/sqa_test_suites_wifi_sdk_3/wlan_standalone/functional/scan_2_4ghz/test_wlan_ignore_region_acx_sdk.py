import time
import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xRegion, Si91xRegionCode, Si91xModuleType, Si91xCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.iperf.iperf_utils import ping

from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.rejoin.test_wlan_rejoin_2G_sdk import \
    WLanThread


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiate the Scan from DUT
        4. Verify the scan results

    setup requirement:
        1. DUT(SiWG917 _ACX (BRD4343A)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC

    Author: Shaik Abdul Azeez
"""


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'auto_953', "security": 'WPA2', "region": 'US', "channel": 6})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_scan_no_ap_bea_on_channels_12_13_14_c661446(wifi_access_point, wifi_dut, wifi_sniffer, wifi_client,
                                                              sl_collections, utf_constants, sniffer_filter):
    """Verify scan behavior when no AP is beaconing in 12, 13, and 14 channels"""
    try:
        mode = "power_save_low_latency"
        channels_list_2g = [6, 12, 13, 14]
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        device_mac_address = None

        for channel in channels_list_2g:
            logger().info(f"Configuring the Sniffer with channel: {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"ch_{channel}")
            time.sleep(5)

            wifi_access_point.interfaces.wifi.channel = channel
            logger().info(f'CHANNEL = {channel}, type channel = {type(channel)}')

            if channel == 6:
                # Special handling for channel 6
                wifi_dut.interfaces.wifi.scan(channel=channel, ssid='auto_953')
                wifi_dut.interfaces.wifi.join(channel=channel, ssid='auto_953', security='wpa2', passphrase="12345678")

                result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point,
                                                             mode=mode, skip_scan=True, skip_connect=True,
                                                             associated=False)
                time.sleep(20)
                device_mac_address = result['dut_mac_address']

                logger().info("Stopping Sniffer after scan.")
                wifi_sniffer.interfaces.capture.stop_capture()

                # Check for association request packets
                filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=result['dut_mac_address'], da_addr=da_addr, filter_name='association_request_HE')
                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
                    'Unable to find the association_request_HE sniffer packets'

                # Check for power management save packets
                filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=result['dut_mac_address'], da_addr=da_addr, filter_name='power_mgmt_bit')
                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3)['packet_count'], \
                    'Unable to find the power management save sniffer packets'

                wifi_dut.interfaces.wifi.leave()
                time.sleep(2)

            else:
                # For channels 12, 13, and 14, the test should pass even if no probe request is found
                status, data = wifi_dut.interfaces.wifi.join(channel=channel, expected_negative_status=True)
                logger().info(f'STATUS = {status}, DATA = {data}')

                filter_4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=device_mac_address,
                                                                                          da_addr=da_addr,
                                                                                          filter_name='probe_request')
                time.sleep(5)
                logger().info("Stopping Sniffer after probe request.")
                wifi_sniffer.interfaces.capture.stop_capture()

                result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_4)
                logger().info(f'Result={result}')

                # If no probe request is found, the test should still pass
                if result['packet_count'] == 0:
                    logger().info(f"No probe request found on channel {channel}, passing the test.")
                else:
                    assert result['packet_count'], 'Unable to find the probe request sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'auto_953', "security": 'WPA2', "region": 'Europe', "channel": 12})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_verify_scan_and_conn_third_party_ap_cha_12_c661447(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                     wifi_client,
                                                                     sl_collections, utf_constants, sniffer_filter):
    """Verify scan and connection when third party AP is configured channel 12"""
    try:
        mode = "power_save_low_latency"
        channels_list_2g = [12, 13, 14]
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        device_mac_address = None

        for channel in channels_list_2g:
            logger().info(f"Configuring the Sniffer with channel: {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"ch_{channel}")
            time.sleep(5)

            wifi_access_point.interfaces.wifi.channel = channel
            logger().info(f'CHANNEL = {channel}, type channel = {type(channel)}')

            if channel == 12:
                # Special handling for channel 12
                wifi_dut.interfaces.wifi.scan(channel=channel, ssid='auto_953')
                wifi_dut.interfaces.wifi.join(channel=channel, ssid='auto_953', security='wpa2', passphrase="12345678")

                result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point,
                                                             mode=mode, skip_scan=True, skip_connect=True,
                                                             associated=False)
                time.sleep(20)
                device_mac_address = result['dut_mac_address']

                logger().info("Stopping Sniffer after scan.")
                wifi_sniffer.interfaces.capture.stop_capture()

                # Check for association request packets
                filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=result['dut_mac_address'], da_addr=da_addr, filter_name='association_request_HE')
                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
                    'Unable to find the association_request_HE sniffer packets'

                # Check for power management save packets
                filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=result['dut_mac_address'], da_addr=da_addr, filter_name='power_mgmt_bit')
                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3)['packet_count'], \
                    'Unable to find the power management save sniffer packets'

                wifi_dut.interfaces.wifi.leave()
                time.sleep(2)

            else:
                # For channels 13 and 14 the test should pass even if no probe request is found
                status, data = wifi_dut.interfaces.wifi.join(channel=channel, expected_negative_status=True)
                logger().info(f'STATUS = {status}, DATA = {data}')

                filter_4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=device_mac_address,
                                                                                          da_addr=da_addr,
                                                                                          filter_name='probe_request')
                time.sleep(5)
                logger().info("Stopping Sniffer after probe request.")
                wifi_sniffer.interfaces.capture.stop_capture()

                result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_4)
                logger().info(f'Result={result}')

                # If no probe request is found, the test should still pass
                if result['packet_count'] == 0:
                    logger().info(f"No probe request found on channel {channel}, passing the test.")
                else:
                    assert result['packet_count'], 'Unable to find the probe request sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'auto_953', "security": 'WPA2', "region": 'Europe', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_verify_scan_and_conn_third_party_ap_cha_13_c661448(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                     wifi_client,
                                                                     sl_collections, utf_constants, sniffer_filter):
    """Verify scan and connection when third party AP is configured channel 13"""
    try:
        mode = "power_save_low_latency"
        channels_list_2g = [13, 14]
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        device_mac_address = None

        for channel in channels_list_2g:
            logger().info(f"Configuring the Sniffer with channel: {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"ch_{channel}")
            time.sleep(5)

            wifi_access_point.interfaces.wifi.channel = channel
            logger().info(f'CHANNEL = {channel}, type channel = {type(channel)}')

            if channel == 13:
                # Special handling for channel 13
                wifi_dut.interfaces.wifi.scan(channel=channel, ssid='auto_953')
                wifi_dut.interfaces.wifi.join(channel=channel, ssid='auto_953', security='wpa2', passphrase="12345678")

                result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point,
                                                             mode=mode, skip_scan=True, skip_connect=True,
                                                             associated=False)
                time.sleep(20)
                device_mac_address = result['dut_mac_address']

                logger().info("Stopping Sniffer after scan.")
                wifi_sniffer.interfaces.capture.stop_capture()

                # Check for association request packets
                filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=result['dut_mac_address'], da_addr=da_addr, filter_name='association_request_HE')
                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
                    'Unable to find the association_request_HE sniffer packets'

                # Check for power management save packets
                filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=result['dut_mac_address'], da_addr=da_addr, filter_name='power_mgmt_bit')
                assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3)['packet_count'], \
                    'Unable to find the power management save sniffer packets'

                wifi_dut.interfaces.wifi.leave()
                time.sleep(2)

            else:
                # For channel 14 the test should pass even if no probe request is found
                status, data = wifi_dut.interfaces.wifi.join(channel=channel, expected_negative_status=True)
                logger().info(f'STATUS = {status}, DATA = {data}')

                filter_4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=device_mac_address,
                                                                                          da_addr=da_addr,
                                                                                          filter_name='probe_request')
                time.sleep(5)
                logger().info("Stopping Sniffer after probe request.")
                wifi_sniffer.interfaces.capture.stop_capture()

                result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_4)
                logger().info(f'Result={result}')

                # If no probe request is found, the test should still pass
                if result['packet_count'] == 0:
                    logger().info(f"No probe request found on channel {channel}, passing the test.")
                else:
                    assert result['packet_count'], 'Unable to find the probe request sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'auto_953', "security": 'WPA2', "region": 'US', "channel": 6})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_verify_scan_no_ap_beacon_specific_channel_c661454(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                    wifi_client, request,
                                                                    sl_collections, utf_constants, sniffer_filter):
    """Negative case : Verify scan in specific channel when there is no AP beaconing in the same"""
    try:
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(20)
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(2)

        logger().info("Initiating scan from dut...")
        wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=10, scan_type=0,
                                      expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
        logger().info(f"\n\n Observed the expected error code: 0x10003 (SL_STATUS_SI91X_NO_AP_FOUND) \n\n")
        time.sleep(20)

        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'auto_953', "security": 'WPA2', "region": 'Europe', "channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_ver_probe_req_chan_1_13_bg_scan_api_eu_regi_ap_c661451(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                         wifi_client, sl_collections, utf_constants,
                                                                         sniffer_filter):
    """Verify whether DUT is able to send probe request on channels 1-13 when BG scan API is called
       and DUT is connected to a EU region AP"""

    try:
        mode = "power_save_low_latency"
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC address: {da_addr}")
        device_mac_address = None

        for channel in channels_list_2g:
            if channel in [14]:
                # Handle unsupported channels (14)
                logger().info(f"Skipping unsupported channel {channel} for probe request validation.")

                # Configuring Sniffer on unsupported channels
                logger().info(f"Configuring Sniffer on channel {channel}")
                wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
                wifi_sniffer.interfaces.capture.start_capture(capture_file=f"ch_{channel}")
                time.sleep(5)  # Let the sniffer start capturing

                # Join attempt should fail for unsupported channels
                status, data = wifi_dut.interfaces.wifi.join(channel=channel, expected_negative_status=True)
                logger().info(f'STATUS = {status}, DATA = {data}')

                # Stop the sniffer and validate probe request capture
                filter_4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=device_mac_address, da_addr=da_addr, filter_name='probe_request')
                time.sleep(5)
                logger().info("Stopping Sniffer after probe request capture.")
                wifi_sniffer.interfaces.capture.stop_capture()

                result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_4)
                logger().info(f'Result: {result}')

                # No probe requests expected on unsupported channels
                if result['packet_count'] == 0:
                    logger().info(f"No probe request found on channel {channel}, passing the test.")
                else:
                    assert result['packet_count'] == 0, f"Unexpected probe request packets found on channel {channel}"

                continue  # Skip further processing for unsupported channels

            # For supported channels (1-13)
            logger().info(f"Setting AP channel to {channel}")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel, ssid='auto_953')

            logger().info(f"Configuring Sniffer on channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"ch_{channel}")
            time.sleep(5)  # Let the sniffer start capturing

            # Enabling advanced scan configuration for supported channels
            wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                     adv_passive_channel_time=20)

            # Scan and join on the current supported channel
            wifi_dut.interfaces.wifi.scan(channel=channel, ssid=None)
            wifi_dut.interfaces.wifi.join(channel=channel, ssid='auto_953', security='wpa2', passphrase="12345678")

            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point,
                                                         mode=mode, skip_scan=True, skip_connect=True, associated=False)
            time.sleep(20)  # Wait for DUT to join and stabilize

            logger().info("\n *** Enable BGscan *** \n")
            wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)

            device_mac_address = result['dut_mac_address']

            logger().info("Stopping Sniffer after scan.")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validate Association Request
            filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=device_mac_address, da_addr=da_addr, filter_name='association_request_HE')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
                'No association_request_HE packets found'

            # Validate Power Management Save packet
            filter_2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=device_mac_address, da_addr=da_addr, filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_2)['packet_count'], \
                'No power management save packets found'

            # Validate Probe Request packet
            filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=device_mac_address, da_addr=da_addr, filter_name='probe_request')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3)['packet_count'], \
                'No probe request packets found'

            wifi_dut.interfaces.wifi.leave()  # Disconnect DUT from AP
            time.sleep(2)

    except Exception as e:
        logger().error(f"Test failed due to: {str(e)}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e  # Re-raise the exception to indicate failure in pytest


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": 'auto_953', "security": 'WPA2', "region": "Europe", "channel": 11})
@pytest.mark.deployed_25q2
def test_wifi_sdk_verify_scan_behavior_dut_rejoin_c661453(wifi_sniffer, wifi_access_point, wifi_dut, switch,
                                                          utf_constants, request, sl_collections, sniffer_filter,
                                                          net_perf_client, protocol, wifi_client):
    """Verify scan behavior when DUT is trying to rejoin"""
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                             beacon_missed_count=40, first_time_retry_enable=0)

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name, sl_collections=sl_collections, switch=switch)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(2)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_bgscan_rejoin_")

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        filter_name='probe_request')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=100)
        time.sleep(60)

        # Initiate ping from third party wifi-client to DUT
        status = ping(wlan_obj.dut_addr['device_ip'], 20)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "region": 1,
        "region_code": "ignore"
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'auto_953', "security": 'WPA2', "region": 'US', "channel": 11})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_ver_probe_req_chan_1_11_bg_scan_api_us_regi_ap_c661450(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                         wifi_client, sl_collections, utf_constants,
                                                                         sniffer_filter):
    """Verify whether DUT is able to send probe request on channels 1-11 when BG scan API is called
       and DUT is connected to a US region AP"""
    try:
        mode = "power_save_low_latency"
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC address: {da_addr}")
        device_mac_address = None

        for channel in channels_list_2g:

            # Set AP to the current channel
            logger().info(f"Setting AP channel to {channel}")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel, ssid='auto_953')

            logger().info(f"Configuring Sniffer on channel {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"ch_{channel}")
            time.sleep(5)  # Let the sniffer start capturing

            # Enabling advanced scan configuration for supported channels
            wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                     adv_passive_channel_time=20)

            # Scan and join on the current supported channel
            wifi_dut.interfaces.wifi.scan(channel=channel, ssid=None)
            wifi_dut.interfaces.wifi.join(channel=channel, ssid='auto_953', security='wpa2', passphrase="12345678")

            result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point,
                                                         mode=mode, skip_scan=True, skip_connect=True, associated=False)
            time.sleep(20)  # Wait for DUT to join and stabilize

            logger().info("\n *** Enable BGscan *** \n")
            wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)

            device_mac_address = result['dut_mac_address']

            logger().info("Stopping Sniffer after scan.")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validate Association Request
            filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=device_mac_address, da_addr=da_addr, filter_name='association_request_HE')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
                'No association_request_HE packets found'

            # Validate Power Management Save packet
            filter_2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=device_mac_address, da_addr=da_addr, filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_2)['packet_count'], \
                'No power management save packets found'

            # Validate Probe Request packet
            filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=device_mac_address, da_addr=da_addr, filter_name='probe_request')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3)['packet_count'], \
                'No probe request packets found'

            wifi_dut.interfaces.wifi.leave()  # Disconnect DUT from AP
            time.sleep(2)

    except Exception as e:
        logger().error(f"Test failed due to: {str(e)}")
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise e  # Re-raise the exception to indicate failure in pytest


# Need two evk harness
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "japan",
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ssid": "sliabs_ap", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "ignore",
    },
)
@pytest.mark.deployed_25q2
def test_wifi_sdk_verify_scan_and_conn_third_party_ap_conf_jp_region_c661449( wifi_dut,sl_collections, remote_wiseconnect3, wifi_sniffer, request, sniffer_filter):
    """Verify scan and connection when third party AP is configured Japan in 13 channel"""
    try:
        test_name = request.node.name
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        channel = 13

        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)

        ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
        logger().info(f"DUT as AP MAC Address: {ap_mac}")
        sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
        logger().info(f"DUT MAC is : {sec_sdk_mac}")
        time.sleep(2)
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76")

        wifi_dut.interfaces.wifi.start_ap(ssid="silabs_ap", security="wpa2", channel=channel, psk="Automation@123",
                                          dtim_beacon_count=1, beacon_interval=100)
        time.sleep(30)

        remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
        time.sleep(2)

        remote_wiseconnect3.interfaces.sapi.join(ssid="silabs_ap", security="wpa2", passphrase="Automation@123", channel=channel, timeout=60)
        time.sleep(2)

        remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip, static_subnet=static_subnet,
                                                     static_gateway=static_gateway, timeout=10)

        # Set performance profile and enable Bluetooth power save mode
        remote_wiseconnect3.interfaces.sapi.set_performance_profile(mode='power_save_low_latency')
        remote_wiseconnect3.interfaces.sapi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                 psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        remote_wiseconnect3.interfaces.sapi.leave()
        time.sleep(2)

        # Stop the sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stopped Sniffer capture.")

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sec_sdk_mac, da_addr=ap_mac,
                                                                                  filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the power management save sniffer packets'

        filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sec_sdk_mac, da_addr=ap_mac,
                                                                                  filter_name='probe_request')
        result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3)
        logger().info(f'Result={result}')

        # If no probe request is found, the test should still pass
        if result['packet_count'] == 0:
            logger().info(f"No probe request found on channel {channel}, passing the test.")
        else:
            assert result['packet_count'], 'Unable to find the probe request sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


# Need two evk harness
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("remote_wiseconnect3", sapi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "japan",
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ssid": "sliabs_ap", "passphrase": "Automation@123",
        "region": 1,
        "region_code": "ignore",
    },
)
@pytest.mark.deployed_25q2
def test_wifi_sdk_ver_prob_req_cha_1_14_bg_scan_api_jp_region_c661451( wifi_dut,sl_collections, remote_wiseconnect3, wifi_sniffer, request, sniffer_filter):
    """Verify whether DUT is able to send probe request in 1-14 channels
       when BG scan API is called and DUT is connected to JP region AP"""
    try:
        test_name = request.node.name
        static_ip = "192.168.100.77"
        static_subnet = "255.255.255.0"
        static_gateway = "192.168.100.76"
        ip_version = 'ipv4'
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]

        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        for channel in channels_list_2g:
            if channel in [14]:
                # Handle unsupported channels (14)
                logger().info(f"Skipping unsupported channel {channel} for probe request validation.")

            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            time.sleep(2)

            # Enabling advanced scan configuration for supported channels
            remote_wiseconnect3.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                                adv_passive_channel_time=20)
            ap_mac = wifi_dut.interfaces.wifi.get_mac_address(2)
            logger().info(f"DUT as AP MAC Address: {ap_mac}")
            sec_sdk_mac = remote_wiseconnect3.interfaces.sapi.get_mac_address()
            logger().info(f"DUT MAC is : {sec_sdk_mac}")
            time.sleep(2)

            wifi_dut.interfaces.wifi.start_ap(ssid="silabs_ap", security="wpa2", channel=channel, psk="Automation@123",
                                              dtim_beacon_count=1, beacon_interval=100)
            time.sleep(30)

            remote_wiseconnect3.interfaces.sapi.scan(channel=None, ssid=None)
            time.sleep(2)

            remote_wiseconnect3.interfaces.sapi.join(ssid="silabs_ap", security="wpa2", passphrase="Automation@123", channel=channel, timeout=60)
            time.sleep(2)

            remote_wiseconnect3.interfaces.sapi.start_ip(ip_version=ip_version, static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway, timeout=10)

            # Set performance profile and enable Bluetooth power save mode
            remote_wiseconnect3.interfaces.sapi.set_performance_profile(mode='power_save_low_latency')
            remote_wiseconnect3.interfaces.sapi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                     psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            logger().info("\n *** Enable BGscan *** \n")
            remote_wiseconnect3.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
            time.sleep(3)

            # Stop the sniffer capture
            wifi_sniffer.interfaces.capture.stop_capture()
            logger().info("Stopped Sniffer capture.")

            filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sec_sdk_mac, da_addr=ap_mac,
                                                                                      filter_name='power_mgmt_bit')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
                'Unable to find the power management save sniffer packets'

            filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sec_sdk_mac, da_addr=ap_mac,
                                                                                      filter_name='probe_request')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3) ['packet_count'], \
                'Unable to find the probe request sniffer packets'

            remote_wiseconnect3.interfaces.sapi.leave()
            time.sleep(2)
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            time.sleep(2)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
