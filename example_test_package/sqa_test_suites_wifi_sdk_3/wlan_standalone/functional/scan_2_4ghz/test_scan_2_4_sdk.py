import time
import re
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xRegion, Si91xRegionCode, Si91xModuleType, Si91xCustomFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf_wiseconnect_3.tests.sl_status import SLStatus
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.mbssid.test_wlan_mbssid_sdk \
    import WLanThread


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Enable the wlan and bt power save mode in dut after the connection
        3. Initiate the Scan from DUT
        4. Verify the scan results

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC

    Author: Shaik Abdul Azeez and Anshul Bhargava(477822 and 477824)
"""


class WifiJoinThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, wifi_sniffer=None,
                 ping_count=None, test_case=None, sl_collections=None, sniffer_filter=None,
                 power_save=None, ap_mac_address=None, test_case_no=None, net_perf_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None
        self.power_save = power_save
        self.ap_mac_address = ap_mac_address
        self.test_case_no = test_case_no
        self.net_perf_client = net_perf_client

    def run(self):
        try:
            logger().info(" ====== configuring the Sniffer with access point channel ====== ")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_case)

            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     power_save=True, mode='power_save_low_latency',
                                                                     ping_after_power_save=True, retry_count=3,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated
                                                                     )
            if self.test_case_no == 477823:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                protocols = ["TCP"]
                traffic_types = ["TX"]
                for protocol in protocols:
                    for traffic_type in traffic_types:
                        self.sl_collections.run_traffic(
                            wifi_dut=self.wifi_dut,
                            net_perf_client=self.net_perf_client,
                            protocol=protocol,
                            device_ip=self.dut_addr['device_ip'],
                            host_ip=host_ip,
                            timeout=65,
                            traffic_type=traffic_type,
                        )
            time.sleep(2)
            logger().info("disconnecting to ap.....")

            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(2)
            logger().info("Stop Sniffer finally")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(2)
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
# This test case verifies All Channels Scan in 2.4 Ghz by giving channel number as Zero
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_all_scan_channels_c19056(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                           sl_collections):
    try:
        test_name = request.node.name
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan Response Based on RSSI
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_check_rssi_c19060(wifi_dut, wifi_access_point, sl_collections):
    try:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        time.sleep(20)
        logger().info(scan_results)
        scan_count = len(scan_results)
        assert scan_count > 0, "Scan results not found"
        previous_rssi = 0

        for count in scan_results:
            assert previous_rssi >= count.rssi, "scan result is not based on the rssi"
            previous_rssi = count.rssi
            logger().info(f"scan results are based on rssi: {count.rssi}")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_ssid_32bytes_c19064(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                           sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        ssid_list = ['test123test123test123test123test', 'test1*@test1*#test1*@test1*$test',
                     'test12.test12.test12.test12.test', '了是不了是不了是不了']

        for ssid in ssid_list:
            logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            time.sleep(5)
            # initiates the access point with channel given in list
            logger().info(f"Setting access point with ssid {ssid}...")
            wifi_access_point.interfaces.wifi.start_ap(ssid=ssid)
            time.sleep(10)
            logger().info(f"\n######=====>>>>Configuring the 32byte SSID: {ssid}\n")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=wifi_access_point.interfaces.wifi.channel, ssid=ssid)
            time.sleep(20)
            logger().info("\nscan_results\n")
            assert len(scan_results) >= 1, f"32 bytes ssid not found in scan results"
            logger().info(f"Validate Probe req(Broadcast)")
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_ssid', "broadcast_ssid": False})
# This case verifies the scan in hidden mode of AP for all channels
@pytest.mark.legacy_deployed
def test_wifi_sdk_hidden_scan_all_channels_c19062(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                  sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr,
            hidden_ssid="\"\"",
            filter_name="hidden_ssid_probe_request_packet")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan failed"
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            f'Unable to find probe request broadcast packet in channel:{wifi_access_point.interfaces.wifi.channel}'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_us_region_2_4_c19067(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                            sl_collections):
    try:
        logger().info("Configured DUT in US region")
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr, da_addr=da_addr, filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels in US region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan functionality with max scan of dut
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_max_aps_c19061(wifi_dut, wifi_access_point, sl_collections):
    try:
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        channel_bitmap_2_4 = 0
        # enables the scan in DUT with the given channel bitmap value
        logger().info("Initiating selective channel scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
        time.sleep(20)
        logger().info(scan_results)
        logger().info(len(scan_results))
        if len(scan_results) == 11:
            assert True, f"Dut has scanned {len(scan_results)} Aps"
        else:
            assert False, f"To scan more number of APs, Need to keep setup in open air environment"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan functionality for channles 1-11
@pytest.mark.legacy_deployed
def test_wifi_sdk_all_chan_scan_with_channel_bitmap_c19057(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                           sl_collections, sniffer_filter):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(3)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "Scan results not found"
            channel_selected = 0
            for count in scan_results:
                assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# Verifies the scan functionality with the channel 1,6,8
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_selective_channel_c19058(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channel_list = [1, 6, 8]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(3)
            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4, )
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list), f"Scan should happen only in selected channels"

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")

            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# Verifies the scan functionality with the channel 1,3,6,11
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_selective_channel_c19059(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channel_list = [1, 3, 6, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_sel_ch_{channel}")
            time.sleep(5)

            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1, "Scan results not found"
            for count in scan_results:
                assert (count.rf_channel in channel_list), "Scan should happen only in selected channels"

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in selected channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_all_channels_in_EU_region_c19070(wifi_dut, wifi_sniffer, wifi_client, request, sl_collections,
                                                        sniffer_filter):
    try:
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(5)
            logger().info("enable the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "scan failed"
            logger().info(scan_results)

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in Europe region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "japan"
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_all_channels_in_japan_region_c19071(wifi_dut, wifi_sniffer, wifi_client, request, sniffer_filter,
                                                           sl_collections):
    try:
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        for channel in channels_list_2g:
            if channel == 14:
                logger().info(f"channel : {channel} not supported by NUC,skipping the channel")
                continue
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(5)

            logger().info("enable the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan Failed"
            logger().info(scan_results)

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in Japan region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": "hidden_ssid", "broadcast_ssid": False})
# Verifies the scan in selected channels with the ap set in hidden mode
@pytest.mark.legacy_deployed
def test_wifi_sdk_hidden_scan_sel_chan_c19063(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                              sl_collections):
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        channel_list = [1, 5, 9]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        for channel in channel_list:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")

            logger().info("Starting the access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            time.sleep(5)
            logger().info("Initiating the scan in DUT with the given channel bitmap value...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None,
                                                         scan_bitmap_2_4=channel_bitmap_2_4)
            time.sleep(20)
            logger().info(scan_results)
            assert len(scan_results) >= 1

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=sa_addr,
                hidden_ssid="\"\"",
                filter_name="hidden_ssid_probe_request_packet")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 4,
        "region_code": "worldwide"
    }
)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_all_channels_in_worldwide_region_c148601(wifi_dut, wifi_sniffer, wifi_client, request,
                                                                sniffer_filter, sl_collections):
    try:
        test_name = request.node.name
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        for channel in channels_list_2g:
            if channel == 14:
                logger().info(f"channel : {channel} not supported by NUC,skipping the channel")
                continue
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(5)

            logger().info("enable the scan in dut on channel 0...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan Failed"
            logger().info(scan_results)

            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in worldwide region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
# This test case verifies the scan in us region with cahnnels 12,13,14
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_in_US_region_for_channel_12_13_14_c19068(wifi_dut, wifi_access_point, sl_collections):
    try:
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")

        logger().info("Setting DUT in bt power save...")
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode8)

        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        channel_list = [12, 13, 14]
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100
            logger().info(f"Initiating the scan in DUT with the given channel bitmap value ---->>>{count}")
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4,
                                          expected_status=SLStatus.SL_STATUS_SI91X_INVALID_CHANNEL)
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'Korea'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_all_channels_in_korea_region_c477822(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                            sniffer_filter, sl_collections):
    """Verify Whether DUT is able to scan till 13 channels when it is configured in Korea Region"""
    try:
        test_name = request.node.name
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        true_result_list = []
        false_result_list = []
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert probe_not_captured_channel_list == [], logger().info(f"**** unable to find the Probe requests  in all "
                                                                    f"these channels:{probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'Korea'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_in_korea_region_for_channel_14_c477824(wifi_access_point, wifi_dut, wifi_sniffer, request,
                                                              sl_collections):
    """Verify Whether DUT is throwing error or not when scan in 14 channel and DUT is configured in Korea Region"""
    try:
        test_name = request.node.name
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(2)

        logger().info("Initiating scan from dut...")
        wifi_dut.interfaces.wifi.scan(ssid=None, channel=14, scan_bitmap_2_4=16384, scan_type=0,
                                      expected_status=SLStatus.SL_STATUS_SI91X_INVALID_CHANNEL)
        logger().info(f"\n\n Observed the expected error code: 0x1000A (SL_STATUS_SI91X_INVALID_CHANNEL) \n\n")
        time.sleep(20)

        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'europe'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_scan_with_deep_sleep_c537999(wifi_dut, request, wifi_sniffer, sniffer_filter, wifi_access_point,
                                               sl_collections):
    """Verify wlan scan with deep sleep(It should contain TA should go
       to deep sleep and M4 should wake up based on alarm or periodic)"""
    if (wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 20)) and (
            wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 21)):
        # If this condition is true, the device is NCP, and the test case should be skipped
        logger().info("NCP Device detected. Skipping the test case.")
        pytest.skip("Test case is not applicable for NCP device")

    try:
        test_name = request.node.name
        mode = "high_performance"
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)

            logger().info("Initiating m4 ta secure_handshake...")
            wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0, scan_type=0,
                                                         bg_scan_periodicity=10)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)

            wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode8,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            logger().info(f"Enabling M4 power save")
            wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=20000)

            logger().info(f"....Applying performance profile mode : {mode}")
            wifi_dut.interfaces.wifi.set_performance_profile(mode)

            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

            if bool(output) is False:
                false_result_list.append(bool(output))
                probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert probe_not_captured_channel_list == [], logger().info(f"**** unable to find the Probe requests  in all "
                                                                    f"these channels:{probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "region": 'europe'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.deployed_25q2
def test_wifi_sdk_scan_when_config_ap_is_not_available_c538001(wifi_dut, wifi_access_point, request, wifi_sniffer,
                                                               sniffer_filter, sl_collections):
    """Trigger scan command when configured access point
       is not available(DUT should throw 0x10003 error(No AP found))"""

    try:
        if (wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 20)) and (
                wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 21)):
            # If this condition is true, the device is NCP, and the test case should be skipped
            logger().info("NCP Device detected. Skipping the test case.")
            pytest.skip("Test case is not applicable for NCP device")
        else:
            wifi_access_point.interfaces.wifi.stop_ap()
            time.sleep(20)
            test_name = request.node.name

            logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
            time.sleep(2)

            logger().info("Initiating m4 ta secure_handshake...")
            wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

            logger().info("Initiating scan from dut...")
            wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=0, bg_scan_periodicity=10,
                                          expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
            logger().info(f"\n\n Observed the expected error code: 0x10003 (SL_STATUS_SI91X_NO_AP_FOUND) \n\n")
            time.sleep(20)

            logger().info(" ====== Going to stop the sniffer capture ====== ")
            wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "region": 'europe'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_verify_scan_possible_error_code_c538002(wifi_dut, wifi_access_point, request, wifi_sniffer,
                                                          sniffer_filter, sl_collections):
    """Verify WLAN scan possible error codes)))"""
    if (wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 20)) and (
            wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 21)):
        # If this condition is true, the device is NCP, and the test case should be skipped
        logger().info("NCP Device detected. Skipping the test case.")
        pytest.skip("Test case is not applicable for NCP device")

    try:
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(20)
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(2)

        logger().info("Initiating m4 ta secure_handshake...")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        logger().info("Initiating scan from dut...")
        wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=0, bg_scan_periodicity=10,
                                      expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
        logger().info(f"\n\n Observed the expected error code: 0x10003 (SL_STATUS_SI91X_NO_AP_FOUND) \n\n")
        time.sleep(20)

        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "ssid": 'Explore@WiFi', "region": 'europe'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.deployed_25q2
def test_wifi_sdk_verify_dut_scan_spe_char_ssid_or_not_c538003(wifi_dut, wifi_access_point, request, wifi_sniffer,
                                                               sniffer_filter, sl_collections):
    """Verify whether DUT is able to scan special characters SSID or not"""
    if (wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 20)) and (
            wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 21)):
        # If this condition is true, the device is NCP, and the test case should be skipped
        logger().info("NCP Device detected. Skipping the test case.")
        pytest.skip("Test case is not applicable for NCP device")

    try:
        test_name = request.node.name
        mode = "high_performance"
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        probe_captured_channel_list = []
        probe_not_captured_channel_list = []
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)

            logger().info("Initiating m4 ta secure_handshake...")
            wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid='Explore@WiFi', scan_bitmap_2_4=0, scan_type=0,
                                                         bg_scan_periodicity=10)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)

            wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
            wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode8,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

            logger().info(f"Enabling M4 power save")
            wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=20000)

            logger().info(f"....Applying performance profile mode : {mode}")
            wifi_dut.interfaces.wifi.set_performance_profile(mode)

            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']

            if bool(output) is False:
                false_result_list.append(bool(output))
                probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert probe_not_captured_channel_list == [], logger().info(f"**** unable to find the Probe requests  in all "
                                                                    f"these channels:{probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'testing_korea', "security": 'WPA2', "region": 'Korea',
                                               "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.WLAN_Dev_sanity_917
def test_wifi_sdk_conn_to_AP_in_korea_reg_C477823(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, request,
                                                  sl_collections,
                                                  sniffer_filter, wifi_client, net_perf_client):
    """Check the connectivity and data Transfer when DUT enabled in Korea Region"""

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    test_case = request.node.name
    ping_count = utf_constants.get("ping_count")
    wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case=test_case,
                              ping_count=ping_count, ap_mac_address=ap_mac_address,
                              wifi_client=wifi_client, test_case_no=477823, net_perf_client=net_perf_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "china"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'China', "channel": 13})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_all_channels_in_China_region_c662088(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                            sniffer_filter, sl_collections):
    """Verify Whether DUT is able to scan all channels
       when it is configured in China Region"""
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting the wifi region in China")
        channel = 0
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
        time.sleep(2)
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=channel, ssid=None, scan_bitmap_2_4=0, scan_type=0)
        time.sleep(10)
        assert (len(scan_results) >= 1), "Scan failed"
        logger().info(scan_results)
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "china"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'China'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_type_extended_enabled_in_China_region_c662089(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                                     sniffer_filter, sl_collections):
    """ Verify whether DUT is able to scan more than 11 scan
        results when SL_WIFI_SCAN_TYPE_EXTENDED is enabled"""
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting the wifi region in China")
        channel = 0
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
        time.sleep(2)
        for _ in range(3):
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=channel, ssid=None, scan_bitmap_2_4=0, scan_type=2)
            time.sleep(10)
            assert (len(scan_results) > 11), "Scan failed"
            logger().info(scan_results)

        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "china"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'China'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_scan_connect_type_extended_enabled_in_China_region_c662090(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                             request, sniffer_filter, sl_collections):
    """ Verify whether DUT is able connect to AP which comes
        after 11 scan results when SL_WIFI_SCAN_TYPE_EXTENDED is enabled"""
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting the wifi region in China")
        channel = 0
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
        time.sleep(2)
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=channel, ssid=None, scan_bitmap_2_4=0, scan_type=2)
        time.sleep(10)
        assert (len(scan_results) >= 11), "Scan failed"
        logger().info(scan_results)

        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'US'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_type_extended_enabled_c653150(wifi_sniffer, wifi_dut, wifi_access_point, request,
                                                     sniffer_filter, sl_collections):
    """ Verify whether DUT is able to scan more than 11 scan results
        when SL_WIFI_SCAN_TYPE_EXTENDED is enabled"""
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting the wifi region in US")
        channel = 0
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
        time.sleep(2)
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=channel, ssid=None, scan_bitmap_2_4=0, scan_type=2)
        time.sleep(10)
        assert (len(scan_results) > 11), "Scan failed"
        logger().info(scan_results)

        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case is not automatable marked manually as skip.")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "region": 'US'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_scan_connect_type_extended_enabled_c653151(wifi_sniffer, wifi_dut, wifi_access_point,
                                                             request, sniffer_filter, sl_collections):
    """ Verify whether DUT is able connect to AP which comes after
        11 scan results when SL_WIFI_SCAN_TYPE_EXTENDED is enabled"""
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        logger().info("Setting the wifi region in US")
        channel = 0
        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
        time.sleep(2)
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=channel, ssid=None, scan_bitmap_2_4=0, scan_type=0)
        network_to_connect = ""
        if len(scan_results) > 11:
            network_to_connect = scan_results[12].ssid
            wifi_dut.interfaces.wifi.join(ssid=network_to_connect, passphrase="", channel=6)
        time.sleep(10)
        assert (len(scan_results) >= 1), "Scan failed"
        # logger().info(scan_results)

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
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "worldwide"
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "ssid": 'My_Special!SSID@2023'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_passive_scan_in_worldwide_domain_c538000(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                                           sniffer_filter, sl_collections):
    """Verify passive scan in the worldwide domain."""
    try:
        test_name = request.node.name
        logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(5)

        logger().info("Initiating passive scan from DUT...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0, scan_type=1)

        time.sleep(20)  # Wait for scan results to populate
        logger().info(scan_results)

        assert len(scan_results) >= 1, "Scan results not found"

        logger().info("Stopping sniffer finally")
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
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_scan_with_high_beacon_length_c538006(wifi_access_point, wifi_dut, request, wifi_sniffer,
                                                       sniffer_filter, sl_collections):
    """Verify WLAN scan with a third-party AP configured with a high beacon length (max 512 bytes)."""
    if (wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 20)) and (
            wifi_dut.interfaces.wifi.oper_mode_opts.ext_custom_features & (1 << 21)):
        # If this condition is true, the device is NCP, and the test case should be skipped
        logger().info("NCP Device detected. Skipping the test case.")
        pytest.skip("Test case is not applicable for NCP device")
    try:
        test_name = request.node.name
        packet_filter2 = '    Frame Length:'

        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(2)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {ap_bssid}")

        logger().info("Initiating m4 ta secure_handshake...")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)

        logger().info("Initiating scan from DUT...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0, scan_type=0,
                                                     bg_scan_periodicity=10)
        time.sleep(20)  # Wait for scan to complete
        assert len(scan_results) >= 1, "Scan failed"
        logger().info(scan_results)

        logger().info("Stopping sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_bssid,
                                                                                        filter_name="beacon")
        logger().info("Validating Probe req(Broadcast)")
        sniffer_validation_result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                                       packet_filter2=packet_filter2)
        assert sniffer_validation_result['packet_count'], \
            f'Unable to find beacon packet in channel: {wifi_access_point.interfaces.wifi.channel}'

        pattern = r"Frame Length:\s+(\d+)\s+bytes"
        # Open the file and search for the pattern
        capture_file_path = './reports/filter2_file.txt'

        try:
            with open(capture_file_path, 'r') as file:
                for line in file.readlines():
                    match = re.search(pattern, line)
                    if match:
                        # Extract the frame length in bytes
                        frame_length = int(match.group(1))
                        if frame_length < 512:
                            return "Fail: Frame Length is less than 512 bytes"
                        logger().info(f"Frame Length: {frame_length} bytes")
        except FileNotFoundError:
            logger().error(f"Capture file not found: {capture_file_path}")
            raise

    except Exception as e:
        logger().error(f"Exception occurred: {e}")  # Log the exception
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        raise  # Re-raise the exception after handling to ensure test failure is reported


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
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "japan",
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "Automation@123", "channel": 14
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "region": 1,
        "region_code": "japan",
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "Automation@123", "channel": 14
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C19073')
@pytest.mark.legacy_deployed
def test_wifi_sdk_verify_11b_rates_channel14_c19073(wifi_dut, remote_wiseconnect3, sl_collections):
    """ Verify whether module is using only 11b rates in channel 14 in JP region """

    try:
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP", security="wpa2", psk="Automation@123", channel=14,
                                          dtim_beacon_count=1, beacon_interval=100)
        """ set data rate in b(11Mbps) mode and Verify """
        remote_wiseconnect3.interfaces.sapi.set_transmit_rate(rate_protocol="802.11b", data_rate="11Mbps")

        logger().info("Initiating scan from dut...")
        scan_results = remote_wiseconnect3.interfaces.sapi.scan(channel=0, ssid=None, scan_bitmap_2_4=8192, scan_type=0,
                                                                bg_scan_periodicity=10)
        assert (len(scan_results) >= 1), "Scan failed"
        logger().info(scan_results)
        time.sleep(10)

    except Exception as e:
        logger().error(f"Exception occurred: {e}")  # Log the exception
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.test_src_map_id('C653152')
@pytest.mark.deployed_25q2
def test_wifi_sdk_scan_with_mbssid_extended_scan_c653152(wifi_access_point, wifi_dut, request, wifi_sniffer,
                                                         sniffer_filter, sl_collections):
    """Verified wherther DUT is able scan MBSSID AP,
       when SL_WIFI_SCAN_TYPE_EXTENDED is enabled."""

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sniffer_filter=sniffer_filter, sl_collections=sl_collections)

    try:
        test_name = request.node.name
        logger().info(f"configuring the Sniffer with the channel : {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(5)

        wlan_obj.verfiy_T_and_NT_based_mbssid_in_dut_list(scan_type=True)

        logger().info("Stopping sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().error(f"Exception occurred: {e}")  # Log the exception
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "korea"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2', "region": 'Korea', "channel": 13, "ssid": 'Azeez456'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_setup_dut_sta_mode_korea_region_conn_ap_chan_13_c477830(wifi_access_point, wifi_dut, wifi_sniffer,
                                                                          request,
                                                                          sniffer_filter, sl_collections):
    """Setup the DUT in STA operating mode, set the region to korea
       and connect to AP which is in Korea region and operating in 13th channel."""
    try:
        test_name = request.node.name
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        channel = 13
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        logger().info(f"configuring the Sniffer with the channel : {channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
        time.sleep(2)
        logger().info("Initiating scan from dut...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=0)
        time.sleep(20)
        assert (len(scan_results) >= 1), "Scan failed"
        logger().info(scan_results)
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                        filter_name="probe_request")
        logger().info(f"Validate Probe req(Broadcast)")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request broadcast packet in channel'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wifi_scan_no_ap_in_closed_room_c687827(wifi_dut, wifi_access_point, request, wifi_sniffer,
                                                         sniffer_filter, sl_collections):
    """Verify Wi-Fi scan results when there is no AP available in the envirnoment(Closed room))))"""

    try:
        wifi_access_point.interfaces.wifi.stop_ap()
        time.sleep(20)
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}.pcap")
        time.sleep(2)

        logger().info("Initiating scan from dut...")
        wifi_dut.interfaces.wifi.scan(ssid="None", scan_bitmap_2_4=0, scan_type=0,
                                      expected_status=SLStatus.SL_STATUS_SI91X_NO_AP_FOUND)
        logger().info(f"\n\n Observed the expected error code: 0x10003 (SL_STATUS_SI91X_NO_AP_FOUND) \n\n")
        time.sleep(20)

        logger().info(" ====== Going to stop the sniffer capture ====== ")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


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
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "japan",
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "Automation@123", "channel": 14
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "region": 1,
        "region_code": "japan",
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "Automation@123"
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wifi_sdk_do_scan_in_channel_12_13_14_c19072(wifi_dut, remote_wiseconnect3, request, wifi_sniffer,
                                                     sl_collections):
    """ Do scan in channels 12,13,14 in JP region """
    try:
        test_name = request.node.name
        channels_list = [12, 13, 14]
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list:
            wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP", security="wpa2", psk="Automation@123",
                                              dtim_beacon_count=1, beacon_interval=100, channel=channel)
            time.sleep(10)
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)

            logger().info("Initiating scan from dut...")
            scan_results = remote_wiseconnect3.interfaces.sapi.scan(channel=0, ssid=None, scan_bitmap_2_4=14336,
                                                                    scan_type=0, bg_scan_periodicity=10)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)
            time.sleep(20)

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(2)
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
            time.sleep(10)

    except Exception as e:
        logger().error(f"Exception occurred: {e}")  # Log the exception
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'EU_SILABS_AP',
        'security': 'WPA2',
        'passphrase': '123123123',
        'region': 'Europe'
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_Verify_DS_param_in_EU_region_c719887(wifi_sniffer, wifi_dut, wifi_access_point, sniffer_filter,
                                                       request, sl_collections):
    """ Verify DS param in probe request of DUT in EU region"""
    try:
        test_name = request.node.name
        logger().info("Setting DUT in wlan power save...")
        wifi_dut.interfaces.wifi.set_performance_profile(mode="standby_power_save_with_ram_retention")
        logger().info("Enabling rejoin...")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        channel_list = [11, 12, 13]
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channel_list:
            logger().info("Starting access point with custom channel...")
            wifi_access_point.interfaces.wifi.start_ap(channel=channel)
            logger().info("Initiating scan...")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_with_channel_{channel}")
            logger().info("Initiating scan...")
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
            time.sleep(20)
            logger().info(scan_results)

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_req_ds_param")
            logger().info(f"Validate DS Param in Probe req")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], \
                f'Unable to find DS Param in probe request packet in channel:{channel}'

            logger().info(f"found DS Param in Probe req in channel:{channel}'")
        logger().info("DUT scan success in all channels")
        logger().info("Dut is able to scan successfully in Europe region")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_all_scan_channels_c789529(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                            sl_collections):
    # This test case verifies All Channels Scan in 2.4 Ghz by giving channel number as Zero
    try:
        channels_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        true_result_list = []
        false_result_list = []
        Probe_captured_channel_list = []
        Probe_not_captured_channel_list = []
        test_name = request.node.name
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=50)
        output = wifi_dut.interfaces.wifi.get_advanced_scan_configuration()
        logger().info(f"adv_active_channel_time = {output['adv_active_channel_time']}")

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        for channel in channels_list_2g:
            logger().info(f"configuring the Sniffer with the channel : {channel}")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{channel}")
            time.sleep(2)
            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            time.sleep(20)
            assert (len(scan_results) >= 1), "Scan failed"
            logger().info(scan_results)
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,
                                                                                            filter_name="probe_request")
            logger().info(f"Validate Probe req(Broadcast)")
            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            if bool(output) is False:
                false_result_list.append(bool(output))
                Probe_not_captured_channel_list.append(channel)
            else:
                true_result_list.append(bool(output))
                Probe_captured_channel_list.append(channel)
            logger().info(f"True list = {true_result_list}")
            logger().info(f"false list = {false_result_list}")
        assert Probe_not_captured_channel_list == [], logger().info(
            f"**** unable to find the Probe requests  in all these channels:{Probe_not_captured_channel_list}")
        logger().info(f"found Probe req(Broadcast) in all the channel:{Probe_captured_channel_list}'")
        logger().info("DUT scan success in all channels")
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=-12)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, expected_status=SLStatus.SL_STATUS_TIMEOUT)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
def test_wifi_sdk_scan_congested_channel_c925907(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    """Verify the scan in the congested channel (channel 1)."""
    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")

        logger().info(f"Configuring the sniffer for channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}_ch_{wifi_access_point.interfaces.wifi.channel}")
        time.sleep(2)

        logger().info("Initiating scan from DUT...")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=wifi_access_point.interfaces.wifi.channel, ssid=None)
        time.sleep(20)

        assert len(scan_results) > 0, "Scan failed or no results found"
        logger().info(f"Scan results: {scan_results}")

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, filter_name="probe_request")
        logger().info("Validating probe requests")
        validation_result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)
        assert validation_result['packet_count'] > 0, "No probe requests captured"

        logger().info("Scan in congested channel verified successfully")
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
def test_PMU_good_time_Functionality_c919215(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    """Verify PMU good time functionality using 'sl_si91x_set_nwp_config_request' API by configuring different values."""

    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")
        config_val = [900, 1500, 2000]
        for val in config_val:
            logger().info(f"Configuring PMU good time with value: {val}")
            wifi_dut.interfaces.wifi.write_nwp_config(code = 16,config_val=val)
            time.sleep(2)  # Wait for the configuration to take effect
            logger().info(f"Configured val = {val} PMU good time successfully ")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
def test_XTAL_good_time_Functionality_c919214(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    """Verify XTAL good time functionality using 'sl_si91x_set_nwp_config_request' API by configuring different values."""

    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")
        config_val = [600, 2000, 3000, 4000, 5000]
        for val in config_val:
            logger().info(f"Configuring XTAL good time with value: {val}")
            wifi_dut.interfaces.wifi.write_nwp_config(code= 8, config_val=val)
            time.sleep(2)  # Wait for the configuration to take effect
            logger().info(f"Configured val = {val} XTAL good time successfully ")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
def test_configuring_wrong_config_values_PMU_c919217(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    """API functionality by configuring wrong config values of PMU good time"""

    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")
        config_val = [500]
        for val in config_val:
            logger().info(f"Configuring PMU good time with value: {val}")
            wifi_dut.interfaces.wifi.write_nwp_config(code = 16,config_val=val, expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
            time.sleep(2)  # Wait for the configuration to take effect
            logger().info(f"Configured val = {val} Observed the expected error successfully ")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1})
def test_configuring_wrong_config_values_XTAL_c919216(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter, sl_collections):
    """API functionality by configuring wrong config values of XTAL good time"""

    try:
        test_name = request.node.name
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")
        config_val = [6000]
        for val in config_val:
            logger().info(f"Configuring XTAL good time with value: {val}")
            wifi_dut.interfaces.wifi.write_nwp_config(code= 8, config_val=val, expected_status=SLStatus.SL_STATUS_INVALID_PARAMETER)
            time.sleep(2)  # Wait for the configuration to take effect
            logger().info(f"Configured val = {val} Observed the expected error successfully ")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
