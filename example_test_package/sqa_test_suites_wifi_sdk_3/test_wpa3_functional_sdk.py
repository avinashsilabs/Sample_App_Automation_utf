import time
import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xExtCustomFeatureBitMap, Si91xJoinFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9117
        1. Configuration of DUT in 2G : B/G/N/AX
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Enable the power save mode in DUT & BLE
        6. Stop the sniffer  
        7. Analyizing all sniffer capture packets for wpa3 functionality
    setup requirement:
        1. DUT(RS9117)
        2. WSDK 3.0 Board
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Benazeer K
"""


class WifiConnectionThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, time_period=None, sniffer_filter=None,
                 data=None, ping_count=None, data_transfer=True, test_name=None, sl_collections=None, wifi_client=None,
                 traffic_type=None, dut_leave=True, protocol=None, net_perf_client=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.time_period = time_period
        self.data = data
        self.ping_count = ping_count
        self.protocol = protocol
        self.device_ip = None
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.dut_leave = dut_leave
        self.test_name = test_name

    def run(self):
        try:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            if self.test_case_no == 34513:
                transfer_type = 1
                protocol = 6
                throughput_type = 3
                size = 1460

            if self.test_case_no == 34515:
                transfer_type = 2
                protocol = 17
                throughput_type = 4
                size = 1470

            if self.test_case_no == 34512:
                transfer_type = 1
                protocol = 6
                throughput_type = 1
                size = 1460

            if self.test_case_no == 34514:
                transfer_type = 2
                protocol = 17
                throughput_type = 2
                size = 1470

            if self.test_case_no == 34503:
                logger().info(f"\n\nscanning for wpa3 Access Point with different combinations of scan\n\n\n")
                scan_dict = [{"ssid": None, "channel": 0},
                             {"ssid": None, "channel": self.wifi_access_point.interfaces.wifi.channel},
                             {"ssid": self.wifi_access_point.interfaces.wifi.ssid,
                              "channel": self.wifi_access_point.interfaces.wifi.channel}]

                for i in range(len(scan_dict)):
                    assert self.wifi_dut.interfaces.wifi.scan(ssid=scan_dict[i]['ssid'],
                                                              channel=scan_dict[i]['channel'])
                    time.sleep(3)

            if self.test_case_no == 34509:
                """ Enabling the rejion feature """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
            if self.test_case_no == 34511:
                """ Enabling the BG-Scan feature """
                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                              adv_passive_channel_time=20)
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.scan(bgscan=False, bg_scan_periodicity=10)

            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     power_save=True, ping_after_power_save=True)
            logger().info("DUT successfully connected with AP")
            time.sleep(2)
            if self.data_transfer:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                if self.traffic_type == "TX":
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=
                    self.dut_addr['device_ip'], protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0)
                    # # get and print throughput
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp is not None, "Throughput not found"
                    logger().info("data transfer successful")
                    time.sleep(3)
                if self.traffic_type == "RX":
                    # Iperf Client Started
                    if self.protocol == "UDP":
                        bandwidth = "68M"
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                        self.dut_addr['device_ip'], protocol=self.protocol, bandwidth=bandwidth)
                    else:
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                        self.dut_addr['device_ip'], protocol=self.protocol)

                    self.net_perf_client.interfaces.net_perf.start()

                    logger().info("receiving data from Host")
                    # open socket and listen for data
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0)
                    logger().info("data received is successful")
                    time.sleep(3)

            time.sleep(2)
            if self.test_case_no == 34509:
                logger().info("This is rejoin")
            else:
                self.wifi_dut.interfaces.wifi.leave()
                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.stop_capture()
                logger().info("Stop Sniffer finally")
                time.sleep(2)
                packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    wlan_addr=self.dut_addr['dut_mac_address'],
                    filter_name="wpa3_confirm_commit_message")
                logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

                packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    wlan_addr=self.dut_addr['dut_mac_address'],
                    filter_name="wpa3_4_way_handshake_message")
                logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")

                snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                    'packet_count']
                assert snif_pkt_count, "Unable to find the commit & confirm packets."

                snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
                    'packet_count']
                assert snif_pkt_count, "Unable to find association & ea pols packets."

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_scan_wpa3_c34503_04_05_07(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                            sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name
    '''Verifying scan for wpa3 configured access point'''
    logger().info(f"This test case will cover four test cases c34503, c34504, c34505, c34507")
    wlan_obj = WifiConnectionThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    sniffer_filter=sniffer_filter, test_case_no=34503, data_transfer=False)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_conn_deconn_reconn_wpa3_C34508(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    test_name = request.node.name
    '''Verifying connection, disconnection and reconnection with WPA3 configured Access Point'''

    wlan_obj = WifiConnectionThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                    ping_count=ping_count, test_name=test_name, sniffer_filter=sniffer_filter,
                                    sl_collections=sl_collections, data_transfer=False)
    try:
        for i in range(0, iter_count):
            wlan_obj.start()
            wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_bg_scan_specific_ch_wpa3_c34511(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                  sniffer_filter, sl_collections, wifi_client):
    test_name = request.node.name
    channel_list_2g = [1, 6, 11]
    probe_check_dict = {}
    probe_not_captured_channel_list = []
    channel_bitmap_2_4 = 0

    for count in channel_list_2g:
        channel_bitmap_2_4 += 1 << (count - 1)
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable |
                                Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                 adv_passive_channel_time=20,
                                                                 adv_enable_instant_scan=1)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        time.sleep(2)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
        dut_add_dict=sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, associated=False,
                                            ping_after_power_save=True)
        time.sleep(2)
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(
            f"\n\n Broadcast Probe request packet validation is start for channel = {channel_list_2g}\n\n")
        for channel in channel_list_2g:
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(10)
            ping_count = 10
            device_ip = dut_add_dict['device_ip']
            status = ping(device_ip, ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")
            time.sleep(10)
            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter\
                (sa_addr=dut_add_dict['dut_mac_address'], filter_name="probe_request")

            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            probe_check_dict[channel] = int(output)

            logger().info(f'\n\n ***** probe check dictionary : {probe_check_dict} ***** \n\n')
            for key, value in probe_check_dict.items():
                if value == 0:
                    probe_not_captured_channel_list.append(key)

            logger().info(f"probe not captured channel list: {probe_not_captured_channel_list}")
            assert probe_not_captured_channel_list == [], f"probe not captured channel list: {probe_not_captured_channel_list}"
            logger().info(f"probe requests are captured in all the configured channels, Hence the test case is PASS")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_bg_scan_in_all_ch_wpa3_c34510(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                  sniffer_filter, sl_collections):
    test_name = request.node.name
    channel_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    probe_check_dict = {}
    probe_not_captured_channel_list = []
    channel_bitmap_2_4 = 0

    for count in channel_list_2g:
        channel_bitmap_2_4 += 1 << (count - 1)
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable |
                                Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                 adv_passive_channel_time=20,
                                                                 adv_enable_instant_scan=1)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        time.sleep(2)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
        dut_add_dict = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                           associated=False,
                                                           ping_after_power_save=True)
        time.sleep(2)
        wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(
            f"\n\n Broadcast Probe request packet validation is start for channel = {channel_list_2g}\n\n")
        for channel in channel_list_2g:
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(10)
            ping_count = 10
            device_ip = dut_add_dict['device_ip']
            status = ping(device_ip, ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")
            time.sleep(10)
            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter \
                (sa_addr=dut_add_dict['dut_mac_address'], filter_name="probe_request")

            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            probe_check_dict[channel] = int(output)

            logger().info(f'\n\n ***** probe check dictionary : {probe_check_dict} ***** \n\n')
            for key, value in probe_check_dict.items():
                if value == 0:
                    probe_not_captured_channel_list.append(key)

            logger().info(f"probe not captured channel list: {probe_not_captured_channel_list}")
            assert probe_not_captured_channel_list == [], f"probe not captured channel list: {probe_not_captured_channel_list}"
            logger().info(f"probe requests are captured in all the configured channels, Hence the test case is PASS")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_rejoin_with_wpa3_security_c34509(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                                   sniffer_filter, switch, sl_collections):
    try:
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        ''' Verify Rejoin Functionality in WPA3 Security'''
        state = switch.interfaces.pdu_switch.get_state()
        logger().info("pdu switch state : " + str(state))
        if state == 'true':
            logger().info('PDU is ready for use')
        else:
            logger().info(f'\n\n Please check the AP & PDU current state')
            assert False
        '''Verifying the scan results with-in the configure time interval of 500 Milli-Seconds '''
        wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                        wifi_sniffer=wifi_sniffer,
                                        ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                        data_transfer=False, test_case_no=34509)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(3)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name="probe_request")
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        time.sleep(2)
        if state == 'true':
            logger().info('#### Turn off the Access Point')
            switch.interfaces.pdu_switch.turn_off()
        time.sleep(30)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info('##### Turn on Access point #####')
        state = switch.interfaces.pdu_switch.get_state()
        logger().info(f"checking status: {state}")
        if state == 'false':
            switch.interfaces.pdu_switch.turn_on()
            logger().info(
                f"PDU was off, trying to turn on using PDU, Please wait for 60 seconds "
                f"to check DUT is rejoined to that AP or not ........")
            time.sleep(60)
        if wifi_dut.interfaces.wifi.associated is True:
            logger().info(f"Initiating ping to DUT ip {wlan_obj.dut_addr['device_ip']} after successful rejoin")
        ping_count = 10
        device_ip = wlan_obj.dut_addr['device_ip']
        status = ping(device_ip, ping_count)
        assert status, "DUT not responding for ping request......"
        if status == 1:
            logger().info('#### Ping successful ####')
        else:
            logger().info('#### Ping unsuccessful ####')
        logger().info("ping to DUT is successful....")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Probe Request packets'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exeception=e)
        logger().info(f"\n\n **** Details of the Exception are:{str(e)} *****\n\n")
        assert False, "Failed"
    finally:
        if state == 'false':
            switch.interfaces.pdu_switch.turn_on()
            logger().info(
                f"PDU was off, trying to turn on using PDU, Please wait for 60 seconds ........")
            time.sleep(60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_2_4_tcp_rx_wpa3_C34513(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, wifi_client,
                                         sniffer_filter, sl_collections, net_perf_client, protocol):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name
    '''Verifying connection and TCP RX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    net_perf_client=net_perf_client, protocol=protocol, data_transfer=True,
                                    traffic_type="RX", wifi_client=wifi_client, test_case_no=34513,
                                    sniffer_filter=sniffer_filter
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_2_4_udp_rx_wpa3_c34515(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, wifi_client,
                                         sniffer_filter, sl_collections, net_perf_client, protocol):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name
    '''Verifying connection and UDP RX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    net_perf_client=net_perf_client, protocol=protocol, data_transfer=True,
                                    traffic_type="RX", sniffer_filter=sniffer_filter, wifi_client=wifi_client,
                                    test_case_no=34515
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_2_4_tcp_tx_wpa3_c34512(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, wifi_client,
                                         sniffer_filter, sl_collections, net_perf_client, protocol):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name
    '''Verifying connection and TCP TX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    net_perf_client=net_perf_client, protocol=protocol, data_transfer=True,
                                    traffic_type="RX", sniffer_filter=sniffer_filter, wifi_client=wifi_client,
                                    test_case_no=34512
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_2_4_udp_tx_wpa3_c34514(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, wifi_client,
                                         sniffer_filter, sl_collections, net_perf_client, protocol):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name
    '''Verifying connection and UDP TX traffic with WPA3 configured Access Point'''
    wlan_obj = WifiConnectionThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                    ping_count=ping_count, test_name=test_name, sl_collections=sl_collections,
                                    net_perf_client=net_perf_client, protocol=protocol, data_transfer=True,
                                    traffic_type="RX", sniffer_filter=sniffer_filter, wifi_client=wifi_client,
                                    test_case_no=34514
                                    )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
