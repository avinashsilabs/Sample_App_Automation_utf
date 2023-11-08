import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Run the traffic TCP/UDP TX & RX.
        5. Verify the throughput of values TCP/UDP TX & RX values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Shaik Abdul Azeez
"""

class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, sl_collections=None, ping_count=None, utf_constants=None,
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase = testcase
        self.utf_constants = utf_constants
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.test_case_no = test_case_no
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.dut_addr = None

    def run(self):
        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(3)

        if self.test_case_no == 19292:
            static_ip = '192.168.50.210'
            static_subnet = '255.255.255.0'
            static_gateway = '192.168.50.1'
            ip_version = 'ipv4'
            logger().info(f"=======>>>>>Verifying Static IP<<<<<<<======")
            self.sl_collections.scan(wifi_dut=self.wifi_dut)
            self.sl_collections.connect(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point)
            self.wifi_dut.interfaces.wifi.start_ip(ip_version=ip_version, static_ip=static_ip,
                                                   static_subnet=static_subnet,
                                                   static_gateway=static_gateway, timeout=10)
            device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
            logger().info(f"Device is {device_ip}")
            time.sleep(2)
            status = ping(device_ip, self.ping_count)
            mode = 'power_save_low_latency'
            dtim_aligned_type = 0
            num_of_dtim_skip = 0
            listen_interval = 0
            assert (status is True), "DUT is not responding to ping request from third party device"
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip, listen_interval)
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                          psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
            time.sleep(2)
            status = ping(device_ip, self.ping_count)
            assert (status is True), "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")

        else:
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=3, ping_count=self.ping_count)
        time.sleep(2)
        if self.test_case_no == 19293 or self.test_case_no == 19256:
            logger().info(f"Verifying dhcp renewal")
            time.sleep(10)
        if self.data_transfer:
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            if self.traffic_type == "TX":
                # starting iperf
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=
                self.dut_addr['device_ip'], protocol=self.protocol)
                self.net_perf_client.interfaces.net_perf.start()
                logger().info("sending data from DUT")
                timeout = 100
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    size=1460, ttl=30, throughput_type=1, qos=0, timeout=timeout+2)
                # # get and print throughput
                tp = self.net_perf_client.interfaces.net_perf.process_output()
                assert tp is not None, "Throughput not found"
                logger().info("data transfer successful")
                time.sleep(3)
            if self.traffic_type == "RX":
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                self.dut_addr['device_ip'], protocol=self.protocol, bandwidth="68M")

                self.net_perf_client.interfaces.net_perf.start()

                logger().info("receiving data from Host")
                # open socket and listen for data
                timeout = 100
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1460, ttl=90, throughput_type=3, qos=0, timeout=timeout+2)
                logger().info("data received is successful")
                time.sleep(3)
        if self.test_case_no == 19295:
            time.sleep(60)
        if self.test_case_no == 19296:
            time.sleep(15)
        if self.test_case_no == 19293:
            logger().info(f"\n######======>>>>>>Waiting for dhcp renewal packets<<<<<<======#######\n")
            time.sleep(1800)
            self.wifi_dut.interfaces.wifi.leave()
            logger().info(f"Disconnection will issued after verification")
            self.wifi_sniffer.interfaces.capture.stop_capture()
        else:
            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_sniffer.interfaces.capture.stop_capture()

    def delta_between_dhcp_req_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff


@pytest.mark.start_state("wifi_dut", wifi="init")
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
def test_wifi_sdk_verify_static_ip_allocation_to_dut_c19292(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants,
                                                            wifi_client, request, sl_collections, sniffer_filter):
    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")
    sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"Device mac address: {sa_addr}")
    da_addr = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {da_addr}")

    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=capture_filename, wifi_client=wifi_client, sl_collections=sl_collections,
                              ping_count=ping_count, test_case_no=19292)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)["packet_count"], \
            'Unable to find the power save sniffer packets'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.parametrize("dhcp_lease", [120])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120", "security": 'OPEN'})
@pytest.mark.start_state("wifi_dut", wifi="init")
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
def test_wifi_sdk_dhcp_renewal_time_to_2_min_renewal_func_c19293(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                                 utf_constants, request, sl_collections, dhcp_lease,
                                                                 sniffer_filter):
    time_delta = 60
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=capture_filename, wifi_client=wifi_client, sl_collections=sl_collections,
                              ping_count=ping_count, test_case_no=19293)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Waiting for half an hour to verify dhcp renewal ")
        time.sleep(2)
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        time.sleep(2)
        device_address = {'sa_addr': wlan_obj.dut_addr['dut_mac_address'], 'da_addr': da_addr,
                          'wlan_addr': wlan_obj.dut_addr['dut_mac_address']}
        filters_name = {1: 'power_mgmt_bit', 2: 'dhcp'}
        output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'
        filters_name_1 = {1: 'dhcp_renewal'}
        output_2 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name_1,
                                                                        packet_filter2=packet_filter2)
        logger().info(f'\n OUTPUT 1 = {output_2}\n')
        assert all(output_2.values()), 'Unable to find expected filter'
        dhcp_request_packets_time_delta_list = wlan_obj.delta_between_dhcp_req_packet()
        logger().info(f'Probe packet time delta list= {dhcp_request_packets_time_delta_list}')
        dhcp_request_packets_time_delta_list.pop(0)
        logger().info(f'DHCP Req packet time delta list after removing 0 = {dhcp_request_packets_time_delta_list}')

        for time_diff in dhcp_request_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(50, time_delta)
            if is_between is False:
                logger().info(f"{is_between}")
                status = is_between
                logger().info(f'\n{time_diff} value is out of range so test case is failed\n')
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "100", "security": 'OPEN'})
@pytest.mark.start_state("wifi_dut", wifi="init")
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
def test_wifi_sdk_tcp_tx_functionality_while_dhcp_renewal_c19295(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,net_perf_client,
                                                                 protocol, utf_constants, request, sl_collections, sniffer_filter):
    time_delta = 60
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=capture_filename, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol,sl_collections=sl_collections, ping_count=ping_count, data_transfer=True,
                              traffic_type="TX", test_case_no=19295)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Waiting for half an hour to verify dhcp renewal ")
        time.sleep(2)
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        time.sleep(2)
        device_address = {'sa_addr': wlan_obj.dut_addr['dut_mac_address'], 'da_addr': da_addr,
                          'wlan_addr': wlan_obj.dut_addr['dut_mac_address']}
        filters_name = {1: 'power_mgmt_bit', 2: 'dhcp'}
        output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'
        filters_name_1 = {1: 'dhcp_renewal'}
        output_2 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name_1,
                                                                        packet_filter2=packet_filter2)
        logger().info(f'\n OUTPUT 1 = {output_2}\n')
        assert all(output_2.values()), 'Unable to find expected filter'
        dhcp_request_packets_time_delta_list = wlan_obj.delta_between_dhcp_req_packet()
        logger().info(f'Probe packet time delta list= {dhcp_request_packets_time_delta_list}')
        dhcp_request_packets_time_delta_list.pop(0)
        logger().info(f'DHCP Req packet time delta list after removing 0 = {dhcp_request_packets_time_delta_list}')

        for time_diff in dhcp_request_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(50, time_delta)
            if is_between is False:
                logger().info(f"{is_between}")
                status = is_between
                logger().info(f'\n{time_diff} value is out of range so test case is failed\n')
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "100", "security": 'OPEN'})
@pytest.mark.start_state("wifi_dut", wifi="init")
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
def test_wifi_sdk_tcp_rx_functionality_while_dhcp_renewal_c19296(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,net_perf_client,
                                                                 protocol, utf_constants, request, sl_collections, sniffer_filter):
    time_delta = 60
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=capture_filename, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, ping_count=ping_count,data_transfer=True,
                              traffic_type="RX", test_case_no=19296)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Waiting for half an hour to verify dhcp renewal ")
        time.sleep(2)
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        time.sleep(2)
        device_address = {'sa_addr': wlan_obj.dut_addr['dut_mac_address'], 'da_addr': da_addr,
                          'wlan_addr': wlan_obj.dut_addr['dut_mac_address']}
        filters_name = {1: 'power_mgmt_bit', 2: 'dhcp'}
        output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'
        filters_name_1 = {1: 'dhcp_renewal'}
        output_2 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name_1,
                                                                        packet_filter2=packet_filter2)
        logger().info(f'\n OUTPUT 1 = {output_2}\n')
        assert all(output_2.values()), 'Unable to find expected filter'
        dhcp_request_packets_time_delta_list = wlan_obj.delta_between_dhcp_req_packet()
        logger().info(f'Probe packet time delta list= {dhcp_request_packets_time_delta_list}')
        dhcp_request_packets_time_delta_list.pop(0)
        logger().info(f'DHCP Req packet time delta list after removing 0 = {dhcp_request_packets_time_delta_list}')

        for time_diff in dhcp_request_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(50, time_delta)
            if is_between is False:
                logger().info(f"{is_between}")
                status = is_between
                logger().info(f'\n{time_diff} value is out of range so test case is failed\n')
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
