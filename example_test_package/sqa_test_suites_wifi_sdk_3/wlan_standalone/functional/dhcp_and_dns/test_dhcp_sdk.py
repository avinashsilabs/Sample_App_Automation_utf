import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xTCPIPFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xOperatingMode, Si91xPowerSaveModes, \
    Si91xPowerSaveProcedureTypes
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from random import randint


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
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, test_case_no=None, ssl_server=None, ssl_data_transfer=None):
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
        self.ssl_server = ssl_server
        self.ssl_data_transfer = ssl_data_transfer

    def run(self):
        logger().info(f"Enabling DHCP lease time")
        self.wifi_access_point.interfaces.wifi.enable_dhcp_ap()
        time.sleep(2)
        logger().info("starting the sniffer capture")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(2)

        if self.test_case_no == 19293 or self.test_case_no == 19295 or self.test_case_no == 19296 or self.test_case_no == 551871 or self.test_case_no == 551872:
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=3, ping_count=self.ping_count)
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
                timeout = 100
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    size=1460, ttl=60, throughput_type=1, qos=0, timeout=timeout+2)
                # # get and print throughput
                tp = self.net_perf_client.interfaces.net_perf.process_output()
                assert tp is not None, "Throughput not found"
                logger().info("data transfer successful")
                time.sleep(3)
            if self.traffic_type == "RX":
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                self.dut_addr['device_ip'], protocol=self.protocol)
                self.net_perf_client.interfaces.net_perf.start()
                logger().info("receiving data from Host")
                # open socket and listen for data
                timeout = 100
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1460, ttl=30, throughput_type=3, qos=0, timeout=timeout + 2)
                time.sleep(5)
                logger().info("data received is successful")

        if self.ssl_data_transfer:
            if self.traffic_type == "TX":
                buffer_length = 1370
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                self.ssl_server.interfaces.ssl.start_server()
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket()
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port,
                                              timeout=15)
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                          server_port=port1)
                pkt_count = 50000
                time.sleep(1)
                server_socket_no = 1
                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
                logger().info(f"Number of bytes sent by dut {result}")
                bytes_sent = result
                bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
                logger().info(
                    f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)

            if self.traffic_type == "RX":
                buffer_length = 1370
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                self.ssl_server.interfaces.ssl.start_server()
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.set_socket_config()
                # Open ssl client socket in the DUT
                time.sleep(2)
                sock = self.wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                 protocol="IPPROTO_TCP")
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
                local_port = randint(5001, 60000)
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port,
                                              timeout=15)
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                          server_port=port1)
                socket_no = 1
                pkt_count = 50000
                duration = 60
                self.ssl_server.interfaces.ssl.send_data(socket_no, pkt_count, msg_length=buffer_length, duration=duration)
                time.sleep(80)
                bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(socket_no)
                result = self.wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, no_of_pkts="pkt_count", ttl=30)
                logger().info(f"*** result of rx_stats in wifidut {result}")
                bytes_received = int(result)
                logger().info(f"bytes sent by remote peer -> {bytes_sent}")
                logger().info(f"bytes received on socket {sock} -> {bytes_received}")
                logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)

        if self.test_case_no == 19295:
            time.sleep(120)
        if self.test_case_no == 19296:
            time.sleep(120)
        if self.test_case_no == 551871:
            time.sleep(120)
        if self.test_case_no == 551872:
            time.sleep(120)
        if self.test_case_no == 19293:
            logger().info(f"\n==========>>>>>>Waiting up to 1800 seconds for dhcp renewal packets<<<<<<===========\n")
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
                                                            request, sl_collections, sniffer_filter):
    try:
        capture_filename = request.node.name
        ping_count = utf_constants.get("ping_count")
        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        static_ip = UtfConfig.instance().defaults["wifi"].get("static_ip", None)
        logger().info(f"in harness static_ip flag set to be : {static_ip}")
        static_subnet = UtfConfig.instance().defaults["wifi"].get("static_subnet", None)
        logger().info(f"in harness static_subnet flag set to be : {static_subnet}")
        static_gateway = UtfConfig.instance().defaults["wifi"].get("static_gateway", None)
        logger().info(f"in harness static_gateway flag set to be : {static_gateway}")
        ip_version = 'ipv4'
        logger().info(f"=======>>>>>Verifying Static IP<<<<<<<======")
        sl_collections.scan(wifi_dut=wifi_dut)
        sl_collections.connect(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point)
        wifi_dut.interfaces.wifi.start_ip(ip_version=ip_version, static_ip=static_ip, static_subnet=static_subnet,
                                          static_gateway=static_gateway, timeout=10)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")
        logger().info(f"Device is {device_ip}")
        time.sleep(2)
        status = ping(device_ip, ping_count)
        mode = 'power_save_low_latency'
        dtim_aligned_type = 0
        num_of_dtim_skip = 0
        listen_interval = 0
        assert (status is True), "DUT is not responding to ping request from third party device"
        wifi_dut.interfaces.wifi.set_performance_profile(mode, dtim_aligned_type, num_of_dtim_skip, listen_interval)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        time.sleep(2)
        status = ping(device_ip, ping_count)
        assert (status is True), "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        wifi_sniffer.interfaces.capture.stop_capture()
        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
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
                                                                 utf_constants, request, sl_collections, dhcp_lease, sniffer_filter):
    time_delta = 60
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    status = None
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=capture_filename, wifi_client=wifi_client, sl_collections=sl_collections,
                              ping_count=ping_count, test_case_no=19293)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
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
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
        assert status, 'value is out of range so test case is failed'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "100", "security": 'OPEN'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("dhcp_lease", [100])
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
def test_wifi_sdk_tcp_tx_functionality_while_dhcp_renewal_c19295(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                                 net_perf_client, protocol, utf_constants, request, sl_collections, dhcp_lease, sniffer_filter):
    time_delta = 60
    status = None
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=capture_filename, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, ping_count=ping_count,
                              data_transfer=True,
                              traffic_type="TX", test_case_no=19295)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
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
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
        assert status, 'value is out of range so test case is failed'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("dhcp_lease", [100])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "100", "security": 'OPEN'})
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
def test_wifi_sdk_tcp_rx_functionality_while_dhcp_renewal_c19296(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                                                 net_perf_client,
                                                                 protocol, utf_constants, request, sl_collections, dhcp_lease,
                                                                 sniffer_filter):
    time_delta = 60
    status = None
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=capture_filename, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections, ping_count=ping_count,
                              data_transfer=True,
                              traffic_type="RX", test_case_no=19296)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
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
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
        assert status, 'value is out of range so test case is failed'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                               | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1) |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"dhcp_lease": "100", "security": 'OPEN', "standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "close_sockets", "disassociated",])
@pytest.mark.parametrize("dhcp_lease", [100])
def test_wifi_sdk_ssl_tx_functionality_while_dhcp_renewal_c551871(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                  utf_constants, request, sl_collections, dhcp_lease, ssl_server, sniffer_filter):
    time_delta = 60
    status = None
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                              testcase=capture_filename, sl_collections=sl_collections, ping_count=ping_count,
                              ssl_server=ssl_server, ssl_data_transfer=True, traffic_type="TX", test_case_no=551871)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
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
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
        assert status, 'value is out of range so test case is failed'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL |
                          Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
                               | Si91xExtCustomFeatureBitMap.Feature192kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1) |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"dhcp_lease": "100", "security": 'OPEN', "standard": 'gnbax'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "close_sockets", "disassociated",])
@pytest.mark.parametrize("dhcp_lease", [100])
def test_wifi_sdk_ssl_rx_functionality_while_dhcp_renewal_c551872(wifi_access_point, wifi_sniffer, wifi_dut,
                                                                  utf_constants, request, sl_collections, dhcp_lease, ssl_server, sniffer_filter):
    time_delta = 60
    status = None
    packet_filter2 = '        DHCP: Request (3)'
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_access_point=wifi_access_point, wifi_dut=wifi_dut,
                              testcase=capture_filename, sl_collections=sl_collections, ping_count=ping_count,
                              ssl_server=ssl_server, ssl_data_transfer=True, traffic_type="RX", test_case_no=551872)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
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
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
        assert status, 'value is out of range so test case is failed'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.parametrize("dhcp_lease", [60])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
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
def test_wifi_sdk_legacy_dhcp_discover_failure_c683173(wifi_sniffer, wifi_access_point, wifi_dut,
                                                       request, sl_collections, dhcp_lease, sniffer_filter):
    capture_filename = request.node.name
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.3")
        time.sleep(60)

        wifi_dut.interfaces.wifi.start_ip(expected_status=SLStatus.SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE)
        logger().info(f"\n\n Observed the expected error code: 0x1FF9C (SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE) \n\n")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='dhcp_discover')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp discover sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


@pytest.mark.parametrize("dhcp_lease", [60])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
@pytest.mark.start_state("wifi_dut", wifi="init")
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
def test_wifi_sdk_legacy_dhcp_request_failure_c683174(wifi_sniffer, wifi_access_point, wifi_dut,
                                                      request, sl_collections, dhcp_lease, sniffer_filter):
    capture_filename = request.node.name
    mode = "power_save_low_latency"
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Start the DHCP process on the DUT
        ip_config = wifi_dut.interfaces.wifi.start_ip()
        wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr, filter_name='dhcp_request')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp request sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


@pytest.mark.parametrize("min_discover_retry_interval,max_discover_retry_interval,min_discover_retries", [(5, 100, 5), (10, 100, 6), (5, 20, 6)])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
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
def test_wifi_sdk_dhcp_discover_fail_after_retries_min_max_inter_c683175(wifi_sniffer, wifi_access_point, wifi_dut,request,
                                                                         sl_collections, sniffer_filter, min_discover_retry_interval,
                                                                         max_discover_retry_interval, min_discover_retries):
    """Verify DHCP discover failure by setting minimum and maximum retry interval"""

    capture_filename = request.node.name
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.3", dhcp_lease=60)
        time.sleep(100)

        wifi_dut.interfaces.wifi.start_ip(min_discover_retry_interval=min_discover_retry_interval, max_discover_retry_interval=max_discover_retry_interval,
                                          min_discover_retries=min_discover_retries, enable_dhcp=1,
                                          expected_status=SLStatus.SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE, timeout=20, async_timeout=300)
        time.sleep(200)
        logger().info(f"\n\n Observed the expected error code: 0x1FF9C (SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE) \n\n")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='dhcp_discover')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp discover sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


@pytest.mark.parametrize("min_request_retry_interval,max_request_retry_interval,max_request_retries", [(5, 10, 5), (10, 100, 20), (10, 6, 6)])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
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
def test_wifi_sdk_dhcp_request_fail_after_retries_min_max_inter_c683176(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                                                        sl_collections, sniffer_filter, min_request_retry_interval,
                                                                        max_request_retry_interval, max_request_retries):

    """ Verify DHCP request failure by setting minimum and maximum retry interval """

    capture_filename = request.node.name
    mode = "power_save_low_latency"
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Start the DHCP process on the DUT
        ip_config = wifi_dut.interfaces.wifi.start_ip(min_request_retry_interval=min_request_retry_interval,
                                                      max_request_retry_interval=max_request_retry_interval,
                                                      max_request_retries=max_request_retries, enable_dhcp=1, async_timeout=300)
        time.sleep(200)

        wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr, filter_name='dhcp_request')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp request sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


@pytest.mark.parametrize("min_discover_retry_interval,max_discover_retry_interval,min_discover_retries", [(5, 100, 8)])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
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
def test_wifi_sdk_dhcp_discover_fail_by_setting_retry_value_c683177(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                                                    sl_collections, sniffer_filter, min_discover_retry_interval,
                                                                    max_discover_retry_interval, min_discover_retries):
    """Verify DHCP discover failure by setting retry value"""

    capture_filename = request.node.name
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.3", dhcp_lease=60)
        time.sleep(100)

        wifi_dut.interfaces.wifi.start_ip(min_discover_retry_interval=min_discover_retry_interval, max_discover_retry_interval=max_discover_retry_interval,
                                          min_discover_retries=min_discover_retries, enable_dhcp=1,
                                          expected_status=SLStatus.SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE, timeout=150, async_timeout=600)
        time.sleep(400)
        logger().info(f"\n\n Observed the expected error code: 0x1FF9C (SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE) \n\n")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='dhcp_discover')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp discover sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


@pytest.mark.parametrize("min_request_retry_interval,max_request_retry_interval,max_request_retries", [(5, 100, 8), (7, 700, 9), (9, 1000, 10)])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
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
def test_wifi_sdk_dhcp_request_fail_by_setting_retry_value_c683178(wifi_sniffer, wifi_access_point, wifi_dut,request,
                                                                   sl_collections, sniffer_filter, min_request_retry_interval,
                                                                   max_request_retry_interval, max_request_retries):

    """ Verify DHCP request failure by setting retry value """

    capture_filename = request.node.name
    mode = "power_save_low_latency"
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Start the DHCP process on the DUT
        ip_config = wifi_dut.interfaces.wifi.start_ip(min_request_retry_interval=min_request_retry_interval,
                                                      max_request_retry_interval=max_request_retry_interval,
                                                      max_request_retries=max_request_retries, enable_dhcp=1, async_timeout=300)
        time.sleep(400)

        wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)


        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr, filter_name='dhcp_request')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp request sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


@pytest.mark.parametrize("min_discover_retry_interval,max_discover_retry_interval,min_discover_retries", [(5, 100, 0)])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
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
def test_wifi_sdk_dhcp_discover_by_setting_retry_value_0_c683179(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                 request, sl_collections, sniffer_filter, min_discover_retry_interval,
                                                                 max_discover_retry_interval, min_discover_retries):
    """Verify DHCP Discover retry value by setting to 0"""

    capture_filename = request.node.name
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.3", dhcp_lease=60)
        time.sleep(100)

        wifi_dut.interfaces.wifi.start_ip(min_discover_retry_interval=min_discover_retry_interval, max_discover_retry_interval=max_discover_retry_interval,
                                          min_discover_retries=min_discover_retries, enable_dhcp=1,
                                          expected_status=SLStatus.SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE, timeout=20, async_timeout=300)
        time.sleep(200)
        logger().info(f"\n\n Observed the expected error code: 0x1FF9C (SL_STATUS_SI91X_DHCP_HANDSHAKE_FAILURE) \n\n")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='dhcp_discover')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp discover sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


@pytest.mark.parametrize("min_request_retry_interval,max_request_retry_interval,max_request_retries", [(5, 10, 0)])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "60", "security": 'OPEN'})
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
def test_wifi_sdk_dhcp_request_by_setting_retry_value_0_c683179(wifi_sniffer, wifi_access_point, wifi_dut, request,
                                                                sl_collections, sniffer_filter, min_request_retry_interval,
                                                                max_request_retry_interval, max_request_retries):

    """Verify DHCP request retry value by setting to 0"""

    capture_filename = request.node.name
    mode = "power_save_low_latency"
    try:
        logger().info("Configuring the Sniffer with access point channel.")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Start the DHCP process on the DUT
        ip_config = wifi_dut.interfaces.wifi.start_ip(min_request_retry_interval=min_request_retry_interval,
                                                      max_request_retry_interval=max_request_retry_interval,
                                                      max_request_retries=max_request_retries, enable_dhcp=1, async_timeout=300)
        time.sleep(200)

        wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"....Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2, psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr, filter_name='dhcp_request')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the dhcp request sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)


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
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
def test_wifi_sdk_verify_config_ip_and_get_ip_address_api_c693569(wifi_access_point, wifi_dut, sl_collections):

    """Verify sl_net_configure_ip and sl_net_get_ip_address APIs"""
    try:
        static_ip = UtfConfig.instance().defaults["wifi"].get("static_ip", None)
        logger().info(f"in harness static_ip flag set to be : {static_ip}")

        static_subnet = UtfConfig.instance().defaults["wifi"].get("static_subnet", None)
        logger().info(f"in harness static_subnet flag set to be : {static_subnet}")

        static_gateway = UtfConfig.instance().defaults["wifi"].get("static_gateway", None)
        logger().info(f"in harness static_gateway flag set to be : {static_gateway}")

        ip_version = 'ipv4'
        logger().info(f"=======>>>>>Verifying Static IP<<<<<<<======")
        sl_collections.scan(wifi_dut=wifi_dut)
        sl_collections.connect(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point)
        wifi_dut.interfaces.wifi.start_ip(ip_version=ip_version, static_ip=static_ip, static_subnet=static_subnet,
                                          static_gateway=static_gateway, timeout=10)

        get_ip = wifi_dut.interfaces.wifi.get_ip_address()
        logger().info(f"GET_IP: {get_ip}")
        time.sleep(30)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["reset"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Client
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_verify_ip_change_notification_c19294(wifi_dut, wifi_access_point, wifi_sniffer, sl_collections,
                                                       request, utf_constants):
    capture_filename = request.node.name
    ping_count = utf_constants.get("ping_count")
    mode = 'power_save_low_latency'

    try:
        # Configure DHCP AP settings for AP
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.100", dhcp_lease="120")
        logger().info("Configuring the Sniffer with access point channel.")

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting capture with Sniffer, using test case name as filename.")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        # Initialize Wi-Fi DUT as a client
        wifi_dut.interfaces.wifi.is_sl_net_enabled = True
        wifi_dut.interfaces.wifi.init(mode="client")

        logger().info("Initiating scan...")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(20)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "Scan results not found"

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device MAC address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # Start IP and get device IP
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
        time.sleep(2)

        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip: {device_ip}")
        time.sleep(2)
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"Ping is successful")
        time.sleep(2)

        # Apply performance profile mode and power save settings
        logger().info(f"Applying performance profile mode : {mode}")
        wifi_dut.interfaces.wifi.set_performance_profile(mode)
        wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                      psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        time.sleep(5)

        # Change DHCP range on AP and allow time for IP change
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.100", dhcp_end="192.168.50.200", dhcp_lease="120")
        time.sleep(120)

        # Check for events indicating IP change
        events = []
        for i in range(0, 3):
            time.sleep(30)
            events = wifi_dut.interfaces.wifi.get_async_events()
            logger().info(f"Captured events: {events}")
            if len(events) >= 1:
                break

        assert len(events) >= 1, "TCP Remote terminate event not found"
        ip_change_notification = ""
        for event in events:
            logger().info(f"Event Type: {event.event_type}, Event Data: {event.event_data}")
            if event.event_type == AsyncEventIdentifiers.IP_CHANGE_NOTIFICATION:
                ip_change_notification = event.event_data
                break

        assert ip_change_notification, "Unable to find IP change notification"
        logger().info(f"IP Change Notification: {ip_change_notification}")

        logger().info("IP change notification event received by DUT when range changed in AP")

    except Exception as e:
        # Handle any exceptions
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        # Cleanup: stop sniffer and restore AP settings
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2", dhcp_end="192.168.50.254")
        time.sleep(60)