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
import random
import string
import threading
from threading import Thread


def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan for 2.4Gh with LWIP stack enabled and validate the WLAN functionality.

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Sakshi Agrawal
"""

Map_security = {
    "OPEN": 0,
    "WPA": 1,
    "WPA2": 2,
    "WEP": 3,
    "WPAEnterprise": 4,
    "WPA2Enterprise": 5,
    "WPA_WPA2_MIXED": 6,
    "WPA3": 7,
    "WPA3_TRANSITION": 8,
    "WPA3Enterprise": 9,
    "WPA3_TRANSITION_ENTERPRISE": 10,
}


class TCPTXThread(ThreadBase):
    """This thread is responsible for TCP data transfer"""

    def __init__(self, wifi_dut=None, wifi_client=None, device_ip=None, protocol=None, keepalive_timeout=0,
                 remote_socket_factory=None, port=5001, no_of_pkts=1, data_transfer=True):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.device_ip = device_ip
        self.protocol = protocol
        self.keepalive_timeout = keepalive_timeout
        self.remote_socket_factory = remote_socket_factory
        self.client_socket = None
        self.server_socket = None
        self.no_of_pkts = no_of_pkts
        self.port = port
        self.data_transfer = data_transfer

    def tx_data_transfer(self):
        data_length = 50
        sent_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=data_length))
        for i in range(self.no_of_pkts):
            logger().info(f"\n ****** Starting TCP TX Data Transfer from DUT to server at iteration {i + 1} \n ******")
            try:
                self.wifi_dut.interfaces.wifi.lwipSocketSend(socket_fd=self.client_socket, data=sent_data)
                received_data = (self.server_socket.recv_data_tcp(len(sent_data)))
                logger().info(f"\nReceived Data: {received_data}\n")
                assert (sent_data == received_data), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().info(f"Socket Data Transfer Failed Within Duration")

        logger().info("\n ****** data transfer successful ****** \n")

    def run(self):
        local_port = self.port
        server_ip = self.wifi_client.interfaces.wifi.get_ip_address()

        self.server_socket = self.remote_socket_factory.interfaces.socket.create_socket()
        self.server_socket.start_server(port=local_port)
        logger().info(f"\n ****** TCP Server started successfully at port : {local_port}  ****** \n")

        self.client_socket = self.wifi_dut.interfaces.wifi.lwipSocketCreate(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                            protocol="IPPROTO_TCP")
        logger().info(f"\n ****** Socket open successfully : {self.client_socket} ****** \n")

        if self.keepalive_timeout > 0:
            self.wifi_dut.interfaces.wifi.lwipSetSocketOpt(socket_fd=self.client_socket, option_level="SOL_SOCKET",
                                                           option_name="SO_KEEPALIVE", option_val=1)
            self.wifi_dut.interfaces.wifi.lwipSetSocketOpt(socket_fd=self.client_socket, option_level="IPPROTO_TCP",
                                                           option_name="TCP_KEEPIDLE", option_val=30)
            logger().info(f"\n ****** Keepalive timeout {self.keepalive_timeout} sec set successfully on DUT ******\n")

        for count in range(3):
            connect_status = False
            try:
                self.wifi_dut.interfaces.wifi.lwipSocketConnect(socket_fd=self.client_socket, server_ip=server_ip,
                                                                server_port=local_port)
                connect_status = True
                break
            except:
                logger().info(f"\n ****** Socket connection failed in DUT...retry_count:{count + 1} ****** \n")
                assert connect_status, "Socket connection failed in DUT"
        logger().info("\n *********** Socket connection is successful ************ \n")

        if self.data_transfer:
            self.tx_data_transfer()

        if self.keepalive_timeout > 0:
            logger().info("Verifying keepalive functionality by waiting for timeout period...")
            time.sleep(self.keepalive_timeout * 3)


class TCPRXThread(ThreadBase):
    """This thread is responsible for TCP data reception (DUT as server)"""

    def __init__(self, wifi_dut=None, wifi_client=None, device_ip=None, protocol=None, keepalive_timeout=0,
                 remote_socket_factory=None, port=5002, no_of_pkts=1, data_transfer=True):
        super().__init__()
        self.thread_lock = threading.Lock()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.device_ip = device_ip
        self.protocol = protocol
        self.keepalive_timeout = keepalive_timeout
        self.remote_socket_factory = remote_socket_factory
        self.client_socket = None
        self.server_socket = None
        self.accepted_socket = None
        self.port = port
        self.no_of_pkts = no_of_pkts
        self.data_transfer = data_transfer

    def RX_data_transfer(self):
        self.no_of_pkts = 10
        data_length = 50
        sent_data = "".join(random.choices(string.ascii_uppercase + string.digits, k=data_length))
        for i in range(self.no_of_pkts):
            logger().info(
                f"\n ****** Starting TCP RX Data Transfer from Client to DUT Server at iteration {i + 1} ****** \n")
            try:
                # Send data from remote client to DUT server
                self.client_socket.send_data_tcp(sent_data)

                # Receive data on DUT server
                received_data = self.wifi_dut.interfaces.wifi.lwipSocketReceive(socket_fd=self.accepted_socket)
                logger().info(f"\nDUT Server Received Data: {received_data}\n")
                assert (sent_data == received_data), f"Data mismatch in sent and received data"
            except Exception as e:
                logger().error(f"TCP RX Socket Data Transfer Failed: {e}")
                raise e

        logger().info("\n ****** TCP RX data transfer successful ****** \n")

    def run(self):
        server_port = self.port  # Different port than TCP TX

        # DUT acts as TCP server
        self.server_socket = self.wifi_dut.interfaces.wifi.lwipSocketCreate(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                            protocol="IPPROTO_TCP")
        logger().info(f"\n ****** TCP Server Socket created successfully : {self.server_socket} ****** \n")

        # Bind and listen on DUT
        self.wifi_dut.interfaces.wifi.lwipSocketBind(socket_fd=self.server_socket, device_ip=self.device_ip,
                                                     server_port=server_port)
        self.wifi_dut.interfaces.wifi.lwipSocketListen(socket_fd=self.server_socket, backlog=1)
        logger().info(f"\n ****** TCP Server listening on {self.device_ip}:{server_port} ****** \n")

        if self.keepalive_timeout > 0:
            self.wifi_dut.interfaces.wifi.lwipSetSocketOpt(socket_fd=self.server_socket, option_level="SOL_SOCKET",
                                                           option_name="SO_KEEPALIVE", option_val=1)
            self.wifi_dut.interfaces.wifi.lwipSetSocketOpt(socket_fd=self.server_socket, option_level="IPPROTO_TCP",
                                                           option_name="TCP_KEEPIDLE", option_val=30)
            logger().info(
                f"\n ****** Keepalive timeout {self.keepalive_timeout} sec set successfully on DUT server ******\n")

        # Remote client connects to DUT server
        self.client_socket = self.remote_socket_factory.interfaces.socket.create_socket()

        connect_status = False
        for count in range(3):
            try:
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (
                            self.wifi_dut.interfaces.wifi.lwipSocketAccept,
                            self.server_socket,
                        ),
                        (
                            self.client_socket.connect_client_tcp,
                            self.device_ip,
                            server_port,
                        ),
                    ],
                    timeout=10,
                )

                # Get the accepted socket descriptor from the result
                self.accepted_socket = result[0] if result else None
                self.accepted_socket = int(self.accepted_socket.decode().strip())
                connect_status = True
                break
            except:
                logger().info(f"\n ****** Socket connection failed in DUT...retry_count:{count + 1} ****** \n")
        assert connect_status, "Socket connection failed in DUT"
        logger().info(f"\n ****** Connection accepted on DUT server : {self.accepted_socket} ****** \n")

        if self.data_transfer:
            self.RX_data_transfer()

        if self.keepalive_timeout > 0:
            logger().info("Verifying keepalive functionality by waiting for timeout period...")
            time.sleep(self.keepalive_timeout * 3)


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, sl_collections=None, profile=None,
                 capture_filename=None, test_case_no=None, power_save=True, leave=True, stop_capture=True,
                 wifi_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.dut_addr = None
        self.ap_addr = None
        self.sl_collections = sl_collections
        self.capture_filename = capture_filename
        self.test_case_no = test_case_no
        self.profile = profile
        self.device_ip = None
        self.power_save = power_save
        self.wifi_client = wifi_client
        self.leave = leave
        self.stop_capture = stop_capture

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

    def run(self):
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.capture_filename}.pcap"
        )
        self.dut_addr = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.ap_addr = self.wifi_access_point.interfaces.wifi.bssid

        self.wifi_dut.interfaces.wifi.sl_net_set_profile(
            ssid=self.profile["ssid"],
            security=Map_security[self.profile["security"]],
            credential_id=(1 if Map_security[self.profile["security"]] != 0 else 0),
            priority=1,
            profile_id=0,
            channel=self.profile["channel"],
            encryption=self.profile["encryption_type"],
        )
        self.wifi_dut.interfaces.wifi.sl_net_set_credential(credential=self.profile["passphrase"], cred_id=1)
        self.wifi_dut.interfaces.wifi.sl_net_up(mode="client")
        ip_config = self.wifi_dut.interfaces.wifi.display_device_ip_lwip()
        self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info("=========== pinging DUT before power save ===============")

        status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.power_save:
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
            self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                               psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
        logger().info("=========== pinging DUT after power save ===============")
        status = self.sl_collections.ping(device_ip=self.device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        if self.test_case_no == 919174:
            logger().info(f"\n==========>>>>>>Waiting up to 900 seconds for dhcp renewal packets<<<<<<===========\n")
            time.sleep(1800)

        if self.leave:
            self.wifi_dut.interfaces.wifi.leave()
            logger().info(f"Disconnection will issued after verification")

        if self.stop_capture:
            self.wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
        "dhcp_lease": "120",
    },
)
def test_wifi_sdk_dhcp_renewal_time_to_2_min_renewal_func_LWIP_c919174(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                       request, sl_collections, sniffer_filter):
    """This test case verifies DHCP renewal time to 2 min renewal functionality in LWIP stack for 30 min duration"""
    capture_filename = request.node.name
    time_delta = 60
    packet_filter2 = '        DHCP: Request (3)'
    packet_filter3 = '        DHCP: Ack (5)'

    profile = {
        "ssid": "ssid_profile1",
        "channel": 6,
        "security": "OPEN",
        "passphrase": "1234567890",
        "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
    }
    req_status = None
    ack_status = None
    wlan_obj = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                              test_case_no=919174)

    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        device_address = {'sa_addr': wlan_obj.dut_addr, 'da_addr': wlan_obj.ap_addr,
                          'wlan_addr': wlan_obj.dut_addr}
        filters_name = {1: 'power_mgmt_bit', 2: 'dhcp'}
        output_1 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                        device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'

        filters_name_1 = {1: 'dhcp_renewal'}
        output_2 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter, device_address,
                                                                        filters_name=filters_name_1,
                                                                        packet_filter2=packet_filter2)
        logger().info(f'\n OUTPUT 2 = {output_2}\n')
        assert all(output_2.values()), 'Unable to find expected filter'
        dhcp_request_packets_time_delta_list = wlan_obj.delta_between_dhcp_req_packet()
        logger().info(f'DHCP ACK packet time delta list= {dhcp_request_packets_time_delta_list}')
        dhcp_request_packets_time_delta_list.pop(0)
        logger().info(f'DHCP Req packet time delta list after removing 0 = {dhcp_request_packets_time_delta_list}')

        filters_name_2 = {1: 'dhcp_ack'}
        device_address2 = {'sa_addr': wlan_obj.ap_addr, 'da_addr': wlan_obj.dut_addr, }
        output_3 = sl_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter, device_address2,
                                                                        filters_name=filters_name_2,
                                                                        packet_filter2=packet_filter3)
        logger().info(f'\n OUTPUT 3 = {output_3}\n')
        assert all(output_2.values()), 'Unable to find expected filter'
        dhcp_ack_packets_time_delta_list = wlan_obj.delta_between_dhcp_req_packet()
        logger().info(f'DHCP ACK packet time delta list= {dhcp_ack_packets_time_delta_list}')
        dhcp_ack_packets_time_delta_list.pop(0)
        logger().info(f'DHCP ACK packet time delta list after removing 0 = {dhcp_ack_packets_time_delta_list}')

        for time_diff in dhcp_request_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(45, time_delta + 5)
            if is_between is False:
                logger().info(f"{is_between}")
                req_status = is_between
                break
            else:
                logger().info(f"{is_between}")
                req_status = is_between

        for time_diff in dhcp_ack_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(45, time_delta + 5)
            if is_between is False:
                logger().info(f"{is_between}")
                ack_status = is_between
                break
            else:
                logger().info(f"{is_between}")
                ack_status = is_between

        if not req_status:
            logger().info("DHCP Request time not within range so looking for DHCP Ack time")
            assert ack_status, 'value is out of range so test case is failed'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_tcp_open_send_close_socket_c919180(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client, protocol):
    """This test case Verifies the tcp client socket is open, send data,close functionality"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919180, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        tcp_thread = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                 protocol=protocol,
                                 remote_socket_factory=remote_socket_factory, keepalive_timeout=30, no_of_pkts=10)
        tcp_thread.start()
        tcp_thread.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        device_address = {'sa_addr': wifi_thread.dut_addr, 'da_addr': wifi_thread.ap_addr,
                          'ta_addr': wifi_thread.dut_addr, 'ra_addr': wifi_thread.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("\n ================== Closing all LWIP sockets ================== \n")
        wifi_dut.interfaces.wifi.lwip_close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_verify_tcp_keep_alive_functionality_c919181(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client, protocol):
    """This test case Verifies the tcp keep alive functionality"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919181, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        tcp_thread = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                 protocol=protocol,
                                 remote_socket_factory=remote_socket_factory, keepalive_timeout=30, no_of_pkts=10)
        tcp_thread.start()
        tcp_thread.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, wifi_thread.dut_addr,
                                               wifi_thread.ap_addr, sniffer_filter)
        logger().info(f"Starting the Keep Alive Validation with duration {tcp_thread.keepalive_timeout} seconds")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=wifi_thread.dut_addr, ra_addr=wifi_thread.ap_addr, filter_name="keep_alive")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], f"Keep alive packets not found in sniffer packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("\n ================== Closing all LWIP sockets ================== \n")
        wifi_dut.interfaces.wifi.lwip_close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_tcp_tx_rx_simultaneously_c919183(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client, protocol):
    """This test case Verifies the tcp client socket is open, send data,close functionality"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919180, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()
        tcp_tx_thread = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                    protocol=protocol, remote_socket_factory=remote_socket_factory, no_of_pkts=100)
        tcp_rx_thread = TCPRXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                    protocol=protocol, remote_socket_factory=remote_socket_factory, no_of_pkts=100)
        tcp_tx_thread.start()
        tcp_rx_thread.start()
        tcp_tx_thread.wait_for_exit()
        tcp_rx_thread.wait_for_exit()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        device_address = {'sa_addr': wifi_thread.dut_addr, 'da_addr': wifi_thread.ap_addr,
                          'ta_addr': wifi_thread.dut_addr, 'ra_addr': wifi_thread.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("\n ================== Closing all LWIP sockets ================== \n")
        wifi_dut.interfaces.wifi.lwip_close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_2_tcp_client_data_transfer_using_1_socket_c919184(
        sniffer_filter, wifi_access_point, wifi_dut, sl_collections, wifi_sniffer, request,
        remote_socket_factory, wifi_client, protocol):
    """This test case Verifies the tcp client socket is open, send data,close functionality"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919180, leave=False, stop_capture=False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        logger().info("Starting data transfer on socket 1")
        tcp_tx_thread1 = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                     protocol=protocol, remote_socket_factory=remote_socket_factory, port=5001,
                                     keepalive_timeout=30, no_of_pkts=1)
        tcp_tx_thread1.start()
        tcp_tx_thread1.wait_for_exit()

        logger().info("Starting data transfer on socket 2 and keep the socket 1 in idle state")
        tcp_tx_thread2 = TCPTXThread(wifi_dut=wifi_dut, wifi_client=wifi_client, device_ip=wifi_thread.device_ip,
                                     protocol=protocol, remote_socket_factory=remote_socket_factory, port=5002,
                                     no_of_pkts=100)
        tcp_tx_thread2.start()
        tcp_tx_thread2.wait_for_exit()

        logger().info(
            "\n After successfully data Transfer from socket 2 and till then socket 1 is in idle state, check socket 1 is still in active state\n ")
        tcp_tx_thread1.tx_data_transfer()

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Disconnection will issued after verification")
        wifi_dut.interfaces.wifi.leave()

        device_address = {'sa_addr': wifi_thread.dut_addr, 'da_addr': wifi_thread.ap_addr,
                          'ta_addr': wifi_thread.dut_addr, 'ra_addr': wifi_thread.ap_addr}

        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'probe_req_response', 3: 'ps_poll',
                        4: 'dhcp_4_way_handshake_packets', 5: 'tcp_syn_with_syn_ack_with_ack'}

        output = sl_collections.sniffer_validation_for_packet_filters(
            wifi_sniffer, sniffer_filter, device_address, filters_name=filters_name)

        logger().info(f'\n OUTPUT  = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("\n ================== Closing all LWIP sockets ================== \n")
        wifi_dut.interfaces.wifi.lwip_close_sockets()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
def test_wifi_sdk_dhcp_garp_verification_c919194(sniffer_filter, wifi_access_point, wifi_dut, sl_collections,
                                                 wifi_sniffer, request, wifi_client):
    """this test case verifies DHCP ACD no conflict GARP functionality"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, profile=profile, capture_filename=capture_filename,
                                     wifi_client=wifi_client,
                                     test_case_no=919194)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(filter_name='garp_packet')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: GARP packet not found in sniffer packets'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(dut_ip=wifi_thread.device_ip,
                                                                                        da_addr=wifi_thread.dut_addr,
                                                                                        filter_name='no_adc_conflict')
        assert not \
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2, negative_test=True)[
            'packet_count'], \
            'Sniffer: DHCP ACD conflict packet found in sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated", "sl_net_deinit_client"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
def test_wifi_sdk_dhcp_discon_connect_garp_verification_c919223(sniffer_filter, wifi_access_point, wifi_dut,
                                                                sl_collections, wifi_sniffer, request, wifi_client):
    """this test case verifies DHCP ACD no conflict GARP functionality"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        i = 0
        logger().info(f"\n ======================== Starting the loop for 15 minutes ======================== \n")
        start_time = time.time()
        while time.time() - start_time < 900:
            logger().info(f"\n =============== Iteration number: {i + 1} ================= \n")
            i = i + 1
            wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         wifi_sniffer=wifi_sniffer,
                                         sl_collections=sl_collections, profile=profile,
                                         capture_filename=capture_filename, wifi_client=wifi_client,
                                         test_case_no=919224)

            wifi_thread.start()
            wifi_thread.wait_for_exit()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(filter_name='garp_packet')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Sniffer: GARP packet not found in sniffer packets'

            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_ip=wifi_thread.device_ip,
                da_addr=wifi_thread.dut_addr,
                filter_name='no_adc_conflict')
            assert not \
            wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2, negative_test=True)[
                'packet_count'], \
                'Sniffer: DHCP ACD conflict packet found in sniffer packets'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCPIPBypass,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["sl_net_init_client"])
@pytest.mark.end_state("wifi_dut", wifi=["reset"])
@pytest.mark.config(
    "wifi_access_point",
    wifi={
        "ssid": "ssid_profile1",
        "security": "OPEN",
        "passphrase": "1234567890",
        "channel": 6,
    },
)
def test_wifi_sdk_dhcp_deinit_init_cycle_garp_verification_c919225(sniffer_filter, wifi_access_point, wifi_dut,
                                                                   sl_collections, wifi_sniffer, request, wifi_client):
    """this test case verifies DHCP ACD no conflict GARP functionality"""
    try:
        test_name = request.node.name
        capture_filename = request.node.name

        profile = {
            "ssid": "ssid_profile1",
            "channel": 6,
            "security": "OPEN",
            "passphrase": "1234567890",
            "encryption_type": "SL_WIFI_DEFAULT_ENCRYPTION",
        }
        i = 0
        start_time = time.time()
        logger().info(
            f"\n ======================== Starting the loop for 15 minutes ====================== \n")
        while time.time() - start_time < 900:
            logger().info(f"\n ================= Iteration number: {i + 1} ================= \n")
            if i != 0:
                logger().info(f"\n =========== Initializing the network stack ===============\n")
                wifi_dut.interfaces.wifi.sl_net_init(mode='client')
            i = i + 1
            wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         wifi_sniffer=wifi_sniffer,
                                         sl_collections=sl_collections, profile=profile,
                                         capture_filename=capture_filename, wifi_client=wifi_client,
                                         test_case_no=919225)

            wifi_thread.start()
            wifi_thread.wait_for_exit()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(filter_name='garp_packet')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Sniffer: GARP packet not found in sniffer packets'

            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                dut_ip=wifi_thread.device_ip,
                da_addr=wifi_thread.dut_addr,
                filter_name='no_adc_conflict')
            assert not \
            wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2, negative_test=True)[
                'packet_count'], \
                'Sniffer: DHCP ACD conflict packet found in sniffer packets'

            logger().info(f"\n =========== Deinitializing the network stack ===============\n")
            wifi_dut.interfaces.wifi.sl_net_deinit(mode='client')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()