import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveModes,
    DeviceConstants,
    Si91xPowerSaveProcedureTypes,
    Si91xCustomFeatureBitMap,
    SocketOptions,
    Si91xOperatingMode,
    Si91xCustomSyncSockOptParms
)
from threading import Thread
import threading
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from random import randint
import random
import string

"""The testcases added in this file run below test steps for DUT(Soc917)
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP or UDP socket(Client/server) at DUT/RASPBERRY - PI
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
        8. Verify TCP rx & tx with high performance sockets
        9. Verify data transfer with different window size and with different RSSI values.
        
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC device for Sniffer
        
    Author: Harshitha M / Saurabh Sharma
"""


def logger():
    return get_logger(__name__)


class SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None, ap_mac_address=None,
                 sniffer_filter=None):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter

    def verify_sniffer_validation(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address, da_addr=self.ap_mac_address, filter_name='probe_req_response')
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address, da_addr=self.ap_mac_address,
            filter_name='assoc_req_resp_eapol_4_way_handshake')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address, da_addr=self.ap_mac_address, ta_addr=self.dut_mac_address,
            ra_addr=self.ap_mac_address, filter_name='dhcp_4_way_handshake_packets')
        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address, filter_name='ps_poll')

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe_req_response packet in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'unable to find shcp 4 way hand shake packets in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find ps poll packets in sniffer'


class data_transfer:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def receive_data_socket(self, remote_socket, no_of_pkts, data_size, proto_type=0):
        fail_count = 0
        if proto_type == 0:
            remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
        else:
            remote_socket.interfaces.socket.set_recv_timeout(use_client_socket=True, socket_type=1)
        for count in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.interfaces.socket.recv_data_tcp(data_size)
            else:
                data, address = remote_socket.interfaces.socket.recv_data_udp(data_size)
            if not isinstance(data, str):
                fail_count = fail_count + 1
                if fail_count == 5:
                    break
                else:
                    continue
            self.rcv_data = self.rcv_data + len(data)
        logger().info(f"Total bytes received on socket opened remotely -> {self.rcv_data}")


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 sl_collections=None, test_name=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.dut_addr = None
        self.device_ip = None
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer

    def run(self):
        try:
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     ping_after_power_save=True)
            logger().info(
                f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

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
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_tcp_open_send_close_socket_c19347(sniffer_filter, wifi_access_point, wifi_dut, remote_socket,
                                                    sl_collections, wifi_sniffer, request):
    """This test case Verfies the tcp client socket is open, send data,close functionality"""
    try:
        no_of_pkts = 10000
        pkt_length = 1460
        local_port = randint(5001, 6000)
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        remote_socket.interfaces.socket.time_limit = 1800
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        remote_socket.interfaces.socket.start_server(port=local_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port
        tcp_socket_id = wifi_dut.interfaces.wifi.socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
        bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id,
                                                      device_ip=wifi_thread.dut_addr['device_ip'],
                                                      server_port=server_port, timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")
        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                          server_port=server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            data_transfer_obj = data_transfer()
            th_start = Thread(target=data_transfer_obj.receive_data_socket,
                              args=(remote_socket, no_of_pkts, pkt_length, 0), daemon=True)
            th_start.start()
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(tcp_socket_id, pkt_length, no_of_pkts)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=tcp_socket_id)
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], da_addr=ap_mac_address,
            ta_addr=wifi_thread.dut_addr['dut_mac_address'],
            filter_name='tcp_syn_with_syn_ack_with_ack')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'unable to find tcp 4 way hand shake packets in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_udp_open_send_data_close_socket_c19348(sniffer_filter, wifi_access_point, wifi_dut, remote_socket,
                                                         sl_collections, wifi_sniffer, request):
    """This test case Verfies the udp client socket is open, send data,close functionality"""
    try:
        no_of_pkts = 10000
        pkt_length = 1460
        local_port = randint(5001, 6000)
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        remote_socket.interfaces.socket.start_server(socket_type=1)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port
        udp_socket_id = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                        protocol="IPPROTO_UDP")
        logger().info(f"Socket open successfully : {udp_socket_id}")
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {udp_socket_id} which is expected")
        bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=udp_socket_id,
                                                      device_ip=wifi_thread.dut_addr['device_ip'],
                                                      server_port=local_port, timeout=5)
        logger().info(f"Bind socket successfully: {bind_response}")
        logger().info("DUT is connecting to server socket")
        data_transfer_obj = data_transfer()
        th_start = Thread(target=data_transfer_obj.receive_data_socket,
                            args=(remote_socket, no_of_pkts, pkt_length, 1), daemon=True)
        th_start.start()
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            udp_socket_id, pkt_length, no_of_pkts, server_ip=server_ip, server_port=local_port, time_interval=120)
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=udp_socket_id)
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        remote_socket.interfaces.socket.stop()
        time.sleep(2)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity
                    | Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_tcp_socket_dut_client_c19349(sniffer_filter, wifi_access_point, wifi_dut, remote_socket,
                                               sl_collections, wifi_sniffer, request):
    """Verify 10 sockets functionality open 10 tcp client sockets and connect to server sockets and send data"""
    try:
        no_of_pkts = 10000
        pkt_length = 1460
        socket_id_value = set()
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        for local_port in range(6000, 6010):
            remote_socket.interfaces.socket.start_server(port=local_port, connections=10)
            server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
            server_port = remote_socket.interfaces.socket.server_port
            tcp_socket_id = wifi_dut.interfaces.wifi.socket()
            logger().info(f"Socket open successfully : {tcp_socket_id}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
            bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id,
                                                          device_ip=wifi_thread.dut_addr['device_ip'],
                                                          server_port=server_port, timeout=5)
            logger().info(f"Bind socket successfully: {bind_response}")
            logger().info("DUT is connecting to server socket")
            connect_status = False
            for count in range(3):
                try:
                    wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                              server_port=server_port)
                    connect_status = True
                    break
                except:
                    logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                    time.sleep(10)
            assert connect_status, "Socket connection failed in DUT"
            logger().info("Socket connection is successful")
            socket_id_value.add(tcp_socket_id)
            logger().info(f'Socket values = {socket_id_value}')
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            for tcp_socket_id in range(0, 10):
                server_port = 6001
                data_transfer_obj = data_transfer()
                th_start = Thread(target=data_transfer_obj.receive_data_socket,
                                  args=(remote_socket, no_of_pkts, pkt_length, 0), daemon=True)
                th_start.start()
                current_port = server_port + tcp_socket_id
                bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(tcp_socket_id, pkt_length, no_of_pkts,
                                                                     server_ip=server_ip, server_port=current_port)
                logger().info(f"Number of bytes sent by dut {bytes_sent}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], da_addr=ap_mac_address,
            ta_addr=wifi_thread.dut_addr['dut_mac_address'],
            filter_name='tcp_syn_with_syn_ack_with_ack')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'unable to find tcp 4 way hand shake packets in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_sdk_udp_socket_dut_client_c19350(wifi_access_point, wifi_dut, remote_socket, wifi_sniffer, sl_collections,
                                               request, sniffer_filter):
    """Verify 10 sockets functionality open 10 UDP client sockets and connect to server sockets"""
    try:
        no_of_pkts = 10000
        pkt_length = 1460
        socket_id_value = set()
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        for local_port in range(6001, 6011):
            remote_socket.interfaces.socket.start_server(socket_type=1)
            server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
            server_port = remote_socket.interfaces.socket.server_port
            logger().info(f"DUT opens tcp client socket")
            udp_socket_id = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                            protocol="IPPROTO_UDP")
            logger().info(f"Socket open successfully : {udp_socket_id}")
            logger().info("Initiating socket bind from DUT")
            wifi_dut.interfaces.wifi.bind(udp_socket_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port)
            socket_id_value.add(udp_socket_id)
            logger().info(f'Socket values = {socket_id_value}')
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            for udp_socket_id in range(0, 10):
                local_port = 6001
                data_transfer_obj = data_transfer()
                th_start = Thread(target=data_transfer_obj.receive_data_socket,
                                  args=(remote_socket, no_of_pkts, pkt_length, 1), daemon=True)
                th_start.start()
                current_port = local_port + udp_socket_id
                bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(udp_socket_id, pkt_length, no_of_pkts,
                                                                     server_ip=server_ip, server_port=current_port)
                logger().info(f"Number of bytes sent by dut {bytes_sent}")
        # for sock_value in socket_id_value:
        #     wifi_dut.interfaces.wifi.bsdSockClose(sock_value)
        #     time.sleep(1)
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_5tcp_5udp_socket_c19352(wifi_access_point, wifi_dut, remote_socket, wifi_sniffer, sl_collections,
                                          request, sniffer_filter):
    """Verify 10 sockets functionality open 5TCP & 5UDP client sockets"""
    try:
        socket_id_value = set()
        data = "HellofromUDPclient"
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        for local_port in range(6001, 6006):
            remote_socket.interfaces.socket.start_server(port=local_port, connections=10)
            server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
            server_port = remote_socket.interfaces.socket.server_port
            tcp_socket_id = wifi_dut.interfaces.wifi.socket()
            logger().info(f"Socket open successfully : {tcp_socket_id}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {tcp_socket_id} which is expected")
            bind_response = wifi_dut.interfaces.wifi.bind(socket_fd=tcp_socket_id,
                                                          device_ip=wifi_thread.dut_addr['device_ip'],
                                                          server_port=server_port, timeout=5)
            logger().info(f"Bind socket successfully: {bind_response}")
            logger().info("DUT is connecting to server socket")
            connect_status = False
            for count in range(3):
                try:
                    wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=tcp_socket_id, server_ip=server_ip,
                                                              server_port=server_port)
                    connect_status = True
                    break
                except:
                    logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                    time.sleep(10)
            assert connect_status, "Socket connection failed in DUT"
            logger().info("Socket connection is successful")
            socket_id_value.add(tcp_socket_id)
            logger().info(f'Socket values = {socket_id_value}')
            bytes_sent = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=tcp_socket_id, data=data, timeout=30)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
        for local_port in range(6007, 6012):
            remote_socket.interfaces.socket.start_server(socket_type=1)  # 0-TCP, 1-UDP
            server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
            server_port = remote_socket.interfaces.socket.server_port
            logger().info(f"DUT opens tcp client socket")
            udp_socket_id = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_DGRAM",
                                                            protocol="IPPROTO_UDP")
            logger().info(f"Socket open successfully : {udp_socket_id}")
            logger().info("Initiating socket bind from DUT")
            wifi_dut.interfaces.wifi.bind(udp_socket_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port)
            socket_id_value.add(udp_socket_id)
            logger().info(f'Socket values = {socket_id_value}')
        logger().info(f'Socket values = {socket_id_value}')
        for sock_value in socket_id_value:
            wifi_dut.interfaces.wifi.bsdSockClose(sock_value)
            time.sleep(1)
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], da_addr=ap_mac_address,
            ta_addr=wifi_thread.dut_addr['dut_mac_address'],
            filter_name='tcp_syn_with_syn_ack_with_ack')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'unable to find tcp 4 way hand shake packets in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Dependency On Jira SI91X-14417")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config("net_perf_client",
                    net_perf={"host_role": IperfConstants.SERVER_MODE, "mss_value": '1460', "tcp_window_size": '50k'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_socket_tcp_data_transfer_mss_c19356(wifi_access_point, wifi_dut, remote_socket, wifi_sniffer,
                                                      sl_collections,
                                                      sniffer_filter, net_perf_client, protocol, wifi_client):
    """Verify TCP data transfer when remote peer Window size is less than MSS"""

    try:
        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        wifi_dut.interfaces.wifi.leave()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_tcp_data_receive_check_c19360(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                            sniffer_filter, remote_socket_factory, wifi_client):

    """Validation of data and length by giving length in read command over TCP server socket"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        socket_id = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        logger().info(f"Successfully opened tcp client socket and socket id received is {socket_id} which is expected")
        local_port = 5001
        wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port, timeout=5, asynch=1)

        wifi_dut.interfaces.wifi.listen(socket_fd=socket_id, backlog=1, asynch=1)

        ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketAccept, socket_id, 1),
                (
                    client_socket.connect_client_tcp,
                    wifi_thread.dut_addr['device_ip'],
                    local_port,
                ),
            ],
            timeout=10,
        )

        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
        buffer_length = len(tx_buffer)
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            logger().info(f"Remote peer sending data over socket {socket_id} and data:{tx_buffer}")
            client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_id + 1)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{socket_id} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")

        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
        client_socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_udp_receive_c19361(wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections,
                                 sniffer_filter, remote_socket, wifi_client):

    """Validation of data and length by giving length in read command over udp"""
    try:
        local_port = 5001
        test_name = request.node.name
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        remote_socket.interfaces.socket.start_server(socket_type=1)
        sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port, asynch=1)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, ip_len=4, server_port=local_port)

        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_udp(tx_buffer, wifi_thread.dut_addr['device_ip'], local_port)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)

    finally:
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA', "cipher": "TKIP", "passphrase": '123456789',
                                               "standard": '11bg'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_tcp_udp_data_receive_WPA_TKIP_c71653(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket_factory,
        remote_socket, wifi_client):

    """Verify TCP ,UDP data reception of STAUT in WPA-TKIP mode"""
    try:
        test_name = request.node.name
        local_port = 5001
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        socket_id = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        logger().info(f"Successfully opened tcp client socket and socket id received is {socket_id} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port, timeout=5, asynch=1)

        wifi_dut.interfaces.wifi.listen(socket_fd=socket_id, backlog=1, asynch=1)

        ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketAccept, socket_id, 1),
                (client_socket.connect_client_tcp, wifi_thread.dut_addr['device_ip'], local_port),
            ],
            timeout=10,
        )

        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
        buffer_length = len(tx_buffer)
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            logger().info(f"Remote peer sending data over socket {socket_id} and data:{tx_buffer}")
            client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_id + 1)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{socket_id} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")

        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
        remote_socket_factory.interfaces.socket.close_all()
        logger().info("Successfully closed opened socket in the DUT")
        time.sleep(20)

        """ ************************************** Creating UDP Socket *******************************************"""
        local_port_udp = 6001
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        remote_socket.interfaces.socket.start_server(socket_type=1)
        sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port_udp, asynch=1)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, ip_len=4,
                                                  server_port=local_port_udp)

        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_udp(tx_buffer, wifi_thread.dut_addr['device_ip'], local_port_udp)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584, "priority": 8}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA', "cipher": "TKIP", "passphrase": '123456789',
                                               "standard": '11bg'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_wifi_tcp_udp_data_tx_WPA_TKIP_c19365(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket_factory,
        remote_socket, wifi_client):
    """Verify TCP ,UDP data reception of STAUT in WPA-TKIP mode"""
    try:
        test_name = request.node.name
        no_of_pkts = 10000
        pkt_length = 1460
        local_port = 5001
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        remote_socket.interfaces.socket.start_server(port=local_port)
        socket_id = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                         protocol="IPPROTO_TCP")
        logger().info(f"Socket open successfully : {socket_id}")
        logger().info(f"Successfully opened tcp client socket and socket id received is {socket_id} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port, timeout=5, asynch=1)

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=socket_id, server_ip=server_ip,
                                                          server_port=local_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        time.sleep(5)
        data_transfer_obj = data_transfer()
        th_start = Thread(target=data_transfer_obj.receive_data_socket, args=(remote_socket, no_of_pkts, pkt_length, 0),
                          daemon=True)
        th_start.start()
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=socket_id, pkt_length=pkt_length, no_of_pkts=no_of_pkts, time_interval=120, server_ip=server_ip,
            server_port=local_port)
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        time.sleep(2)
        logger().info("Data sent by DUT and received on remote peer is matching")
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket_id)
        remote_socket_factory.interfaces.socket.close_all()
        logger().info("Successfully closed opened socket in the DUT")

        time.sleep(10)

        """ ************************************** Creating UDP Socket *******************************************"""
        local_port_udp = 6001
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
        remote_socket.interfaces.socket.start_server(socket_type=1)
        sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened udp client socket and socket id received is {sock} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                      server_port=local_port_udp, asynch=1)

        data_transfer_obj = data_transfer()
        th_start = Thread(target=data_transfer_obj.receive_data_socket,
                          args=(remote_socket, no_of_pkts, pkt_length, 1), daemon=True)
        th_start.start()
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=sock, pkt_length=pkt_length, no_of_pkts=no_of_pkts, time_interval=120, server_ip=server_ip,
            server_port=local_port)
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        logger().info("Data sent by DUT and received on remote peer is matching")
        time.sleep(1)
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name="ps_poll")
        logger().info(f"***** Validating PS POLL Packets ******")
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find PS POLL Packets"

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_10_tcp_socket_dut_server_c19351(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket_factory,
        wifi_client):
    """Verify 10 sockets functionality open 10 TCP server sockets and client sockets connect to it"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'***** AP MAC ADDRESS {ap_mac_address} ****')
        client_socket = []
        server_port_base = 5001
        tcp_socks = []
        for count in range(0, 10):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                        protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1, count),
                    (client_socket[count].connect_client_tcp, wifi_thread.dut_addr['device_ip'], local_port),
                ],
                timeout=10,
            )
        count = 0
        for sock_no in tcp_socks:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            logger().info(f"Remote peer sending data over socket {sock_no} and data:{tx_buffer}")
            client_socket[count].send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            count += 1
            wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=2, time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{sock_no} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "close_sockets"])
def test_5tcp_5udp_dut_server_socket_c19353(
        wifi_sniffer, wifi_dut, wifi_access_point, request, sl_collections, sniffer_filter, remote_socket_factory,
        wifi_client, remote_socket):
    """Verify 10 sockets functionality open 5TCP server +5UDP server sockets"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                     sl_collections=sl_collections, test_name=test_name, sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        client_socket = []
        server_port_base = 5001
        tcp_socks = []
        udp_socks = []
        for count in range(0, 5):
            local_port = server_port_base + count
            logger().info(f'Server port = {local_port}')
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.Asyncsocket(
                domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : {sock}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=local_port, timeout=5, asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)
            ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1, count),
                    (client_socket[count].connect_client_tcp, wifi_thread.dut_addr['device_ip'], local_port),
                ],
                timeout=10,
            )

        count = 0
        for sock_no in tcp_socks:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
            buffer_length = len(tx_buffer)
            logger().info(f"Remote peer sending data over socket {sock_no} and data:{tx_buffer}")
            client_socket[count].send_data_tcp(tx_buffer, use_server_socket=False)
            time.sleep(1)
            count += 1
            wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=2, time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no + 1)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{sock_no} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received on DUT is matching")

        start_port = 8001
        start_port_dut = 6001
        for sock_count in range(0, 5):
            port = start_port + sock_count
            port_dut = start_port_dut + sock_count
            remote_socket.interfaces.socket.start_server(port=port, socket_type=1)
            sock_id = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
            udp_socks.append(sock_id)
            logger().info(
                f"Successfully opened UDP client socket and socket id received is {sock_id} which is expected")
            if sock_count == 10:
                assert sock_id == 10, f"socket id received is wrong, expected is 0"
            elif sock_count == 11:
                assert sock_id == 11, f"socket id received is wrong, expected is 1"
            elif sock_count == 12:
                assert sock_id == 12, f"socket id received is wrong, expected is 2"
            elif sock_count == 13:
                assert sock_id == 13, f"socket id received is wrong, expected is 3"
            elif sock_count == 14:
                assert sock_id == 14, f"socket id received is wrong, expected is 4"

            wifi_dut.interfaces.wifi.bind(socket_fd=sock_id, device_ip=wifi_thread.dut_addr['device_ip'],
                                          server_port=port_dut, asynch=1)

        for socket_no in range(10, 15):
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=50))
            data_length = len(data_sent)
            if socket_no == 10:
                start_port_dut = 6001
            elif socket_no == 11:
                start_port_dut = 6002
            elif socket_no == 12:
                start_port_dut = 6003
            elif socket_no == 13:
                start_port_dut = 6004
            elif socket_no == 14:
                start_port_dut = 6005
            logger().info(f"###################### start_port from DUT : {start_port_dut}  ######################")

            remote_socket.interfaces.socket.send_data_udp(
                tx_buffer=data_sent, server_ip=wifi_thread.dut_addr['device_ip'], port=start_port_dut)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_no)
            logger().info(f"###################### Buffer Data  {data_sent}  ######################")
            logger().info(f"###################### Buffer Data Length  {data_length}  ######################")
            logger().info(f"###################### Received Data: {buffer_rx} ######################")
            assert data_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {socket_no} opened in the DUT is not matched "
        time.sleep(2)
        for sock in tcp_socks:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        for socket in udp_socks:
            logger().info(f"Closing socket_id->{socket}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
