import re
import time
from threading import Thread
from utf.utils.thread_base import ThreadBase
from random import randint
from utf.utils.subprocess_manager import SubprocessManager
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf import UtfDatabaseProperties
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116ExtTCPIPFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116DataRate, RS9116RejoinParams, RS9116ExtCustomFeatureBitMap, \
    RS9116BTFeatureBitMap, SocketOptions
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.iperf.iperf_utils import print_dict
import random
import string

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP or UDP socket(Client/server) at DUT/RESPI
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
        8. Verify TCP rx & tx with high performance sockets
        9. Verify data transfer with different window size and with different RSSI values.
    setup requirement:
        1. DUT(RS9116/RS9117)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC device for Sniffer
"""
'''Author: Jyothi Nagireddy'''


def logger():
    return get_logger(__name__)


class AttenuatorValuesVariation(ThreadBase):
    def __init__(self, wifi_dut, rf_attenuator, att_channel, db_value):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.rf_attenuator = rf_attenuator
        self.att_channel = att_channel
        self.db_value = db_value

    def run(self):
        logger().info(f'\n\n ******* Set the attenuator value for {self.att_channel} **********\n\n')
        self.wifi_dut.interfaces.wifi.set_attenuator(self.rf_attenuator, self.att_channel, self.db_value)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class RemoteDataTransfer:
    def send_data(self, remote_socket, data_size, test_run_time=300, proto_type=0, server_ip=None,
                      server_port=None):
        sw = Stopwatch()
        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=data_size))
        while sw.elapsed_sec < test_run_time:
            if proto_type == 0:
               data = remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)
            else:
                data = remote_socket.interfaces.socket.send_data_udp(tx_buffer, server_ip, server_port)
                time.sleep(0.1)
            self.sent_data = self.sent_data + data
        logger().info(f"Total bytes sent on socket opened remotely -> {self.sent_data}")

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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.parametrize("number_of_pkts", [10000])
def test_wifi_sdk_tcp_close_c19347(wifi_sniffer, remote_socket, wifi_dut, utf_constants, wifi_access_point, number_of_pkts, sl_collections):
    """Verify TCP client socket is open, send data, and close socket"""
    try:
        data_size = 1460
        remote_socket.interfaces.socket.time_limit = 1800
        data_obj = RemoteDataTransfer()
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19347")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        logger().info(f"DUT opens tcp client socket")
        sock = wifi_dut.interfaces.wifi.socket(protocol= IPPROTO_TCP, timeout=15)
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"tcp socket opened in DUT connects to the tcp server")
        wifi_dut.interfaces.wifi.bsdSocketConnect(sock)
        th_start = Thread(target=data_obj.receive_data_socket,
                          args=(remote_socket, number_of_pkts, data_size, 0), daemon=True)
        th_start.start()
        # bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
        # logger().info(f"Number of bytes sent by dut {bytes_sent}")
        th_start.join()
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert "success" in result, f"unable the close socket"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find ps poll in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.parametrize("number_of_pkts", [10000])
def test_wifi_sdk_udp_close_c19348(wifi_sniffer, remote_socket, wifi_dut, utf_constants, wifi_access_point, number_of_pkts, sl_collections):
    """Verify UDP client socket is open, send data, and close socket"""
    try:
        data_size = 1460
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_C19348")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        logger().info(f"DUT opens udp client socket")
        sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_UDP, timeout=15)
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"udp socket opened in DUT connects to the udp server")
        wifi_dut.interfaces.wifi.bsdSocketConnect(sock)
        data_obj = RemoteDataTransfer()
        th_start = Thread(target=data_obj.receive_data_socket,
                          args=(remote_socket, number_of_pkts, data_size, 0), daemon=True)
        th_start.start()
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port
        # bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
        #                                                      server_ip=server_ip, server_port=server_port)
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        th_start.join(5)
        logger().info(f"DUT closes the socket.socket id is mentioned in sock variable")
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert b"success" in result, "Unable to close the udp socket"

        logger().info("Successfully closed opened socket in the DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find ps poll in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
                               RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "server_socket_limit": 10,
        "client_socket_limit": 10,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_socket_c19349(wifi_sniffer, utf_constants, wifi_access_point, wifi_dut, remote_socket, sl_collections):
    try:
        """Verify 10 sockets functionality open 10 TCP client sockets and connect to server sockets"""
        socket_id_value = set()
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19349")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(10)
        for port_number in range(6000, 6010):
            logger().info(f"Open TCP socket remotely")
            remote_socket.interfaces.socket.start_server(port=port_number, connections=10)
            logger().info(f"DUT opens tcp client socket")
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
            logger().info(f"socket id received is {sock} which is expected")
            local_port = randint(5001, 60000)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            logger().info(f"tcp socket opened in DUT connects to the tcp server")
            wifi_dut.interfaces.wifi.bsdSocketConnect(sock)
            socket_id_value.add(sock)
        logger().info(f'Socket values = {socket_id_value}')
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'
    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
                               RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "client_socket_limit": 10,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_udp_socket_c19350(wifi_access_point, wifi_dut, utf_constants, remote_socket, wifi_sniffer, sl_collections):
    """Verify 10 sockets functionality open 10 UDP client sockets and connect to server sockets"""
    try:
        socket_id_value = set()
        # wifi_dut.interfaces.wifi.set_socket_limit(10, 10)
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19350")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(20)
        for port_number in range(6001, 6011):
            logger().info(f"Open UDP socket remotely")
            remote_socket.interfaces.socket.start_server(socket_type=1)
            logger().info(f"DUT opens udp client socket")
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_UDP, timeout=15)
            logger().info(f"Socket binds at (device_ip, 5001) in DUT")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, port_number)
            logger().info(f"udp socket opened in DUT connects to the udp server")
            wifi_dut.interfaces.wifi.bsdSocketConnect(sock)
            socket_id_value.add(sock)
        logger().info(f'Socket values = {socket_id_value}')
        for sock_value in socket_id_value:
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_value)
            time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
                               RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "client_socket_limit": 10,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_10_tcp_socket_c19351(wifi_access_point, wifi_dut, utf_constants, remote_socket, wifi_sniffer,
                                         remote_socket_factory, sl_collections):
    """Verify 10 sockets functionality open 10 TCP server sockets and client sockets connect to it"""
    try:
        # wifi_dut.interfaces.wifi.set_socket_limit(10, 10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19351")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(20)
        server_port_base = 5001
        for count in range(0, 5):
            server_port = server_port_base + count
            logger().info(f"DUT opens tcp client socket")
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
            wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        client_socket = []
        for count in range(0, 5):
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            server_port = server_port_base + count
            result = ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, count),
                    (
                        client_socket[count].connect_client_tcp,
                        device_ip,
                        server_port,
                    ),
                ],
                timeout=10,
            )

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
                               RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "client_socket_limit": 10,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_5tcp_5udp_socket_c19352(wifi_access_point, wifi_dut, remote_socket, utf_constants, wifi_sniffer, sl_collections):
    """Verify 10 sockets functionality open 5TCP & 5UDP client sockets."""
    try:
        socket_id_value = set()
        send_bytes = 1000
        # wifi_dut.interfaces.wifi.set_socket_limit(10, 10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19352")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(20)
        for port_number in range(6001, 6006):
            logger().info(f"Open UDP socket remotely")
            remote_socket.interfaces.socket.start_server(port=port_number, connections=10)
            logger().info(f"DUT opens tcp client socket")
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
            logger().info(f"socket id received is {sock} which is expected")
            local_port = randint(5001, 60000)
            logger().info(f"Socket binds at (device_ip, 5001) in DUT")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            logger().info(f"tcp socket opened in DUT connects to the tcp server")
            wifi_dut.interfaces.wifi.bsdSocketConnect(sock, remote_socket.interfaces.socket, server_port=port_number)
            send_response = wifi_dut.interfaces.wifi.bsdSocketSend(sock, send_bytes)
            logger().info(f'SEND-RESPONSE = {send_response}')
            socket_id_value.add(sock)

        for port_number in range(6007, 6012):
            logger().info(f"Open UDP socket remotely")
            remote_socket.interfaces.socket.start_server(socket_type=1)
            logger().info(f"DUT opens udp client socket")
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_UDP, timeout=15)
            logger().info(f"socket id received is {sock} which is expected")
            logger().info(f"Socket binds at (device_ip, 5001) in DUT")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, port_number)
            logger().info(f"udp socket opened in DUT connects to the udp server")
            wifi_dut.interfaces.wifi.bsdSocketConnect(sock)
            socket_id_value.add(sock)
        logger().info(f'Socket values = {socket_id_value}')
        for sock_value in socket_id_value:
            logger().info(f"DUT closes the socket.socket id is mentioned in sock variable")
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_value)
            assert b"success" in result, "Unable to close the udp socket"
            wifi_dut.interfaces.wifi.close_socket(sock_value)
            time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'
    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
                               RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "server_socket_limit": 10,
        "client_socket_limit": 10,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_5tcp_5udp_socket_c19353(wifi_access_point, wifi_dut, utf_constants, sl_collections, remote_socket_factory, wifi_sniffer):
    """Verify 10 sockets functionality open 5TCP server +5UDP server sockets."""
    try:
        socket_id_value = []
        server_port = 7001
        wifi_dut.interfaces.wifi.set_socket_limit(10, 10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19353")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(20)
        server_port_base = 5001
        for count in range(0, 5):
            server_port = server_port_base + count
            logger().info(f"DUT opens tcp client socket")
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
            logger().info(f"socket id received is {sock} which is expected")
            logger().info(f"Socket binds at (device_ip, 5001) in DUT")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
            wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        client_socket = []
        for count in range(0, 5):
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            server_port = server_port_base + count
            result = ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, count),
                    (
                        client_socket[count].connect_client_tcp,
                        device_ip,
                        server_port,
                    ),
                ],
                timeout=10,
            )
            socket_id_value.append(result)
        logger().info(f'Socket values = {socket_id_value}')
        start_port = 7001
        for sock_count in range(0, 5):
            port = start_port + sock_count
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.start_server(port=port, socket_type=SOCKET_TYPE_UDP)
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_UDP, timeout=15)

            if sock_count == 0:
                local_port = 7001
                assert sock == 0, f"socket id received is wrong, expected is 0"
            elif sock_count == 1:
                local_port = 7002
                assert sock == 1, f"socket id received is wrong, expected is 1"
            elif sock_count == 2:
                local_port = 7003
                assert sock == 2, f"socket id received is wrong, expected is 2"
            elif sock_count == 3:
                local_port = 7004
                assert sock == 3, f"socket id received is wrong, expected is 3"
            elif sock_count == 4:
                local_port = 7005
                assert sock == 4, f"socket id received is wrong, expected is 4"

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        server_ip = remote_socket_factory.interfaces.socket.sockets[0].hostname_or_ip_address()

        for socket_no in range(0, 5):
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            if socket_no == 0:
                server_port = 7001
            elif socket_no == 1:
                server_port = 7002
            elif socket_no == 2:
                server_port = 7003
            elif socket_no == 3:
                server_port = 7004
            elif socket_no == 4:
                server_port = 7005

            wifi_dut.interfaces.wifi.bsdSocketSend(sock, data_length, server_ip, server_port)

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'

    finally:
         logger().info("\n******Stop Sniffer finally******")
         wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "client_socket_limit": 10,
        "tx_wait_time": 16000,
    }
)
def test_wifi_sdk_tcp_rejoin_c19354(wifi_sniffer, wifi_access_point, utf_constants, wifi_dut, wifi_client, switch, sl_collections):
    """Verify TCP data transfer functionality while STA is in rejoin process(Send 10,000 packets from the module with
       size 1460)"""
    try:
        send_bytes = 1460
        end_time_sec = 100
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=30)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19354")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                             beacon_missed_count=40, first_time_retry_enable=0)
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        tcp_socket_id = wifi_dut.interfaces.wifi.socket(protocol= IPPROTO_TCP, timeout=15)
        wifi_dut.interfaces.wifi.bind(tcp_socket_id, device_ip)
        wifi_dut.interfaces.wifi.bsdGetSocketOpt(tcp_socket_id, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
        connect_response = wifi_dut.interfaces.wifi.bsdSocketConnect(tcp_socket_id)
        logger().info(f"Connect response : {connect_response}")
        time.sleep(10)
        if connect_response is False:
            logger().info("Unable to connect with Server")
            assert connect_response
        else:
            sw = Stopwatch()
            check_flag = False
            while sw.elapsed_sec < end_time_sec:
                send_response = wifi_dut.interfaces.wifi.bsdSocketSend(tcp_socket_id, send_bytes, timeout=60)
                logger().info(f'SEND-RESPONSE = {send_response}')
                time.sleep(1)
                while sw.elapsed_sec < 30:
                   send_response = wifi_dut.interfaces.wifi.bsdSocketSend(tcp_socket_id, send_bytes, timeout=60)
                   logger().info(f'SEND-RESPONSE = {send_response}')
                   time.sleep(1)

                if check_flag is not True:
                   logger().info('***** Turn off Access point *****')
                   switch.interfaces.pdu_switch.turn_off(delay=20)
                   logger().info('******* Turn on Access point **********')
                   switch.interfaces.pdu_switch.turn_on(delay=30)
                   check_flag = True

        time.sleep(5)
        logger().info("Stop sniffer capture")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                        filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                        filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
        'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                        filter_name="pwr_mgt")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
        'Unable to find pwr mgt in Sniffer'

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=20)
        wifi_dut.interfaces.wifi.leave()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_http_socket_tcp_c19358(wifi_sniffer, wifi_dut, wifi_access_point, sl_collections, utf_constants):
    """Try to open TCP server socket on port 80 when HTTP server is enabled"""
    try:
        port_number = 80
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19358")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        sock_id = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        logger().info(f'\n Socket id = {sock_id}\n')
        wifi_dut.interfaces.wifi.bind(sock_id, device_ip, port_number)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.listen(sock_id, 1)
        assert exc_info.value.error_code == 0xFFFFFFFF, f"DUT sent wrong error code. expected is {0xFFFFFFFF}"
        # with pytest.raises(WlanError) as exc_info:
        # # wifi_dut.interfaces.wifi.wlan_get_status()
        # assert exc_info.value.error_code == 0xFF81, f"DUT sent wrong error code. expected is {0xFF81}"
        logger().info(f"DUT sent error code -> {exc_info.value.error_code} which is expected when trying to open socket at "
                      f"{port_number} port number when http server is enabled in the DUT")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        assert result, f"unable to close the socket"
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPSServer |
                          RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.
            WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_https_socket_tcp_c71652(wifi_sniffer, wifi_dut, wifi_access_point, sl_collections, utf_constants):
    """Try to open TCP server socket on port 443 when HTTPs server is enabled"""
    try:
        port_number = 443
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c71652")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        sock_id = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        logger().info(f'\n Socket id = {sock_id}\n')
        wifi_dut.interfaces.wifi.bind(sock_id, device_ip, port_number)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.listen(sock_id, 1)
        assert exc_info.value.error_code == 0xFFFFFFFF, f"DUT sent wrong error code. expected is {0xFFFFFFFF}"

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xFF81, f"DUT sent wrong error code. expected is {0xFF81}"
        logger().info(f"DUT sent error code -> {exc_info.value.error_code} which is expected when trying to open socket at "
                      f"{port_number} port number when http server is enabled in the DUT")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.TCP_IP_TOTAL_SOCKETS_1 | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_socket_limit_c19359(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket, sl_collections, utf_constants):
    """Open more than one socket when only one socket is selected in opermode command."""
    try:
        port_number = 5002
        device_port = 5001
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19359")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        time.sleep(20)
        remote_socket.interfaces.socket.start_server()
        logger().info(f"Open TCP socket in the DUT")
        logger().info(f"DUT opens tcp client socket")
        sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"tcp socket opened in DUT connects to the tcp server")
        wifi_dut.interfaces.wifi.bsdSocketConnect(sock, remote_socket.interfaces.socket)
        # wifi_dut.interfaces.wifi.send_data_pkts(sock, 10, 10)

        sock_id = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        logger().info(f'Socket_id = {sock_id}')

        wifi_dut.interfaces.wifi.bind(sock_id, device_ip, port_number)

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.bsdSocketConnect(sock_id, remote_socket.interfaces.socket, server_port=port_number)
        assert exc_info.value.error_code == 0xFF80, f"DUT sent wrong error code. expected is {0xFF80}"
        logger().info(f'\n\n DUT is able to return 0xff80 while connecting to the 2nd TCP server socket.\n\n')
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert "success" in result, "unable to close opened tcp socket"
        logger().info("Successfully closed opened socket in the DUT")
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        assert "success" in result, "unable to close opened tcp socket"
        logger().info("Successfully closed opened socket in the DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()

pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.parametrize("test_run_time", [60])
def test_wifi_sdk_tcp_data_receive_check_c19360(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                             test_run_time, sl_collections, utf_constants):
    try:
        """Open more than one socket when only one socket is selected in opermode command."""
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19360")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        logger().info(f"DUT opens tcp client socket")
        sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"tcp socket opened in DUT connects to the tcp server")
        wifi_dut.interfaces.wifi.bsdSocketConnect(sock)
        tx_buffer = "12345678901234567890123456789012345678901234567890"
        buffer_length = len(tx_buffer)
        sw = Stopwatch()
        iteration_count = 1
        while sw.elapsed_sec < test_run_time:
            logger().info(f"######################Iteration count {iteration_count}######################")
            logger().info(f"send 50 bytes of data from tcp server opened remotely")
            remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)
            logger().info(f"DUT receives data over tcp socket after execution of below api")
            try:
                buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_id=sock,
                                                                                            data_len=buffer_length)
            except:
                logger().info("resetting the DUT as receive API is a blocking call. SAPI driver is in the blocking mode")
                wifi_dut.interfaces.wifi.reset()
                assert 0, "DUT is not able to receive data over TCP socket"
            iteration_count = iteration_count + 1
        assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
        assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
        logger().info("contents of data sent and receive are matched")
        result = wifi_dut.interfaces.wifi.bsdSockClose(sock)
        assert "success" in result, "unable to close opened tcp socket in the dut"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find ps poll in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_tcp_remote_terminate_c19362(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, sl_collections, utf_constants):
    """TCP remote terminate after Tx from module.Cehck total bytes sent by module"""
    try:
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19362")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = randint(5001, 50000)
        execute_command = ['iperf', '-s', '-i 1', '-p', str(server_port)]
        iperf_process = SubprocessManager(execute_command)
        iperf_process.start()
        logger().info(f"DUT opens tcp client socket")
        sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        logger().info(f"Socket binds at (device_ip, 5001) in DUT")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"tcp socket opened in DUT connects to the tcp server")
        wifi_dut.interfaces.wifi.bsdSocketConnect(sock)
        data_length = 1460
        no_of_pkts = 1000
        bytes_triggered = (data_length * no_of_pkts)
        logger().info(f"DUT sends 50 bytes of data over tcp socket")
        wifi_dut.interfaces.wifi.send_data_pkts(sock, data_length, no_of_pkts)
        time.sleep(3)
        iperf_process.stop()
        # events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
                remote_terminate = event.event_data
            else:
                assert 1, f"Remote terminate event is not received by DUT even though tcp socket connected is closed"
        if remote_terminate:
            logger().info("Remote terminate event is received by DUT when tcp socket connected is closed")
            socket_id = int(remote_terminate.split(b",")[1].split(b":")[1])
            bytes_sent = int(remote_terminate.split(b",")[2].split(b":")[1])
            logger().info(f"Number of bytes sent on socket {socket_id}->  {bytes_sent}")
            assert bytes_triggered == bytes_sent, 'Number of bytes triggered by host and actually sent by dut are not ' \
                                                  'matched. triggered {bytes_triggered} bytes, But actually ' \
                                                  'sent {bytes_sent} bytes'
            logger().info("Number of bytes triggered by host and actually sent by dut are matched")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find ps poll in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower |
                               RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "server_socket_limit": 10,
        "client_socket_limit": 10,
    }
)
def test_wifi_sdk_tcp_max_limit_c19364(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, remote_socket, remote_socket_factory, sl_collections):
    """Open TCP severs socket more than maximum and connect TCP clients"""
    try:
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19364")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        server_port_base = 5001
        for count in range(0, 10):
            server_port = server_port_base + count
            logger().info(f'Server port = {server_port}')
            logger().info(f"DUT opens tcp client socket")
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
            logger().info(f"socket id received is {sock} which is expected")
            if count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0"
            if count == 1:
                assert sock == 1, f"socket id received is wrong, expected is 1"
            if count == 2:
                assert sock == 2, f"socket id received is wrong, expected is 2"
            if count == 3:
                assert sock == 3, f"socket id received is wrong, expected is 3"
            if count == 4:
                assert sock == 4, f"socket id received is wrong, expected is 4"
            if count == 5:
                assert sock == 5, f"socket id received is wrong, expected is 5"
            if count == 6:
                assert sock == 6, f"socket id received is wrong, expected is 6"
            if count == 7:
                assert sock == 7, f"socket id received is wrong, expected is 7"
            if count == 8:
                assert sock == 8, f"socket id received is wrong, expected is 8"
            if count == 9:
                assert sock == 9, f"socket id received is wrong, expected is 9"

            # Socket binds at (device_ip, server_port) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
            wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        client_socket = []
        for count in range(0, 10):
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            result = ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, count),
                    (
                        client_socket[count].connect_client_tcp,
                        device_ip,
                        server_port_base + count,
                    ),
                ],
                timeout=10,
            )

            socket_id = result[0]
            logger().info(f'Socket id = {socket_id}')
            if count == 0:
                assert socket_id == 9, f"socket id received is wrong, expected is 9"
            if count == 1:
                assert socket_id == 10, f"socket id received is wrong, expected is 10"
            if count == 2:
                assert socket_id == 11, f"socket id received is wrong, expected is 11"
            if count == 3:
                assert socket_id == 12, f"socket id received is wrong, expected is 12"
            if count == 4:
                assert socket_id == 13, f"socket id received is wrong, expected is 13"
            if count == 5:
                assert socket_id == 14, f"socket id received is wrong, expected is 14"
            if count == 6:
                assert socket_id == 15, f"socket id received is wrong, expected is 15"
            if count == 7:
                assert socket_id == 16, f"socket id received is wrong, expected is 16"
            if count == 8:
                assert socket_id == 17, f"socket id received is wrong, expected is 17"
            if count == 9:
                assert socket_id == 18, f"socket id received is wrong, expected is 18"
        logger().info(f'\n\n Trying to open 11th socket\n')

        sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, 7002)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.listen(sock, 1)
        assert exc_info.value.error_code == 0xFFFFFFFF, f"DUT sent wrong error code. expected is {0xFFFFFFFF}"
        # with pytest.raises(WlanError) as exc_info:
        #     wifi_dut.interfaces.wifi.wlan_get_status()
        # assert exc_info.value.error_code == 0xFF81, f"DUT sent wrong error code. expected is {0xFF81}"
        logger().info(f"DUT sent error code -> {exc_info.value.error_code} which is expected when trying to open socket at "
                      f"443 port number when https server is enabled in the DUT")

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e
    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.skip("iperf-dut-support-NA")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "client_socket_limit": 10,
    }
)
def test_wifi_sdk_tcp_udp_data_transfer_c19365(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, net_perf_client,
                                                protocol, sl_collections, utf_constants):
    """Verify TCP ,UDP data transfer and reception of STAUT in WPA-TKIP mode"""
    try:
        device_port = 5201
        iperf_execution_time = 650
        pkt_length = 1460
        no_of_pkts = 100
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c19365')
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        ''' Start Iperf traffic RESPI as a server & DUT as a client'''
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                        device_ip=device_ip, protocol=protocol,
                                                        time_out=iperf_execution_time)
        net_perf_client.interfaces.net_perf.start()

        # Open TCP/UDP client socket at DUT side
        if protocol == 'TCP':
            logger().info(f'\n\n Open {protocol} socket at DUT side \n')
            sock_id = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        else:
            logger().info(f'\n\n Open {protocol} socket at DUT side \n')
            sock_id =wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_UDP, timeout=15)

        wifi_dut.interfaces.wifi.bind(sock_id, device_ip, device_port)
        wifi_dut.interfaces.wifi.bsdSocketConnect(sock_id, host_ip, server_port=device_port)

        sw = Stopwatch()
        while sw.elapsed_sec < iperf_execution_time:
            logger().info(f'sw.elapsed_sec = {sw.elapsed_sec}, iperf_execution_time ={iperf_execution_time}')
            # wifi_dut.interfaces.wifi.send_data_pkts(sock_id, pkt_length, no_of_pkts, timeout=iperf_execution_time)

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None
        if tp is not None:
            print_dict("##     ", tp)
        events = wifi_dut.interfaces.wifi.get_async_events()
        for event in events:
            if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
                remote_terminate = event.event_data
            else:
                assert 1, f"Remote terminate event is not received by DUT even though tcp socket connected is closed"
        if remote_terminate:
            logger().info("Remote terminate event is received by DUT when tcp socket connected is closed")
            logger().info(f'Remote terminate = {remote_terminate}')
            socket_id = int(remote_terminate.split(b",")[1].split(b":")[1])
            bytes_sent = int(remote_terminate.split(b",")[2].split(b":")[1])
            logger().info(f"Number of bytes sent on socket {socket_id}->  {bytes_sent}")
            assert bytes_triggered == bytes_sent, f"Number of bytes triggered by host and actually sent by dut  are not " \
                                                  f"matched. triggered {bytes_triggered} bytes, But actually sent {bytes_sent} bytes "
            logger().info("Number of bytes triggered by host and actually sent by dut are matched")

        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "server_socket_limit": 8,
        "client_socket_limit": 8,
    }
)
def test_wifi_sdk_tcp_tx_rx_c19366(wifi_sniffer, wifi_access_point, wifi_dut, remote_socket,
                                                    remote_socket_factory, sl_collections, utf_constants):

    '''Verify TCP tx and Rx by opening 8 TCP high performance socket'''
    try:
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_case_c19366")
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        server_port_base = 5001
        for count in range(0, 8):
            server_port = server_port_base + count
            logger().info(f'Server port = {server_port}')
            sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
            ''' As per test case requirement need to pass TCP high performance socket value '''
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, SocketOptions.SOL_SOCKET,
                                                       SocketOptions.SO_HIGH_PERFORMANCE_SOCKET,
                                                       SocketOptions.high_performance_socket)
            if count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0"
            if count == 1:
                assert sock == 1, f"socket id received is wrong, expected is 1"
            if count == 2:
                assert sock == 2, f"socket id received is wrong, expected is 2"
            if count == 3:
                assert sock == 3, f"socket id received is wrong, expected is 3"
            if count == 4:
                assert sock == 4, f"socket id received is wrong, expected is 4"
            if count == 5:
                assert sock == 5, f"socket id received is wrong, expected is 5"
            if count == 6:
                assert sock == 6, f"socket id received is wrong, expected is 6"
            if count == 7:
                assert sock == 7, f"socket id received is wrong, expected is 7"
            if count == 8:
                assert sock == 8, f"socket id received is wrong, expected is 8"
            if count == 9:
                assert sock == 9, f"socket id received is wrong, expected is 9"

            wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
            wifi_dut.interfaces.wifi.listen(sock, backlog=1)
        client_socket = []
        for count in range(0, 8):
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            result = ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.bsdSocketAccept, count),
                    (
                        client_socket[count].connect_client_tcp,
                        device_ip,
                        server_port_base + count,
                    ),
                ],
                timeout=10,
            )
            socket_id = result[0]
            logger().info(f'Socket id = {socket_id}')

            if count == 0:
                assert socket_id == 9, f"socket id received is wrong, expected is 9"
            if count == 1:
                assert socket_id == 10, f"socket id received is wrong, expected is 10"
            if count == 2:
                assert socket_id == 11, f"socket id received is wrong, expected is 11"
            if count == 3:
                assert socket_id == 12, f"socket id received is wrong, expected is 12"
            if count == 4:
                assert socket_id == 13, f"socket id received is wrong, expected is 13"
            if count == 5:
                assert socket_id == 14, f"socket id received is wrong, expected is 14"
            if count == 6:
                assert socket_id == 15, f"socket id received is wrong, expected is 15"
            if count == 7:
                assert socket_id == 16, f"socket id received is wrong, expected is 16"
            if count == 8:
                assert socket_id == 17, f"socket id received is wrong, expected is 17"
            if count == 9:
                assert socket_id == 18, f"socket id received is wrong, expected is 18"
        logger().info(f'\n\n Trying to open 11th socket\n')
        sock = wifi_dut.interfaces.wifi.socket(protocol=IPPROTO_TCP, timeout=15)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, 7002)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.listen(sock, 1)
        assert exc_info.value.error_code == 0xFFFFFFFF, f"DUT sent wrong error code. expected is {0xFFFFFFFF}"
        # with pytest.raises(WlanError) as exc_info:
        #     wifi_dut.interfaces.wifi.wlan_get_status()
        # assert exc_info.value.error_code == 0xFF81, f"DUT sent wrong error code. expected is {0xFF81}"
        # logger().info(f"DUT sent error code -> {exc_info.value.error_code} which is expected when trying to open "
        #               f"socket at 7002 port number in the DUT")

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    else:
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.skip("iperf-dut-support-NA")
@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.
            Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "client_socket_limit": 10,
    }
)
def test_wifi_sdk_tcp_udp_socket_data_transfer_c19363(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                            net_perf_client, protocol, rf_attenuator, sl_collections, utf_constants):

    '''Verify data transfer, auto rate and handling of Buffer Full and Buffer empty by STAUT when RSSI value of AP is
     ~ -30dbm to -90dbm'''
    '''Note - Current attenuator does not support over 60DBM attenuation, so I comment out the 70 to 90 dbm limit'''
    try:
        att_channel = 1

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_c19363')
        device_ip, dut_mac_address = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")
        ''' Start Iperf traffic DUT as a client and Linux machine as a server'''
        # wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out)
        # iperf code
        '''  Change the attenuation value by 10 step '''
        attenuator_obj = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 30)
        attenuator_obj1 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 40)
        attenuator_obj2 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 50)
        attenuator_obj3 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 60)
        # attenuator_obj4 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 70)
        # attenuator_obj5 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 80)
        # attenuator_obj6 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 90)
        # wlan_obj.start()
        # time.sleep(10)
        attenuator_obj.start()
        attenuator_obj.wait_for_exit()
        time.sleep(20)
        attenuator_obj1.start()
        attenuator_obj1.wait_for_exit()
        time.sleep(20)
        attenuator_obj2.start()
        attenuator_obj2.wait_for_exit()
        time.sleep(20)
        attenuator_obj3.start()
        attenuator_obj3.wait_for_exit()
        time.sleep(20)
        # attenuator_obj4.start()
        # attenuator_obj4.wait_for_exit()
        # time.sleep(20)
        # attenuator_obj5.start()
        # attenuator_obj5.wait_for_exit()
        # time.sleep(20)
        # attenuator_obj6.start()
        # attenuator_obj6.wait_for_exit()
        # time.sleep(20)
        # wlan_obj.wait_for_exit()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Probe_request")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find probe request in Sniffer'
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="ps_poll")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find ps poll in Sniffer'
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find pwr mgt in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="DHCP discovery, offer, request, ack packet")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            filter_name="Verify TCP SYN ,SYN-ACK,ACK packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)['packet_count'], \
            'Unable to find Verify TCP SYN ,SYN-ACK,ACK packets in Sniffer'

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        logger().info(f"\n******Found Assertion --> {e}******\n")
        raise e

    finally:
        logger().info("\n******Stop Sniffer finally******")
        wifi_sniffer.interfaces.capture.stop_capture()








