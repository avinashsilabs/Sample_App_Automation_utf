import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    DeviceConstants,
    RS9116AsyncEventType,
    RS9116PowerSaveProcedureTypes,
    RS9116CustomFeatureBitMap,
    SocketType,
    SocketOptions,
)
from utf.interfaces.wifi import WlanError
from utf.interfaces.cli import CLITransportException
from threading import Thread
import threading
import string
import random
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
import math
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.thread_base import ThreadBase
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf.utils.subprocess_manager import SubprocessManager
from random import randint
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from retry import retry

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
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC device for Sniffer
"""
'''Author: Vinod & Vivek'''


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class IopTcpIpSockets:
    def open_socket(self, wifi_dut, dut_ip) -> int:
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            tcp_socket_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            if isinstance(tcp_socket_id, int):
                logger().info(f"Socket open successfully : {tcp_socket_id}")
            else:
                logger().error(f"Unable to open socket id: {tcp_socket_id}")
                raise RuntimeError(tcp_socket_id)

            time.sleep(5)
            bind_response = wifi_dut.interfaces.wifi.bind(tcp_socket_id, dut_ip)
            if bind_response.decode().split(">")[1].replace("'", '').strip() == 'success':
                logger().info(f"Bind socket successfully: {bind_response}")
            else:
                logger().error(f"Unable to bind socket: {bind_response}")
                raise RuntimeError(bind_response)
        return tcp_socket_id

    def connect_socket(self, wifi_dut, tcp_socket_id: int):
        retry_limit: int = 2
        connect_status = False
        for retry in range(1, retry_limit):
            connect_response = wifi_dut.interfaces.wifi.connect(tcp_socket_id)
            logger().info(f"Connect response : {connect_response}")
            if connect_response.decode() == '':
                logger().info(f"Unable to connect socket: {connect_response} in {retry} try")
                if retry < retry_limit:
                    pass
            elif connect_response.decode().split(">")[1].strip() == 'success':
                logger().info(f"Socket connected successfully in {retry} try")
                connect_status = True
                break
            logger().info(f"Socket connected with server in: {retry + 1} time")
        return connect_status


class tx_rx:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def join_get_ip(self, wifi_sniffer, wifi_dut, wifi_access_point, capture_filename):
        ping_count = 10
        result = wifi_dut.interfaces.wifi.version()
        logger().info(f"DUT firmware version: {result}")
        # configure interface for the channel of the access point
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        for count in range(1, 3):
            try:
                scan_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger().info("Scanning to the Wifi Access Point")
                wifi_dut.interfaces.wifi.scan(ssid=None)
                scan_fail = 0
                break
            except:
                logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                time.sleep(1)
        if scan_fail:
            logger().info(f"Scanning to the AP has failed")
            assert scan_fail == 0, "Scanning to the AP is failed"

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")
        logger().info("Start the sniffer")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )

        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
        for count in range(1, 3):
            try:
                join_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger().info("Joining to the Wifi Access Point")
                wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
                join_fail = 0
                break
            except:
                logger().info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        if join_fail:
            logger().info(f"Joining to the AP has failed")
            assert join_fail == 0, "Joining to the AP is failed"
        for count in range(1, 3):
            ip_fail = 1
            try:
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                logger().info("DUT gets ipaddress through DHCP ")
                ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=120, retries=6)
                ip_fail = 0
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(15)
        if ip_fail:
            logger().info(f"DUT unable to get IP address")
            assert ip_fail == 0, "ip setting in DUT has failed"
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
        ping(device_ip, ping_count)
        return mac_address

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

    @staticmethod
    @retry(Exception, delay=15, tries=3)
    def get_ip(wifi_dut):
        logger().info("DUT gets ip address through DHCP")
        wifi_dut.interfaces.wifi.start_ip(timeout=120, retries=6)
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        return device_ip


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out):
        super().__init__()
        self.iperf_obj = RunTraffic()
        self.wifi_dut = wifi_dut
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.host_ip = host_ip
        self.time_out = time_out

    def run(self):
        self.iperf_obj.start_iperf_dut_as_client(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip,
                                                 self.host_ip, self.time_out)


class RunTraffic:
    def start_iperf_dut_as_client(self, wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out):
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                        device_ip=device_ip, protocol=protocol, time_out=time_out)

        net_perf_client.interfaces.net_perf.start()

        # open socket and send traffic
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None
        if tp is not None:
            print_dict("##     ", tp)


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


def dut_clean_up(wifi_dut):
    logger().info("\n\n ---------------------------- Cleaning UP the DUT -------------------------------")
    try:
        logger().info("Closing all sockets opened in DUT")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(5)
    except Exception as err:
        logger().info(
            f"******* Exception occurred while cleaning up the DUT\nException is:{err}\nRecovering the DUT using reset **********")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)
    logger().info("\n ---------------------------- Cleaning UP of DUT is Completed -------------------")


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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("number_of_pkts", [10000])
# The test case checks tcp close functionality
def test_wifi_tcp_close_c19347(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, number_of_pkts):
    try:
        capture_filename = "test_wifi_tcp_close_TC19347"
        data_size = 1460
        remote_socket.interfaces.socket.time_limit = 1800
        join_obj = tx_rx()

        dut_mac_address = join_obj.join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
        tx_rx_obj = tx_rx()
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, number_of_pkts, data_size, 0), daemon=True)
        th_start.start()
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        th_start.join(5)
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")
    finally:
        dut_clean_up(wifi_dut)


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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("number_of_pkts", [10000])
# The test case checks udp socket close functionality
def test_wifi_udp_close_c19348(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, number_of_pkts):
    try:
        capture_filename = "test_wifi_udp_close_TC19348"
        data_size = 1460
        join_obj = tx_rx()

        dut_mac_address = join_obj.join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        logger().info("Starting udp socket remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(socket_type=1)
        # Open UDP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "socket id received is not matched. Expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        tx_rx_obj = tx_rx()
        th_start = Thread(target=tx_rx_obj.receive_data_socket,
                          args=(remote_socket, logger(), number_of_pkts, data_size, 1), )
        th_start.start()
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                             server_ip=server_ip, server_port=server_port)
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        th_start.join(5)
        # DUT closes the socket.socket id is mentioned in sock variable
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "Unable to close the udp socket"

        logger().info("Successfully closed opened socket in the DUT")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")
        wifi_dut.interfaces.wifi.leave()
    finally:
        dut_clean_up(wifi_dut)


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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_tcp_socket_dut_client_c19349(wifi_sniffer, wifi_access_point, wifi_dut, remote_socket):
    try:
        capture_filename = "test_socket_tcp_C19349"
        validation = True
        socket_id_value = set()
        '''Verify 10 sockets functionality open 10 TCP client sockets and connect to server sockets'''
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        time.sleep(10)
        for port_number in range(6000, 6010):
            # Open TCP socket remotely
            remote_socket.interfaces.socket.start_server(port=port_number, connections=10)
            # Open TCP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()

            wifi_dut.interfaces.wifi.bind(sock, device_ip, port_number)
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket, server_port=port_number)
            socket_id_value.add(sock)

        logger().info(f'Socket values = {socket_id_value}')
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        # DHCP discovery, offer, request, ack packet
        packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                         f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || wlan.addr ' \
                         f'== {dut_mac_address})'
        # Verify TCP SYN ,SYN-ACK,ACK packets
        packet_filter5 = f'tcp.flags == 0x002 || (tcp.flags == 0x012) || tcp.flags == 0x010 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
            'Unable to find Verify PS-Poll & PWMGT bit'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)['packet_count'], \
            'Unable to find TCP SYN ,SYN-ACK,ACK packets'
    finally:
        dut_clean_up(wifi_dut)


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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_udp_socket_dut_client_c19350(wifi_access_point, wifi_dut, remote_socket, wifi_sniffer):
    try:
        capture_filename = "test_socket_tcp_C19350"
        validation = True
        socket_id_value = set()
        '''Verify 10 sockets functionality open 10 UDP client sockets and connect to server sockets'''
        wifi_dut.interfaces.wifi.set_socket_limit(10, 10)
        remote_socket.interfaces.socket.time_limit = 3600
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        time.sleep(20)
        for port_number in range(6001, 6011):
            # Open UDP socket remotely
            remote_socket.interfaces.socket.start_server(socket_type=1)
            # Open UDP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_udp_client_socket()

            wifi_dut.interfaces.wifi.bind(sock, device_ip, port_number)
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket, server_port=port_number)
            socket_id_value.add(sock)

        logger().info(f'Socket values = {socket_id_value}')
        for sock_value in socket_id_value:
            wifi_dut.interfaces.wifi.close_socket(sock_value)
            time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        # DHCP discovery, offer, request, ack packet
        packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                         f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
            'Unable to find Verify PS-Poll & PWMGT bit'
    finally:
        dut_clean_up(wifi_dut)


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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_10_tcp_socket_dut_server_c19351(wifi_access_point, wifi_dut, remote_socket, wifi_sniffer,
                                         remote_socket_factory):
    try:
        capture_filename = "test_socket_tcp_C19351"
        validation = True

        '''Verify 10 sockets functionality open 10 TCP server sockets and client sockets connect to it'''
        wifi_dut.interfaces.wifi.set_socket_limit(10, 10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        time.sleep(20)
        server_port_base = 5001
        for count in range(0, 5):
            server_port = server_port_base + count
            # The below api opens ssl server socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()

            wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
            wifi_dut.interfaces.wifi.listen(sock, backlog=0)
            time.sleep(3)
        client_socket = []
        for count in range(0, 5):
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            server_port = server_port_base + count
            ThreadBase.call_functions_simultaneously(
                [(wifi_dut.interfaces.wifi.accept, count),
                 (client_socket[count].connect_client_tcp, device_ip, server_port)], timeout=30)

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        # DHCP discovery, offer, request, ack packet
        packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                         f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        packet_filter5 = f'tcp.flags == 0x002 || (tcp.flags == 0x012) || tcp.flags == 0x010 && (wlan.addr == ' \
                         f'{ap_bssid} || wlan.addr == {dut_mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find DHCP discovery, offer, request, ack packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find Verify PS-Poll & PWMGT bit'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find TCP SYN ,SYN-ACK,ACK packets'
    finally:
        dut_clean_up(wifi_dut)


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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_5tcp_5udp_socket_c19352(wifi_access_point, wifi_dut, remote_socket, wifi_sniffer):
    try:
        capture_filename = "test_socket_c19352"
        validation = True
        socket_id_value = set()
        send_bytes = 1000

        '''Verify 10 sockets functionality open 5TCP & 5UDP client sockets.'''
        wifi_dut.interfaces.wifi.set_socket_limit(10, 10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        time.sleep(20)
        for port_number in range(6001, 6006):
            # Open UDP socket remotely
            remote_socket.interfaces.socket.start_server(port=port_number, connections=10)
            # Open UDP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()

            wifi_dut.interfaces.wifi.bind(sock, device_ip, port_number)
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket, server_port=port_number)
            time.sleep(2)
            send_response = wifi_dut.interfaces.wifi.send(sock, send_bytes)
            logger().info(f'SEND-RESPONSE = {send_response}')
            socket_id_value.add(sock)

        for port_number in range(6007, 6012):
            # Open UDP socket remotely
            remote_socket.interfaces.socket.start_server(socket_type=1)
            # Open UDP socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_udp_client_socket()

            wifi_dut.interfaces.wifi.bind(sock, device_ip, port_number)
            wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket, server_port=port_number)
            socket_id_value.add(sock)

        logger().info(f'Socket values = {socket_id_value}')
        for sock_value in socket_id_value:
            wifi_dut.interfaces.wifi.close_socket(sock_value)
            time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        # DHCP discovery, offer, request, ack packet
        packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                         f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        packet_filter5 = f'tcp.flags == 0x002 || (tcp.flags == 0x012) || tcp.flags == 0x010 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find DHCP discovery, offer, request, ack packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find Verify PS-Poll & PWMGT bit'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find TCP SYN ,SYN-ACK,ACK packets'
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.skip("Testcase not deployed")
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_5tcp_5udp_dut_server_socket_c19353(wifi_access_point, wifi_dut, remote_socket_factory, wifi_sniffer):
    try:
        capture_filename = "test_socket_c19353"
        validation = True
        socket_id_value = []
        server_port = 7001

        '''Verify 10 sockets functionality open 5TCP server +5UDP server sockets.'''
        wifi_dut.interfaces.wifi.set_socket_limit(10, 10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        client_socket = []
        server_port_base = 5001
        for count in range(0, 5):
            server_port = server_port_base + count
            # The below api opens ssl server socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
            wifi_dut.interfaces.wifi.listen(sock, backlog=0)
            time.sleep(3)
        for count in range(0, 5):
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            server_port = server_port_base + count
            result = ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.accept, count),
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
            sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
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

            wifi_dut.interfaces.wifi.send_to(sock, data_length, server_ip, server_port)

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || wlan.addr == ' \
                         f'{dut_mac_address})'
        # DHCP discovery, offer, request, ack packet
        packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                         f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
            'Unable to find Verify PS-Poll & PWMGT bit'
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
def test_socket_tcp_data_transfer_rejoin_c19354(wifi_sniffer, wifi_access_point, wifi_dut, switch):
    validation = True
    rejoin_value = 0
    send_bytes = 1460
    end_time_sec = 100
    tcp_socket_obj = IopTcpIpSockets()

    '''Verify TCP data transfer functionality while STA is in rejoin process(Send 10,000 packets from the module with
    size 1460)'''
    logger().info('******* Turn on Access point **********')
    switch.interfaces.pdu_switch.turn_on(delay=30)
    # wifi_access_point.interfaces.wifi.start_ap()

    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=4, beacon_missedcount=40,
                                        first_time_retry=0)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='tcp_data_transfer_c19354')
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(2)

        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || wlan.addr == ' \
                         f'{dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter3 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, device_ip)
        time.sleep(5)
        logger().info(f"Setting the tcp retry count for the socket_id->{tcp_socket_id} to {SocketOptions.TCP_MAX_RETRY}"
                      f" seconds")
        wifi_dut.interfaces.wifi.set_socket_option(tcp_socket_id, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)

        time.sleep(10)
        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            check_flag = False
            while sw.elapsed_sec < end_time_sec:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes, timeout=60)
                logger().info(f'SEND-RESPONSE = {send_response}')
                time.sleep(1)
                while sw.elapsed_sec < 30:
                    send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes, timeout=60)
                    logger().info(f'SEND-RESPONSE = {send_response}')
                    time.sleep(1)

                if check_flag is not True:
                    logger().info('***** Turn off Access point *****')
                    switch.interfaces.pdu_switch.turn_off(delay=20)
                    # wifi_access_point.interfaces.wifi.stop_ap()
                    # time.sleep(20)

                    logger().info('******* Turn on Access point **********')
                    switch.interfaces.pdu_switch.turn_on(delay=30)
                    # wifi_access_point.interfaces.wifi.start_ap()
                    # time.sleep(30)
                    check_flag = True

        time.sleep(5)
        logger().info("Stop sniffer capture")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find Verify PS-Poll & PWMGT bit'
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
        dut_clean_up(wifi_dut)


@pytest.mark.config("net_perf_client",
                    net_perf={"host_role": IperfConstants.SERVER_MODE, "mss_value": '1460', "tcp_window_size": '50k'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
def test_socket_tcp_data_transfer_mss_c19356(wifi_access_point, wifi_dut, wifi_client, net_perf_client,
                                             protocol):
    try:
        time_out = 650
        '''Verify TCP data transfer when remote peer Window size is less than MSS'''
        for i in range(1, 2):
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')

            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            time.sleep(2)

            device_ip = tx_rx().get_ip(wifi_dut)
            logger().info(f"DUT ip address: {device_ip}")

            host_ip = wifi_client.interfaces.wifi.get_ip_address()

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

            ''' Start Iperf traffic DUT as a client and Linux machine as a server'''
            wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out)
            wlan_obj.start()
            wlan_obj.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config("net_perf_client",
                    net_perf={"host_role": IperfConstants.SERVER_MODE, "mss_value": '1000', "tcp_window_size": '1460'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
def test_socket_tcp_data_transfer_mss_c19357(wifi_access_point, wifi_dut, wifi_client, net_perf_client,
                                             protocol):
    try:
        time_out = 10
        send_traffic = RunTraffic()
        '''Send TCP data size with more than MSS'''
        '''Note - Filed UTF JIRA'''
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(2)

        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        ''' Start Iperf traffic DUT as a client and Linux machine as a server'''
        events = wifi_dut.interfaces.wifi.get_async_events()

        with pytest.raises(WlanError) as exc_info:
            for event in events:
                send_traffic.start_iperf_dut_as_client(wifi_dut, net_perf_client, protocol, device_ip, host_ip,
                                                       time_out)
                if event.event_type == RS9116AsyncEventType.IPERF_SEND_TO:
                    iperf_send_fail = event.event_data
                    logger().info(f'\n\n IPERF = {iperf_send_fail}\n\n\n')
        assert exc_info.value.error_code == 0x005A, f"DUT send message is too long {0x005A}"
    finally:
        dut_clean_up(wifi_dut)


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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_socket_tcp_c19358(wifi_sniffer, wifi_dut, wifi_access_point):
    try:
        capture_filename = "test_http_socket_tcp_c19358"
        port_number = 80

        '''Try to open TCP server socket on port 80 when HTTP server is enabled'''
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        device_ip = tx_rx().get_ip(wifi_dut)
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        time.sleep(20)

        sock_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f'\n Socket id = {sock_id}\n')

        wifi_dut.interfaces.wifi.bind(sock_id, device_ip, port_number)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.listen(sock_id, 1)
        assert exc_info.value.error_code == 0xFFFFFFFF, f"DUT sent wrong error code. expected is {0xFFFFFFFF}"

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xFF81, f"DUT sent wrong error code. expected is {0xFF81}"
        logger().info(
            f"DUT sent error code -> {exc_info.value.error_code} which is expected when trying to open socket at "
            f"{port_number} port number when http server is enabled in the DUT")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.close_socket(sock_id)
        wifi_dut.interfaces.wifi.leave()
    finally:
        dut_clean_up(wifi_dut)


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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_https_socket_tcp_c71652(wifi_sniffer, wifi_dut, wifi_access_point):
    try:
        capture_filename = "test_https_socket_tcp_c19358"
        validation = True
        port_number = 443

        '''Try to open TCP server socket on port 443 when HTTPs server is enabled'''
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        device_ip = tx_rx().get_ip(wifi_dut)
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        time.sleep(20)

        sock_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f'\n Socket id = {sock_id}\n')

        wifi_dut.interfaces.wifi.bind(sock_id, device_ip, port_number)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.listen(sock_id, 1)
        assert exc_info.value.error_code == 0xFFFFFFFF, f"DUT sent wrong error code. expected is {0xFFFFFFFF}"

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xFF81, f"DUT sent wrong error code. expected is {0xFF81}"
        logger().info(
            f"DUT sent error code -> {exc_info.value.error_code} which is expected when trying to open socket at "
            f"{port_number} port number when http server is enabled in the DUT")

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        # DHCP discovery, offer, request, ack packet
        packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                         f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find DHCP discovery, offer, request, ack packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find Verify PS-Poll & PWMGT bit'

        wifi_dut.interfaces.wifi.close_socket(sock_id)
        wifi_dut.interfaces.wifi.leave()
    finally:
        dut_clean_up(wifi_dut)


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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_socket_limit_c19359(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket):
    try:
        capture_filename = "test_socket_limit_c19359"
        validation = True
        port_number = 5002
        device_port = 5001

        '''Open more than one socket when only one socket is selected in opermode command.'''
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f'Device IP = {device_ip}')

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        time.sleep(20)
        remote_socket.interfaces.socket.start_server(port=device_port)
        time.sleep(3)
        # Open TCP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f'Socket_id = {sock}')
        wifi_dut.interfaces.wifi.bind(sock, device_ip, device_port)
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket, server_port=device_port)
        wifi_dut.interfaces.wifi.send_data_pkts(sock, 10, 10)

        sock_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f'Socket_id = {sock_id}')
        wifi_dut.interfaces.wifi.bind(sock_id, device_ip, port_number)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.connect_to_server(sock_id, remote_socket.interfaces.socket,
                                                       server_port=port_number)
        assert exc_info.value.error_code == 0xFF80, f"DUT sent wrong error code. expected is {0xFF80}"
        logger().info(f'\n\n DUT is able to return 0xff80 while connecting to the 2nd TCP server socket.\n\n')

        wifi_dut.interfaces.wifi.close_socket(sock)
        wifi_dut.interfaces.wifi.close_socket(sock_id)

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter3 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find Verify PS-Poll & PWMGT bit'

        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"decryption_key : {decryption_key}")
        logger().info("DHCP decryption is in progress...this may take some time")
        dhcp_list = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
        logger().info(f"dhcp_list : {dhcp_list}")
        assert dhcp_list, "DHCP packets not found"
        wifi_dut.interfaces.wifi.leave()
    finally:
        dut_clean_up(wifi_dut)


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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("test_run_time", [60])
def test_wifi_tcp_data_receive_check_c19360(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point,
                                            test_run_time):
    try:
        # The test case checks data receive functionality over tcp socket
        capture_filename = "test_wifi_tcp_data_receive_check_TC19360"
        join_obj = tx_rx()

        dut_mac_address = join_obj.join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        server_port = remote_socket.interfaces.socket.server_port
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket, server_port=server_port)

        tx_buffer = "12345678901234567890123456789012345678901234567890"
        buffer_length = len(tx_buffer)
        sw = Stopwatch()
        iteration_count = 1
        while sw.elapsed_sec < test_run_time:
            logger().info(f"######################Iteration count {iteration_count}######################")
            # send 50 bytes of data from tcp server opened remotely
            remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)
            # DUT receives data over tcp socket after execution of below api
            try:
                buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock,
                                                                                    data_len=buffer_length)
            except:
                logger().info(
                    "resetting the DUT as receive API is a blocking call. SAPI driver is in the blocking mode")
                wifi_dut.interfaces.wifi.reset()
                assert 0, "DUT is not able to receive data over TCP socket"
            iteration_count = iteration_count + 1

        assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
        assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
        logger().info("contents of data sent and receive are matched")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket in the dut"
        remote_socket.interfaces.socket.socket_close_indication(1)
        logger().info("Successfully closed opened socket in the DUT")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")
        wifi_dut.interfaces.wifi.leave()
    finally:
        dut_clean_up(wifi_dut)


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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("test_run_time", [60])
# The test case checks data receive functionality over udp socket
@pytest.mark.skip()
def test_wifi_udp_receive_c19361(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, test_run_time):
    try:
        capture_filename = "test_wifi_udp_receive_TC19361"
        join_obj = tx_rx()
        dut_mac_address = join_obj.join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        logger().info("Starting udp socket remotely at port number 5001")
        remote_socket.interfaces.socket.start_server(socket_type=1)
        # Open UDP socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
        assert sock == 0, "socket id received is not matched. Expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        tx_buffer = "12345678901234567890123456789012345678901234567890"
        buffer_length = len(tx_buffer)
        # send 50 bytes of data from udp socket opened remotely
        remote_socket.interfaces.socket.send_data_udp(tx_buffer, device_ip, port=5001)
        try:
            buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length,
                                                                                timeout=50)
            assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
            assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
        except:
            logger().info("resetting the DUT as receive API is a blocking call. SAPI driver is in the blocking mode")
            wifi_dut.interfaces.wifi.reset()
            assert 0, "DUT is not able to receive data over UDP socket"

        logger().info("contents of data sent and receive are matched")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close udp socket opened in the dut"

        logger().info("Successfully closed opened socket in the DUT")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")
        wifi_dut.interfaces.wifi.leave()
    finally:
        dut_clean_up(wifi_dut)


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
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_tcp_remote_terminate_c19362(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point):
    try:
        capture_filename = "test_wifi_tcp_remote_terminate_TC19362"
        validation = True
        join_obj = tx_rx()

        dut_mac_address = join_obj.join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # tcp socket opened in DUT connects to the tcp server
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = randint(5001, 50000)
        execute_command = ['iperf', '-s', '-i 1', '-p', str(server_port)]
        iperf_process = SubprocessManager(execute_command)
        iperf_process.start()
        # DUT opens tcp client sockets
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

        wifi_dut.interfaces.wifi.connect(sock, server_ip, server_port)
        data_length = 1460
        no_of_pkts = 1000
        bytes_triggered = (data_length * no_of_pkts)
        # DUT sends 50 bytes of data over tcp socket
        wifi_dut.interfaces.wifi.send_data_pkts(sock, data_length, no_of_pkts)
        time.sleep(3)
        iperf_process.stop()
        time.sleep(1)
        events = wifi_dut.interfaces.wifi.get_async_events()
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

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")
        wifi_dut.interfaces.wifi.leave()
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.skip("Testcase not deployed")
@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
def test_socket_verify_data_transfer_with_attenuator_c19363(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client,
                                                            net_perf_client, protocol, rf_attenuator):
    try:
        validation = True
        time_out = 300
        att_channel = 1

        '''Verify data transfer, auto rate and handling of Buffer Full and Buffer empty by STAUT when RSSI value of AP is
         ~ -30dbm to -90dbm'''
        '''Note - Current attenuator does not support over 60DBM attenuation, so I comment out the 70 to 90 dbm limit'''

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='tcp_data_transfer_attenuator_c19363')

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(2)

        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip address: {host_ip}")

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # DHCP discovery, offer, request, ack packet
        packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                         f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        # Verify TCP SYN ,SYN-ACK,ACK packets
        packet_filter5 = f'tcp.flags == 0x002 || (tcp.flags == 0x012) || tcp.flags == 0x010 && (wlan.addr == ' \
                         f'{ap_bssid} || wlan.addr == {dut_mac_address})'

        time.sleep(10)

        ''' Start Iperf traffic DUT as a client and Linux machine as a server'''
        wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out)
        '''  Change the attenuation value by 10 step '''
        attenuator_obj = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 30)
        attenuator_obj1 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 40)
        attenuator_obj2 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 50)
        attenuator_obj3 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 60)
        # attenuator_obj4 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 70)
        # attenuator_obj5 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 80)
        # attenuator_obj6 = AttenuatorValuesVariation(wifi_dut, rf_attenuator, att_channel, 90)

        wlan_obj.start()
        time.sleep(10)
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
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
            'Unable to find Verify PS-Poll & PWMGT bit'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find TCP SYN ,SYN-ACK,ACK packets'
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.skip("Testcase not deployed")
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
        "server_socket_limit": 10,
        "client_socket_limit": 10,
    }
)
def test_tcp_socket_max_limit_c19364(wifi_sniffer, wifi_access_point, wifi_dut, remote_socket, remote_socket_factory):
    try:
        validation = True
        capture_filename = "test_socket_max_limit_C19364"

        '''Open TCP severs socket more than maximum and connect TCP clients'''

        remote_socket.interfaces.socket.time_limit = 3600
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(2)

        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        server_port_base = 5001
        for count in range(0, 10):
            server_port = server_port_base + count
            logger().info(f'Server port = {server_port}')
            # The below api opens ssl server socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
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
            wifi_dut.interfaces.wifi.listen(sock, backlog=0)
            time.sleep(3)
        client_socket = []
        for count in range(0, 10):
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            result = ThreadBase.call_functions_simultaneously(
                [
                    (wifi_dut.interfaces.wifi.accept, count),
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

        # Probe req & response packet
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                         f'{dut_mac_address} || wlan.addr == {ap_bssid})'
        # Association req & response packet & EAPOL 4 way handshake packet
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                         f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # DHCP discovery, offer, request, ack packet
        packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                         f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
        # Verify PS-Poll & PWMGT bit
        packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                         f'wlan.addr == {dut_mac_address})'
        # Verify TCP SYN ,SYN-ACK,ACK packets
        packet_filter5 = f'tcp.flags == 0x002 || (tcp.flags == 0x012) || tcp.flags == 0x010 && (wlan.addr == {ap_bssid} ' \
                         f'|| wlan.addr == {dut_mac_address})'

        logger().info(f'\n\n Trying to open 11th socket\n')

        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, 7002)
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.listen(sock, 1)
        assert exc_info.value.error_code == 0xFFFFFFFF, f"DUT sent wrong error code. expected is {0xFFFFFFFF}"
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.wlan_get_status()
        assert exc_info.value.error_code == 0xFF81, f"DUT sent wrong error code. expected is {0xFF81}"
        logger().info(
            f"DUT sent error code -> {exc_info.value.error_code} which is expected when trying to open socket at "
            f"443 port number when https server is enabled in the DUT")

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Probe req & response packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find DHCP discovery, offer, request, ack packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
            'Unable to find Verify PS-Poll & PWMGT bit'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)['packet_count'], \
            'Unable to find TCP SYN ,SYN-ACK,ACK packets'
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
def test_tcp_udp_socket_data_transfer_tx_c19365(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, net_perf_client,
                                                protocol):
    try:
        device_port = 5201
        iperf_execution_time = 650
        pkt_length = 1460
        no_of_pkts = 100
        '''Verify TCP ,UDP data transfer and reception of STAUT in WPA-TKIP mode'''
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='tcp_data_transfer_c19365')
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(2)
        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        ''' Start Iperf traffic RASPI as a server & DUT as a client'''
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                        device_ip=device_ip, protocol=protocol,
                                                        time_out=iperf_execution_time + 5)
        net_perf_client.interfaces.net_perf.start()
        # Open TCP/UDP client socket at DUT side
        if protocol == 'TCP':
            logger().info(f'\n\n Open {protocol} socket at DUT side \n')
            sock_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        else:
            logger().info(f'\n\n Open {protocol} socket at DUT side \n')
            sock_id = wifi_dut.interfaces.wifi.open_udp_client_socket()

        wifi_dut.interfaces.wifi.bind(sock_id, device_ip, device_port)
        wifi_dut.interfaces.wifi.connect_to_server(sock_id, host_ip, server_port=device_port)

        sw = Stopwatch()
        bytes_triggered = 0
        while sw.elapsed_sec < iperf_execution_time:
            logger().info(f'sw.elapsed_sec = {sw.elapsed_sec}, iperf_execution_time ={iperf_execution_time}')
            tx_bytes = wifi_dut.interfaces.wifi.send_data_pkts(sock_id, pkt_length, no_of_pkts,
                                                               timeout=iperf_execution_time)
            bytes_triggered += tx_bytes

        time.sleep(10)
        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None
        if tp is not None:
            print_dict("##     ", tp)

        events = wifi_dut.interfaces.wifi.get_async_events()
        remote_terminate = False
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
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
def test_tcp_tx_rx_8_high_performance_socket_c19366(wifi_sniffer, wifi_access_point, wifi_dut, remote_socket,
                                                    remote_socket_factory):
    validation = True
    capture_filename = "test_high_performance_socket_c19366"

    '''Verify TCP tx and Rx by opening 8 TCP high performance socket'''

    remote_socket.interfaces.socket.time_limit = 3600
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    result = wifi_dut.interfaces.wifi.start_ip()
    device_ip = result.ip.decode()
    logger().info(f"DUT ip address: {device_ip}")

    wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=8, tcp_rx_high_performance_sockets=1)

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    server_port_base = 5001
    for count in range(0, 8):
        server_port = server_port_base + count
        logger().info(f'Server port = {server_port}')
        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        ''' As per test case requirement need to pass TCP high performance socket value '''
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET,
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

        # Socket binds at (device_ip, server_port) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
        wifi_dut.interfaces.wifi.listen(sock, backlog=1)
    client_socket = []
    for count in range(0, 8):
        client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
        result = ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.accept, count),
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

    # Probe req & response packet
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004 || wlan.fc.type_subtype == 0x0005) && (wlan.addr == ' \
                     f'{dut_mac_address} || wlan.addr == {ap_bssid})'
    # Association req & response packet & EAPOL 4 way handshake packet
    packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1) || ' \
                     f'(wlan_rsna_eapol.keydes.key_info.key_type == 1) && (wlan.addr == {ap_bssid} || ' \
                     f'wlan.addr == {dut_mac_address})'
    # DHCP discovery, offer, request, ack packet
    packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                     f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
    # Verify PS-Poll & PWMGT bit
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                     f'wlan.addr == {dut_mac_address})'
    # Verify TCP SYN ,SYN-ACK,ACK packets
    packet_filter5 = f'tcp.flags == 0x002 || (tcp.flags == 0x012) || tcp.flags == 0x010 && (wlan.addr == ' \
                     f'{ap_bssid} || wlan.addr == {dut_mac_address})'

    logger().info(f'\n\n Trying to open 11th socket\n')

    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    logger().info(f"socket id received is {sock} which is expected")
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 7002)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.listen(sock, 1)
    assert exc_info.value.error_code == 0xFFFFFFFF, f"DUT sent wrong error code. expected is {0xFFFFFFFF}"
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.wlan_get_status()
    assert exc_info.value.error_code == 0xFF81, f"DUT sent wrong error code. expected is {0xFF81}"
    logger().info(f"DUT sent error code -> {exc_info.value.error_code} which is expected when trying to open "
                  f"socket at 7002 port number in the DUT")

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find Probe req & response packet'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
        'Unable to find Association req & response packet & EAPOL 4 way handshake packet'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
        'Unable to find DHCP discovery, offer, request, ack packet'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count'], \
        'Unable to find Verify PS-Poll & PWMGT bit'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)['packet_count'], \
        'Unable to find TCP SYN ,SYN-ACK,ACK packets'


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
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
    }
)
def test_tcp_socket_windows_size7_c19367(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point):
    test_run_time = 120
    capture_filename = "test_size7_c19367"
    total_window_size = 1460 * 7
    local_port = 5001
    validation = True

    '''Open ltcp socket with window size 7 in socket create command'''
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    result = wifi_dut.interfaces.wifi.start_ip()
    device_ip = result.ip.decode()
    logger().info(f"DUT ip address: {device_ip}")

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, tcp_rx_high_performance_sockets=1,
                                           tcp_rx_only_sockets=1, tcp_rx_window_size_cap=7, tcp_rx_window_div_factor=7)

    logger().info("Starting tcp server remotely at port number 5001")
    socket_id = remote_socket.interfaces.socket.start_server()
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    logger().info(f"socket id received is {sock} which is expected")

    ''' As per test case requirement need to pass TCP high performance socket value '''
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_HIGH_PERFORMANCE_SOCKET,
                                               SocketOptions.high_performance_socket)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)

    tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
    buffer_length = len(tx_buffer)
    sw = Stopwatch()
    iteration_count = 1
    while sw.elapsed_sec < test_run_time:
        logger().info(f"######################Iteration count {iteration_count}######################")
        # send 50 bytes of data from tcp server opened remotely
        remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)
        # DUT receives data over tcp socket after execution of below api
        try:
            buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length)
        except:
            logger().info("resetting the DUT as receive API is a blocking call. SAPI driver is in the blocking mode")
            wifi_dut.interfaces.wifi.reset()
            assert 0, "DUT is not able to receive data over TCP socket"
        iteration_count = iteration_count + 1

    assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
    assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
    logger().info("contents of data sent and receive are matched")
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket in the dut"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger().info("Successfully closed opened socket in the DUT")

    packet_filter1 = f'(wlan.addr == {dut_mac_address} && tcp.flags == 0x002 && tcp.window_size_value == {total_window_size})'

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'DUT unable to send TCP sync ack with window size 7'

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower |
                               RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_tcp_udp_socket_data_transfer_rx_c71653(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory):
    """Verify TCP ,UDP data reception of STAUT in WPA-TKIP mode"""
    try:
        capture_filename = "test_c71653"
        test_run_time = 5
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        time.sleep(2)

        device_ip = tx_rx().get_ip(wifi_dut)
        logger().info(f"DUT ip address: {device_ip}")

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        device_port = randint(5001, 5010)
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        # The below api opens ssl server socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, device_port)
        wifi_dut.interfaces.wifi.listen(sock, backlog=0)
        time.sleep(3)
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        result = ThreadBase.call_functions_simultaneously(
            [(wifi_dut.interfaces.wifi.accept, sock),
             (client_socket.connect_client_tcp, device_ip, device_port)], timeout=30)
        socket_id = result[0]
        logger().info(f'Socket id = {socket_id}')
        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
        buffer_length = len(tx_buffer)
        logger().info(f'\n Buffer Length = {buffer_length}\n')
        sw = Stopwatch()
        iteration_count = 1
        while sw.elapsed_sec < test_run_time:
            logger().info(f"######################Iteration count {iteration_count}######################")
            # send 50 bytes of data from tcp server opened remotely
            client_socket.send_data_tcp(tx_buffer)
            # DUT receives data over tcp socket after execution of below api
            wifi_dut.interfaces.wifi.receive_from(socket_id=sock + 1, data_len=buffer_length)
            iteration_count = iteration_count + 1
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        dut_clean_up(wifi_dut)


