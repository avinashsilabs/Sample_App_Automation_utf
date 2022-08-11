# Test author: Vinod.G
# Test suite: TCP/UDP test suite
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, \
    RS9116AsyncEventType, SocketOptions, RS9116PowerSaveProcedureTypes, RS9116CustomFeatureBitMap, SocketType
from utf.utils.subprocess_manager import SubprocessManager
from threading import Thread
import time
from random import randint
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch
import threading
import string
import random


def logger():
    return get_logger(__name__)

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket 
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

pytestmark = [
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
    ]


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
        self.iperf_obj.start_iperf_dut_as_client(self.wifi_dut, self.net_perf_client, self.protocol, self.device_ip, self.host_ip, self.time_out)


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


class AccessPointOnOff(ThreadBase):
    def __init__(self, wifi_access_point, switch):
        super().__init__()
        self.wifi_access_point = wifi_access_point
        self.switch = switch

    def run(self):
        logger().info('******* Turn off the AP radio **********')
        self.switch.interfaces.pdu_switch.turn_off()
        time.sleep(60)
        logger().info('******* Turn on the AP radio **********')
        self.switch.interfaces.pdu_switch.turn_on()


class tx_rx:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def receive_data_socket(self, remote_socket, logger, no_of_pkts, data_size, proto_type=0):
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
        logger.info(f"Total bytes received on socket opened remotely -> {self.rcv_data}")

    def send_data(self, remote_socket, logger, data_size, test_run_time=300, proto_type=0, server_ip=None,
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
        logger.info(f"Total bytes sent on socket opened remotely -> {self.sent_data}")


def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(wait_time)
    logger.info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    logger.info("Wait for 5 seconds")
    time.sleep(5)
    logger.info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()


def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    logger.info("Start the sniffer")
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
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
    if join_fail:
        logger.info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"
    for count in range(1, 3):
        ip_fail = 1
        try:
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            logger.info("DUT gets ipaddress through DHCP ")
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("number_of_pkts", [10000])
# The test case checks tcp close functionality
def test_wifi_tcp_close_TC19347(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, logger, number_of_pkts,
                                ):
    capture_filename = "test_wifi_tcp_close_TC19347"
    data_size = 1460
    remote_socket.interfaces.socket.time_limit = 1800
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    logger.info("Starting tcp server remotely at port number 5001")
    remote_socket.interfaces.socket.start_server()
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    logger.info(f"socket id received is {sock} which is expected")
    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # tcp socket opened in DUT connects to the tcp server
    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    tx_rx_obj = tx_rx()
    th_start = Thread(target=tx_rx_obj.receive_data_socket,
                      args=(remote_socket, logger, number_of_pkts, data_size, 0), daemon=True)
    th_start.start()
    bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts)
    logger.info(f"Number of bytes sent by dut {bytes_sent}")
    th_start.join(5)
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger.info("Successfully closed opened socket in the DUT")
    wifi_dut.interfaces.wifi.leave()
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("test_run_time", [60])
# The test case checks data receive functionality over tcp socket
def test_wifi_tcp_data_receive_check_TC19360(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, logger,
                                             test_run_time):
    capture_filename = "test_wifi_tcp_data_receive_check_TC19360"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    logger.info("Starting tcp server remotely at port number 5001")
    remote_socket.interfaces.socket.start_server()
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    logger.info(f"socket id received is {sock} which is expected")
    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)

    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    sw = Stopwatch()
    iteration_count = 1
    while sw.elapsed_sec < test_run_time:
        logger.info(f"######################Iteration count {iteration_count}######################")
        # send 50 bytes of data from tcp server opened remotely
        remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)
        # DUT receives data over tcp socket after execution of below api
        try:
            buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length)
        except:
            logger.info("resetting the DUT as receive API is a blocking call. SAPI driver is in the blocking mode")
            wifi_dut.interfaces.wifi.reset()
            assert 0, "DUT is not able to receive data over TCP socket"
        iteration_count = iteration_count + 1

    assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
    assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
    logger.info("contents of data sent and receive are matched")
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket in the dut"
    remote_socket.interfaces.socket.socket_close_indication(1)
    logger.info("Successfully closed opened socket in the DUT")
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("number_of_pkts", [10000])
# The test case checks udp socket close functionality
def test_wifi_udp_close_TC19348(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, logger, number_of_pkts):
    capture_filename = "test_wifi_udp_close_TC19348"
    data_size = 1460
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    logger.info("Starting udp socket remotely at port number 5001")
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
    assert sock == 0, "socket id received is not matched. Expected is 0"
    logger.info(f"socket id received is {sock} which is expected")
    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    tx_rx_obj = tx_rx()
    th_start = Thread(target=tx_rx_obj.receive_data_socket,
                      args=(remote_socket, logger, number_of_pkts, data_size, 1), )
    th_start.start()
    server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
    server_port = remote_socket.interfaces.socket.server_port
    bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(sock, data_size, number_of_pkts,
                                                         server_ip=server_ip, server_port=server_port)
    logger.info(f"Number of bytes sent by dut {bytes_sent}")
    th_start.join(5)
    # DUT closes the socket.socket id is mentioned in sock variable
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "Unable to close the udp socket"

    logger.info("Successfully closed opened socket in the DUT")
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("test_run_time", [60])
# The test case checks data receive functionality over udp socket
@pytest.mark.skip()
def test_wifi_udp_receive_TC19361(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, logger,test_run_time):
    capture_filename = "test_wifi_udp_receive_TC19361"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    logger.info("Starting udp socket remotely at port number 5001")
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    logger.info(f"socket id received is {sock} which is expected")
    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    # send 50 bytes of data from udp socket opened remotely
    remote_socket.interfaces.socket.send_data_udp(tx_buffer, device_ip, port=5001)
    try:
        buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length, timeout=50)
        assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
        assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
    except:
        logger.info("resetting the DUT as receive API is a blocking call. SAPI driver is in the blocking mode")
        wifi_dut.interfaces.wifi.reset()
        assert 0, "DUT is not able to receive data over UDP socket"

    logger.info("contents of data sent and receive are matched")
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close udp socket opened in the dut"

    logger.info("Successfully closed opened socket in the DUT")
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_tcp_remote_terminate_TC19362(wifi_sniffer, remote_socket, wifi_dut, wifi_access_point, logger):
    capture_filename = "test_wifi_tcp_remote_terminate_TC19362"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
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
    logger.info(f"socket id received is {sock} which is expected")
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
    logger.info("Remote terminate event is received by DUT when tcp socket connected is closed")
    socket_id = int(remote_terminate.split(b",")[1].split(b":")[1])
    bytes_sent = int(remote_terminate.split(b",")[2].split(b":")[1])
    logger.info(f"Number of bytes sent on socket {socket_id}->  {bytes_sent}")
    assert bytes_triggered == bytes_sent, f"Number of bytes triggered by host and actually sent by dut  are not " \
                                          f"matched. triggered {bytes_triggered} bytes, But actually sent {bytes_sent} bytes "
    logger.info("Number of bytes triggered by host and actually sent by dut are matched")

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


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
def test_socket_tcp_data_transfer_rejoin_c19354(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, net_perf_client,
                                                protocol, switch):
    validation = True
    time_out = 240

    '''Verify TCP data transfer functionality while STA is in rejoin process(Send 10,000 packets from the module with 
    size 1460)'''
    logger().info(f'Check PDU state = {pdu_state}')
    state = wifi_access_point.interfaces.wifi.switch.get_state()
    logger().info("pdu switch state : " + str(state))
    if state == 'true':
        logger().info('PDU is ready for use')
    else:
        logger().info(f'\n\n Please check the AP & PDU current state')
        assert False


    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='tcp_data_transfer_c19354')
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    time.sleep(2)

    result = wifi_dut.interfaces.wifi.start_ip()
    device_ip = result.ip.decode()
    logger().info(f"DUT ip address: {device_ip}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()

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
    # DHCP discovery, offer, request, ack packet
    packet_filter3 = f'((((dhcp.option.dhcp == 5)) || (dhcp.option.dhcp == 1)) || (dhcp.option.dhcp == 2)) || ' \
                     f'(dhcp.option.dhcp == 3) && (wlan.addr == {ap_bssid} || wlan.addr == {dut_mac_address})'
    # Verify PS-Poll & PWMGT bit
    packet_filter4 = f'wlan.fc.type_subtype == 0x001a && wlan.fc.pwrmgt == 1 && (wlan.addr == {ap_bssid} || ' \
                     f'wlan.addr == {dut_mac_address})'

    time.sleep(10)

    ''' Start Iperf traffic DUT as a client and Linux machine as a server'''
    wlan_obj = WifiJoinThread(wifi_dut, net_perf_client, protocol, device_ip, host_ip, time_out)
    '''  Turn off and turn on the AP '''
    ap_obj = AccessPointOnOff(wifi_access_point, switch)

    wlan_obj.start()
    time.sleep(5)
    ap_obj.start()
    ap_obj.wait_for_exit()
    wlan_obj.wait_for_exit()

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