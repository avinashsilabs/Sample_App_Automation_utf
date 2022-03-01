# Test author: Vinod.G
# Test suite: TCP/UDP test suite
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, DeviceConstants, \
    RS9116AsyncEventType, SocketOptions
from utf.utils.subprocess_manager import SubprocessManager
from threading import Thread
import time
from random import randint

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
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "rejoin_max_retry": 10,
            "scan_interval": 6,
            "beacon_missed_count": 40,
            "first_time_retry": 0,
            }
        )
    ]


def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(wait_time)
    logger.info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    logger.info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks tcp close functionality
def test_wifi_tcp_close_TC3745(wifi_dut, wifi_access_point, remote_socket):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open tcp socket in remote device(Raspberry pi or static device)
    remote_socket.interfaces.socket.start_server()
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    # tcp socket opened in DUT connects to the tcp server
    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    # DUT sends 50 bytes of data over tcp socket
    wifi_dut.interfaces.wifi.send(sock, 50)
    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks data receive functionality over tcp socket
def test_wifi_tcp_data_receive_check_TC3758(wifi_dut, wifi_access_point, remote_socket):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    remote_socket.interfaces.socket.start_server()
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    # tcp socket opened in DUT connects to the tcp server
    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)

    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    # send 50 bytes of data from tcp server opened remotely
    remote_socket.interfaces.socket.send_data_tcp(tx_buffer)
    # DUT receives data over tcp socket after execution of below api
    buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length)
    assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
    assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket in the dut"
    remote_socket.interfaces.socket.socket_close_indication(1)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks udp socket close functionality
def test_wifi_udp_close_TC3746(wifi_dut, wifi_access_point, remote_socket):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open UDP socket remotely
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    # DUT binds to socket(device_ip, 5001)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    # DUT sends data over udp socket
    wifi_dut.interfaces.wifi.send_to(sock, 50, remote_socket.interfaces.socket.server_ip,
                                     remote_socket.interfaces.socket.server_port)
    # DUT closes the socket.socket id is mentioned in sock variable
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "Unable to close the udp socket"


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# The test case checks data receive functionality over udp socket
def test_wifi_udp_receive_TC3758(wifi_dut, wifi_access_point, remote_socket):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()

    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    # Open UDP socket remotely
    remote_socket.interfaces.socket.start_server(socket_type=1)
    # Open UDP socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    # DUT binds to socket(device_ip, 5001)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    # send 50 bytes of data from udp socket opened remotely
    remote_socket.interfaces.socket.send_data_udp(tx_buffer, device_ip, port=5001)
    # DUT receives data over udp socket after execution of below api
    buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length)
    assert buffer_length == buffer_length_rx, "buffer length sent and received is not matched"
    assert tx_buffer.encode() == buffer_rx, "contents of data sent and receive are not matched"
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close udp socket opened in the dut"


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_tcp_remote_terminate_TC3758(wifi_dut, wifi_access_point, remote_socket, logger):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
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
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)

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

    socket_id = int(remote_terminate.split(b",")[1].split(b":")[1])
    bytes_sent = int(remote_terminate.split(b",")[2].split(b":")[1])
    logger.info(f"Number of bytes sent on socket {socket_id}->  {bytes_sent}")
    assert bytes_triggered == bytes_sent, f"Number of bytes triggered and sent by dut are not matched. triggered {bytes_triggered} bytes, But actually sent {bytes_sent} bytes "


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_tcp_rejoin_TC3758(wifi_dut, wifi_access_point, remote_socket, logger):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
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

    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5001)

    wifi_dut.interfaces.wifi.connect(sock, server_ip, server_port)
    data_length = 1460
    no_of_pkts = 50000
    bytes_triggered = (data_length * no_of_pkts)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, data_length, no_of_pkts)
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 10, logger), )
    thread.start()
    time.sleep(5)
    iperf_process.stop()
    time.sleep(1)
    data_received = iperf_process.get_all_lines()

    receive_stats = 0
    for count in data_received:
        if "sec" in count:
            if ("Bytes" in count) and (not ("KBytes" in count)) and (not ("MBytes" in count)):
                receive_stats = receive_stats + (float(count.split("Bytes")[0].split("sec")[1].strip()))
            elif "KBytes" in count:
                receive_stats = receive_stats + (float(count.split("KBytes")[0].split("sec")[1].strip()) * 1024)
            elif "MBytes" in count:
                receive_stats = receive_stats + (float(count.split("MBytes")[0].split("sec")[1].strip()) * 1024 * 1024)
    logger.info(f"Bytes sent on the DUT -> {bytes_triggered}, received on remote tcp socket {receive_stats}")
