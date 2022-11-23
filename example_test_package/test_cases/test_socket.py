import pytest

from utf_wiseconnect.devices.rs911x import DeviceConstants, RS9116OperatingMode, RS9116Band


def test_socket(wifi_networked_dut, remote_socket, logger):
    device_ip = wifi_networked_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    remote_socket.interfaces.socket.start_server()

    sock = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()

    assert sock == 0, f"socket id received is wrong, expected is 0"

    wifi_networked_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    wifi_networked_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    wifi_networked_dut.interfaces.wifi.send(sock, 50)

    wifi_networked_dut.interfaces.wifi.close_socket(sock)
    remote_socket.interfaces.socket.socket_close_indication(1)
    wifi_networked_dut.interfaces.wifi.leave()


def test_wifi_tcp_recv_data(wifi_dut, wifi_access_point, remote_socket, logger):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    # Open tcp socket in remote device(Raspberry pi or static device)
    remote_socket.interfaces.socket.start_server(port=5000)
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5000)
    # tcp socket opened in DUT connects to the tcp server

    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    # DUT sends 20 bytes of data over tcp socket
    data_len = 20
    wifi_dut.interfaces.wifi.send(sock, data_len)

    logger.info("Start receiving the packets...")
    data = remote_socket.interfaces.socket.recv_data_tcp(data_len)

    logger.info(f"{data}")
    assert data is not None
    assert len(data) == data_len

    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.remote_socket("raspi_ip_socket")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.Default,
        "security": "WPA",
        "ssid": "Test_Socket_DUT_AP",
        "passphrase": "12345678",
        "channel": 1,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA",
        "ssid": "Test_Socket_DUT_AP",
        "passphrase": "12345678",
        "channel": 1,
        "interface": "wlan0"
    },
)
@pytest.mark.config(
    "remote_socket",
    socket={
        "interface": "wlan0"
    },
)
def test_wifi_tcp_recv_data_dut_ap(wifi_dut, wifi_client, remote_socket, logger):
    wifi_dut.interfaces.wifi.start_ap()
    # DUT connects to AP after join_ap API is executed
    wifi_client.interfaces.wifi.join()

    device_ip = wifi_client.interfaces.wifi.client_gateway_ip

    assert (wifi_client.interfaces.wifi.ping(server_ip=device_ip)< 0.1)

    # Open tcp socket in remote device(Raspberry pi or static device)
    remote_socket.interfaces.socket.start_server(port=5000)
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5000)
    # tcp socket opened in DUT connects to the tcp server

    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    # DUT sends 20 bytes of data over tcp socket
    data_len = 20
    wifi_dut.interfaces.wifi.send(sock, data_len)

    logger.info("Start receiving the packets...")
    data = remote_socket.interfaces.socket.recv_data_tcp(data_len)

    logger.info(f"{data}")
    assert data is not None
    assert len(data) == data_len

    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)