import random
import string
import pytest

from utf_wiseconnect.devices.rs911x import DeviceConstants


def test_wifi_remote_tcp_recv_data(wifi_dut, wifi_access_point, remote_socket, logger):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    logger.info(f"device_ip - {device_ip}")

    # Open tcp socket in remote device(Raspberry pi or static device)
    remote_socket.interfaces.socket.start_server(port=5000)
    # DUT opens tcp client socket
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5000)
    # tcp socket opened in DUT connects to the tcp server

    wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)

    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
    logger.info(f"data sent - {data_sent}")

    data_len = len(data_sent)
    wifi_dut.interfaces.wifi.send_data((sock), data_len, data_sent)

    logger.info("Start receiving the packets...")
    data = remote_socket.interfaces.socket.recv_data_tcp(data_len)

    logger.info(f"Received data - {data}")
    assert data is not None
    assert len(data) == data_len
    assert data_sent == data, "Data sent by DUT and received on remote peer is not matched"

    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    remote_socket.interfaces.socket.socket_close_indication(1)
