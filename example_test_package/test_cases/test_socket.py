from utf_wiseconnect.devices.rs911x import DeviceConstants


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
