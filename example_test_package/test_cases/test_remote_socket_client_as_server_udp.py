import random
import string
import time

import pytest

from utf.interfaces.socket.ip_remote_socket import RemoteSocket
from utf.utils import get_random_data
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import (
    DeviceConstants,
    RS9116OperatingMode,
    RS9116Band,
)

from utf.interfaces.socket import SOCKET_TYPE_UDP


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.Default,
        "security": "WPA",
        "ssid": "Test_Socket_DUT_AP_1",
        "passphrase": "12345678",
        "channel": 2,
    },
)
@pytest.mark.config(
    "wifi_clients",
    linux_shell={
        0: {"type": "shell.shell"},
        1: {
            "type": "shell.ssh_shell",
            "remote": "10.207.16.93",
            "username": "pi",
            "password": "raspberry",
            "use_paramiko_expect": False,
        },
    },
    wifi={
        0: {
            "security": "WPA",
            "ssid": "Test_Socket_DUT_AP_1",
            "passphrase": "12345678",
            "channel": 2,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA",
            "ssid": "Test_Socket_DUT_AP_1",
            "passphrase": "12345678",
            "channel": 2,
            "interface": "wlan0",
        },
    },
)
@pytest.mark.config(
    "remote_socket",
    socket={"interface": "wlan0", "primary_interface": "wlan0"},
)
@pytest.mark.wifi_clients(["raspi_wifi", "raspi_wifi_ssh"])
@pytest.mark.remote_socket("raspi_ip_remote_socket")
def test_single_remote_wifi_client_as_server_dut_as_ap_udp(
    wifi_dut, wifi_clients, remote_socket, logger
):
    wifi_dut.interfaces.wifi.start_ap()

    wifi_client_ip_list = []
    device_ip = ""
    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.join()
        if device_ip == "":
            device_ip = wifi_client.interfaces.wifi.client_gateway_ip
        wifi_client_ip_list.append(wifi_client.interfaces.wifi.get_ip_address())
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 5

    logger.info(f"Wifi Client IP List: {wifi_client_ip_list}")
    remote_socket.interfaces.socket.start_server(
        server_ip=wifi_client_ip_list[1], port=5000, socket_type=SOCKET_TYPE_UDP
    )
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5000)

    data_sent = get_random_data(20)
    data_len = len(data_sent)

    wifi_dut.interfaces.wifi.send_to(sock, data_len, wifi_client_ip_list[1], 5000)
    logger.info(f"Data sent from dut to client: {data_sent}")
    data_receive, address = remote_socket.interfaces.socket.recv_data_udp(data_len)
    logger.info(f"Data receieved from dut to client: {data_receive}")
    assert len(data_sent) == len(data_receive)

    data_sent = get_random_data(20)
    logger.info(f"Data sent from client to dut: {data_sent}")
    data_len = len(data_sent)

    remote_socket.interfaces.socket.send_data_udp(data_sent, device_ip, port=5000)
    recv_data_length, recv_data = wifi_dut.interfaces.wifi.receive_from(
        socket_id=sock, data_len=data_len
    )
    logger.info(f"Data recv from dut to client: {recv_data}")
    assert data_len == recv_data_length
    assert data_sent == recv_data.decode()

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result
    remote_socket.interfaces.socket.socket_close_indication(1)

    if isinstance(remote_socket.interfaces.socket, RemoteSocket):
        remote_socket.interfaces.socket.close_tunnel()

    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.Default,
        "security": "WPA",
        "ssid": "Test_Socket_DUT_AP_1",
        "passphrase": "12345678",
        "channel": 2,
        "server_socket_limit": 4,
        "client_socket_limit": 4,
    },
)
@pytest.mark.config(
    "wifi_clients",
    linux_shell={
        0: {"type": "shell.shell"},
        1: {
            "type": "shell.ssh_shell",
            "remote": "10.207.16.93",
            "username": "pi",
            "password": "raspberry",
            "use_paramiko_expect": False,
        },
    },
    wifi={
        0: {
            "security": "WPA",
            "ssid": "Test_Socket_DUT_AP_1",
            "passphrase": "12345678",
            "channel": 2,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA",
            "ssid": "Test_Socket_DUT_AP_1",
            "passphrase": "12345678",
            "channel": 2,
            "interface": "wlan0",
        },
    },
)
@pytest.mark.wifi_clients(["raspi_wifi", "raspi_wifi_ssh"])
@pytest.mark.config(
    "remote_socket_factory", socket={"remote_ip_list": ["10.207.16.93"]}
)
def test_multi_remote_wifi_client_as_server_dut_as_ap_udp(
    wifi_dut, wifi_clients, remote_socket_factory, logger
):
    socket_count = 2  # sockets to open on each wifi client
    wifi_dut.interfaces.wifi.start_ap()
    client_sockets = []
    client_ips = []
    device_ip = "169.0.0.0"

    for index, wifi_client in enumerate(wifi_clients):
        wifi_client.interfaces.wifi.join()
        device_ip = wifi_client.interfaces.wifi.client_gateway_ip
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 5
        for _ in range(0, socket_count):
            client_ips.append(host_ip)  # four hosts totally
            if index == 0:
                client_socket = remote_socket_factory.interfaces.socket.create_socket(
                    interface="wlan0"
                )
            else:
                client_socket = remote_socket_factory.interfaces.socket.create_socket(
                    interface="wlan0", remote_index=index - 1
                )
            client_sockets.append(client_socket)
    logger.info(f"Client IP address list: {client_ips}")

    server_base_port = 5001
    dut_sockets = []

    for index, client_socket in enumerate(client_sockets):
        server_port = server_base_port + index
        logger.info(f"Client socket: {client_socket}")
        client_socket.start_server(
            server_ip=client_ips[index], port=server_port, socket_type=SOCKET_TYPE_UDP
        )
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
        wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
        dut_sockets.append(sock)

    data_sent = []
    for _ in client_sockets:
        data_sent.append(get_random_data(20))

    results = ThreadBase.call_functions_simultaneously(
        [
            (
                wifi_dut.interfaces.wifi.send_to,
                dut_sockets[index],
                len(data),
                client_ips[index],
                server_base_port + index,
            )
            for index, data in enumerate(data_sent)
        ]
    )

    for index, client_socket in enumerate(client_sockets):
        logger.info(f"Data sent from dut to client: {data_sent[index]}")
        data_receive, address = client_socket.recv_data_udp(len(data_sent[index]))
        assert len(data_sent[index]) == len(data_receive)

    data_sent = []
    for _ in client_sockets:
        data_sent.append(get_random_data(20))

    results = ThreadBase.call_functions_simultaneously(
        [
            (
                client_socket.send_data_udp,
                data_sent[index],
                device_ip,
                server_base_port + index,
            )
            for index, client_socket in enumerate(client_sockets)
        ]
    )

    time.sleep(2)

    for index, client_socket in enumerate(client_sockets):
        logger.info(f"Data sent from client to dut: {data_sent[index]}")
        recv_data_length, recv_data = wifi_dut.interfaces.wifi.receive_from(
            socket_id=dut_sockets[index], data_len=len(data_sent[index])
        )
        logger.info(f"Data recv from client to dut: {recv_data}")
        assert len(data_sent[index]) == recv_data_length
        assert data_sent[index] == recv_data.decode()

    for index, client_socket in enumerate(client_sockets):
        result = wifi_dut.interfaces.wifi.close_socket(dut_sockets[index])
        logger.info("Closed socket in DUT")
        assert b"success" in result
        client_socket.socket_close_indication(1)
        if isinstance(client_socket, RemoteSocket):
            client_socket.close_tunnel()

    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.leave()


@pytest.mark.wifi_clients(["raspi_wifi", "raspi_wifi_ssh"])
@pytest.mark.config(
    "wifi_dut",
    wifi={"server_socket_limit": 4, "client_socket_limit": 4},
)
@pytest.mark.config(
    "wifi_clients",
    linux_shell={
        0: {"type": "shell.shell"},
        1: {
            "type": "shell.ssh_shell",
            "remote": "10.07.16.93",
            "username": "pi",
            "password": "raspberry",
            "use_paramiko_expect": False,
        },
    },
    wifi={0: {"interface": "wlan0"}, 1: {"interface": "wlan0"}},
)
@pytest.mark.config(
    "remote_socket_factory", socket={"remote_ip_list": ["10.207.16.93"]}
)
def test_multiple_remote_wifi_clients_as_server_dut_as_sta_udp(
    wifi_dut, wifi_access_point, wifi_clients, remote_socket_factory, logger
):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    client_ips = []
    client_sockets = []
    for index, wifi_client in enumerate(wifi_clients):
        if wifi_access_point != wifi_client:
            wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 5
        client_ips.append(host_ip)
        if index == 0:
            client_socket = remote_socket_factory.interfaces.socket.create_socket(
                interface="wlan0"
            )
        else:
            client_socket = remote_socket_factory.interfaces.socket.create_socket(
                interface="wlan0", remote_index=index - 1
            )
        client_sockets.append(client_socket)
    logger.info(f"Client IP address list: {client_ips}")

    server_base_port = 5001
    dut_sockets = []
    data_sent = []
    for index, client_socket in enumerate(client_sockets):
        client_ip = client_ips[index]
        server_port = server_base_port + index

        client_socket.start_server(server_ip=client_ip, port=server_port)
        time.sleep(2)
        sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
        dut_sockets.append(sock)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
        data_sent.append(get_random_data(20))

    results = ThreadBase.call_functions_simultaneously(
        [
            (wifi_dut.interfaces.wifi.send_data, dut_sockets[index], len(data), data)
            for index, data in enumerate(data_sent)
        ]
    )

    for index, client_socket in enumerate(client_sockets):
        data = data_sent[index]
        logger.info(f"Data sent to client {index} - {data}")
        data_recv = client_socket.recv_data_tcp(len(data))
        logger.info(f"Data received in client {index} - {data_recv}")
        assert data_recv == data

    for index, client_socket in enumerate(client_sockets):
        result = wifi_dut.interfaces.wifi.close_socket(dut_sockets[index])
        assert (
            b"success" in result
        ), f"unable to close opened tcp socket in the dut for socket_id -> {dut_sockets[index]}"
        logger.info(f"Successfully close socket_id -> {dut_sockets[index]}")
        client_socket.socket_close_indication(1)
        if isinstance(client_socket, RemoteSocket):
            client_socket.close_tunnel()

    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.leave()
