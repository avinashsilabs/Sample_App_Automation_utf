import random
import string
import time

import pytest

from utf.utils import get_random_data
from utf.utils.thread_base import ThreadBase
from utf.interfaces.socket.ip_remote_socket import RemoteSocket
from utf_wiseconnect.devices.rs911x import DeviceConstants, RS9116OperatingMode, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116Band


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
    "wifi_clients",
    linux_shell={
        0: {
            "type": 'shell.shell'
        },
        1: {
            "type": 'shell.ssh_shell',
            "remote": "10.207.16.93",
            "username": "pi",
            "password": "raspberry",
            "use_paramiko_expect": False
        }
    },
    wifi={
        0: {
            "security": "WPA",
            "ssid": "Test_Socket_DUT_AP",
            "passphrase": "12345678",
            "channel": 1,
            "interface": "wlan0"
        },
        1: {
            "security": "WPA",
            "ssid": "Test_Socket_DUT_AP",
            "passphrase": "12345678",
            "channel": 1,
            "interface": "wlan0"
        }
    }
)
@pytest.mark.config(
    "remote_socket",
    socket={
        "interface": "wlan0",
        "primary_interface": "wlan0"
    },
)
@pytest.mark.wifi_clients(["raspi_wifi", "raspi_wifi_ssh"])
@pytest.mark.remote_socket("raspi_ip_remote_socket")
#https://jira.silabs.com/browse/UTF-1801
def test_single_remote_wifi_client_as_server_dut_as_ap(wifi_dut, wifi_clients, remote_socket, logger):
    """
    Illustrate the usage of sockets on a remote client (Raspberry) as server and dut as AP without standalone remote_socket fixture that works with single sockets
    """
    [primary_raspi_wifi_client, wifi_client] = wifi_clients
    wifi_dut.interfaces.wifi.start_ap()
    # DUT connects to AP after join_ap API is executed
    primary_raspi_wifi_client.interfaces.wifi.join()
    device_ip = primary_raspi_wifi_client.interfaces.wifi.client_gateway_ip

    wifi_client.interfaces.wifi.join()
    remote_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert (wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 5)

    # Open tcp socket in remote device(Raspberry pi or static device)
    remote_socket.interfaces.socket.start_server(server_ip=remote_ip, port=5000)
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


@pytest.mark.wifi_clients(["raspi_wifi", "raspi_wifi_ssh"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.Default,
        "security": "WPA",
        "ssid": "Test_Socket_DUT_AP1",
        "passphrase": "12345678",
        "channel": 1,
        "server_socket_limit": 4,
        "client_socket_limit": 4
    },
)
@pytest.mark.config(
    "wifi_clients",
    linux_shell={
        0: {
            "type": 'shell.shell'
        },
        1: {
            "type": 'shell.ssh_shell',
            "remote": "10.207.16.93",
            "username": "pi",
            "password": "raspberry",
            "use_paramiko_expect": False
        }
    },
    wifi={
        0: {
            "security": "WPA",
            "ssid": "Test_Socket_DUT_AP1",
            "passphrase": "12345678",
            "channel": 1,
            "interface": "wlan0"
        },
        1: {
            "security": "WPA",
            "ssid": "Test_Socket_DUT_AP1",
            "passphrase": "12345678",
            "channel": 1,
            "interface": "wlan0",
        }
    },
)
@pytest.mark.config(
    "remote_socket_factory",
    socket={
        "remote_ip_list": ['10.207.16.93']
    }
)
#https://jira.silabs.com/browse/UTF-1802
def test_multiple_remote_wifi_clients_as_server_dut_as_ap(wifi_dut, wifi_clients, remote_socket_factory, logger):
    """
    Illustrate the usage of sockets on local and remote client (Raspberry) as server and dut as AP with remote_socket_factory
    """
    device_ip="169.0.0.0"
    wifi_dut.interfaces.wifi.start_ap()

    client_ips = []
    client_sockets = []
    for index, wifi_client in enumerate(wifi_clients):
        wifi_client.interfaces.wifi.join()
        device_ip = wifi_client.interfaces.wifi.client_gateway_ip
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 5
        client_ips.append(host_ip)
        if index == 0:
            client_socket = remote_socket_factory.interfaces.socket.create_socket(interface="wlan0")
        else:
            client_socket = remote_socket_factory.interfaces.socket.create_socket(interface="wlan0", remote_index=index-1)
        client_sockets.append(client_socket)
    logger.info(f"Client IP address list: {client_ips}")

    server_base_port = 5001
    dut_sockets = []
    for index, client_socket in enumerate(client_sockets):
        client_ip = client_ips[index]
        server_port = server_base_port + index

        client_socket.start_server(server_ip=client_ip, port=server_port)
        time.sleep(2)
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        dut_sockets.append(sock)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
        time.sleep(2)
        wifi_dut.interfaces.wifi.connect_to_server(sock, client_ip, server_port=server_port)

    data_sent = [get_random_data(20), get_random_data(20)]

    results = ThreadBase.call_functions_simultaneously(
        [(wifi_dut.interfaces.wifi.send_data, dut_sockets[index], len(data), data) for index, data in enumerate(data_sent)]
    )

    for index, client_socket in enumerate(client_sockets):
        data = data_sent[index]
        logger.info(f"Data sent to client {index} - {data}")
        data_recv = client_socket.recv_data_tcp(len(data))
        logger.info(f"Data received in client {index} - {data_recv}")
        assert data_recv == data

    for index, client_socket in enumerate(client_sockets):
        result = wifi_dut.interfaces.wifi.close_socket(dut_sockets[index])
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id -> {dut_sockets[index]}"
        logger.info(f"Successfully close socket_id -> {dut_sockets[index]}")

    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.leave()


@pytest.mark.wifi_clients(["raspi_wifi", "raspi_wifi_ssh"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "server_socket_limit": 4,
        "client_socket_limit": 4
    },
)
@pytest.mark.config(
    "wifi_clients",
    linux_shell={
        0: {
            "type": 'shell.shell'
        },
        1: {
            "type": 'shell.ssh_shell',
            "remote": "10.07.16.93",
            "username": "pi",
            "password": "raspberry",
            "use_paramiko_expect": False
        }
    },
    wifi={
        0: {
            "interface": "wlan0"
        },
        1: {
            "interface": "wlan0"
        }
    },
)
@pytest.mark.config(
    "remote_socket_factory",
    socket={
        "remote_ip_list": ['10.207.16.93']
    }
)
def test_multiple_remote_wifi_clients_as_server_dut_as_sta(wifi_dut, wifi_access_point, wifi_clients, remote_socket_factory, logger):
    """
    Illustrate the usage of sockets on local and remote client (Raspberry) as server and dut as station with remote_socket_factory
    """
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
            client_socket = remote_socket_factory.interfaces.socket.create_socket(interface="wlan0")
        else:
            client_socket = remote_socket_factory.interfaces.socket.create_socket(interface="wlan0", remote_index=index-1)
        client_sockets.append(client_socket)
    logger.info(f"Client IP address list: {client_ips}")

    server_base_port = 5001
    dut_sockets = []
    for index, client_socket in enumerate(client_sockets):
        client_ip = client_ips[index]
        server_port = server_base_port + index

        client_socket.start_server(server_ip=client_ip, port=server_port)
        time.sleep(2)
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        dut_sockets.append(sock)
        wifi_dut.interfaces.wifi.bind(sock, device_ip, server_port)
        time.sleep(2)
        wifi_dut.interfaces.wifi.connect_to_server(sock, client_ip, server_port=server_port)

    data_sent = [get_random_data(20), get_random_data(20)]

    results = ThreadBase.call_functions_simultaneously(
        [(wifi_dut.interfaces.wifi.send_data, dut_sockets[index], len(data), data) for index, data in enumerate(data_sent)]
    )

    for index, client_socket in enumerate(client_sockets):
        data = data_sent[index]
        logger.info(f"Data sent to client {index} - {data}")
        data_recv = client_socket.recv_data_tcp(len(data))
        logger.info(f"Data received in client {index} - {data_recv}")
        assert data_recv == data

    for index, client_socket in enumerate(client_sockets):
        result = wifi_dut.interfaces.wifi.close_socket(dut_sockets[index])
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id -> {dut_sockets[index]}"
        logger.info(f"Successfully close socket_id -> {dut_sockets[index]}")

    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.leave()
