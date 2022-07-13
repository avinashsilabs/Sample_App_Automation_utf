import random

import pytest

from utf.utils.thread_base import ThreadBase
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP
from utf_wiseconnect.devices.rs911x import DeviceConstants, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap
from contextlib import ExitStack

pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.dut("rs9116_sapi"),
    pytest.mark.wifi_access_point("raspi_wifi")
]

class ServerSocketXferThread(ThreadBase):
    def __init__(self, wifi_dut, dut_socket, server_socket, num_packets, num_bytes):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.dut_socket = dut_socket
        self.server_socket = server_socket
        self.num_packets = num_packets
        self.num_bytes = num_bytes

    def run(self):
        # socket opened in DUT connects to the server
        self.wifi_dut.interfaces.wifi.connect_to_server(
            self.dut_socket, self.server_socket
        )
        for _ in range(0, self.num_packets):
            # DUT sends num_bytes bytes of data over socket
            self.wifi_dut.interfaces.wifi.send(
                self.dut_socket, self.num_bytes, timeout=3
            )

        # DUT closes the client socket
        result = self.wifi_dut.interfaces.wifi.close_socket(self.dut_socket)
        assert b"success" in result, "unable to close opened socket"

        self.server_socket.socket_close_indication(1)


def test_socket_factory_tcp_server(
    wifi_networked_dut, wifi_access_point, remote_socket_factory, logger
):
    s1 = remote_socket_factory.interfaces.socket.create_socket()
    s1.start_server(port=5000, socket_type=SOCKET_TYPE_TCP)

    sock = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
    device_ip = wifi_networked_dut.interfaces.wifi.ip.ip.decode(
        DeviceConstants.ENCODING
    )
    wifi_networked_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    # tcp socket opened in DUT connects to the tcp server
    wifi_networked_dut.interfaces.wifi.connect_to_server(sock, s1)
    # DUT sends 50 bytes of data over tcp socket
    wifi_networked_dut.interfaces.wifi.send(sock, 50)
    # DUT closes the tcp socket
    result = wifi_networked_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket"
    s1.socket_close_indication(1)


@pytest.mark.parametrize("num_sockets", 3)
def test_multiple_sockets_tcp_server(
    wifi_networked_dut, wifi_access_point, remote_socket_factory, num_sockets, logger
):

    device_ip = wifi_networked_dut.interfaces.wifi.ip.ip.decode(
        DeviceConstants.ENCODING
    )
    threads = []
    start_port = 5000
    for i in range(0, num_sockets):
        port = start_port + i
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket.start_server(port=port, socket_type=SOCKET_TYPE_TCP)
        dut_socket = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
        wifi_networked_dut.interfaces.wifi.bind(dut_socket, device_ip, port)
        num_packets = 5
        num_bytes = 50
        socket_thread = ServerSocketXferThread(
            wifi_networked_dut, dut_socket, server_socket, num_packets, num_bytes
        )
        threads.append(socket_thread)

    # start all threads and wait for exit
    with ExitStack() as thread_stack:
        for thread in threads:
            thread_stack.enter_context(thread)


class ClientSocketXferThread(ThreadBase):
    def __init__(
        self,
        wifi_dut,
        dut_socket,
        client_socket,
        device_ip,
        device_port,
        num_packets,
        num_bytes,
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.dut_socket = dut_socket
        self.client_socket = client_socket
        self.device_ip = device_ip
        self.device_port = device_port
        self.num_packets = num_packets
        self.num_bytes = num_bytes

    def run(self):
        # simultaneously call connect on the client and accept on the server
        # server_socket is return from the "accept" call
        results = ThreadBase.call_functions_simultaneously(
            [
                (self.wifi_dut.interfaces.wifi.accept, self.dut_socket),
                (
                    self.client_socket.connect_client_tcp,
                    self.device_ip,
                    self.device_port,
                ),
            ],
            timeout=10,
        )
        server_socket = results[0]
        self.logger.info(f"server socket: {server_socket}")
        for _ in range(0, self.num_packets):
            data = bytes([random.randint(0, 255) for _ in range(0, self.num_bytes)])
            self.client_socket.send_data_tcp(data)
            receive_response = self.wifi_dut.interfaces.wifi.receive(
                server_socket, 1024
            )
            self.logger.info(f"receive_response : {receive_response}")

        self.wifi_dut.interfaces.wifi.close_socket(server_socket)
        self.wifi_dut.interfaces.wifi.close_socket(self.dut_socket)


@pytest.mark.parametrize("num_sockets", 1)
@pytest.mark.config(
          "wifi_dut",
          wifi={
              "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.TCP_IP_TOTAL_SOCKETS(10),
              "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10)
          },
      )
def test_multiple_sockets_tcp_client(
    wifi_networked_dut, wifi_access_point, remote_socket_factory, num_sockets, logger
):

    device_ip = wifi_networked_dut.interfaces.wifi.ip.ip.decode(
        DeviceConstants.ENCODING
    )
    threads = []
    start_port = 5000
    for i in range(0, num_sockets):
        port = start_port + i
        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        dut_socket = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
        wifi_networked_dut.interfaces.wifi.bind(dut_socket, device_ip, port)
        wifi_networked_dut.interfaces.wifi.listen(dut_socket)

        num_packets = 5
        num_bytes = 50
        socket_thread = ClientSocketXferThread(
            wifi_networked_dut,
            dut_socket,
            client_socket,
            device_ip,
            port,
            num_packets,
            num_bytes,
        )
        threads.append(socket_thread)

    # start all threads and wait for exit
    with ExitStack() as thread_stack:
        for thread in threads:
            thread_stack.enter_context(thread)
