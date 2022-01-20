import pytest as pytest

from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.iperf import iperf_utils
from interfaces.iperf.Iperf_constants import IperfConstants
from utils.logger import get_logger
from utils.subprocess_manager import SubprocessManager


def logger():
    return get_logger(__name__)


@pytest.mark.skip
def test_sapi_socket(wifi_networked_dut):
    if isinstance(wifi_networked_dut.interfaces.wifi, RSSAPICommands):
        tcp_socket_id = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f"tcp_socket_id : {tcp_socket_id}")

        bind_response = wifi_networked_dut.interfaces.wifi.bind(1234,
                                                                iperf_utils.get_device_ip(
                                                                    wifi_networked_dut.interfaces.wifi.ip,
                                                                    IperfConstants.SAPI), tcp_socket_id)
        logger().info(f"bind_response: {bind_response}")

        SubprocessManager.simple_execute("iperf -s -p 5001")
        connect_response = wifi_networked_dut.interfaces.wifi.connect(socket_id=tcp_socket_id,
                                                                      server_ip=iperf_utils.get_host_ip(),
                                                                      server_port=5001)
        logger().info(f"connect_response: {connect_response}")

        send_response = wifi_networked_dut.interfaces.wifi.send(tcp_socket_id, 1024)
        logger().info(f"send_response: {send_response}")

        send_to_response = wifi_networked_dut.interfaces.wifi.send_to(tcp_socket_id, 1024, iperf_utils.get_host_ip(),
                                                                      5001)
        logger().info(f"send_to_response: {send_to_response}")

        close_response = wifi_networked_dut.interfaces.wifi.close_socket(tcp_socket_id)
        logger().info(f"close_tcp_socket_response: {close_response}")

        udp_socket_id = wifi_networked_dut.interfaces.wifi.open_udp_client_socket()
        logger().info(f"udp_socket_id: {udp_socket_id}")

        close_response = wifi_networked_dut.interfaces.wifi.close_socket(udp_socket_id)
        logger().info(f"close_udp_socket_response: {close_response}")

        tcp_socket_id = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f"tcp_socket_id : {tcp_socket_id}")

        bind_response = wifi_networked_dut.interfaces.wifi.bind(1234,
                                                                iperf_utils.get_device_ip(
                                                                    wifi_networked_dut.interfaces.wifi.ip,
                                                                    IperfConstants.SAPI), tcp_socket_id)
        logger().info(f"bind_response: {bind_response}")

        listen_response = wifi_networked_dut.interfaces.wifi.listen(tcp_socket_id)
        logger().info(f"listen_response : {listen_response}")
        device_ip = iperf_utils.get_device_ip(wifi_networked_dut.interfaces.wifi.ip, IperfConstants.SAPI)

        SubprocessManager.simple_execute(f"iperf -c {device_ip} -p 5001")

        new_socket = wifi_networked_dut.interfaces.wifi.accept(tcp_socket_id)
        logger().info(f"accept_response : {new_socket}")

        receive_response = wifi_networked_dut.interfaces.wifi.receive(new_socket, 1024)
        logger().info(f"receive_response : {receive_response}")


@pytest.mark.skip
def test_at_socket(wifi_networked_dut):
    if isinstance(wifi_networked_dut.interfaces.wifi, RSSAPICommands):
        socket_id = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket(server_ip='192.168.0.132',
                                                                              server_port=5001,
                                                                              local_port=1235)
        wifi_networked_dut.interfaces.wifi.open_udp_client_socket(server_ip='192.168.0.132',
                                                                  server_port=5002,
                                                                  local_port=1234)
        logger().info(f"AT: socketID: {socket_id}")
