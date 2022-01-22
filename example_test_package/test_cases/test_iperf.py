from interfaces.iperf.iperf_constants import IperfConstants
import pytest
from utils.iperf.iperf_utils import print_dict


prefix = "##     "


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict(prefix, iperf_throughput)


@pytest.mark.parametrize('iperf', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}},
     {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}},
                                        ], indirect=['iperf'])
def test_device_as_server(iperf, wifi_access_point, wifi_dut, wifi_client, logger):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip()
    device_ip = result.ip.decode(IperfConstants.ENCODING)

    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    iperf_process = iperf.start(host_ip=host_ip, device_ip=device_ip, wifi_dut=wifi_dut)

    tp = iperf.get_metrics(iperf_process)
    logger.info(f"Throughput : {tp}")

    __print_throughput(iperf.iperf_throughput)
    logger.info("test_host_as_udp_server completed !!")


@pytest.mark.parametrize('iperf', [{IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}},
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}},
                                        ], indirect=['iperf'])
def test_host_as_server(iperf, wifi_access_point, wifi_dut, wifi_client, logger):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(result)

    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    iperf_process = iperf.start(host_ip=host_ip, device_ip=device_ip, wifi_dut=wifi_dut)

    protocol = iperf.server_options["protocol"]
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        iperf.server_options[protocol]["port"],
        protocol,
        iperf.client_options,
    )

    tp = iperf.get_metrics(iperf_process)
    logger.info(f"Throughput : {tp}")

    __print_throughput(iperf.iperf_throughput)
    logger.info("test_host_as_udp_server completed !!")
