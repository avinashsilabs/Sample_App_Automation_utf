import threading

from interfaces.iperf.iperf_constants import IperfConstants
import pytest

from interfaces.iperf.iperf_device_output_parser import Result
from utils.iperf.iperf_utils import print_dict


prefix = "##     "


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict(prefix, iperf_throughput)


@pytest.mark.parametrize('iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}},
     {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}},
                                        ], indirect=['iperf1'])
def test_device_as_server(iperf1, wifi_access_point, wifi_dut, wifi_client, logger):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    iperf1.init_client(host_ip=host_ip, device_ip=device_ip)

    result = Result(iperf1.protocol)

    time = iperf1.client_options["time"]
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=iperf1.device_log_file_handle,
            result=result,
            protocol=iperf1.protocol,
            port=iperf1.client_options[iperf1.protocol]["port"],
            device_ip=device_ip,
            data_len=iperf1.client_options[iperf1.protocol]["data_len"],
            time=time) as obj:
        iperf1.start()
        if obj["listener"] is not None:
            obj["listener"].read_from_device(obj["socket_id"], time)

    tp = iperf1.process_output(result)
    __print_throughput(tp)


@pytest.mark.parametrize('iperf1', [{IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}},
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}},
                                        ], indirect=['iperf1'])
def test_host_as_server(iperf1, wifi_access_point, wifi_dut, wifi_client, logger):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    iperf1.init_server(host_ip=host_ip, device_ip=device_ip)
    iperf1.start()

    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        iperf1.server_options[iperf1.protocol]["port"],
        iperf1.protocol,
        iperf1.client_options,
    )

    tp = iperf1.process_output()
    __print_throughput(tp)
