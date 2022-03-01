from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import pytest
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.logger import get_logger
import time


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_device_as_server(
    net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol
):
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    # # preparing iperf
    net_perf_client.interfaces.net_perf.init_client(
        device_ip=device_ip, protocol=protocol
    )

    # verifying host_ip
    wifi_dut.interfaces.wifi.ping(
        server_ip=str(net_perf_client.interfaces.net_perf.host_ip)
    )

    # creating results object for sharing between host and dut
    result = Result(net_perf_client.interfaces.net_perf.protocol)

    # open socket and start listening
    with wifi_dut.interfaces.wifi.start_socket_reader(
        log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
        result=result,
        protocol=net_perf_client.interfaces.net_perf.protocol,
        port=net_perf_client.interfaces.net_perf.client_port,
        device_ip=device_ip,
        data_len=net_perf_client.interfaces.net_perf.client_data_len,
        time=net_perf_client.interfaces.net_perf.client_timeout,
    ) as obj:
        # start iperf
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(
            obj, net_perf_client.interfaces.net_perf.client_timeout
        )

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)


@pytest.mark.net_perf_client("static_iperf")
@pytest.mark.config(
    "net_perf_client",
    net_perf={
        "host_role": IperfConstants.SERVER_MODE,
        "tos_value": IperfTrafficType.Video,
    },
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_host_as_server(net_perf_client, wifi_access_point, wifi_dut, protocol):
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    # preparing iperf
    net_perf_client.interfaces.net_perf.init_server(
        device_ip=device_ip, protocol=protocol
    )
    # verifying host_ip
    wifi_dut.interfaces.wifi.ping(
        server_ip=str(net_perf_client.interfaces.net_perf.host_ip)
    )
    # starting iperf
    net_perf_client.interfaces.net_perf.start()
    time.sleep(2)
    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        net_perf_client.interfaces.net_perf.host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)
