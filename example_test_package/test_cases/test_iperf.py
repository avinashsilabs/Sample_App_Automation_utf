from interfaces.iperf.iperf_constants import IperfConstants
import pytest
from interfaces.iperf.iperf_device_output_parser import Result
from utils.iperf.iperf_utils import print_dict


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


@pytest.mark.parametrize('iperf', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}},
     {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}},
                                        ], indirect=['iperf'])
def test_device_as_server(iperf, wifi_access_point, wifi_dut, wifi_client, logger):
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    # preparing wifi_client
    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # preparing iperf
    iperf.init_client(host_ip=host_ip, device_ip=device_ip)

    # creating results object for sharing between host and dut
    result = Result(iperf.protocol)

    # open socket and start listening
    time = iperf.client_options["time"]
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=iperf.device_log_file_handle,
            result=result,
            protocol=iperf.protocol,
            port=iperf.client_options[iperf.protocol]["port"],
            device_ip=device_ip,
            data_len=iperf.client_options[iperf.protocol]["data_len"],
            time=time) as obj:
        # start iperf
        iperf.start()
        # capture device output
        wifi_dut.interfaces.wifi.read_from_device(obj, time)

    # get and print throughput
    tp = iperf.process_output(result)
    assert tp is not None
    __print_throughput(tp)


@pytest.mark.skip
@pytest.mark.parametrize('iperf', [{IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}},
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}},
                                        ], indirect=['iperf'])
def test_host_as_server(iperf, wifi_access_point, wifi_dut, wifi_client, logger):
    # preparing wifi_dut
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    # preparing wifi_client
    if wifi_access_point != wifi_client:
        wifi_client.interfaces.wifi.join_ap(wifi_access_point)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # starting iperf
    iperf.init_server(host_ip=host_ip, device_ip=device_ip)
    iperf.start()

    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        iperf.server_options[iperf.protocol]["port"],
        iperf.protocol,
        iperf.client_options,
    )

    # get and print throughput
    tp = iperf.process_output()
    assert tp is not None
    __print_throughput(tp)
