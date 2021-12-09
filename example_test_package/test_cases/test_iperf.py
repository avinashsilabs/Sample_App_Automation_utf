from utils.iperf.Iperf_constants import IperfConstants
import pytest
from utils.logger import get_logger


def logger():
    return get_logger(__name__)

@pytest.mark.parametrize('run_iperf', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }], indirect=['run_iperf'])
def test_device_as_tcp_server(run_iperf):
    logger().info("test_device_as_tcp_server completed !!")
    assert run_iperf.iper_process_success


@pytest.mark.parametrize('run_iperf', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }], indirect=['run_iperf'])
def test_device_as_udp_server(run_iperf):
    logger().info("test_device_as_udp_server completed !!")
    assert run_iperf.iper_process_success

@pytest.mark.parametrize('run_iperf', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }], indirect=['run_iperf'])
def test_host_as_tcp_server(run_iperf):
    logger().info("test_host_as_tcp_server completed !!")
    assert run_iperf.iper_process_success


@pytest.mark.parametrize('run_iperf', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }], indirect=['run_iperf'])
def test_host_as_udp_server(run_iperf):
    logger().info("test_host_as_udp_server completed !!")
    assert run_iperf.iper_process_success
