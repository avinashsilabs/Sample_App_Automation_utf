from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band
from utf.interfaces.iperf.iperf_constants import IperfConstants
import pytest
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
import time


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        # "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36,
        "set_send_feature_frame": True,
        "rf_type": 0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36}
)
@pytest.mark.parametrize("channel", [36])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_device_as_server_ap_tcp_rx_c20725(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    ping_count = 10
    logger().info(f"********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_server_ap_tcp_rx')
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    status = ping(device_ip, ping_count)
    assert status == True, f"Ping failed"

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip), f"ping failed"

    iter_count = 3
    for i in range(0, iter_count):
        # preparing iperf
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

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
                time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
            # start iperf
            net_perf_client.interfaces.net_perf.start()
            # capture device output
            wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, 'Unable to retrieve the Throughput information'
        __print_throughput(tp)

    wifi_client.interfaces.wifi.leave()
    logger().info("******* Initiating disconnection from STA(Raspberry pi)*******")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("******* Sniffer capture stopped*******")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        # "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36,
        "set_send_feature_frame": True,
        "rf_type": 0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36}
)
@pytest.mark.parametrize("channel", [36])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_device_as_server_ap_udp_rx_c20723(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    ping_count = 10
    logger().info(f"********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_device_as_server_ap_udp_rx')
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    status = ping(device_ip, ping_count)
    assert status == True, f"Ping failed"

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip), f"ping failed"

    iter_count = 3
    for i in range(0, iter_count):
        # preparing iperf
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

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
                time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
            # start iperf
            net_perf_client.interfaces.net_perf.start()
            # capture device output
            wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, 'Unable to retrieve the Throughput information'
        __print_throughput(tp)

    wifi_client.interfaces.wifi.leave()
    logger().info("******* Initiating disconnection from STA(Raspberry pi)*******")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("******* Sniffer capture stopped*******")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        # "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36,
        "set_send_feature_frame": True,
        "rf_type": 0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36}
)
@pytest.mark.parametrize("channel", [36])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_host_as_server_ap_tcp_tx_c20724(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    ping_count = 10
    logger().info(f"********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_host_as_server_ap_tcp_tx')
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    status = ping(device_ip, ping_count)
    assert status == True, f"Ping failed"

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip), f"ping failed"

    iter_count = 3
    for i in range(0, iter_count):
        # starting iperf
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()

        # open socket and send traffic
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, 'Unable to retrieve the Throughput information'
        __print_throughput(tp)

    wifi_client.interfaces.wifi.leave()
    logger().info("******* Initiating disconnection from STA(Raspberry pi)*******")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("******* Sniffer capture stopped*******")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        # "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36,
        "set_send_feature_frame": True,
        "rf_type": 0,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36}
)
@pytest.mark.parametrize("channel", [36])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
def test_host_as_server_ap_udp_tx_c20722(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    ping_count = 10
    logger().info(f"********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_host_as_server_ap_udp_tx')
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    status = ping(device_ip, ping_count)
    assert status == True, f"Ping failed"

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip), f"ping failed"

    iter_count = 3
    for i in range(0, iter_count):
        # starting iperf
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()

        # open socket and send traffic
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, 'Unable to retrieve the Throughput information'
        __print_throughput(tp)

    wifi_client.interfaces.wifi.leave()
    logger().info("******* Initiating disconnection from STA(Raspberry pi)*******")

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("******* Sniffer capture stopped*******")
