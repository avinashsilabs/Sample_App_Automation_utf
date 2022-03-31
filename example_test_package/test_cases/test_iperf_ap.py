from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band
from utf.interfaces.iperf.iperf_constants import IperfConstants
import pytest
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
import time


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_device_as_server_ap(net_perf_client, wifi_dut, wifi_client, protocol):
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

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
    assert tp is not None
    __print_throughput(tp)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678", "channel": 36}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_host_as_server_ap(net_perf_client, wifi_dut, wifi_client, protocol):
    wifi_dut.interfaces.wifi.start_ap()
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

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
    assert tp is not None
    __print_throughput(tp)

@pytest.mark.config("wifi_dut", wifi={"oper_mode": RS9116OperatingMode.AccessPoint})
@pytest.mark.config("net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}} })
@pytest.mark.config("secondary_net_perf_client", net_perf={"device": {"TCP": {"port": 5201,"data_len": 1460},"UDP": {"port": 5202, "data_len": 1460}}})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP,IperfConstants.UDP])
def test_device_as_ap_with_two_sta_connected_primary_raspi_as_server(net_perf_client, secondary_net_perf_client, wifi_dut, wifi_clients, protocol):
    host_ips = []
    wifi_dut.interfaces.wifi.start_ap()

    # connecting raspi to dut access point
    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.join()
        time.sleep(0.5)
        assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 0.1
        )
        host_ips.extend([wifi_client.interfaces.wifi.client_ip_address])

    # preparing iperf server with primary raspi
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ips[0], device_ip=host_ips[1], protocol=protocol, host_role=IperfConstants.SERVER_MODE)
    net_perf_client.interfaces.net_perf.start()
    time.sleep(2)

    # preparing iperf client with secondary raspi
    secondary_net_perf_client.interfaces.net_perf.init_client(host_ip=host_ips[1], device_ip=host_ips[0], protocol=protocol, host_role=IperfConstants.CLIENT_MODE)
    secondary_net_perf_client.interfaces.net_perf.start()
    
    #waiting till time out for iperf client send data to iperf server
    time.sleep(net_perf_client.interfaces.net_perf.client_timeout)
    tp_server = net_perf_client.interfaces.net_perf.process_output()
    secondary_net_perf_client.interfaces.net_perf.clean_files()
    assert tp_server is not None
    __print_throughput(tp_server)

@pytest.mark.config("wifi_dut", wifi={"oper_mode": RS9116OperatingMode.AccessPoint})
@pytest.mark.config("secondary_net_perf_client", net_perf={"host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}} })
@pytest.mark.config("net_perf_client", net_perf={"device": {"TCP": {"port": 5201,"data_len": 1460},"UDP": {"port": 5202, "data_len": 1460}}})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
def test_device_as_ap_with_two_sta_connected_secondary_raspi_as_server(net_perf_client, secondary_net_perf_client, wifi_dut, wifi_clients, protocol):
    host_ips = []
    wifi_dut.interfaces.wifi.start_ap()

    # connecting raspi to dut access point
    for wifi_client in wifi_clients:
        wifi_client.interfaces.wifi.join()
        time.sleep(0.5)
        assert (
            wifi_client.interfaces.wifi.ping(
                server_ip=wifi_client.interfaces.wifi.client_gateway_ip
            )
            < 0.1
        )
        host_ips.extend([wifi_client.interfaces.wifi.client_ip_address])

    # preparing iperf server with secpndary raspi
    secondary_net_perf_client.interfaces.net_perf.init_server(host_ip=host_ips[1], device_ip=host_ips[0], protocol=protocol, host_role=IperfConstants.SERVER_MODE)
    secondary_net_perf_client.interfaces.net_perf.start()
    time.sleep(2)

    # preparing iperf client with primary raspi
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ips[0], device_ip=host_ips[1], protocol=protocol, host_role=IperfConstants.CLIENT_MODE)
    net_perf_client.interfaces.net_perf.start()
    
    #waiting till time out for iperf client send data to iperf server
    time.sleep(secondary_net_perf_client.interfaces.net_perf.client_timeout)
    tp_server = secondary_net_perf_client.interfaces.net_perf.process_output()
    net_perf_client.interfaces.net_perf.clean_files()
    assert tp_server is not None
    __print_throughput(tp_server)

