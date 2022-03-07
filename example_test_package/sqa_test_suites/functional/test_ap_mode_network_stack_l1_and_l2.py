import pytest
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.logger import get_logger

def logger():
    return get_logger(__name__)

def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [36])
def test_TCP_Tx_data_on_remote_peer_C19462(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Tx_data_on_remote_peer_C19462')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # preparing iperf
    logger().info("******* preparing iperf ********")
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    logger().info("******* creating results object for sharing between host and dut ********")
    result = Result(net_perf_client.interfaces.net_perf.protocol)

    # open socket and start listening
    logger().info("******* open socket and start listening ********")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        logger().info("******* start iperf ********")
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        logger().info("******* capture device output ********")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    # get and print throughput
    logger().info("******* get and print throughput ********")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_client.interfaces.wifi.leave()
    logger().info("******* TCP remote terminated *******")
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [36])
def test_TCP_Rx_C19464(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Rx_C19464')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # starting iperf
    logger().info("****** starting iperf ******")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    logger().info("****** open socket and send traffic ******")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    # get and print throughput
    logger().info("****** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [36])
def test_UDP_Tx_data_on_Remote_peer_C19463(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Tx_data_on_Remote_peer_C19463')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # preparing iperf
    logger().info("****** preparing iperf ******")
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

    # creating results object for sharing between host and dut
    logger().info("****** creating results object for sharing between host and dut ******")
    result = Result(net_perf_client.interfaces.net_perf.protocol)

    # open socket and start listening
    logger().info("****** open socket and start listening ******")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        logger().info("****** start iperf ******")
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        logger().info("****** capture device output ******")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

    # get and print throughput
    logger().info("****** get and print throughput ******")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "band": RS9116Band.FiveGHz,
        "security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [36])
def test_UDP_Rx_data_C19465(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    mode = 'static'
    ip_address = '192.168.100.76'
    subnet = '255.255.255.0'
    gateway = '192.168.100.76'
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Rx_data_C19465')
    logger().info("********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(
        "This command is added to terminate existing wlan0 if it is already there. If it is not there it will throw warning please ignore below error")
    wifi_client.interfaces.wifi.join()
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()

    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

    # starting iperf
    logger().info("********** starting iperf ********")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic
    logger().info("********** open socket and send traffic ********")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    # get and print throughput
    logger().info("********** get and print throughput ********")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
