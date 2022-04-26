import pytest
import time
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116FeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap,RS9116CoexMode)
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.logger import get_logger

"""Test Author = Rakesh Nayini

        1. DUT in AP Mode
        2. Required A7 EVK(DUT) board     
        3. Start the sniffer before connection
        4. Stop the sniffer
        5. Initiate ping from the dut
        6. Analyizing all sniffer capture packets and find the arp announcement packet

setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
"""


def logger():
    return get_logger(__name__)


# Configure below time parameter to run the test case for specific time lapse # below is the 30 mins given as default
logger().info("configure the time lapse to run the test case...")
time_lapse = 30


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


# Configuring static IP to DUT
mode = 'static'
ip_address = '192.168.100.76'
subnet = '255.255.255.0'
gateway = '192.168.100.76'


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "IperfConstants.TCP"])
def test_TCP_Tx_data_C19462(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    time.sleep(5)
    logger().info(f"********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(f"******* start capturing with Sniffer by giving the test case name as filename *******")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Tx_data_C19462')
    logger().info(f"********** DUT works as a Ap mode *********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    wifi_client.interfaces.wifi.join()
    logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    assert wifi_client.interfaces.wifi.ping(device_ip), f"Client failed to ping DUT"
    logger().info("***** starting iperf *****")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()
    logger().info(f"***** open socket and send traffic *****")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("***** get and print throughput *****")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_client.interfaces.wifi.leave()
    logger().info("******* wifi client remote terminated *******")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "IperfConstants.UDP"])
def test_UDP_Tx_data_C19463(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    time.sleep(5)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Tx_data_C19463')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    wifi_client.interfaces.wifi.join()
    logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    assert wifi_client.interfaces.wifi.ping(device_ip), f"Client failed to ping DUT"
    logger().info("***** starting iperf *****")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()
    logger().info("***** open socket and send traffic *****")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info("***** get and print throughput *****")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_client.interfaces.wifi.leave()
    logger().info("******* wifi client remote terminated *******")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "IperfConstants.TCP"])
def test_TCP_Rx_data_C19464(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                            wifi_access_point):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Rx_data_C19464')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    wifi_client.interfaces.wifi.join()
    logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    assert wifi_client.interfaces.wifi.ping(device_ip), f"Client failed to ping DUT"
    logger().info("***** preparing iperf *****")
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    logger().info("***** creating results object for sharing between host and dut *****")
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info("***** open socket and start listening *****")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info("***** start iperf *****")
        net_perf_client.interfaces.net_perf.start()
        logger().info("***** capture device output *****")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    logger().info("***** get and print throughput *****")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_client.interfaces.wifi.leave()
    logger().info("******* wifi client remote terminated *******")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )
    time.sleep(2)

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "IperfConstants.UDP"])
def test_UDP_Rx_data_C19465(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Rx_data_C19465')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    wifi_client.interfaces.wifi.join()
    logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    assert wifi_client.interfaces.wifi.ping(device_ip), f"Client failed to ping DUT"
    logger().info("***** preparing iperf *****")
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    logger().info("***** creating results object for sharing between host and dut *****")
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info("***** open socket and start listening *****")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info("***** start iperf *****")
        net_perf_client.interfaces.net_perf.start()
        logger().info("***** capture device output *****")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    logger().info("***** get and print throughput *****")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_client.interfaces.wifi.leave()
    logger().info("******* wifi client remote terminated *******")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "IperfConstants.TCP"])
def test_host_as_server_ap_TCP_C19480(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_host_as_server_ap_TCP_C19480')
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    wifi_client.interfaces.wifi.join()
    logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    assert wifi_client.interfaces.wifi.ping(device_ip), f"Client failed to ping DUT"
    t_end = time.time() + 60 * time_lapse
    while time.time() < t_end:
        logger().info("***** starting iperf *****")
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("***** open socket and send traffic *****")
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )
        logger().info("***** get and print throughput *****")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None
        __print_throughput(tp)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info("Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_client.interfaces.wifi.leave()
    logger().info("******* Remote terminated *******")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"}
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "IperfConstants.UDP"])
def test_host_as_server_ap_UDP_C19481(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_host_as_server_ap_UDP_C19481')
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********")
    wifi_client.interfaces.wifi.join()
    logger().info(f"******** Wi-Fi client join with AP(DUT) ********")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    assert wifi_client.interfaces.wifi.ping(device_ip), f"Client failed to ping DUT"
    t_end = time.time() + 60 * time_lapse
    while time.time() < t_end:
        logger().info("***** starting iperf *****")
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("***** open socket and send traffic *****")
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
        )
        logger().info("***** get and print throughput *****")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None
        __print_throughput(tp)
    wifi_client.interfaces.wifi.leave()
    logger().info("******* Remote terminated *******")
    time.sleep(2)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info("Validate Probe req(Broadcast/Unicast), authentication ,association, eapol")
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )

