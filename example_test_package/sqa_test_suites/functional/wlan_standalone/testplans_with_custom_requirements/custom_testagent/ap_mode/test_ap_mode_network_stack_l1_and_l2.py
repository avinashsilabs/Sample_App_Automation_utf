import time
from random import randint
from threading import Thread

import pytest
from retry import retry
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116FeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap, RS9116CoexMode,
    SocketType,
)

"""Test Author = Rakesh Nayini
    Reworked by CG, Rashmi & Team.

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


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


# Configuring static IP to DUT
mode = 'static'
static_ip = '192.168.100.76'
static_subnet = '255.255.255.0'
static_gateway = '192.168.100.76'


def run_iperf_dut_as_client(wifi_dut, net_perf_client, host_ip, dut_ip, protocol, iperf_time=60):
    ping_count = 5
    for count in range(3):
        try:
            logger().info("***** preparing iperf dut as client *****")
            net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, protocol=protocol,
                                                            time_out=iperf_time)
            logger().info("Verifying host connection")
            ping_from_client(dut_ip, ping_count)
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** open socket and send traffic *****")
            wifi_dut.interfaces.wifi.send_traffic_from_device(
                host_ip,
                dut_ip,
                net_perf_client.interfaces.net_perf.server_port,
                net_perf_client.interfaces.net_perf.protocol,
                net_perf_client.interfaces.net_perf.client_options,
            )
            logger().info("***** Adding 5 sec sleep before printing throughput *****")
            time.sleep(5)
            logger().info("***** get and print throughput *****")
            tp = net_perf_client.interfaces.net_perf.process_output()
            assert tp is not None, 'Unable to retrieve the Throughput information'
            __print_throughput(tp)
            net_perf_client.interfaces.net_perf.close_files()
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)
            break
        except:
            net_perf_client.interfaces.net_perf.close_files()
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)


def run_iperf_dut_as_server(wifi_dut, net_perf_client, host_ip, dut_ip, protocol, iperf_time=60):
    ping_count = 5
    for count in range(3):
        try:
            logger().info(f"***** preparing iperf dut as server *****")
            net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=dut_ip, protocol=protocol,
                                                            time_out=iperf_time)
            time.sleep(3)
            logger().info("***** creating results object for sharing between host and dut *****")
            result = Result(net_perf_client.interfaces.net_perf.protocol)
            time.sleep(3)
            logger().info("Verifying host connection")
            ping_from_client(dut_ip, ping_count)
            logger().info("***** open socket and start listening *****")
            with wifi_dut.interfaces.wifi.start_socket_reader(
                    log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
                    result=result,
                    protocol=net_perf_client.interfaces.net_perf.protocol,
                    port=net_perf_client.interfaces.net_perf.client_port,
                    device_ip=dut_ip,
                    data_len=net_perf_client.interfaces.net_perf.client_data_len,
                    time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
                logger().info("***** start iperf *****")
                net_perf_client.interfaces.net_perf.start()
                logger().info("***** capture device output *****")
                wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
            logger().info("***** Adding 5 sec sleep before printing throughput *****")
            time.sleep(5)
            logger().info("***** get and print throughput *****")
            tp = net_perf_client.interfaces.net_perf.process_output(result)
            assert tp is not None, 'Unable to retrieve Throughput '
            __print_throughput(tp)
            net_perf_client.interfaces.net_perf.close_files()
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)
            break
        except:
            net_perf_client.interfaces.net_perf.close_files()
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)


def run_tcp_traffic(wifi_dut, remote_socket, dut_ip):
    logger().info("Starting TCP server socket remotely")
    proto_type = "TCP"
    no_of_packets = 10000
    packet_length = 4
    local_port = randint(6000, 6100)

    remote_socket.interfaces.socket.interface = "wlan0"
    logger().info("Starting TCP Server socket at remote device")
    remote_socket.interfaces.socket.start_server(port=local_port)
    server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
    server_port = remote_socket.interfaces.socket.server_port

    logger().info("Opening TCP client socket in DUT")
    tcp_socket_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    logger().info(f"Socket open successfully : {tcp_socket_id}")
    time.sleep(5)

    logger().info("Binding TCP socket in DUT")
    bind_response = wifi_dut.interfaces.wifi.bind(tcp_socket_id, dut_ip, local_port)
    logger().info(f"Bind socket successfully: {bind_response}")

    logger().info("DUT is connecting to server socket")
    connect_status = False
    for count in range(3):
        try:
            wifi_dut.interfaces.wifi.connect_to_server(tcp_socket_id, remote_socket.interfaces.socket, server_port)
            connect_status = True
            break
        except:
            logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
            time.sleep(10)
    assert connect_status, "Socket connection failed in DUT"
    logger().info("Socket connection is successful")
    time.sleep(3)

    # Send and receive data.
    t1 = Thread(target=receive_data_socket, args=(remote_socket, no_of_packets, packet_length, proto_type), )
    for count in range(3):
        try:
            logger().info("Receiving TCP data from DUT")
            t1.start()
            time.sleep(2)
            logger().info("DUT Sending Data packets")
            bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(tcp_socket_id, pkt_length=packet_length,
                                                                 no_of_pkts=no_of_packets,
                                                                 server_ip=server_ip, server_port=server_port)
            logger().info(f"Number of bytes sent by dut {bytes_sent}")
            break
        except Exception as err:
            logger().info(f"Error is {err}")
            error_code = "0x9"
            if error_code in str(err):
                raise err
            logger().info(f"Unable to send data packets from DUT...retry:{count + 1}")
            t1.join()
            time.sleep(30)

    time.sleep(5)
    logger().info("Closing opened socket in DUT")
    try:
        result = wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        assert b"success" in result, "Unable to close the udp socket"
        logger().info("Socket closed successfully")
    except:
        logger().info("Unable to close the socket")
    t1.join()


def receive_data_socket(remote_socket, no_of_packets, packet_length, proto_type="TCP"):
    try:
        fail_count = 0
        rcv_data = 0
        if proto_type == "TCP":
            logger().info("Setting TCP socket receive timeout in remote server")
            remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
        else:
            logger().info("Setting UDP socket receive timeout in remote server")
            remote_socket.interfaces.socket.set_recv_timeout(use_client_socket=True, socket_type=1)
        logger().info("Receiving data at remote server")
        for count in range(0, no_of_packets):
            if proto_type == "TCP":
                data = remote_socket.interfaces.socket.recv_data_tcp(packet_length)
            else:
                data, address = remote_socket.interfaces.socket.recv_data_udp(packet_length)
            if not isinstance(data, str):
                fail_count = fail_count + 1
                if fail_count == 5:
                    break
                else:
                    continue
            rcv_data = rcv_data + len(data)
        time.sleep(3)
        logger().info(f"Total bytes received on socket opened remotely -> {rcv_data}")
        time.sleep(10)
        remote_socket.interfaces.socket.stop()
    except Exception as err:
        logger().warning(f"Error is:{err}")


@retry(Exception, delay=10, tries=3)
def client_join(wifi_client, ssid="RS9116_AP"):
    logger().info(f"wifi_client is: {wifi_client.name}")
    wifi_client.interfaces.wifi.join(ssid=ssid)


@retry(Exception, delay=10, tries=4)
def ping_from_client(dut_ip, ping_count):
    status = ping(dut_ip, ping_count)
    assert status, "Failed to ping DUT...RASPI-STA is disconnected from DUT-AP"


@pytest.fixture()
def teardown(wifi_dut):
    yield
    try:
        logger().info("Cleaning up the DUT")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.wireless_deinit()
        logger().info("Closing all opened sockets in DUT")
        wifi_dut.interfaces.wifi.close_sockets()
        time.sleep(3)
    except:
        logger().info("Recovering the DUT")
        wifi_dut.interfaces.wifi.reset()


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "server_socket_limit": 5,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Validate_UDP_Rx_data_C19465(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                                           utf_constants, teardown):
    validation = True
    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    dut_mac_address = None
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Rx_data_C19465')
        time.sleep(3)

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
        logger().info(" ********** Started DUT as an AP ********* ")

        logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
        client_join(wifi_client, ssid="RS9116_AP")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping_from_client(dut_ip, ping_count)
        logger().info("***** Ping successful *****")
        time.sleep(5)

        if not dut_mac_address:
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

        logger().info("***** Initiating UDP RX traffic *****")
        run_iperf_dut_as_server(wifi_dut, net_perf_client, host_ip, dut_ip, protocol)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the beacon frame in sniffer **********")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "not found beacon from DUT"
        logger().info("********* Beacon found from DUT********")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                         f'!(wlan.fc.type_subtype == 0x0008)  or' \
                         f'(wlan.fc.type_subtype == 0x0000) or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Iteration '{count + 1}' completed")


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "server_socket_limit": 5,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Validate_TCP_Rx_data_C19464(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                                           utf_constants, teardown):
    validation = True
    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    dut_mac_address = None
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Rx_data_C19464')
        time.sleep(3)

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
        logger().info(" ********** Started DUT as an AP ********* ")

        logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
        client_join(wifi_client, ssid="RS9116_AP")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping_from_client(dut_ip, ping_count)
        logger().info("***** Ping successful *****")
        time.sleep(5)

        if not dut_mac_address:
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

        logger().info("***** Initiating TCP RX traffic *****")
        run_iperf_dut_as_server(wifi_dut, net_perf_client, host_ip, dut_ip, protocol)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the beacon frame in sniffer **********")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "not found beacon from DUT"
        logger().info("********* Beacon found from DUT********")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                         f'!(wlan.fc.type_subtype == 0x0008) or' \
                         f'(wlan.fc.type_subtype == 0x0000)  or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Iteration '{count + 1}' completed")


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Validate_TCP_Tx_data_C19462(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                                           utf_constants, teardown):
    validation = True
    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    dut_mac_address = None
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Tx_C19462')
        time.sleep(3)

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
        logger().info(" ********** Started DUT as an AP ********* ")

        logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
        client_join(wifi_client, ssid="RS9116_AP")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping_from_client(dut_ip, ping_count)
        logger().info("***** Ping successful *****")
        time.sleep(5)

        if not dut_mac_address:
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

        logger().info("***** Initiating TCP TX traffic from DUT *****")
        run_iperf_dut_as_client(wifi_dut, net_perf_client, host_ip, dut_ip, protocol)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the beacon frame in sniffer **********")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "not found beacon from DUT"
        logger().info("********* Beacon found from DUT********")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                         f'!(wlan.fc.type_subtype == 0x0008) or' \
                         f'(wlan.fc.type_subtype == 0x0000)  or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Iteration '{count + 1}' completed")


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Validate_UDP_Tx_data_C19463(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                                           utf_constants, teardown):
    validation = True
    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    dut_mac_address = None
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Tx_C19463')
        time.sleep(3)

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
        logger().info(" ********** Started DUT as an AP ********* ")

        logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
        client_join(wifi_client, ssid="RS9116_AP")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping_from_client(dut_ip, ping_count)
        logger().info("***** Ping successful *****")
        time.sleep(5)

        if not dut_mac_address:
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

        logger().info("***** Initiating UDP TX traffic from DUT *****")
        run_iperf_dut_as_client(wifi_dut, net_perf_client, host_ip, dut_ip, protocol)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the beacon frame in sniffer **********")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "not found beacon from DUT"
        logger().info("********* Beacon found from DUT********")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                         f'!(wlan.fc.type_subtype == 0x0008)  or' \
                         f'(wlan.fc.type_subtype == 0x0000) or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Iteration '{count + 1}' completed")


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "client_socket_limit": 10,
        "server_socket_limit": 0,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11}
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_TCP_Socket_Create_Transfer_Terminate_30min_C19480(wifi_sniffer, remote_socket, wifi_dut, wifi_client,
                                                                 channel, utf_constants, teardown):
    validation = True
    test_run_time = utf_constants.get('time_duration')
    expected_error_count = 2
    ping_count = utf_constants.get('ping_count')
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Tx_30min_C19480')
    time.sleep(3)

    ip_dict = wifi_dut.interfaces.wifi.ip
    if not ip_dict:
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                         static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        time.sleep(10)
    logger().info(" ********** Started DUT as an AP ********* ")

    logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
    client_join(wifi_client, ssid="RS9116_AP")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {dut_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")

    logger().info("***** Pinging to DUT from wifi_client  *****")
    ping_from_client(dut_ip, ping_count)
    logger().info("***** Ping successful *****")
    time.sleep(5)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

    sw = Stopwatch()
    logger().info(
        f"***** Starting TCP Socket creation and data transfer for {round((test_run_time / 60), 2)} min *****")
    error_count = 0
    while sw.elapsed_sec <= test_run_time:
        time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
        logger().info(f"Remaining time to complete test is '{time_left}' minutes")
        logger().info("***** Initiating UDP TX traffic from DUT *****")
        try:
            run_tcp_traffic(wifi_dut, remote_socket, dut_ip)
            time.sleep(30)
            logger().info("\n\n")
        except Exception as err:
            logger().error(f"********** {str(err)}********")
            if "0x9" in str(err):
                error_count += 1
    logger().info(f"***** error count observed : {error_count}")
    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the beacon frame in sniffer **********")
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], "not found beacon from DUT"
    logger().info("********* Beacon found from DUT********")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                     f'!(wlan.fc.type_subtype == 0x0008)  or' \
                     f'(wlan.fc.type_subtype == 0x0000)  or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in " \
                         "sniffer "
    assert error_count <= expected_error_count, f"While doing data transfer observed error code of 0x9 which aborts " \
                                                f"TCP data transfer '{expected_error_count}'times in 30 minutes of " \
                                                f"test run "
    logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
    wifi_client.interfaces.wifi.leave()


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "client_socket_limit": 10,
        "server_socket_limit": 0,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_UDP_Socket_Create_Transfer_Terminate_30min_C19481(wifi_sniffer, remote_socket, wifi_dut, wifi_client,
                                                                 channel, utf_constants, teardown):
    validation = True
    test_run_time = utf_constants.get('time_duration')
    ping_count = utf_constants.get('ping_count')
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Tx_30min_C19481')
    time.sleep(3)

    ip_dict = wifi_dut.interfaces.wifi.ip
    if not ip_dict:
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                         static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        time.sleep(10)
    logger().info(" ********** Started DUT as an AP ********* ")

    logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
    client_join(wifi_client, ssid="RS9116_AP")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {dut_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")

    logger().info("***** Pinging to DUT from wifi_client  *****")
    ping_from_client(dut_ip, ping_count)
    logger().info("***** Ping successful *****")
    time.sleep(5)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

    sw = Stopwatch()
    logger().info(
        f"***** Starting UDP Socket creation and data transfer for {round((test_run_time / 60), 2)} min *****")
    while sw.elapsed_sec <= test_run_time:
        time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
        logger().info(f"Remaining time to complete test is '{time_left}' minutes")
        proto_type = "UDP"
        no_of_packets = 10000
        packet_length = 4
        local_port = randint(5001, 6000)

        logger().info("Starting UDP server socket at remote device")
        remote_socket.interfaces.socket.interface = "wlan0"
        remote_socket.interfaces.socket.start_server(socket_type=1)  # 0-TCP, 1-UDP
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()
        server_port = remote_socket.interfaces.socket.server_port

        logger().info("Opening UDP client socket in DUT")
        udp_socket_id = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        logger().info(f"Successfully opened UDP client socket on DUT with socket id:'{udp_socket_id}'")

        logger().info("Initiating socket bind from DUT")
        wifi_dut.interfaces.wifi.bind(udp_socket_id, dut_ip, local_port)
        logger().info("Socket binding is success")

        logger().info("DUT is connecting to server socket")
        connect_status = False
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.connect_to_server(udp_socket_id, remote_socket.interfaces.socket, server_port)
                connect_status = True
                break
            except:
                logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
                time.sleep(10)
        assert connect_status, "Socket connection failed in DUT"
        logger().info("Socket connection is successful")
        time.sleep(3)

        logger().info("Receiving UDP data from DUT")
        t1 = Thread(target=receive_data_socket, args=(remote_socket, no_of_packets, packet_length, proto_type), )
        t1.start()
        time.sleep(2)
        logger().info("DUT is sending UDP data packets")
        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(udp_socket_id, pkt_length=packet_length,
                                                             no_of_pkts=no_of_packets,
                                                             server_ip=server_ip, server_port=server_port)
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        time.sleep(5)
        try:
            logger().info("Closing opened socket in DUT")
            result = wifi_dut.interfaces.wifi.close_socket(udp_socket_id)
            assert b"success" in result, "Unable to close the udp socket"
            logger().info("Successfully closed opened socket in DUT")
        except:
            logger().info("Unable to close the socket")
        t1.join()
        time.sleep(30)
        logger().info("\n\n")

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the beacon frame in sniffer **********")
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], "not found beacon from DUT"
    logger().info("********* Beacon found from DUT********")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                     f'!(wlan.fc.type_subtype == 0x0008)  or' \
                     f'(wlan.fc.type_subtype == 0x0000)  or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

    logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
    wifi_client.interfaces.wifi.leave()
