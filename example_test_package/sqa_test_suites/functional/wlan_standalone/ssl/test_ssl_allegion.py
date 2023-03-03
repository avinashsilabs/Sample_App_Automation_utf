# Test author: Vinod.G, Anusha
# Test suite: Test ssl_allegion
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    RS9116AsyncEventType,
    RS9116OperatingMode,
    DeviceConstants,
    RS9116JoinFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
)
from utf.interfaces.wifi import WlanError
from utf.interfaces.cli import CLITransportException
from utf.interfaces.cli import CLITransport, CLITransportException, CLITransportMode
from utf.utils import get_tls_certificate_dir
from typing import Dict
import string
import random
import time
from threading import Thread
import threading
from utf.utils.time_measurer import TimeMeasurer
import math
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from random import randint
from utf.interfaces.socket import SOCKET_TYPE_TCP

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the client with server socket as specified port number.
        8. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

# Configuring static IP to DUT
mode = 'static'
static_ip = '192.168.100.76'
static_subnet = '255.255.255.0'
static_gateway = '192.168.100.76'


def tcp_socket_rx(remote_socket_factory, index, no_of_pkts, data_size, logger):
    data_length = 0
    index = index - 1
    logger.info(f"TCP Receiving data over socket id {index}")
    for count in range(0, no_of_pkts):
        # logger.info(f"packet receiving on socket id{index}")
        data = remote_socket_factory.interfaces.socket.sockets[index].recv_data_tcp(data_size)
        data_length = data_length + len(data)
    logger.info(f"Total bytes received on socket id {index} -> {data_length} TCP")


def ssl_socket_rx(ssl_server, sock_id, pkt_count, buffer_length, logger):
    logger.info(f"SSL Receiving data over socket id {sock_id}")
    # for iter in range(3):
    # logger.info(f"packet receiving on socket id{sock_id}")
    ssl_server.interfaces.ssl.data_receive((sock_id + 1), pkt_count, buffer_length)


def pdu_switch(switch, logger):
    logger.info("Turning off the AP")
    switch.interfaces.pdu_switch.turn_off()
    logger.info("Successfully powered off AP")
    time.sleep(10)
    logger.info("Again turning on the AP")
    switch.interfaces.pdu_switch.turn_on()


def get_socket_id(sock_fd):
    return int(math.log2(sock_fd))


class FilterPacket:
    def get_beacon_interval(self):
        packet_filter = "Beacon Interval:"
        beacon_interval_ap = None
        count = 0

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                beacon_interval_ap = float(x.split(":")[1].split("[Seconds]")[0].strip())
                beacon_interval_ap = int(beacon_interval_ap * 1000)
                beacon_interval_ap = beacon_interval_ap - (beacon_interval_ap % 100)
                print(f'Beacon Interval = {beacon_interval_ap}')
                break
        filter_file.close()
        return beacon_interval_ap

    def get_dtim_period(self):
        packet_filter = "DTIM period"
        dtim_period_ap = None
        count = 0

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                dtim_period_ap = int(x.split(":")[1].strip())
                print(f'DTIM Period = {dtim_period_ap}')
                break
        filter_file.close()
        return dtim_period_ap


def get_ntp_list(wifi_sniffer, decryption_key: str, print_layers: list, mode=0) -> Dict[str, int]:
    ntp_capture_list = []
    source_ip = ""
    destination_ip = ""
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
    ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "ip":
                ip_layer = str(layer)
                layer_ip = ip_layer.split("\n")
                for count in layer_ip:
                    if "Source" in count:
                        source_ip = count.split(":")[1].strip()
                    if "Destination" in count:
                        destination_ip = count.split(":")[1].strip()

            if layer_name in print_layers:
                ntp_layer = str(layer)
                ntp_capture_list.append(tuple([ntp_layer, packet.sniff_timestamp, source_ip, destination_ip]))
    return ntp_capture_list


def ApWirelessOff(wifi_access_point, wait_time, logger, start_ap=True):
    time.sleep(wait_time)
    logger.info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    if start_ap:
        logger.info(f"Enabling Wireless in AP")
        wifi_access_point.interfaces.wifi.start_ap()


def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger, cert1=None, cert2=None,
                cert3=None, listen_interval_feature=False, listen_interval=1600, rejoin_params=None):
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    if not rejoin_params:
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=20,
                                        scan_interval=6,
                                        beacon_missedcount=40,
                                        first_time_retry=0)
    else:
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_params[0],
                                        scan_interval=rejoin_params[1],
                                        beacon_missedcount=rejoin_params[2],
                                        first_time_retry=rejoin_params[3])
    if listen_interval_feature:
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromPowerSave,
                                         )
    else:
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    if cert1:
        # The below API loads ca-cert into DUT at cert index 0
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0,
                                                     )
    if cert2:
        # The below API loads ca-cert into DUT at cert index 1
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                     cert_index=1,
                                                     )
    if cert3:
        # The below API loads ca-cert into DUT at cert index 2
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                     cert_index=2,
                                                     )

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    if listen_interval_feature:
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                            listen_interval=listen_interval)

    else:
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
    # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
    #                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, 10)
    return mac_address


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "security": "WPA2", "ssid": "SILABS_AP_C19176", "passphrase": "12345678", "channel": 4, "dtim_period": 5,
        "beacon_interval": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19176",
        "passphrase": "12345678",
        "channel": 4,
        "interface": "wlan0",
    },
)
@pytest.mark.parametrize("dtim_period_check", [5])
@pytest.mark.parametrize("beacon_interval_check", [100])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wifi_wireless_statistics_AP_TC19176(wifi_client, wifi_dut, logger, dtim_period_check, beacon_interval_check):
    dut_ip = wifi_dut.interfaces.wifi.ip
    if not dut_ip:
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
        wifi_dut.interfaces.wifi.start_ap()
        time.sleep(10)

    wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19176")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    status = ping(dut_ip, 10)
    operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_dut.interfaces.wifi.wlan_get_stats()
    check_point = False
    if ((operating_mode == RS9116OperatingMode.AccessPoint) and (dtim_period == dtim_period_check) and (
            beacon_interval == beacon_interval_check)):
        logger.info(
            f"Values expected of operating_mode is {RS9116OperatingMode.AccessPoint} and received=={operating_mode},dtim_period is {dtim_period_check} and received=={dtim_period}, beacon_interval is {beacon_interval_check} and received=={beacon_interval}")
        check_point = True
    else:
        logger.info(
            f"Values expected of operating_mode is {RS9116OperatingMode.AccessPoint} and received=={operating_mode},dtim_period is {dtim_period_check} and received=={dtim_period}, beacon_interval is {beacon_interval_check} and received=={beacon_interval}")
    assert check_point == True, "Received wrong values"

    wifi_client.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "start_field.pem"],
        "client_cert": [False, False, "client-certificate.crt"],
        "client_key": [False, False, "private-key.key"],
    }
)
@pytest.mark.parametrize("cert1, cert2",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl2_1AWS_testcaseTC19150(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cert1, cert2, logger
):
    listen_interval = 700
    capture_filename = "test_ssl2_1AWS_testcaseTC19150"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    pkt_count = 5000

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)

        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"

        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(
            f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2

        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
        if sock_count == 0:
            socket_port = port1
            local_port = randint(5001, 20000)
        elif sock_count == 1:
            socket_port = port2
            local_port = randint(20001, 40000)
        else:
            socket_port = 8883
            local_port = randint(40001, 60000)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        if sock_count < 2:
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
        else:
            result = wifi_dut.interfaces.wifi.dns_get(4)
            logger.info(f"dns response is {result}")
            server_ip = result.split(b"\n")[1].split(b":")[1].decode()
            for count in range(0, 3):
                try:
                    wifi_dut.interfaces.wifi.connect(sock, server_ip, socket_port)
                    break
                except:
                    logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
                    time.sleep(1)
                    if count == 2:
                        raise
            logger.info(f"Connection to AWS server on socket id->{sock} is successful")
    socket_no = [1, 2]

    for socket in socket_no:
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout=10)

    result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length,
                                                                 time_interval=600,
                                                                 number_of_pkts=pkt_count, timeout=620)

    socket_list = result
    sock_count = 0
    bytes_sent_list = []
    for socket_stats in socket_list:
        logger.info(
            f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
        bytes_sent_list.append(socket_stats[0])
        sock_count = sock_count + 1

    socket_no = [1, 2]
    for socket in socket_no:
        if ssl_server.interfaces.ssl.socket_connection_status(socket):
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
            assert bytes_sent_list[socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                                  f"remote peer " \
                                                                  f"not matched on socket {socket} "
    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")
    wifi_dut.interfaces.wifi.leave()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2,cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_receive_data_testcaseTC19153(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cert1, cert2, cert3, logger
):
    listen_interval = 700
    capture_filename = "test_ssl_three_sockets_receive_data_testcaseTC19153"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)

        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"

        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(
            f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1

        else:
            cert_index = SocketOptions.CERT_INDEX2

        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
        if sock_count == 0:
            socket_port = port1
        elif sock_count == 1:
            socket_port = port2
        else:
            socket_port = port3

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    for iteration in range(1, 20):
        socket_no = [1, 2, 3]
        for socket in socket_no:
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
            )

            ssl_server.interfaces.ssl.send_data(socket, pkt_count, buffer_length, message=tx_buffer)
            sock = (socket - 1)
            buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock,
                                                                                data_len=buffer_length)

            if not (buffer_length == buffer_length_rx):
                logger.info(
                    f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                    f"not matched ")
            else:
                logger.info(
                    f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                    f"matched ")
            assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
            if not (tx_buffer.encode() == buffer_rx):
                logger.info(
                    f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                    f"is not matched ")
            else:
                logger.info(
                    f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                    f"is matched ")
            assert tx_buffer.encode() == buffer_rx, f"contents of data sent by remote peer and received on the socket " \
                                                    f"id {sock} opened in the DUT is not matched "

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.skip()
def test_ssl_clear_cert2_TC19154(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
):
    capture_filename = "test_ssl_clear_cert2_TC19154"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
    )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    for iteration in range(0, 2):
        if iteration == 1:
            time.sleep(120)
            wifi_dut.interfaces.wifi.reset_soft()
            wifi_dut.interfaces.wifi.wireless_init()
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        if iteration == 0:
            # The below API loads ca-cert into DUT at cert index
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                         cert_index=0,
                                                         )
            # The below API loads ca-cert into DUT at cert index 1
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                         cert_index=1,
                                                         )
            # The below API loads ca-cert into DUT at cert index 2
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                         cert_index=2,
                                                         )
        if iteration == 1:
            wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate, cert_index=2)

        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        # Open ssl client socket in the DUT
        sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock1 == 1, f"socket id received is wrong, expected is 1"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX1)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

        # Open ssl client socket in the DUT
        sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock2 == 2, f"socket id received is wrong, expected is 2"

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX2)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
        if iteration == 0:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
        else:
            with pytest.raises(WlanError) as exc_info:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
            assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

        if iteration == 0:
            socket_no = [1, 2, 3]
        else:
            socket_no = [1, 2]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            if iteration == 0:
                socket_no = [1, 2, 3]
            else:
                socket_no = [1, 2]
            for socket in socket_no:
                if ssl_server.interfaces.ssl.socket_connection_status(socket):
                    # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                    wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                    time.sleep(10)
                    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                         f"not matched on socket {socket} "

                else:
                    assert f"failed to connect on socket no {socket}"

        # Close socket 1
        wifi_dut.interfaces.wifi.close_socket(sock)
        # Close socket 2
        wifi_dut.interfaces.wifi.close_socket(sock1)
        if iteration == 0:
            # Close socket 3
            wifi_dut.interfaces.wifi.close_socket(sock2)
            ssl_server.interfaces.ssl.stop_server()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"],
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_data_tx_while_rejoin_testcaseTC19155(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, switch, logger, cert1, cert2, cert3
):
    capture_filename = "test_ssl_three_sockets_data_tx_while_rejoin_testcaseTC19155"
    listen_interval = 700
    rejoin_params = [40, 6, 40, 0]
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval,
                                  rejoin_params=rejoin_params)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    pkt_count = 30000

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger.info(f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
        if sock_count == 0:
            socket_port = port1
        elif sock_count == 1:
            socket_port = port2
        else:
            socket_port = port3

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    socket_no = [1, 2, 3]
    pkt_rcv_timeout = 90
    for socket in socket_no:
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout)
    sleep_time = 10
    thread = Thread(target=pdu_switch, args=(switch, sleep_time, logger), )
    thread.start()
    result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=1300, time_interval=550,
                                                                 number_of_pkts=pkt_count, timeout=600)

    socket_list = result
    bytes_sent = (pkt_count * buffer_length)
    sock_count = 0
    for socket_stats in socket_list:
        logger.info(
            f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
        assert bytes_sent == socket_stats[0], f"Number of bytes initiated by test and actually sent by DUT are not " \
                                              f"matched. Initiated->{bytes_sent} bytes. But Sent by DUT->{socket_stats[0]} bytes "
        sock_count = sock_count + 1

    socket_no = [1, 2, 3]
    for socket in socket_no:
        if ssl_server.interfaces.ssl.socket_connection_status(socket):
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
            assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                 f"not matched on socket {socket} "

    wifi_sniffer.interfaces.capture.stop_capture()

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"],
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "close_sockets"])
def test_ssl_three_sockets_data_tx_after_rejoin_testcaseTC19156(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                                logger, cert1, cert2, cert3, rs_helper, utf_constants,
                                                                switch):
    try:
        capture_filename = "test_ssl_three_sockets_data_tx_after_rejoin_testcaseTC19156"
        listen_interval = 700
        rejoin_params = [20, 6, 40, 0]
        dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                      listen_interval_feature=True,
                                      listen_interval=listen_interval,
                                      rejoin_params=rejoin_params)

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        pkt_count = 5000

        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            if sock_count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0"
            elif sock_count == 1:
                assert sock == 1, f"socket id received is wrong, expected is 1"
            else:
                assert sock == 2, f"socket id received is wrong, expected is 2"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            logger.info(f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            if sock_count == 0:
                cert_index = SocketOptions.CERT_INDEX0
            elif sock_count == 1:
                cert_index = SocketOptions.CERT_INDEX1
            else:
                cert_index = SocketOptions.CERT_INDEX2
            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                socket_port = port3

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
            Connect_to_server = False
            for recheck in range(3):
                try:
                    # ssl socket opened in DUT connects to the server
                    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
                    Connect_to_server = True
                    break
                except:
                    time.sleep(5)
                    logger.info(f"Except block{recheck}")

            assert Connect_to_server == True, "Connection to server FAILED"

        socket_no = [0, 1, 2]
        for socket in socket_no:
            th_start = Thread(target=ssl_socket_rx, args=(ssl_server, socket, pkt_count, buffer_length, logger), )
            th_start.start()

        wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=1300, time_interval=550,
                                                            number_of_pkts=pkt_count, timeout=700)

        time.sleep(15)
        logger.info("Turning off the AP")
        switch.interfaces.pdu_switch.turn_off()
        time.sleep(5)
        logger.info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        while sw.elapsed_sec <= 300:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
            if rejoin_msg:
                break
        assert rejoin_msg == 1, "rejoin fail event not found even after AP is switched off"
        logger.info("Received rejoir error from DUT")

        logger.info("Again turning on the AP")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(60)
        wifi_dut.interfaces.wifi.associated = False

        logger.info("Initiating wlan_scan from DUT")
        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger.info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

        logger.info("Initiation wlan_connection from DUT")
        rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=False)

        port1 = 5004
        port2 = 5005
        port3 = 5006

        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            if sock_count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0"
            elif sock_count == 1:
                assert sock == 1, f"socket id received is wrong, expected is 1"
            else:
                assert sock == 2, f"socket id received is wrong, expected is 2"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            logger.info(f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            if sock_count == 0:
                cert_index = SocketOptions.CERT_INDEX0
            elif sock_count == 1:
                cert_index = SocketOptions.CERT_INDEX1
            else:
                cert_index = SocketOptions.CERT_INDEX2
            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                socket_port = port3

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
            Connect_to_server = False
            for recheck in range(3):
                try:
                    # ssl socket opened in DUT connects to the server
                    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
                    Connect_to_server = True
                    break
                except:
                    time.sleep(5)
                    logger.info(f"Except block{recheck}")

            assert Connect_to_server == True, "Connection to server FAILED"

        logger.info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")

        try:
            wifi_dut.interfaces.wifi.close_sockets()
        except:
            pass
    except Exception as e:
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        raise e
    finally:
        get_state = switch.interfaces.pdu_switch.get_state()
        if get_state == False:
            switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2,cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_shut_down_testcaseTC19157(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cert1, cert2, cert3, logger
):
    listen_interval = 700
    capture_filename = "test_ssl_three_sockets_shut_down_testcaseTC19157"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    for count in range(1, 11):
        logger.info(f"##############################Iteration count -> {count}###############################")
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)

            if sock_count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0"
            elif sock_count == 1:
                assert sock == 1, f"socket id received is wrong, expected is 1"
            else:
                assert sock == 2, f"socket id received is wrong, expected is 2"

            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            logger.info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            if sock_count == 0:
                cert_index = SocketOptions.CERT_INDEX0
            elif sock_count == 1:
                cert_index = SocketOptions.CERT_INDEX1

            else:
                cert_index = SocketOptions.CERT_INDEX2

            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                socket_port = port3

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

        pkt_count = 100
        buffer_length = 1300
        socket_no = [1, 2, 3]

        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout=10)

        result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                                     time_interval=120,
                                                                     number_of_pkts=pkt_count, timeout=140)

        socket_list = result
        sock_count = 0
        bytes_sent_list = []
        for socket_stats in socket_list:
            logger.info(
                f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
            bytes_sent_list.append(socket_stats[0])
            sock_count = sock_count + 1

        socket_no = [1, 2, 3]
        for socket in socket_no:
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent_list[
                           socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                          f"remote peer " \
                                                          f"not matched on socket {socket} "
        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            result = wifi_dut.interfaces.wifi.close_socket(sock_count)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
            logger.info(f"Successfully closed socket_id->{sock_count}")

        ssl_server.interfaces.ssl.stop_server()

    wifi_dut.interfaces.wifi.leave()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_socket_check_TC19158(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
):
    listen_interval = 700
    capture_filename = "test_socket_check_TC19158"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
    server_ip = ssl_server.interfaces.ssl.hostname_or_ip_address()

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1, f"socket id received is wrong, expected is 1"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2, f"socket id received is wrong, expected is 2"

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
    socket1 = tuple([(sock + 1), 0, port1, port1, server_ip])
    socket2 = tuple([(sock1 + 1), 0, port2, port2, server_ip])
    socket3 = tuple([(sock2 + 1), 0, port3, port3, server_ip])

    sockets_opened, socket_info = wifi_dut.interfaces.wifi.wlan_get_socket_info()
    assert sockets_opened == 3, f"Number of sockets opened in DUT is 3. But shown {sockets_opened} when query " \
                                f"through get_network_params api"
    iter = 0
    if sockets_opened:
        for count in socket_info:
            iter = iter + 1
            if iter == 1:
                assert count[0] == socket1[
                    0], f"socket id received in network query response is wrong for socket {iter} expected is {socket1[0]} "
                assert count[1] == socket1[
                    1], f"socket type received in network query response is wrong for socket {iter} expected is {socket1[1]} "
                assert count[2] == socket1[
                    2], f"source port received in network query response is wrong for socket {iter} expected is {socket1[2]}"
                assert count[3] == socket1[3], f"destination port received in network query response is wrong for " \
                                               f"socket {iter} expected is {socket1[3]} "
                assert count[4] == socket1[
                    4], f"server ip received in network query response is wrong for socket {iter} expected is {socket1[4]}"

            elif iter == 2:
                assert count[0] == socket2[
                    0], f"socket id received in network query response is wrong for socket {iter} expected is {socket2[0]}"
                assert count[1] == socket2[
                    1], f"socket type received in network query response is wrong for socket {iter} expected is {socket2[1]}"
                assert count[2] == socket2[
                    2], f"source port received in network query response is wrong for socket {iter} expected is {socket2[2]}"
                assert count[3] == socket2[3], f"destination port received in network query response is wrong for " \
                                               f"socket {iter} expected is {socket2[3]} "
                assert count[4] == socket2[
                    4], f"server ip received in network query response is wrong for socket {iter} expected is {socket2[4]}"
            elif iter == 3:
                assert count[0] == socket3[
                    0], f"socket id received in network query response is wrong for socket {iter} expected is {socket3[0]}"
                assert count[1] == socket3[
                    1], f"socket type received in network query response is wrong for socket {iter} expected is {socket3[1]}"
                assert count[2] == socket3[
                    2], f"source port received in network query response is wrong for socket {iter} expected is {socket3[2]}"
                assert count[3] == socket3[3], f"destination port received in network query response is wrong for " \
                                               f"socket {iter} expected is {socket3[3]} "
                assert count[4] == socket3[
                    4], f"server ip received in network query response is wrong for socket {iter} expected is {socket3[4]} "

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_close_reopen_socket2_testcaseTC19159(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    bytes_sent = (pkt_count * buffer_length)
    capture_filename = "test_ssl_three_sockets_close_reopen_socket2_testcaseTC19159"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=700)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
        if sock_count == 0:
            socket_port = port1
        elif sock_count == 1:
            socket_port = port2
        else:
            socket_port = port3

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    sock_id = 1
    result = wifi_dut.interfaces.wifi.close_socket(sock_id)
    assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_id}"
    logger.info(f"Successfully closed socket_id->{sock_id}")
    ssl_server.interfaces.ssl.close_socket(socket_no=2)
    time.sleep(10)
    since_time = 0
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
    for event in events:
        logger.info(f"Received the Event Type {event.event_type}, Event data {event.event_data}")
        since_time = event.timestamp + 1
        if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
            logger.info("Received TCP_REMOTE_TERMINATE event")
            remote_terminate = event.event_data
            socket_id = int(remote_terminate.split(b",")[1].split(b":")[1])
            assert socket_id == 1, f"Socket id received in remote terminate event is wrong, expected is 1. But received {socket_id}"
            break
        else:
            logger.info(f"Remote terminate event is not received by DUT even though tcp socket connected is "
                        f"closed ")
            continue

    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 1, f"socket id received is wrong, expected is 1"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    cert_index = SocketOptions.CERT_INDEX1
    logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               cert_index)
    socket_port = 5002
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    pkt_count = 3000
    buffer_length = 1300
    socket_no = [1, 2, 3]

    for socket in socket_no:
        if socket != 2:
            server_sock = socket
        else:
            server_sock = 4
        ssl_server.interfaces.ssl.data_receive(server_sock, pkt_count, buffer_length, pkt_rcv_timeout=10)

    result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                                 time_interval=500,
                                                                 number_of_pkts=pkt_count, timeout=520)

    socket_list = result
    sock_count = 0
    bytes_sent_list = []
    for socket_stats in socket_list:
        logger.info(
            f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
        bytes_sent_list.append(socket_stats[0])
        sock_count = sock_count + 1

    socket_no = [1, 2, 3]
    for socket in socket_no:
        if socket != 2:
            server_sock = socket
        else:
            server_sock = 4
        if ssl_server.interfaces.ssl.socket_connection_status(server_sock):
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_sock)
            assert bytes_sent_list[
                       socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                      f"remote peer " \
                                                      f"not matched on socket {socket - 1} "

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")
    wifi_dut.interfaces.wifi.leave()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_close_reopen_socket2_testcaseTC19160(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    bytes_sent = (pkt_count * buffer_length)
    capture_filename = "test_ssl_three_sockets_close_reopen_socket2_testcaseTC19160"
    listen_interval = 700
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
        if sock_count == 0:
            socket_port = port1
        elif sock_count == 1:
            socket_port = port2
        else:
            socket_port = port3

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    ssl_server.interfaces.ssl.close_socket(socket_no=2)
    time.sleep(10)
    since_time = 0
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
    for event in events:
        since_time = event.timestamp + 1
        logger.info(f"Received the Event Type {event.event_type}, Event data {event.event_data}")
        if event.event_type == RS9116AsyncEventType.TCP_REMOTE_TERMINATE:
            logger.info("Received TCP_REMOTE_TERMINATE event")
            remote_terminate = event.event_data
            socket_id = int(remote_terminate.split(b",")[1].split(b":")[1])
            assert socket_id == 1, f"Socket id received in remote terminate event is wrong, expected is 1. But received {socket_id}"
            break
        else:
            logger.info(f"Remote terminate event is not received by DUT even though tcp socket connected is "
                        f"closed ")
            continue

    sock_id = 1
    result = wifi_dut.interfaces.wifi.close_socket(sock_id)
    assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_id}"
    logger.info(f"Successfully closed socket_id->{sock_id}")
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 1, f"socket id received is wrong, expected is 1"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    cert_index = SocketOptions.CERT_INDEX1
    logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               cert_index)
    socket_port = 5002
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    pkt_count = 3000
    buffer_length = 1300
    socket_no = [1, 2, 3]

    for socket in socket_no:
        if socket != 2:
            server_sock = socket
        else:
            server_sock = 4
        ssl_server.interfaces.ssl.data_receive(server_sock, pkt_count, buffer_length, pkt_rcv_timeout=10)

    result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                                 time_interval=500,
                                                                 number_of_pkts=pkt_count, timeout=520)

    socket_list = result
    sock_count = 0
    bytes_sent_list = []
    for socket_stats in socket_list:
        logger.info(
            f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
        bytes_sent_list.append(socket_stats[0])
        sock_count = sock_count + 1

    socket_no = [1, 2, 3]
    for socket in socket_no:
        if socket != 2:
            server_sock = socket
        else:
            server_sock = 4
        if ssl_server.interfaces.ssl.socket_connection_status(server_sock):
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_sock)
            assert bytes_sent_list[
                       socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                      f"remote peer " \
                                                      f"not matched on socket {socket - 1} "

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")

    wifi_dut.interfaces.wifi.leave()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_2SSL_TX_1TCP_RX_testcaseTC19161(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, remote_socket_factory, cert1, cert2, logger
):
    listen_interval = 700
    capture_filename = "test_2SSL_TX_1TCP_RX_testcaseTC19161"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port3']
    port3 = 5005

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    server_socket = remote_socket_factory.interfaces.socket.create_socket()
    server_socket.time_limit = 3600
    status = server_socket.start_server(port=port3, socket_type=SOCKET_TYPE_TCP)

    for sock_count in range(0, 3):
        if sock_count < 2:
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       eval("SocketOptions.CERT_INDEX" + str(sock_count)))
        else:
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
        if sock_count == 0:
            socket_port = port1
            local_port = randint(5001, 20000)
        elif sock_count == 1:
            socket_port = port2
            local_port = randint(20001, 40000)
        else:
            socket_port = port3
            local_port = randint(40001, 60000)

        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        if sock_count < 2:
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
        else:
            wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket)

    pkt_count = 500
    buffer_length = 100
    socket_no = [0, 1, 2]
    send_list = []
    for sock_id in socket_no:
        if sock_id < 2:
            th_start = Thread(target=ssl_socket_rx, args=(ssl_server, sock_id, pkt_count, buffer_length, logger), )
            send_list.append(th_start)
            th_start.start()

    result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length,
                                                                 time_interval=600,
                                                                 number_of_pkts=pkt_count)
    for sock_id in socket_no:
        for i in range(10):
            if sock_id == 2:
                buffer_length = 100
                tx_buffer = "".join(
                    random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
                )

                remote_socket_factory.interfaces.socket.sockets[0].send_data_tcp(tx_buffer, use_server_socket=True)

                buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=2,
                                                                                    data_len=buffer_length)

                assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem"],
        "set_send_feature_frame": True
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat_count", [10])
def test_ssl_three_sockets_socket_select_receive_data_testcase_TC19162(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3, repeat_count
):
    capture_filename = "test_ssl_three_sockets_socket_select_receive_data_testcase_TC19162"
    listen_interval = 700
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True, listen_interval=listen_interval)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    since_time = 0

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
        if sock_count == 0:
            socket_port = port1
        elif sock_count == 1:
            socket_port = port2
        else:
            socket_port = port3

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    for iteration in range(1, repeat_count):
        logger.info(f"#####################################################Iteration count -> {iteration}")
        for socket in range(0, 3):
            wifi_dut.interfaces.wifi.set_fd(socket_count=3, start_sock_no=0)
            socket_id = 2
            wifi_dut.interfaces.wifi.socket_select(socket_id, select_timeout=60)
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
            )

            ssl_server.interfaces.ssl.send_data((socket + 1), pkt_count, buffer_length, message=tx_buffer)

            time.sleep(5)
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            assert len(events) != 0, "Socket select asynchronous event is not received"
            logger.info(f"Socket select event received")
            sock_list = []
            for event in events:
                if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
                    socket_select_event_payload = event.event_data
                    since_time = event.timestamp + 1
                    logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
                    sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
                    sock_id = get_socket_id(sock_fd)
                    if sock_id is not None:
                        sock_list.append(sock_id)
            if not (len(sock_list)):
                logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
            assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"

            for sock in sock_list:
                logger.info(f"Data is received on the socket id {sock} opened in the DUT")
                buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock,
                                                                                    data_len=buffer_length)
                if not (buffer_length == buffer_length_rx):
                    logger.info(
                        f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                        f"not matched ")
                else:
                    logger.info(
                        f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                        f"matched ")
                assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the " \
                                                          f"socket id {sock} opened in the DUT is not matched "
                if not (tx_buffer.encode() == buffer_rx):
                    logger.info(
                        f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                        f"is not matched ")
                else:
                    logger.info(
                        f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                        f"is matched ")
                assert tx_buffer.encode() == buffer_rx, f"contents of data sent by remote peer and received on the " \
                                                        f"socket " \
                                                        f"id {sock} opened in the DUT is not matched "

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")
    wifi_dut.interfaces.wifi.leave()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.skip()
def test_ssl_three_sockets_load_remove_certs_connection_check_testcaseTC19163(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
):
    capture_filename = "test_ssl_three_sockets_load_remove_certs_connection_check_testcaseTC19163"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    dut_mac_address = mac_address
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
    )
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    for iteration in range(0, 2):
        if iteration == 1:
            wifi_dut.interfaces.wifi.leave()
            wifi_dut.interfaces.wifi.associated = False
            # wifi_dut.interfaces.wifi.initialized = False
            time.sleep(120)
        wifi_dut.interfaces.wifi.scan(ssid=None)
        # DUT connects to AP after join_ap API is executed
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        # The below API loads ca-cert into DUT at cert index 0
        if iteration == 0:
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                         cert_index=0,
                                                         )
            # The below API loads ca-cert into DUT at cert index 1
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert2[0])),
                                                         cert_index=1,
                                                         )
            # The below API loads ca-cert into DUT at cert index 2
            wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                         str(get_tls_certificate_dir().joinpath(cert3[0])),
                                                         cert_index=2,
                                                         )
        else:
            for cert_index in range(0, 3):
                wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                                           cert_index=cert_index)
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, f"socket id received is wrong, expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)

        if iteration == 0:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        else:
            with pytest.raises(WlanError) as exc_info:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
            assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

        # Open ssl client socket in the DUT
        sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock1 == 1, f"socket id received is wrong, expected is 1"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX1)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)

        if iteration == 0:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
        else:
            with pytest.raises(WlanError) as exc_info:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
            assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

        # Open ssl client socket in the DUT
        sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock2 == 2, f"socket id received is wrong, expected is 2"

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 1 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX2)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)

        if iteration == 0:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
        else:
            with pytest.raises(WlanError) as exc_info:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
            assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

        if iteration == 0:
            socket_no = [1, 2, 3]
            for socket in socket_no:
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

            if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                socket_no = [1, 2, 3]
                for socket in socket_no:
                    if ssl_server.interfaces.ssl.socket_connection_status(socket):
                        wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                        time.sleep(10)
                        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                        assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote " \
                                                             f"peer " \
                                                             f"not matched on socket {socket} "

                    else:
                        assert f"failed to connect on socket no {socket}"

            # Close socket 1
            wifi_dut.interfaces.wifi.close_socket(sock)
            # Close socket 2
            wifi_dut.interfaces.wifi.close_socket(sock1)
            # Close socket 3
            wifi_dut.interfaces.wifi.close_socket(sock2)
            ssl_server.interfaces.ssl.stop_server()

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca_ecdsa.crt", "ca_ecdsa.crt", "ca_ecdsa.crt"]
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca_ecdsa.crt", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca_ecdsa.crt", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca_ecdsa.crt", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_connectivity_check_loading_wrong_certs_TC19165(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
):
    listen_interval = 700
    capture_filename = "test_ssl_three_sockets_connectivity_check_loading_wrong_certs_TC19165"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, f"socket id received is wrong, expected is 0"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 0 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl client socket in the DUT
    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1, f"socket id received is wrong, expected is 1"
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX1)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock1, device_ip, port2)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
    assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    # Open ssl client socket in the DUT
    sock2 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock2 == 2, f"socket id received is wrong, expected is 1"

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Enable cert index 1 for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock2, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX2)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock2, device_ip, port3)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)
    assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("repeat_count", [10])
def test_ssl_three_sockets_socket_select_tx_rx_data_testcase_TC19166(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3, repeat_count
):
    listen_interval = 700
    since_time = 0
    capture_filename = "test_ssl_three_sockets_socket_select_tx_rx_data_testcase_TC19166"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
        if sock_count == 0:
            socket_port = port1
        elif sock_count == 1:
            socket_port = port2
        else:
            socket_port = port3

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    for iteration in range(1, repeat_count):
        logger.info(f"#####################################################Iteration count -> {iteration}")
        for socket in range(0, 3):
            if socket < 2:
                wifi_dut.interfaces.wifi.set_fd(socket_count=3, start_sock_no=0)
                socket_id = 2
                wifi_dut.interfaces.wifi.socket_select(socket_id, select_timeout=60)
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
            )
            if socket < 2:
                ssl_server.interfaces.ssl.send_data((socket + 1), pkt_count, buffer_length, message=tx_buffer)
                time.sleep(5)
                events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                assert len(events) >= 1, "Socket select asynchronous event is not received"
                logger.info(f"Socket select event received")
                sock_list = []
                for event in events:
                    if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
                        socket_select_event_payload = event.event_data
                        since_time = event.timestamp + 1
                        logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
                        sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
                        sock_id = get_socket_id(sock_fd)
                        if sock_id is not None:
                            sock_list.append(sock_id)
                if not (len(sock_list)):
                    logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
                assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"

                for sock in sock_list:
                    logger.info(f"Data is received on the socket id {sock} opened in the DUT")
                    buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock,
                                                                                        data_len=buffer_length)
                    if not (buffer_length == buffer_length_rx):
                        logger.info(
                            f"buffer length sent by remote peer and received on the socket id {sock} opened in the "
                            f"DUT is "
                            f"not matched ")
                    else:
                        logger.info(
                            f"buffer length sent by remote peer and received on the socket id {sock} opened in the "
                            f"DUT is "
                            f"matched ")
                    assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the " \
                                                              f"socket id {sock} opened in the DUT is not matched "
                    if not (tx_buffer.encode() == buffer_rx):
                        logger.info(
                            f"contents of data sent by remote peer and received on the socket id {sock} opened in the "
                            f"DUT "
                            f"is not matched ")
                    else:
                        logger.info(
                            f"contents of data sent by remote peer and received on the socket id {sock} opened in the "
                            f"DUT "
                            f"is matched ")
                    assert tx_buffer.encode() == buffer_rx, f"contents of data sent by remote peer and received on the " \
                                                            f"socket " \
                                                            f"id {sock} opened in the DUT is not matched "
            else:
                # The api returns 100 bytes of random data
                data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                data_length = len(data_sent)
                logger.info(f"Sending data {data_sent} over socket_no->{socket}")
                # DUT sends 100 bytes of data over ssl socket
                wifi_dut.interfaces.wifi.send_data(socket, data_length, data_sent)
                server_socket_no = 3
                # SSL server receives the data over ssl socket
                data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                logger.info(f"Data received on remote socket opened is {data_receive}")
                assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                logger.info("Data sent by DUT and received on server is matching")

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")
    wifi_dut.interfaces.wifi.leave()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_query_wireless_stats_TC19175(wifi_sniffer, wifi_dut, wifi_access_point, logger):
    listen_interval = 700
    beacon_interval_obj = FilterPacket()
    dtim_period_obj = FilterPacket()
    validation = True
    packet_filter3 = "    Type/Subtype: Beacon (0x0008)"
    capture_filename = "test_query_wireless_stats_TC19175"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_dut.interfaces.wifi.wlan_get_stats()
    logger.info("****************Beacon Filter******************")
    packet_filter = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter, packet_filter3)[
        'packet_count']

    beacon_interval_ap = beacon_interval_obj.get_beacon_interval()
    if beacon_interval_ap is None:
        logger.info(f'Unable to find Beacon Interval={beacon_interval_ap}')
        assert False
    else:
        logger.info(f'\n\n *** Beacon Interval ={beacon_interval_ap} *** \n')

    packet_filter4 = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008) and (wlan.fixed.beacon == {beacon_interval_ap})'

    dtim_period_ap = dtim_period_obj.get_dtim_period()
    if dtim_period_ap is None:
        logger.info(f'Unable to find DTIM Period={dtim_period_ap}')
        assert False
    else:
        logger.info(f'\n\n *** DTIM Period ={dtim_period_ap} *** \n')

    packet_filter5 = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008) and (wlan.dtim.period == {dtim_period_ap})'

    logger.info(f"Access point Beacon interval -> {beacon_interval_ap},  DTIM period-> {dtim_period_ap}")

    logger.info(f"DUT Beacon interval -> {beacon_interval},  DTIM period-> {dtim_period}")

    assert operating_mode == 0, "Operating mode is not matching, expected is 0"

    assert beacon_interval == beacon_interval_ap, f"AP beacon interval received in wlan stats and actual beacon " \
                                                  f"interval of connected AP is not matched, e" \
                                                  f"xpected is {beacon_interval_ap}. But observed {beacon_interval} "
    assert dtim_period == dtim_period_ap, f"DTIM period received in wlan stats and actual DTIM " \
                                          f"interval of connected AP is not matched, e" \
                                          f"expected is {dtim_period_ap}. But observed {dtim_period} "

    connection = f'(wlan.addr == {dut_mac_address}) and (wlan.addr == {wifi_access_point.interfaces.wifi.bssid}) and (eapol)'
    connection_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, connection)['packet_count']
    assert connection_count, "Association Packets are not captured in the sniffer"
    logger.info(f"Association Packets packets are captured in the sniffer")

    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"dtim": 3, "beacon_interval": 100})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_query_wireless_stats_after_rejoin_TC19177(wifi_sniffer, wifi_dut, wifi_access_point, logger):
    listen_interval = 700
    beacon_interval_obj = FilterPacket()
    dtim_period_obj = FilterPacket()
    validation = True
    packet_filter3 = "    Type/Subtype: Beacon (0x0008)"
    capture_filename = "test_query_wireless_stats_after_rejoin_TC19177"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    wait_time = 5
    ApWirelessOff(wifi_access_point, wait_time, logger)

    operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_dut.interfaces.wifi.wlan_get_stats()
    logger.info("****************Beacon Filter******************")
    packet_filter = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter, packet_filter3)[
        'packet_count']

    beacon_interval_ap = beacon_interval_obj.get_beacon_interval()
    if beacon_interval_ap is None:
        logger.info(f'Unable to find Beacon Interval={beacon_interval_ap}')
        assert False
    else:
        logger.info(f'\n\n *** Beacon Interval ={beacon_interval_ap} *** \n')

    packet_filter4 = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008) and (wlan.fixed.beacon == {beacon_interval_ap})'

    dtim_period_ap = dtim_period_obj.get_dtim_period()
    if dtim_period_ap is None:
        logger.info(f'Unable to find DTIM Period={dtim_period_ap}')
        assert False
    else:
        logger.info(f'\n\n *** DTIM Period ={dtim_period_ap} *** \n')

    packet_filter5 = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008) and (wlan.dtim.period == {dtim_period_ap})'

    logger.info(f"Access point Beacon interval -> {beacon_interval_ap},  DTIM period-> {dtim_period_ap}")

    logger.info(f"DUT Beacon interval -> {beacon_interval},  DTIM period-> {dtim_period}")
    assert operating_mode == 0, "Operating mode is not matching, expected is 0"

    assert beacon_interval == beacon_interval_ap, f"AP beacon interval received in wlan stats and actual beacon " \
                                                  f"interval of connected AP is not matched, e" \
                                                  f"xpected is {beacon_interval_ap}. But observed {beacon_interval} "
    assert dtim_period == dtim_period_ap, f"DTIM period received in wlan stats and actual DTIM " \
                                          f"interval of connected AP is not matched, e" \
                                          f"expected is {dtim_period_ap}. But observed {dtim_period} "

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_rtc_get_multiple_times_TC19179(
        wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold, logger
):
    capture_filename = "test_rtc_get_multiple_times_TC19179"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    ping_count = 10
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time_after_scan = 50
    listen_interval = 700
    set_time_sec = ((set_minutes * 60) + set_seconds)
    firmware_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Firmware version-> {firmware_version}")

    logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                wifi_dut.interfaces.wifi.scan(ssid=None)
                break
            except:
                logger.info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
    scan_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for scan -> {scan_time} seconds")
        logger.info(f"wait for {wait_time_after_scan} seconds")
    scan_logger_time1 = t.duration
    time.sleep(wait_time_after_scan)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    idle_time = wait_time_after_scan + scan_time + scan_logger_time1
    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after scan -> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} after scan "

        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance level ")

        logger.info("get_rtc is working fine after scan")
    scan_logger_time2 = t.duration

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                join_fail = 1
                # DUT connects to AP after join_ap API is executed
                logger.info("Joining the Wifi Access Point")
                wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                                 join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromPowerSave,
                                                 )
                join_fail = 0
                break
            except:
                logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        if join_fail:
            logger.info(f"Joining to the AP has failed")
            assert join_fail == 0, "Joining to the AP is failed"
        for count in range(1, 3):
            ip_fail = 1
            try:
                # DUT gets ipaddress through DHCP process after start_ip API is executed
                logger.info("DUT gets ipaddress through DHCP ")
                wifi_dut.interfaces.wifi.start_ip()
                ip_fail = 0
                break
            except:
                logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        if ip_fail:
            logger.info(f"DUT unable to get IP address")
            assert ip_fail == 0, "ip setting in DUT has failed"
    join_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for connecting to the AP, getting IP and ping for 10 sec  -> {join_time} seconds")
        logger.info(f"wait for 50 seconds")
    join_logger_time = t.duration
    wait_time_after_join = 50
    time.sleep(wait_time_after_join)

    idle_time = wait_time_after_scan + wait_time_after_join + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time
    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after join, ip-> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} after join, ip"
        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance level")
        logger.info("get_rtc is working fine after ip command")

    join_logger_time2 = t.duration
    with TimeMeasurer() as t:
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                            listen_interval=listen_interval)
        ping(device_ip, ping_count)

    power_save_time = t.duration

    with TimeMeasurer() as t:
        logger.info(
            f"Time taken for executing power save api, ping for {ping_count} packets -> {power_save_time} seconds")
        logger.info(f"wait for 50 seconds")
    powersave_logger_time = t.duration
    wait_time_after_powersave = 50
    time.sleep(wait_time_after_powersave)
    idle_time = wait_time_after_scan + wait_time_after_join + wait_time_after_powersave + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time + join_logger_time2 + power_save_time + powersave_logger_time

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec - idle_time

    logger.info(f"idle time after initiating set rtc after power save -> {idle_time}")
    assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is not " \
                                                                                          f"in tolerance leve" \
                                                                                          f"l. Time " \
                                                                                          f"difference observed is {time_dif} after power save"
    logger.info(
        f"Time difference observed between set time and get time is {time_dif} seconds, which is in tolerance level")
    logger.info("get_rtc is working fine after power save command is initiated")

    validation = True
    packet_filter1 = f'(wlan.ta == {mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_2SSL_1TCP_TX_testcaseTC19185(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, remote_socket_factory, cert1, cert2, logger
):
    listen_interval = 700
    list_sock = []
    capture_filename = "test_2SSL_1TCP_TX_testcaseTC19185"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    sock_port = 4999
    for sock_count in range(3):
        sock_port = sock_port + 2
        # Open ssl client socket in the DUT
        if sock_count == 0:
            ssl_server.interfaces.ssl.start_server(port=sock_port, server_cert=cert1[1], server_key=cert1[2])
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            cert_index = SocketOptions.CERT_INDEX0

            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=sock_port)
        elif sock_count == 1:
            ssl_server.interfaces.ssl.start_server(port=sock_port, server_cert=cert2[1], server_key=cert2[2])
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 1, f"socket id received is wrong, expected is 0"
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            cert_index = SocketOptions.CERT_INDEX1

            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=sock_port)
        else:
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            status = server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            assert sock == 2, f"socket id received is wrong, expected is 2"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket, server_port=sock_port)

        list_sock.append(sock)
    logger.info(f"SOCKET LIST{list_sock}")

    send_list = []
    pkt_count = 500
    buffer_length = 100
    data_size = 100
    for sock_id in list_sock:
        if sock_id == 2:
            th_start = Thread(target=tcp_socket_rx,
                              args=(remote_socket_factory, 1, pkt_count, data_size, logger), )
        else:
            th_start = Thread(target=ssl_socket_rx, args=(ssl_server, sock_id, pkt_count, buffer_length, logger), )
        send_list.append(th_start)
        th_start.start()

    wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                        time_interval=60,
                                                        number_of_pkts=pkt_count)

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock in range(3):
        logger.info(f"Closing socket_id->{sock}")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock}"
        logger.info(f"Successfully closed socket_id->{sock}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]
                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_2SSL_1TCP_RX_testcaseTC19187(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, remote_socket_factory, cert1, cert2, logger
):
    listen_interval = 700
    list_sock = []
    capture_filename = "test_2SSL_1TCP_TX_testcaseTC19187"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    sock_port = 4999
    for sock_count in range(3):
        sock_port = sock_port + 2
        # Open ssl client socket in the DUT
        if sock_count == 0:
            ssl_server.interfaces.ssl.start_server(port=sock_port, server_cert=cert1[1], server_key=cert1[2])
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            cert_index = SocketOptions.CERT_INDEX0

            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=sock_port)
        elif sock_count == 1:
            ssl_server.interfaces.ssl.start_server(port=sock_port, server_cert=cert2[1], server_key=cert2[2])
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 1, f"socket id received is wrong, expected is 0"
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            cert_index = SocketOptions.CERT_INDEX1

            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=sock_port)
        else:
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            status = server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            assert sock == 2, f"socket id received is wrong, expected is 2"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket, server_port=sock_port)

        list_sock.append(sock)

    socket_no = [1, 2, 3]
    for i in range(50):
        for socket in socket_no:
            buffer_length = 100
            pkt_count = 10
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
            )
            if socket < 3:
                ssl_server.interfaces.ssl.send_data(socket, pkt_count, buffer_length, message=tx_buffer)
            else:
                remote_socket_factory.interfaces.socket.sockets[0].send_data_tcp(tx_buffer, use_server_socket=True)

            socket_id = (socket - 1)
            buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=socket_id,
                                                                                data_len=buffer_length)

            assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock in list_sock:
        logger.info(f"Closing socket_id->{sock}")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock}"
        logger.info(f"Successfully closed socket_id->{sock}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ca_cert": ["ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_1ssl_2tcp_sockets_send_data_testcaseTC19188(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, remote_socket_factory, cert1, logger
):
    listen_interval = 700
    list_sock = []
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    capture_filename = "test_ssl_three_sockets_send_data_testcaseTC19188"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    sock_port = 4999
    for sock_count in range(3):
        sock_port = sock_port + 2
        # Open ssl client socket in the DUT
        if sock_count == 0:
            ssl_server.interfaces.ssl.start_server(port=sock_port, server_cert=cert1[1], server_key=cert1[2])
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            cert_index = SocketOptions.CERT_INDEX0

            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=sock_port)
        elif sock_count == 1:
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            status = server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            assert sock == 1, f"socket id received is wrong, expected is 1"
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket, server_port=sock_port)
        else:
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            status = server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            assert sock == 2, f"socket id received is wrong, expected is 2"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket, server_port=sock_port)

        list_sock.append(sock)
    logger.info(f"SOCKET LIST{list_sock}")

    pkt_count = 500
    buffer_length = 100
    data_size = 100
    send_list = []

    for sock_id in list_sock:
        if sock_id == 0:
            th_start = Thread(target=ssl_socket_rx, args=(ssl_server, sock_id, pkt_count, buffer_length, logger), )
        else:
            th_start = Thread(target=tcp_socket_rx,
                              args=(remote_socket_factory, sock_id, pkt_count, data_size, logger), )

        send_list.append(th_start)
        th_start.start()

    wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                        time_interval=60,
                                                        number_of_pkts=pkt_count)

    time.sleep(10)

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock in list_sock:
        logger.info(f"Closing socket_id->{sock}")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock}"
        logger.info(f"Successfully closed socket_id->{sock}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_tcp_three_sockets_send_data_testcaseTC19189(
        wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory, remote_socket, logger):
    ping_count = 5
    list_sock = []

    listen_interval = 700
    capture_filename = "test_tcp_three_sockets_send_data_testcaseTC19189"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    status = ping(device_ip, ping_count)
    assert status == 1
    port = 4999
    for sock in range(3):
        port = port + 2
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        time_limit = server_socket.time_limit = 3600
        status = server_socket.start_server(port=port, socket_type=SOCKET_TYPE_TCP)
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()

        if sock == 0:
            local_port = port
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock == 1:
            local_port = port
            assert sock == 1, f"socket id received is wrong, expected is 1"
        elif sock == 2:
            local_port = port
            assert sock == 2, f"socket id received is wrong, expected is 2"

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

        wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket)
        list_sock.append(sock)
    logger.info(f"SOCKET LIST{list_sock}")

    pkt_count = 500
    buffer_length = 100
    data_size = 100
    # send_list = []
    for sock_id in range(1, 4):
        th_start = threading.Thread(target=tcp_socket_rx,
                                    args=(remote_socket_factory, sock_id, pkt_count, data_size, logger), )
        th_start.start()

    wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                        time_interval=600,
                                                        number_of_pkts=pkt_count)

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock in list_sock:
        logger.info(f"Closing socket_id->{sock}")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock}"
        logger.info(f"Successfully closed socket_id->{sock}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.SNTPClient,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_sntp__TC19191(
        wifi_sniffer, wifi_dut, wifi_access_point, logger
):
    listen_interval = 700
    capture_filename = "test_sntp__TC19191"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    sntp_server_address = wifi_dut.interfaces.wifi.get_sntp_server_ip()
    wifi_dut.interfaces.wifi.sntp_create(server_ip=sntp_server_address)
    time.sleep(10)
    asynchronous_request_time = 0
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=asynchronous_request_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.SNTP_EVENT:
            sntp_event = event.event_data
            asynchronous_request_time = event.timestamp + 1
        else:
            assert 1, f"SNTP asynchronous event is not received by DUT after connection request was sent to SNTP server"
    sntp_status = int(sntp_event.split(b":")[1])
    assert sntp_status == 1, "SNTP status received in asynchronous message for SNTP connection request is wrong " \
                             "expected is 1 "

    command_type, sntp_time = wifi_dut.interfaces.wifi.get_sntp_time()
    assert command_type == 2, "Command type received for the body of get_sntp_time response is wrong, expected is 2"
    command_type, sntp_date_time = wifi_dut.interfaces.wifi.get_sntp_timedate()
    assert command_type == 3, "Command type received for the body of get_sntp_timedate response is wrong, expected is 3"
    command_type, ip_version, server_ip = wifi_dut.interfaces.wifi.get_sntp_server_info()
    assert command_type == 6, "Command type received for the body of get_sntp_server_info response is wrong, expected " \
                              "is 6"
    assert ip_version == 4, "Ip version received for the body of get_sntp_server_info response is wrong, expected " \
                            "is 4"
    assert server_ip == sntp_server_address, f"SNTP server ip address received for the body of get_sntp_server_info " \
                                             f"response is wrong, expected " \
                                             "is {sntp_server_address}"

    wifi_dut.interfaces.wifi.sntp_delete()
    time.sleep(5)
    events = wifi_dut.interfaces.wifi.get_async_events(since_time=asynchronous_request_time)
    for event in events:
        if event.event_type == RS9116AsyncEventType.SNTP_EVENT:
            sntp_event = event.event_data
        else:
            assert True, f"SNTP asynchronous event is not received by DUT after SNTP delete is initiated"
    sntp_status = int(sntp_event.split(b":")[1])
    assert sntp_status == 1, "SNTP status received in asynchronous message for SNTP delete request is wrong expected " \
                             "is 1 "
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    ntp_capture_list = get_ntp_list(wifi_sniffer, decryption_key, ["ntp"])
    if not len(ntp_capture_list):
        logger.info(f"NTP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                    f"sniffer file")
    assert len(ntp_capture_list) > 0, f"NTP packets are not captured or one of the 4-way handshake pkts are not " \
                                      f"captured in the sniffer file "

    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == device_ip):
            logger.info(f"SNTP response body received in the sniffer {ntp_pkt}")

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": "ca-chain.cert.pem",
        "set_send_feature_frame": True
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_socket_select_ssl_asynchronous_TC19192(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger
):
    listen_interval = 700
    capture_filename = "test_socket_select_ssl_asynchronous_TC19192"
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    since_time = 0
    for iteration in range(1, 26):
        logger.info(f"##############################Iteration count->{iteration}#######################")
        ssl_server.interfaces.ssl.send_data(1, 1, msg_length=buffer_length, message=tx_buffer)
        wifi_dut.interfaces.wifi.set_fd(socket_count=1)
        wifi_dut.interfaces.wifi.socket_select(0, select_timeout=60)
        # DUT receives data over tcp socket after execution of below api
        time.sleep(10)
        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
        assert len(events) != 0, "Socket select asynchronous event is not received"
        logger.info(f"Socket select event received")
        sock_list = []
        for event in events:
            if event.event_type == RS9116AsyncEventType.SOCKET_SELECT_EVENT:
                socket_select_event_payload = event.event_data
                since_time = event.timestamp + 1
                logger.info(f"Socket select event received with payload->{socket_select_event_payload}")
                sock_fd = int(socket_select_event_payload.split(b",")[1].split(b":")[1].strip(b"\r\n"))
                if sock_fd == 0:
                    logger.info(f"Socket fd received in socket select response is 0 which is not expected")
                assert sock_fd != 0, f"Socket fd received in socket select response is 0 which is not expected"
                sock_id = get_socket_id(sock_fd)
                if sock_id is not None:
                    sock_list.append(sock_id)
        if not (len(sock_list)):
            logger.info("Data is not received on any socket opened in the DUT even though sent by remote peer")
        assert len(sock_list) > 0, "Data is not received on any socket opened in the DUT"

        for sock in sock_list:
            logger.info(f"Data is received on the socket id {sock} opened in the DUT")
            buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=sock, data_len=buffer_length)
            if not (buffer_length == buffer_length_rx):
                logger.info(
                    f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                    f"not matched ")
            else:
                logger.info(
                    f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                    f"matched ")
            assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
            if not (tx_buffer.encode() == buffer_rx):
                logger.info(
                    f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                    f"is not matched ")
            else:
                logger.info(
                    f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                    f"is matched ")
            assert tx_buffer.encode() == buffer_rx, f"contents of data sent by remote peer and received on the socket " \
                                                    f"id {sock} opened in the DUT is not matched "
    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket in the dut"

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_synchronous_select_timeout_testcase_TC19198(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
):
    listen_interval = 700
    capture_filename = "test_ssl_synchronous_select_timeout_testcase_TC19198"
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    socket_select_timeout = 10

    for iteration in range(1, 11):
        logger.info(f"##############################Iteration count {iteration}##########################")
        wifi_dut.interfaces.wifi.set_fd(socket_count=1)

        with TimeMeasurer() as t:
            sock_fd = wifi_dut.interfaces.wifi.socket_select(0, select_timeout=socket_select_timeout,
                                                             asynchronous=0,
                                                             timeout=(socket_select_timeout + 2))
            if sock_fd == 0:
                logger.info("Socket select returned 0 when there is no data on the socket which is expected")
            assert sock_fd == 0, "Socket select response returned socket id even though there is no data on the " \
                                 "socket "

        socket_select_response_timeout = t.duration
        logger.info(
            f"Socket select API returned after {socket_select_response_timeout} seconds when there is no "
            f"data received on the opened socket when timeout given in the API is {socket_select_timeout}")

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket in the dut"

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_synchronous_select_timeout_testcase_TC19200(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
):
    listen_interval = 700
    capture_filename = "test_ssl_synchronous_select_timeout_testcase_TC19200"
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    tx_buffer = "12345678901234567890123456789012345678901234567890"
    buffer_length = len(tx_buffer)
    socket_select_timeout = 10

    for iteration in range(1, 26):
        logger.info(f"##############################Iteration count {iteration}##########################")
        ssl_server.interfaces.ssl.send_data(1, 1, msg_length=buffer_length, message=tx_buffer)
        wifi_dut.interfaces.wifi.set_fd(socket_count=1)
        sock_fd = wifi_dut.interfaces.wifi.socket_select(0, select_timeout=socket_select_timeout,
                                                         asynchronous=0,
                                                         timeout=(socket_select_timeout + 2))
        if sock_fd != 0:
            socket_no = get_socket_id(sock_fd)
            logger.info(f"Data is received on socket id {socket_no}")
        else:
            logger.info(f"Data is not received on socket id {sock} within time->{socket_select_timeout} seconds")
            assert False, f"Data is not received on socket id {sock} within time->{socket_select_timeout} seconds"

        logger.info(f"Data is received on the socket id {socket_no} opened in the DUT")
        buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=socket_no,
                                                                            data_len=buffer_length)
        if not (buffer_length == buffer_length_rx):
            logger.info(
                f"buffer length sent by remote peer and received on the socket id {socket_no} opened in the DUT is "
                f"not matched ")
        else:
            logger.info(
                f"buffer length sent by remote peer and received on the socket id {socket_no} opened in the DUT is "
                f"matched ")
        assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the socket id {socket_no} opened in the DUT is not matched "
        if not (tx_buffer.encode() == buffer_rx):
            logger.info(
                f"contents of data sent by remote peer and received on the socket id {socket_no} opened in the DUT "
                f"is not matched ")
        else:
            logger.info(
                f"contents of data sent by remote peer and received on the socket id {socket_no} opened in the DUT "
                f"is matched ")
        assert tx_buffer.encode() == buffer_rx, f"contents of data sent by remote peer and received on the socket " \
                                                f"id {socket_no} opened in the DUT is not matched "

    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket in the dut"

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"]
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [
                             (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"],
                              ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                               "mosquitto-utf.silabs.com.key.pem"]

                              )
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_three_sockets_tx_rx_data_testcaseTC19201(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
):
    capture_filename = "test_ssl_three_sockets_tx_rx_data_testcaseTC19201"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=700)

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])

    for sock_count in range(0, 3):
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif sock_count == 1:
            assert sock == 1, f"socket id received is wrong, expected is 1"
        else:
            assert sock == 2, f"socket id received is wrong, expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        if sock_count == 0:
            cert_index = SocketOptions.CERT_INDEX0
        elif sock_count == 1:
            cert_index = SocketOptions.CERT_INDEX1
        else:
            cert_index = SocketOptions.CERT_INDEX2
        logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)
        if sock_count == 0:
            socket_port = port1
        elif sock_count == 1:
            socket_port = port2
        else:
            socket_port = port3

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, socket_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    socket_no = [1, 2, 3]

    for iteration in range(1, 101):
        for socket in socket_no:
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
            )
            if socket < 3:
                # The api returns 100 bytes of random data
                data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                data_length = len(data_sent)
                logger.info(f"Sending data {data_sent} over socket_no->{socket - 1}")
                # DUT sends 100 bytes of data over ssl socket
                wifi_dut.interfaces.wifi.send_data(socket - 1, data_length, data_sent)
                server_socket_no = socket
                data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                logger.info(f"Data received on remote socket opened is {data_receive}")
                assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                logger.info("Data sent by DUT and received on server is matching")
            else:
                ssl_server.interfaces.ssl.send_data(socket, pkt_count, buffer_length, message=tx_buffer)
                socket_id = (socket - 1)
                buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.receive_from(socket_id=socket_id,
                                                                                    data_len=buffer_length)
                if not (buffer_length == buffer_length_rx):
                    logger.info(
                        f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                        f"not matched on socket_id->{socket_id}")
                else:
                    logger.info(
                        f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is "
                        f"matched on socket_id->{socket_id}")
                assert buffer_length == buffer_length_rx, f"buffer length sent by remote peer and received on the " \
                                                          f"socket id {sock} opened in the DUT is not matched "
                if not (tx_buffer.encode() == buffer_rx):
                    logger.info(
                        f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                        f"is not matched on socket_id->{socket_id}")
                else:
                    logger.info(
                        f"contents of data sent by remote peer and received on the socket id {sock} opened in the DUT "
                        f"is matched on socket_id->{socket_id}")
                assert tx_buffer.encode() == buffer_rx, f"contents of data sent by remote peer and received on the " \
                                                        f"socket " \
                                                        f"id {sock} opened in the DUT is not matched on socket_id->{socket_id} "

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["start_field.pem", "ca-chain.cert.pem"],
        "client_cert": ["client-certificate.crt", False],
        "client_key": ["private-key.key", False]
    }
)
@pytest.mark.parametrize("cert2",
                         [["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                           "mosquitto-utf.silabs.com.key.pem"]],

                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_ssl_AWS_testcaseTC19202(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, remote_socket_factory, cert2, logger
):
    listen_interval = 700
    capture_filename = "test_ssl_AWS_testcaseTC19202"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)
    port1 = 8883
    port2 = ssl_server.interfaces.ssl.config['device_port3']
    port3 = 5005

    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

    # Tcperver started
    server_socket = remote_socket_factory.interfaces.socket.create_socket()
    server_socket.time_limit = 3600
    status = server_socket.start_server(port=port3, socket_type=SOCKET_TYPE_TCP)

    for sock_count in range(0, 3):
        if sock_count < 2:
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       eval("SocketOptions.CERT_INDEX" + str(sock_count)))
        else:
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)
        if sock_count == 0:
            socket_port = port1
            local_port = randint(5001, 20000)
        elif sock_count == 1:
            socket_port = port2
            local_port = randint(20001, 40000)
        else:
            socket_port = port3
            local_port = randint(40001, 60000)

        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

        if sock_count == 0:
            result = wifi_dut.interfaces.wifi.dns_get(4, "a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com", "NULL",
                                                      "NULL")
            logger.info(f"dns response is {result}")
            server_ip = result.split(b"\n")[1].split(b":")[1].decode()
            for count in range(0, 3):
                try:
                    wifi_dut.interfaces.wifi.connect(sock, server_ip, socket_port)
                    break
                except:
                    logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
                    time.sleep(1)
                    if count == 2:
                        raise
            logger.info(f"Connection to AWS server on socket id->{sock} is successful")
        elif sock_count == 1:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
        elif sock_count == 2:
            wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket)

    pkt_count = 500
    buffer_length = 100
    data_size = 100

    list_sock = [0, 1, 2]
    send_list = []
    for sock_id in list_sock:
        if sock_id == 0:
            continue
        elif sock_id == 1:
            sock_id = 0
            th_start = Thread(target=ssl_socket_rx, args=(ssl_server, sock_id, pkt_count, buffer_length, logger), )

        elif sock_id == 2:
            sock_id = 1
            th_start = Thread(target=tcp_socket_rx,
                              args=(remote_socket_factory, 1, pkt_count, buffer_length, logger), )

        send_list.append(th_start)
        th_start.start()

    result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                                 time_interval=600,
                                                                 number_of_pkts=pkt_count)
    socket_list = result
    bytes_sent = (pkt_count * buffer_length)
    bytes_sent_ssl = (pkt_count * buffer_length)
    sock_count = 0
    for socket_stats in socket_list:
        if sock_count == 0:
            continue
        elif sock_count == 1:
            logger.info(
                f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
            assert bytes_sent_ssl == socket_stats[0], f"Number of bytes initiated by test and actually sent by DUT " \
                                                      f"are not " \
                                                      f"matched. Initiated->{bytes_sent_ssl} bytes. But Sent by DUT->{socket_stats[0]} bytes "
        sock_count = sock_count + 1
    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
    assert bytes_sent_ssl == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                             f"not matched on socket_id->0"

    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
            'ssid': 'TESTAPONE',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 6,

        },
        1: {
            'ssid': 'TESTAPTWO',
            'security': 'WPA2',
            'passphrase': '1234567890',
            'channel': 6,
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_autojoin_functionality_with_Two_APs_TC19181(wifi_sniffer, wifi_access_points, wifi_dut, logger):
    try:
        logger.info(" ====== configuring the sniffer with access point channel ====== ")

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)

        logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_autojoin_functionality_with_Two_APs_TC19181_1')
        listen_interval = 700

        wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[0].interfaces.wifi.ssid, channel=6)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_points[0])
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        logger.info(f"Initiating ping to DUT ip '{device_ip} '")
        status = ping(device_ip, 10)
        assert status == 1, "DUT not responding for ping request......"
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_dut.interfaces.wifi.config_save()
        wifi_dut.interfaces.wifi.config_enable(config=1)
        for i in range(0, 2):
            logger.info(f"RETRYING FOR {i} times")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(3)
            try:
                wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
            except WlanError as e:
                if e.error_code == 0x5a5a:
                    assert e.error_code == 0x5a5a
                    break

        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                            listen_interval=listen_interval)

        wifi_dut.interfaces.wifi.config_enable(config=0)
        wifi_dut.interfaces.wifi.wireless_deinit()
        time.sleep(3)
        wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        eapol = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
        assert eapol, "packets are not captured in the sniffer"

        wifi_dut.interfaces.wifi.associated = False
        logger.info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)

        logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_autojoin_functionality_with_Two_APs_TC19181_2')

        ap_mac_two = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[1].interfaces.wifi.ssid, channel=6)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_points[1])
        logger.info("JOIN TO second AP IS SCUCCESSFUL")
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
        ping(device_ip, 10)

        wifi_dut.interfaces.wifi.leave()

        logger.info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        eapol = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
        assert eapol, "packets are not captured in the sniffer"
    except Exception as e:
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        raise e
    finally:
        logger.info("Disable store configuration")
        wifi_dut.interfaces.wifi.config_enable(config=0)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
            'ssid': 'TESTONE',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 6,

        },
        1: {
            'ssid': 'TESTTWO',
            'security': 'WPA2',
            'passphrase': '123123321',
            'channel': 6,
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
@pytest.mark.end_state("wifi_access_points", wifi="ap_disabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_DNS_Functionality_with_Multiple_APs_TC19183(wifi_sniffer, wifi_access_points, wifi_dut, domain_name, logger):
    validation = True
    listen_interval = 700

    for iteration in range(0, len(wifi_access_points)):
        logger.info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_points[iteration].interfaces.wifi.channel)

        logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_DNS_Functionality_with_Multiple_APs_TC19183')
        wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[iteration].interfaces.wifi.ssid, channel=6)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_points[iteration])
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
        status = ping(device_ip, 10)
        assert status == 1, "DUT not responding for ping request......"

        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                            listen_interval=listen_interval)

        result = wifi_dut.interfaces.wifi.dns_get(4, domain_name, "NULL",
                                                  "NULL")
        logger.info(f"dns response is {result}")
        server_ip = result.split(b"\n")[1].split(b":")[1].decode()
        logger.info(f"server_ip {server_ip}")

        wifi_dut.interfaces.wifi.leave()

        logger.info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_access_points[iteration].interfaces.wifi.stop_ap()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
            'ssid': 'TESTAPONE',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 6,

        },
        1: {
            'ssid': 'TESTAPONE',
            'security': 'WPA2',
            'passphrase': '987654321',
            'channel': 6,
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disable_store_config", "disassociated"])
def test_AutoJoin_Functionality_with_two_APs_with_different_PSK_TC19194(wifi_sniffer, wifi_access_points, wifi_dut,
                                                                         logger):
    try:
        logger.info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)

        logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_AutoJoin_Functionality_with_two_APs_with_different_PSK_TC19194')
        listen_interval = 700
        logger.info(" Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=20)
        wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[0].interfaces.wifi.ssid, channel=6)

        join = 1
        for count in range(3):
            try:
                wifi_dut.interfaces.wifi.join_ap(wifi_access_points[0], timeout=20)
                time.sleep(3)
                join = 0
                break
            except Exception as e:
                if ('0x8') in str(e):
                    wifi_access_points[1].interfaces.wifi.stop_ap()
                    time.sleep(5)
            logger.info(f"Connection failure{count}")
        assert join == 0, "Connection failure"
        ip = 1
        for count in range(0, 2):
            try:
                logger.info("DUT gets ipaddress through DHCP ")
                wifi_dut.interfaces.wifi.start_ip()
                ip = 0
                break
            except:
                logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        assert ip == 0, "ip setting in DUT has failed"

        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                            listen_interval=listen_interval)
        time.sleep(2)
        wifi_dut.interfaces.wifi.config_save()
        wifi_dut.interfaces.wifi.config_enable(config=1)
        error_code = 0
        for i in range(3):
            logger.info(f"RETRYING FOR {i} times")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(3)
            try:
                wifi_dut.interfaces.wifi.dut_init(timeout=20, retries=0)
            except WlanError as e:
                if e.error_code == 0x5a5a:
                    assert e.error_code == 0x5a5a, "Expected error code is 0x5a5a, received wrong error code"
                    error_code = 1
                    break

        time.sleep(3)
        assert error_code == 1, "Expected error code is 0x5a5a, received wrong error code"
        logger.info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        logger.info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)

        logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_AutoJoin_Functionality_with_two_APs_with_different_PSK_TC19194')
        wifi_access_points[1].interfaces.wifi.start_ap()
        time.sleep(5)
        wifi_access_points[0].interfaces.wifi.stop_ap()

        wifi_dut.interfaces.wifi.wireless_deinit()
        time.sleep(3)
        with pytest.raises(WlanError) as e:
            wifi_dut.interfaces.wifi.dut_init(timeout=50, retries=0)
        # Deauthentication received from AP
        assert e.value.error_code == 0x0008, "Observed wrong error code.expected is 0x0008"
        logger.info("joining failed to 2nd AP which has different PSK")
        logger.info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        raise e
    finally:
        logger.info("Disable store configuration")
        wifi_dut.interfaces.wifi.config_enable(config=0)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
            'ssid': 'TESTAPONE95',
            'security': 'WPA2',
            'passphrase': '123456789',
            'channel': 7,

        },
        1: {
            'ssid': 'TESTAPTWO95',
            'security': 'WPA2',
            'passphrase': '123456789',
            'channel': 7,
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "band": 0,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_AutoJoin_Functionality_with_two_APs_with_different_SSID_TC19195(wifi_sniffer, wifi_dut, wifi_access_points,
                                                                          wifi_client, logger):
    try:
        logger.info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)

        logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_AutoJoin_Functionality_with_two_APs_with_different_SSID_TC19195')
        listen_interval = 700
        logger.info(" Enabling rejoin...")
        wifi_dut.interfaces.wifi.rejoin()
        wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[0].interfaces.wifi.ssid, channel=7)
        join = 1
        for i in range(3):
            try:
                wifi_dut.interfaces.wifi.join_ap(wifi_access_points[0])
                time.sleep(3)
                join = 0
                break
            except:
                logger.info(f"Connection failure{i}")
        assert join == 0, "Connection failure"
        ip = 1
        for count in range(0, 2):
            try:
                logger.info("DUT gets ipaddress through DHCP ")
                wifi_dut.interfaces.wifi.start_ip()
                ip = 0
                break
            except:
                logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        assert ip == 0, "ip setting in DUT has failed"

        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                            listen_interval=listen_interval)

        wifi_dut.interfaces.wifi.config_save()
        wifi_dut.interfaces.wifi.config_enable(config=1)
        for i in range(0, 2):
            logger.info(f"RETRYING FOR {i} times")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(3)
            try:
                wifi_dut.interfaces.wifi.dut_init(timeout=20, retries=0)
            except WlanError as e:
                if e.error_code == 0x5a5a:
                    assert e.error_code == 0x5a5a,"Expected error code is 0x5a5a, received wrong error code"
                    break
        time.sleep(3)
        wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                            listen_interval=listen_interval)

        logger.info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        logger.info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)

        logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_AutoJoin_Functionality_with_two_APs_with_different_SSID_TC19195')
        wifi_access_points[1].interfaces.wifi.start_ap()
        time.sleep(5)
        wifi_access_points[0].interfaces.wifi.stop_ap()

        wifi_dut.interfaces.wifi.wireless_deinit()
        time.sleep(3)
        with pytest.raises(WlanError) as e:
            wifi_dut.interfaces.wifi.dut_init(timeout=20, retries=0)
        # access point not found/rejoin failure
        assert e.value.error_code == 0x0003 or e.value.error_code == 0x0019, "Observed wrong error code"
        logger.info("joining failed to 2nd AP which has different SSID")
        wifi_dut.interfaces.wifi.inited = True
        wifi_dut.interfaces.wifi.associated = False

        ap_mac_two = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[1].interfaces.wifi.ssid, channel=7)

        join = 1
        for i in range(3):
            try:
                wifi_dut.interfaces.wifi.join_ap(wifi_access_points[1])
                time.sleep(3)
                join = 0
                break
            except:
                logger.info(f"Connection failure{i}")
        assert join == 0, "Connection failure"
        logger.info("JOIN TO second AP IS SCUCCESSFUL")
        time.sleep(3)
        ip = 1
        for count in range(0, 2):
            try:
                logger.info("DUT gets ipaddress through DHCP ")
                wifi_dut.interfaces.wifi.start_ip()
                ip = 0
                break
            except:
                logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        assert ip == 0, "ip setting in DUT has failed"

        wifi_dut.interfaces.wifi.config_save()
        wifi_dut.interfaces.wifi.config_enable(config=1)
        for i in range(0, 2):
            logger.info(f"RETRYING FOR {i} times")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(3)
            try:
                wifi_dut.interfaces.wifi.dut_init(timeout=20, retries=0)
            except WlanError as e:
                if e.error_code == 0x5a5a:
                    assert e.error_code == 0x5a5a,"Expected error code is 0x5a5a, received wrong error code"
                    break

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        time.sleep(2)
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        raise e
    finally:
        logger.info("Disable store configuration")
        wifi_dut.interfaces.wifi.config_enable(config=0)
        wifi_access_points[1].interfaces.wifi.stop_ap()
        time.sleep(2)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem"],
        "client_cert": ["client-certificate.crt"],
        "client_key": ["private-key.key"],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("domain_name", ["a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "close_sockets"])
def test_SSL_Connection_when_the_Date_RTCTimer_is_expired_TC19199(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, domain_name, logger):
    capture_filename = "test_SSL_Connection_when_the_Date_RTCTimer_is_expired_TC19199"

    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    port = 8883
    ping_count = 10
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2000
    set_week_day = 3
    wait_time = 100
    listen_interval = 700
    set_time_sec = ((set_minutes * 60) + set_seconds)

    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip = 1
    for count in range(0, 2):
        try:
            logger.info("DUT gets ipaddress through DHCP ")
            ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    assert ip == 0, "ip setting in DUT has failed"

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

    wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                        RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                        listen_interval=listen_interval)

    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec - wait_time
    logger.info(f"time diff between set and get rtc'{time_dif}'")

    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"

    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)

    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                               SocketOptions.CERT_INDEX0)

    local_port = randint(40001, 50000)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

    result = wifi_dut.interfaces.wifi.dns_get(4, domain_name, "NULL",
                                              "NULL")
    logger.info(f"dns response is {result}")
    server_ip = result.split(b"\n")[1].split(b":")[1].decode()
    logger.info(f"server_ip {server_ip}")

    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.connect(sock, server_ip, port)
    assert exc_info.value.error_code == 0x00D2, "DUT sent wrong error code, expected is 0x00D2"

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened tcp socket in the dut"

    wifi_dut.interfaces.wifi.leave()

    logger.info("Stop Sniffer finally")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem"],
        "client_cert": ["client-certificate.crt"],
        "client_key": ["private-key.key"],
    }
)
@pytest.mark.store_config
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "disable_store_config"])
def test_TC19138_feature_test(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, remote_socket, domain_name,
                              logger):
    ping_count = 10
    listen_interval = 700
    capture_filename = "test_TC19138_feature_test"
    rejoin_params = [40, 6, 40, 0]

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval, rejoin_params=rejoin_params)
    port = 8883
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, 10)
    assert status == 1, "DUT not responding for ping request......"

    wifi_dut.interfaces.wifi.config_save()
    wifi_dut.interfaces.wifi.config_enable(config=1)

    for i in range(0, 10):
        logger.info(f"Repeating Scenario for {i} time")
        for i in range(0, 2):
            logger.info(f"RETRYING FOR {i} times")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(3)
            try:
                wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
                # time.sleep(5)
            except WlanError as e:
                if e.error_code == 0x5a5a:
                    assert e.error_code == 0x5a5a
                    break

        logger.info(f"Initiating ping to DUT ip {device_ip} after auto join is successful")
        ping(device_ip, ping_count)
        #
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        #
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)

        wifi_dut.interfaces.wifi.bind(sock, device_ip, port)
        result = wifi_dut.interfaces.wifi.dns_get(4, domain_name, "NULL",
                                                  "NULL")
        logger.info(f"dns response is {result}")
        server_ip = result.split(b"\n")[1].split(b":")[1].decode()
        logger.info(f"server_ip {server_ip}")
        wifi_dut.interfaces.wifi.connect(sock, server_ip, port)

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket in the dut"

    wifi_dut.interfaces.wifi.config_enable(config=0)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    packet_filter2 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                     f'and wlan.sa == {dut_mac_address} and wlan.da == {bssid}'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    pwr = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
    assert pwr, "packets are not captured in the sniffer"


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        # "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem"],
        "client_cert": ["client-certificate.crt"],
        "client_key": ["private-key.key"],
    }
)
@pytest.mark.store_config
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "disable_store_config"])
def test_TC19140_auto_connection_reconnection_after_reset(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                          remote_socket, domain_name, logger):
    ping_count = 10
    listen_interval = 700
    capture_filename = "test_TC19140_auto_connection_reconnection_after_reset"
    rejoin_params = [40, 6, 40, 0]

    power_save = 1
    for count in range(3):
        try:
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8,
                                                RS9116PowerSaveProcedureTypes.MaxPowerSave)
            power_save = 0
            break
        except:
            time.sleep(5)
            logger.info(f"Retry_count:{count}")
    assert power_save == 0

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval, rejoin_params=rejoin_params)
    port = 8883
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, 10)
    assert status == 1, "DUT not responding for ping request......"

    wifi_dut.interfaces.wifi.config_save()
    wifi_dut.interfaces.wifi.config_enable(config=1)

    for i in range(0, 10):
        logger.info(f"Repeating Scenario for {i} time")
        for i in range(0, 2):
            logger.info(f"RETRYING FOR {i} times")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(3)
            try:
                wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
                # time.sleep(5)
            except WlanError as e:
                if e.error_code == 0x5a5a:
                    assert e.error_code == 0x5a5a
                    break

        logger.info(f"Initiating ping to DUT ip {device_ip} after auto join is successful")
        status = ping(device_ip, 10)
        assert status == 1, "DUT not responding for ping request......"
        #
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.MaxPowerSave)
        #
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)

        wifi_dut.interfaces.wifi.bind(sock, device_ip, port)
        result = wifi_dut.interfaces.wifi.dns_get(4, domain_name, "NULL",
                                                  "NULL")
        logger.info(f"dns response is {result}")
        server_ip = result.split(b"\n")[1].split(b":")[1].decode()
        logger.info(f"server_ip {server_ip}")
        wifi_dut.interfaces.wifi.connect(sock, server_ip, port)

        for i in range(0, 2):
            logger.info(f"RETRYING FOR {i} times")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(3)
            try:
                wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
                # time.sleep(5)
            except WlanError as e:
                if e.error_code == 0x5a5a:
                    assert e.error_code == 0x5a5a
                    break

        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)

        result = wifi_dut.interfaces.wifi.dns_get(4, domain_name, "NULL",
                                                  "NULL")
        logger.info(f"dns response is {result}")
        server_ip = result.split(b"\n")[1].split(b":")[1].decode()
        logger.info(f"server_ip {server_ip}")
        wifi_dut.interfaces.wifi.connect(sock, server_ip, port)

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket in the dut"
        # wifi_dut.interfaces.wifi.config_enable(config=0)
        # wifi_dut.interfaces.wifi.leave()

    wifi_dut.interfaces.wifi.config_enable(config=0)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    packet_filter2 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                     f'and wlan.sa == {dut_mac_address} and wlan.da == {bssid}'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    pwr = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
    assert pwr, "packets are not captured in the sniffer"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem", "aws_root_cert.crt"],
        "client_cert": ["client-certificate.crt", "A0E1010000000411_cat.crt"],
        "client_key": ["private-key.key", "A0E1010000000411_device.key"],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("domain_name", [
    ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com", "a1ctxhjnkhtvqq.iot.us-east-2.amazonaws.com"], ])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_TC19186_awscloud_with_different_certificate(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, remote_socket, domain_name, logger
):
    ping_count = 10
    listen_interval = 700
    sock_port = 8883
    capture_filename = "test_TC19186_awscloud_with_different_certificate"
    domains = len(domain_name)
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, 10)
    assert status == 1, "DUT not responding for ping request......"

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    for index in range(0, domains):
        if index == 0:
            port = randint(40001, 40100)
        if index == 1:
            port = randint(50001, 50100)
        if index == 2:
            port = randint(50101, 60000)
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   eval("SocketOptions.CERT_INDEX" + str(index)))

        wifi_dut.interfaces.wifi.bind(sock, device_ip, port)

        result = wifi_dut.interfaces.wifi.dns_get(4, domain_name[index], "NULL",
                                                  "NULL")
        logger.info(f"dns response is {result}")
        server_ip = result.split(b"\n")[1].split(b":")[1].decode()

        wifi_dut.interfaces.wifi.connect(sock, server_ip, sock_port)

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened tcp socket in the dut"

    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    packet_filter2 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                     f'and wlan.sa == {dut_mac_address} and wlan.da == {bssid}'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    pwr = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
    assert pwr, "packets are not captured in the sniffer"


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["ca-chain.cert.pem", "start_field.pem", "aws_root_cert.crt"],
        "client_cert": [False, "client-certificate.crt", "A0E1010000000411_cat.crt"],
        "client_key": [False, "private-key.key", "A0E1010000000411_device.key"],
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.parametrize("domain_name", [
    ["a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com", "a1ctxhjnkhtvqq.iot.us-east-2.amazonaws.com"], ])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "close_sockets", "disassociated"])
def test_1openssl_2AWS_C19151(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, domain_name, cert1, logger):
    ping_count = 10
    capture_filename = "test_1openssl_2AWS_C19151"
    listen_interval = 700
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                  listen_interval_feature=True,
                                  listen_interval=listen_interval)

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f'AP BSSID = {bssid}')

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
    for sock_count in range(3):
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)

        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   eval("SocketOptions.CERT_INDEX" + str(sock_count)))
        if sock_count == 0:
            local_port = port1
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=local_port)
        else:
            socket_port = 8883
            local_port = randint(40001, 50000)
            index = sock_count - 1
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            result = wifi_dut.interfaces.wifi.dns_get(4, domain_name[index], "NULL",
                                                      "NULL")
            logger.info(f"dns response is {result}")
            server_ip = result.split(b"\n")[1].split(b":")[1].decode()
            for count in range(0, 3):
                try:
                    wifi_dut.interfaces.wifi.connect(sock, server_ip, socket_port)
                    break
                except:
                    logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
                    time.sleep(1)
                    if count == 2:
                        raise
            logger.info(f"Connection to AWS server on socket id->{sock} is successful")
    for sock_count in range(3):
        logger.info(f"Closing socket_id->{sock_count}")
        wifi_dut.interfaces.wifi.close_socket(sock_count)

    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    packet_filter2 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
                     f'and wlan.sa == {dut_mac_address} and wlan.da == {bssid}'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")

    pwr = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
    assert pwr, "packets are not captured in the sniffer"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_rtc_get_multiple_times_TC19178(
        wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold, logger
):
    capture_filename = "test_rtc_get_multiple_times_TC19178"
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    ping_count = 10
    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time_after_scan = 50
    listen_interval = 700
    set_time_sec = ((set_minutes * 60) + set_seconds)
    firmware_version = wifi_dut.interfaces.wifi.version()
    logger.info(f"Firmware version-> {firmware_version}")

    logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)

    with TimeMeasurer() as t:
        for count in range(1, 3):
            try:
                wifi_dut.interfaces.wifi.scan(ssid=None)
                break
            except:
                logger.info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
                time.sleep(1)
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger.info(f"DUT MAC_Address: {mac_address}")
    scan_time = t.duration
    with TimeMeasurer() as t:
        logger.info(f"Time taken for scan -> {scan_time} seconds")
        logger.info(f"wait for {wait_time_after_scan} seconds")
    scan_logger_time1 = t.duration
    time.sleep(wait_time_after_scan)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    idle_time = wait_time_after_scan + scan_time + scan_logger_time1
    time_dif = get_time_sec - set_time_sec - idle_time

    with TimeMeasurer() as t:
        logger.info(f"idle time after initiating set rtc after scan -> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (time_dif <= tolerance_threshold[1]), f"get time updated is " \
                                                                                              f"not in tolerance " \
                                                                                              f"level. Time " \
                                                                                              f"difference observed is {time_dif} after scan "

        logger.info(
            f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance level ")

        logger.info("get_rtc is working fine after scan")

    validation = True
    packet_filter1 = f'(wlan.ta == {mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem"],
        "client_cert": ["client-certificate.crt"],
        "client_key": ["private-key.key"],
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0
    }
)
@pytest.mark.store_config
@pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "clear_certs"])
def test_Stored_AP_Powered_Off_After_Initial_Connection_C19146(wifi_sniffer, wifi_dut, wifi_access_point, domain_name,
                                                               switch, logger):
    port = 8883
    capture_filename = "test_Stored_AP_Powered_Off_After_Initial_Connection_C19146"
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    exception_count = 0
    for iter in range(10):
        logger.info(f"Iteration of testcase for {iter}th time")
        try:
            power_save = 1
            for count in range(3):
                try:
                    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8,
                                                        RS9116PowerSaveProcedureTypes.MaxPowerSave)
                    power_save = 0
                    break
                except:
                    time.sleep(5)
                    logger.info(f"Retry_count:{count}")
            assert power_save == 0

            time.sleep(5)

            wifi_dut.interfaces.wifi.scan(ssid=None)

            rejoin_params = [0, 6, 40, 0]

            wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_params[0],
                                            scan_interval=rejoin_params[1],
                                            beacon_missedcount=rejoin_params[2],
                                            first_time_retry=rejoin_params[3])

            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

            ip_fetch = False
            for i in range(3):
                try:
                    ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
                    ip_fetch = True
                    break
                except:
                    time.sleep(5)
                    logger.info(f"Except block{i}")

            assert ip_fetch == True, "IP FETCH FAILED"

            mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger.info(f"DUT MAC_Address: {mac_address}")

            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
            #
            wifi_dut.interfaces.wifi.config_save()
            wifi_dut.interfaces.wifi.config_enable(config=1)

            for i in range(0, 2):
                logger.info(f"RETRYING FOR {i} times")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(3)
                try:
                    wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
                except WlanError as e:
                    if e.error_code == 0x5a5a:
                        assert e.error_code == 0x5a5a
                        break

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, "Socket id received is wrong. expected is 0"

            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)

            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)

            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       SocketOptions.CERT_INDEX0)

            local_port = randint(40001, 50000)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

            result = wifi_dut.interfaces.wifi.dns_get(4, domain_name, "NULL",
                                                      "NULL")
            logger.info(f"dns response is {result}")
            server_ip = result.split(b"\n")[1].split(b":")[1].decode()
            logger.info(f"server_ip {server_ip}")

            check = 0
            for i in range(2):
                try:
                    wifi_dut.interfaces.wifi.connect(sock, server_ip, port)
                    check = 1
                    break
                except:
                    logger.info(f"Connection failed")
            assert check == 1, "Connect failed"
            sleep_time = 3060
            thread = Thread(target=pdu_switch, args=(switch, sleep_time, logger), )
            thread.start()
            sw = Stopwatch()
            while sw.elapsed_sec < 4200:
                if (sw.elapsed_sec >= 2100) and (sw.elapsed_sec <= 2110):
                    wifi_dut.interfaces.wifi.wireless_deinit()

                    with pytest.raises(WlanError) as e:
                        wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
                    assert e.value.error_code == 0x0003, "Observed wrong error code"

                if sw.elapsed_sec >= 3140:
                    wifi_dut.interfaces.wifi.wireless_deinit()
                    time.sleep(3)
                    try:
                        wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
                    except WlanError as e:
                        if e.error_code == 0x5a5a:
                            assert e.error_code == 0x5a5a
                            break

        except Exception as e:
            if ('0xfffffffd' in str(e)) or ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or (
                    "0xFFFFFFD5" in str(e)):
                logger.info("Initiating reset for device cleanup")
                wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(10)
                wifi_dut.interfaces.wifi.associated = True
                logger.info("Initializing the DUT")
                wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9, retries=1)
                time.sleep(5)
                exception_count += 1
        finally:
            wifi_dut.interfaces.wifi.leave()
            wifi_dut.interfaces.wifi.config_enable(config=0)
            get_state = switch.interfaces.pdu_switch.get_state()
            if get_state == False:
                switch.interfaces.pdu_switch.turn_on(delay=60)

    assert exception_count <= 3, "Failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    validation = True
    packet_filter1 = f'(wlan.ta == {mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem"],
        "client_cert": ["client-certificate.crt"],
        "client_key": ["private-key.key"],
        "rejoin_max_retry": 0,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0
    }
)
@pytest.mark.store_config
@pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "clear_certs"])
def test_Stored_AP_Powered_OFF_during_boot_C19145(wifi_sniffer, wifi_dut, wifi_access_point, domain_name, switch,
                                                  logger):
    port = 8883
    capture_filename = "test_C19145"
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
    exception_count = 0
    listen_interval = 700
    for iter in range(1):
        logger.info(f"Iteration of testcase for {iter}th time")
        try:
            power_save = 1
            for count in range(3):
                try:
                    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8,
                                                        RS9116PowerSaveProcedureTypes.MaxPowerSave)
                    power_save = 0
                    break
                except:
                    time.sleep(5)
                    logger.info(f"Retry_count:{count}")
            assert power_save == 0

            time.sleep(5)

            wifi_dut.interfaces.wifi.scan(ssid=None)

            rejoin_params = [0, 6, 40, 0]

            wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_params[0],
                                            scan_interval=rejoin_params[1],
                                            beacon_missedcount=rejoin_params[2],
                                            first_time_retry=rejoin_params[3])

            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            time.sleep(2)

            ip_fetch = False
            for i in range(3):
                try:
                    ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
                    ip_fetch = True
                    break
                except:
                    time.sleep(5)
                    logger.info(f"Except block{i}")

            assert ip_fetch == True, "IP FETCH FAILED"

            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
            #
            wifi_dut.interfaces.wifi.config_save()
            wifi_dut.interfaces.wifi.config_enable(config=1)

            for i in range(0, 2):
                logger.info(f"RETRYING FOR {i} times")
                wifi_dut.interfaces.wifi.wireless_deinit()
                time.sleep(3)
                try:
                    wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
                except WlanError as e:
                    if e.error_code == 0x5a5a:
                        assert e.error_code == 0x5a5a
                        break

            wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                                RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                                listen_interval=listen_interval)

            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, "Socket id received is wrong. expected is 0"

            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)

            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                       SocketOptions.TCP_MAX_RETRY)

            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       SocketOptions.CERT_INDEX0)

            local_port = randint(40001, 50000)
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

            result = wifi_dut.interfaces.wifi.dns_get(4, domain_name, "NULL",
                                                      "NULL")
            logger.info(f"dns response is {result}")
            server_ip = result.split(b"\n")[1].split(b":")[1].decode()
            logger.info(f"server_ip {server_ip}")

            check = 0
            for i in range(2):
                try:
                    wifi_dut.interfaces.wifi.connect(sock, server_ip, port)
                    check = 1
                    break
                except:
                    logger.info(f"Connection failed")

            assert check == 1, "Connect failed"

            sleep_time = 3060
            thread = Thread(target=pdu_switch, args=(switch, sleep_time, logger), )
            thread.start()
            sw = Stopwatch()
            while sw.elapsed_sec < 4200:
                if (sw.elapsed_sec >= 2100) and (sw.elapsed_sec <= 2110):
                    wifi_dut.interfaces.wifi.wireless_deinit()

                    with pytest.raises(WlanError) as e:
                        wifi_dut.interfaces.wifi.dut_init(timeout=100, retries=0)
                    assert e.value.error_code == 0x0003, "Observed wrong error code"

            logger.info("ENDED THE TESTCASE")

        except Exception as e:
            if ('0xfffffffd' in str(e)) or ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or (
                    "0xFFFFFFD5" in str(e)):
                logger.info("Initiating reset for device cleanup")
                wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(10)
                wifi_dut.interfaces.wifi.associated = True
                logger.info("Initializing the DUT")
                wifi_dut.interfaces.wifi.wireless_init(oper_mode=0, coex_mode=9, retries=1)
                time.sleep(5)
                exception_count += 1
        finally:
            wifi_dut.interfaces.wifi.leave()
            wifi_dut.interfaces.wifi.config_enable(config=0)
            get_state = switch.interfaces.pdu_switch.get_state()
            if get_state == False:
                switch.interfaces.pdu_switch.turn_on(delay=60)

    assert exception_count <= 3, "Failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    validation = True
    packet_filter1 = f'(wlan.ta == {mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")
