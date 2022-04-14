# Test author: Vinod.G
# Test suite: WLAN_Dynamic_Load_Certificate_GA
import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116PowerSaveProcedureTypes,
    SocketOptions,
    DeviceConstants,
    )
from utf.interfaces.wifi import WlanError
from utf.utils import get_tls_certificate_dir
from utf.utils.iperf.iperf_utils import ping
from random import randint
import string
import random

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


def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
        )

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
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
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLANOnly,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            }
        )
    ]


@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_cert_no_index_TC19638(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1
        ):
    capture_filename = "test_dynamic_load_cert_no_index_TC19638"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # The api returns 100 bytes of random data
    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    data_length = len(data_sent)
    logger.info(f"Sending data {data_sent} over socket_no->{sock}")
    # DUT sends 100 bytes of data over ssl socket
    wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
    server_socket_no = 1
    # SSL server receives the data over ssl socket
    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
    logger.info(f"Data received on remote socket opened is {data_receive}")
    assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
    logger.info("Data sent by DUT and received on server is matching")

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)

    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                         f"not matched on socket {server_socket_no} "
    logger.info(
        f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
    # Close socket 1
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened ssl socket in the dut"
    logger.info("Successfully closed opened socket in the DUT")

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_cert_socket_connected_state_TC19639(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1
        ):
    capture_filename = "test_dynamic_load_cert_no_index_TC19638"
    port1 = ssl_server.interfaces.ssl.config['device_port1']

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    with pytest.raises(WlanError) as exc_info:
        # The below API loads ca-cert into DUT
        # The below API loads ca-cert into DUT at cert index 0
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0,
                                                     )
    assert ((exc_info.value.error_code == 0x5d) or (exc_info.value.error_code == 0x5e)), "observed wrong error code, " \
                                                                                         "expected is 0x5d or 0x5e "

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                             ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_new_cert_TC19640(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1
        ):
    capture_filename = "test_dynamic_load_cert_no_index_TC19638"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    # The api returns 100 bytes of random data
    data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    data_length = len(data_sent)
    logger.info(f"Sending data {data_sent} over socket_no->{sock}")
    # DUT sends 100 bytes of data over ssl socket
    wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
    server_socket_no = 1
    # SSL server receives the data over ssl socket
    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
    logger.info(f"Data received on remote socket opened is {data_receive}")
    assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
    logger.info("Data sent by DUT and received on server is matching")

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)

    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                         f"not matched on socket {server_socket_no} "
    logger.info(
        f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")

    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened ssl socket in the dut"
    logger.info("Successfully closed opened socket in the DUT")

    logger.info(f"clear certificate type -> {RS9116CertificateType.SSLCACertificate}")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=0
                                               )
    # The below API loads ca-cert into DUT at cert index 0
    wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                 str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                 cert_index=0,
                                                 )

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")


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
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_three_ssl_sockets_TC19641(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_dynamic_load_three_ssl_sockets_TC19641"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
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
            local_port = randint(5001, 20000)
        elif sock_count == 1:
            socket_port = port2
            local_port = randint(20001, 40000)
        else:
            socket_port = port3
            local_port = randint(40001, 60000)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    socket_no = [1, 2, 3]
    for socket in socket_no:
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                time.sleep(10)
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                     f"not matched on socket {socket} "
                logger.info(
                    "Number of bytes sent by DUT and received on the remote peer are matched on socket {socket}")

            else:
                assert f"failed to connect on socket no {socket}"

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


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
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_three_ssl_sockets_multiple_iterations_TC19643(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_dynamic_load_three_ssl_sockets_TC19641"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
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
            local_port = randint(5001, 20000)
        elif sock_count == 1:
            socket_port = port2
            local_port = randint(20001, 40000)
        else:
            socket_port = port3
            local_port = randint(40001, 60000)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")

    logger.info(f"Clearing certificate type -> {RS9116CertificateType.SSLCACertificate} at index 0")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=0
                                               )
    logger.info(f"Clearing certificate type -> {RS9116CertificateType.SSLCACertificate} at index 1")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=1
                                               )
    logger.info(f"Clearing certificate type -> {RS9116CertificateType.SSLCACertificate} at index 2")
    wifi_dut.interfaces.wifi.clear_certificate(RS9116CertificateType.SSLCACertificate,
                                               cert_index=2
                                               )
    # The below API loads ca-cert into DUT at cert index 0
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

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


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
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_load_certs_without_erasing_multiple_times_TC19644(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    capture_filename = "test_load_certs_without_erasing_multiple_times_TC19644"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)

    for iteration in range(1, 3):
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
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
                assert sock == 0, f"socket id received is wrong, expected is 0 in iteration {iteration}"
            elif sock_count == 1:
                assert sock == 1, f"socket id received is wrong, expected is 1 in iteration {iteration}"
            else:
                assert sock == 2, f"socket id received is wrong, expected is 2 in iteration {iteration}"
            logger.info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected in iteration {iteration}")
            logger.info(
                f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API in iteration {iteration}")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            if sock_count == 0:
                cert_index = SocketOptions.CERT_INDEX0
            elif sock_count == 1:
                cert_index = SocketOptions.CERT_INDEX1
            else:
                cert_index = SocketOptions.CERT_INDEX2
            logger.info(
                f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API in iteration {iteration}")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                       cert_index)
            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

        if iteration != 1:
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
                                                             f"not matched on socket {socket} in iteration {iteration} "
                        logger.info(
                            "Number of bytes sent by DUT and received on the remote peer are matched on socket {"
                            "socket} "
                            "in iteration {iteration}")

                    else:
                        assert f"failed to connect on socket no {socket} in iteration {iteration}"

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count} in iteration {iteration}")
            result = wifi_dut.interfaces.wifi.close_socket(sock_count)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count} in iteration {iteration} "
            logger.info(f"Successfully closed socket_id->{sock_count} in iteration {iteration}")

        ssl_server.interfaces.ssl.stop_server()
        time.sleep(1)

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


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
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dynamic_load_powersave_not_enabled_TC19646(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    wifi_dut.interfaces.wifi.start_ip()
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
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
            local_port = randint(5001, 20000)
        elif sock_count == 1:
            socket_port = port2
            local_port = randint(20001, 40000)
        else:
            socket_port = port3
            local_port = randint(40001, 60000)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    socket_no = [1, 2, 3]
    for socket in socket_no:
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                time.sleep(10)
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                     f"not matched on socket {socket} "
                logger.info(
                    "Number of bytes sent by DUT and received on the remote peer are matched on socket {socket}")

            else:
                assert f"failed to connect on socket no {socket}"

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")
    wifi_sniffer.interfaces.capture.stop_capture()


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
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.skip()
def test_dynamic_load_powersave_enabled_testcase14(
        wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # The below API loads ca-cert into DUT at cert index 0
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

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
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
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock2, ssl_server.interfaces.ssl, server_port=port3)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                time.sleep(3)
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                     f"not matched on socket {socket} "

            else:
                assert f"failed to connect on socket no {socket}"

    # Close socket 1
    wifi_dut.interfaces.wifi.close_socket(sock)
    # Close socket 2
    wifi_dut.interfaces.wifi.close_socket(sock1)
    # Close socket 3
    wifi_dut.interfaces.wifi.close_socket(sock2)


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
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_store_config"])
def test_dynamic_load_auto_join_TC19645(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3
        ):
    ping_count = 10
    capture_filename = "test_dynamic_load_auto_join_TC19645"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    port3 = ssl_server.interfaces.ssl.config['device_port3']
    bytes_sent = (pkt_count * buffer_length)
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {dut_mac_address}")

    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
        )

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
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
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    wifi_dut.interfaces.wifi.config_save()
    wifi_dut.interfaces.wifi.config_enable(config=1)
    wifi_dut.interfaces.wifi.reset_soft()
    wifi_dut.interfaces.wifi.wireless_init()
    time.sleep(30)

    # The below API loads ca-cert into DUT at cert index 0
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

    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
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
            local_port = randint(5001, 20000)
        elif sock_count == 1:
            socket_port = port2
            local_port = randint(20001, 40000)
        else:
            socket_port = port3
            local_port = randint(40001, 60000)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)

    socket_no = [1, 2, 3]
    for socket in socket_no:
        ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)

    if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
        socket_no = [1, 2, 3]
        for socket in socket_no:
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
                wifi_dut.interfaces.wifi.send_data_pkts((socket - 1), buffer_length, pkt_count)
                time.sleep(10)
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                     f"not matched on socket {socket} "
                logger.info(
                    "Number of bytes sent by DUT and received on the remote peer are matched on socket {socket}")

            else:
                assert f"failed to connect on socket no {socket}"

    for sock_count in range(0, 3):
        logger.info(f"Closing socket_id->{sock_count}")
        result = wifi_dut.interfaces.wifi.close_socket(sock_count)
        assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
        logger.info(f"Successfully closed socket_id->{sock_count}")

    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
