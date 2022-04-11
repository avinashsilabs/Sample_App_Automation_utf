# Test author: Vinod.G
# Test suite: SSL_CLIENT
import time
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
    RS9116PowerSaveProcedureTypes,
    SocketOptions,
    SocketType,
    Cipher,
    DeviceConstants,
    )
import string
import random
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import ping
from random import randint

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

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=20,
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
    ping(device_ip, 10)
    return mac_address


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ca_cert": "ca-chain.cert.pem",
            "set_send_feature_frame": True,
            }
        )
    ]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_client_testcase_TC19109(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger
        ):
    capture_filename = "test_ssl_client_testcase_TC19109"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
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
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.parametrize("repeat", [100])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_client_connect_close_sequence_testcase133(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, repeat
        ):
    capture_filename = "test_ssl_client_connect_close_sequence_testcase133"
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    fail_count = 0
    for iteration in range(0, repeat):
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, f"iteration no->{iteration}:Socket id received is wrong. expected is 0"
        logger.info(
            f"iteration no->{iteration}: Successfully opened tcp client socket and socket id received is {sock} which "
            f"is expected")

        logger.info(
            f"iteration no->{iteration}: Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        try:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        except:
            logger.info(f"Failed to connect on the iteration {iteration}")
            time.sleep(1)
            fail_count = fail_count + 1
            ssl_server.interfaces.ssl.stop_server()
            continue

        # The api returns 100 bytes of random data
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        logger.info(f"iteration no->{iteration}: Sending data {data_sent} over socket_no->{sock}")
        # DUT sends 100 bytes of data over ssl socket
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        # SSL server receives the data over ssl socket
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        logger.info(f"iteration no->{iteration}: Data received on remote socket opened is {data_receive}")
        assert data_sent == data_receive.decode(), f"iteration no->{iteration}:Data sent by DUT and received on " \
                                                   f"server is matching "
        logger.info(f"iteration no->{iteration}: Data sent by DUT and received on server is matching")
        # Close socket 1
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, f"iteration no->{iteration}:unable to close opened ssl socket in the dut"
        logger.info(f"iteration no->{iteration}: Successfully closed opened socket in the DUT")

        if fail_count:
            logger.info(f"{fail_count} times failed to connect to the server out of {repeat} iterations")
        assert fail_count == 0, f"{fail_count} times failed to connect to the server out of {repeat} iterations"
        time.sleep(1)
        ssl_server.interfaces.ssl.stop_server()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_client_tx_rx_bidirectional_testcase_TC19129(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger
        ):
    capture_filename = "test_ssl_client_tx_rx_bidirectional_testcase_TC19129"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    port2 = ssl_server.interfaces.ssl.config['device_port2']
    bytes_sent = (pkt_count * buffer_length)
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    ssl_server.interfaces.ssl.start_server(port=port2)
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                           socket_flag=SocketType.ASYNCHRONOUS)

    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    logger.info(f"Setting TCP-RETRY limit to {SocketOptions.TCP_MAX_RETRY} for the socket-id->{sock} using "
                f"rsi_setsockopt API")
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    local_port = randint(5001, 20000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    sock1 = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock1 == 1, "Socket id received is wrong. expected is 1"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock1} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock1} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock1, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(20001, 40000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock1, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock1, ssl_server.interfaces.ssl, server_port=port2)
    # pkt_count = 1000
    ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length)
    ssl_server.interfaces.ssl.data_receive(2, pkt_count, buffer_length)
    logger.info("Start tx on the DUT on socket_id1")
    wifi_dut.interfaces.wifi.send_data_pkts(sock1, buffer_length, pkt_count)
    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(2)
    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                         f"not matched on socket {2} "
    logger.info("Number of bytes sent by DUT and received on the remote peer are matched")
    logger.info("Wait for 120 seconds to receive data on the socket_id->0")
    time.sleep(120)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_received == (pkt_count * buffer_length), "Packet loss observed while receive test"
    result = wifi_dut.interfaces.wifi.close_socket(sock)
    assert b"success" in result, "unable to close opened ssl socket in the dut"
    logger.info(f"Successfully closed opened socket {sock} in the DUT")
    wifi_dut.interfaces.wifi.close_socket(sock1)
    assert b"success" in result, "unable to close opened ssl socket in the dut"
    logger.info(f"Successfully closed opened socket {sock1} in the DUT")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


# BIT_TLS_RSA_WITH_AES_256_CBC_SHA256 -> Supported with current python version
# BIT_TLS_RSA_WITH_AES_128_CBC_SHA256 -> Supported with current python version
# BIT_TLS_RSA_WITH_AES_256_CBC_SHA -> Supported with current python version
# BIT_TLS_DHE_RSA_WITH_AES_128_CBC_SHA -> Supported with current python version
# BIT_TLS_RSA_WITH_AES_128_CCM_8 -> Not supported with current python version
# BIT_TLS_RSA_WITH_AES_256_CCM_8 -> Not supported with current python version

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [
    [Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256,
     Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA]])
def test_ssl_client_cipher_list_testcase_TC19133(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cipher_list
        ):
    capture_filename = "test_ssl_client_cipher_list_testcase_TC19133"
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    for cipher in cipher_list:
        if cipher == Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256:
            cipher_str = 'TLS_RSA_WITH_AES_256_CBC_SHA256'
        elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256:
            cipher_str = 'TLS_RSA_WITH_AES_128_CBC_SHA256'
        elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA:
            cipher_str = 'TLS_RSA_WITH_AES_256_CBC_SHA'
        elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA:
            cipher_str = 'TLS_RSA_WITH_AES_128_CBC_SHA'
        logger.info(f"Running SSL test when cipher suite selected is {cipher_str}")
        wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, f"Socket id received is wrong. expected is 0 when cipher suite selected is {cipher_str}"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected when "
                    f"cipher suite selected is {cipher_str}")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API when cipher suite "
                    f"selected is {cipher_str}")
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
        logger.info(f"Sending data {data_sent} over socket_no->{sock} when cipher suite selected is {cipher_str}")
        # DUT sends 100 bytes of data over ssl socket
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        # SSL server receives the data over ssl socket
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        logger.info(
            f"Data received on remote socket opened is {data_receive} when cipher suite selected is {cipher_str}")
        assert data_sent == data_receive.decode(), f"Data sent by DUT and received on server is matching when cipher " \
                                                   f"suite selected is {cipher_str} "
        logger.info(f"Data sent by DUT and received on server is matching when cipher suite selected is {cipher_str}")

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
        wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)

        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
        assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                             f"not matched on socket {server_socket_no} when cipher suite selected is {cipher_str}"
        logger.info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received} when cipher suite selected is {cipher_str}")
        # Close socket 1
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut when cipher suite selected is {" \
                                     "cipher_str} "
        logger.info("Successfully closed opened socket in the DUT when cipher suite selected is {cipher_str}")

        ssl_server.interfaces.ssl.stop_server()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
def test_ssl_client_ciphersuite_mismatch_testcase_TC19133(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger
        ):
    capture_filename = "test_ssl_client_ciphersuite_mismatch_testcase_TC19133"
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    logger.info(
        f"Opening SSL server socket remotely with cipher suite->{Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA}")
    wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA)
    logger.info(f"Cipher suite selected in DUT is ECDHE-RSA-AES256-SHA384")
    ssl_server.interfaces.ssl.start_server(cipher_list="ECDHE-RSA-AES256-SHA384")
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
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
    logger.info(f"DUT returned {exc_info.value.error_code} when cipher suite is mismatched")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_socket_limit_testcase_TC19121(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger
        ):
    capture_filename = "test_ssl_socket_limit_testcase_TC19121"

    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=5002)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(port=5003)

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(5001, 20000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5001)

    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 1, "Socket id received is wrong. expected is 1"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    local_port = randint(20001, 40000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5002)

    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 2, "Socket id received is wrong. expected is 2"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    local_port = randint(40001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)

    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=5003)
    assert exc_info.value.error_code == 0xD3, "Observed wrong error code, expected is 0xD3"
    logger.info(f"DUT sent error code->{exc_info.value.error_code} when trying to open third ssl socket which is "
                f"expected")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_client_version_1_2_testcase_TC19119(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger
        ):
    capture_filename = "test_ssl_client_version_1_2_testcase_TC19119"
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server(version="ssl_1.2")
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                f"rsi_setsockopt API")
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_V_1_0_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    local_port = randint(5001, 60000)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
    with pytest.raises(WlanError) as exc_info:
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
    assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
    logger.info(f"DUT returned {exc_info.value.error_code} error when trying to connect to SSL server operating at "
                f"version 1.2 and version selected in DUT is 1.0")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
