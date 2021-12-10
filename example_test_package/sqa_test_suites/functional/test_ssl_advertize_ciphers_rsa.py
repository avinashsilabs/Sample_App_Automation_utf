import pytest
from typing import Dict
import time
import pytest
from devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    SocketType,
    Cipher,
    DefaultCipher,
    )
import string
import random
import os
from utils.stopwatch import Stopwatch

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the client with server socket as specified port number.
        8. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
        9. Analyze the cipher list sent in the tls-client-hello ssl packet and compare with the cipher list selected in
        the dut
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer
"""

"""The below function takes the sniffer capture file as input and return cipher list from tls-client hello ssl record 
packet """


def get_cipher_list(wifi_sniffer, logger, decryption_key: str, print_layers: list, mode=0) -> Dict[str, int]:
    cipher_suite = []
    count = 0
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()

            if layer_name in print_layers:
                tls_layer = str(layer)
                if not "Client Hello" in tls_layer:
                    if mode == 0:
                        return cipher_suite
                else:
                    cipher_suite_temp = []
                    tls_layer = tls_layer.split("\n")
                    for line in tls_layer:
                        if "Cipher Suite:" in line:
                            cipher_suite_temp.append(line.split("Cipher Suite:")[1].strip().split("(")[0].strip())
                    count = count + 1
                    cipher_suite.append(tuple([count, cipher_suite_temp]))
                    if mode == 0:
                        return cipher_suite
    return cipher_suite


def select_cipher_list(cipher_list):
    cipher = 0
    for count in cipher_list:
        if count == 'TLS_RSA_WITH_AES_256_CBC_SHA256':
            cipher = cipher | Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256
        elif count == 'TLS_RSA_WITH_AES_128_CBC_SHA256':
            cipher = cipher | Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256
        elif count == 'TLS_RSA_WITH_AES_256_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA
        elif count == 'TLS_RSA_WITH_AES_128_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA
        elif count == 'TLS_RSA_WITH_AES_128_CCM_8':
            cipher = cipher | Cipher.BIT_TLS_RSA_WITH_AES_128_CCM_8
        elif count == 'TLS_RSA_WITH_AES_256_CCM_8':
            cipher = cipher | Cipher.BIT_TLS_RSA_WITH_AES_256_CCM_8
        elif count == 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256':
            cipher = cipher | Cipher.BIT_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        elif count == 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384':
            cipher = cipher | Cipher.BIT_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        elif count == 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        elif count == 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256':
            cipher = cipher | Cipher.BIT_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        elif count == 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        elif count == 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256':
            cipher = cipher | Cipher.BIT_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        elif count == 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        elif count == 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        elif count == 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        elif count == 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        elif count == 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        elif count == 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        elif count == 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        elif count == 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        elif count == 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        elif count == 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        elif count == 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        elif count == 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA':
            cipher = cipher | Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    return cipher


def ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename,
                         cipher_list, logger, mode, server_cert=None, server_key=None, test_run_time=120):
    if not len(cipher_list):
        expected_cipher = DefaultCipher.cipher_list
    else:
        expected_cipher = cipher_list
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed

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
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    if len(cipher_list):
        cipher = select_cipher_list(cipher_list)
        wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)
    if mode == 3:
        logger.info(f"********Running the test for {test_run_time} seconds*******")
        pkt_count = 100
        sw = Stopwatch()
        count = 0
        while sw.elapsed_sec < test_run_time:
            count = count + 1
            if server_cert is None:
                ssl_server.interfaces.ssl.start_server()
            else:
                ssl_server.interfaces.ssl.start_server(server_cert=server_cert, server_key=server_key)
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, f"socket id received is wrong, expected is 0 on iteration {count}"
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
            server_socket_no = 1
            # The api returns 100 bytes of random data
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
            # SSL server receives the data over ssl socket
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
            assert data_sent == data_receive.decode(), f"data length sent and received is not matching on {count} iteration "

            if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
            wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)

            # # Close socket 1
            wifi_dut.interfaces.wifi.close_socket(sock)
            ssl_server.interfaces.ssl.stop_server()

        wifi_sniffer.interfaces.capture.stop_capture()

        # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, ["tls"], mode=1)
        if not (len(cipher_suite) > 0):
            logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                        "is "
                        "not captured")

        logger.info(f"{len(cipher_suite)} times tls client hello message captured on sniffer log")
        for cipher in cipher_suite:
            cipher_suite_tmp = cipher[1]
            if not (cipher_suite_tmp == expected_cipher):
                logger.info(f"******cipher suite mismatched on iteration {cipher[0]}******\nexpected "
                            f"is {expected_cipher}\nBut "
                            f"observed {cipher_suite_tmp} ")
        logger.info(f"******cipher suite advertised-> {cipher_suite_tmp}*******")

    else:
        # Open ssl server socket in remote device(Raspberry pi or static device)
        if server_cert is None:
            ssl_server.interfaces.ssl.start_server()
        else:
            ssl_server.interfaces.ssl.start_server(server_cert=server_cert, server_key=server_key)
        # Open ssl client socket in the DUT
        if mode == 0:
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif mode == 1:
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                                   socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, f"socket id received is wrong, expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        server_socket_no = 1
        if mode == 0:
            # The api returns 100 bytes of random data
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
            # SSL server receives the data over ssl socket
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
            assert data_sent == data_receive.decode(), f"data length sent and received is not matching"

            if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
            wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
        elif mode == 1:
            ssl_server.interfaces.ssl.send_data(server_socket_no, pkt_count, msg_length=buffer_length)
            time.sleep(60)
            result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
            bytes_received = int(result.split(b":")[1])
            logger.info(f"bytes received on socket {sock} -> {bytes_received}")
            assert bytes_received == (pkt_count * buffer_length), "Packet loss observed while receive test"
        # # Close socket 1
        wifi_dut.interfaces.wifi.close_socket(sock)
        ssl_server.interfaces.ssl.stop_server()

        wifi_sniffer.interfaces.capture.stop_capture()

        # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, ["tls"], mode=0)

        if not (len(cipher_suite) > 0):
            logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                        "is "
                        "not captured")
        cipher_suite = cipher_suite[0][1]
        logger.info(f"******cipher suite advertised-> {cipher_suite}*******")
        if not (cipher_suite == expected_cipher):
            logger.info(f"******cipher suite mismatched ******\nexpected "
                        f"is {expected_cipher}\nBut "
                        f"observed {cipher_suite} ")


def wlan_ssl_connect_disconnect(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename,
                                cipher_list, logger, server_cert=None, server_key=None, test_run_time=120):
    logger.info(f"********Running the test for {test_run_time} seconds*******")
    if not len(cipher_list):
        expected_cipher = DefaultCipher.cipher_list
    else:
        expected_cipher = cipher_list
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed

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
    sw = Stopwatch()
    count = 0
    while sw.elapsed_sec < test_run_time:
        count = count + 1
        wifi_dut.interfaces.wifi.scan(ssid=None)
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        # DUT gets ipaddress through DHCP process after start_ip API is executed
        wifi_dut.interfaces.wifi.start_ip()
        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        if len(cipher_list):
            cipher = select_cipher_list(cipher_list)
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)

            pkt_count = 100

        if server_cert is None:
            ssl_server.interfaces.ssl.start_server()
        else:
            ssl_server.interfaces.ssl.start_server(server_cert=server_cert, server_key=server_key)
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, f"socket id received is wrong, expected is 0 on iteration {count}"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        server_socket_no = 1
        # The api returns 100 bytes of random data
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        # DUT sends 100 bytes of data over ssl socket
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        # SSL server receives the data over ssl socket
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        assert data_sent == data_receive.decode(), f"data length sent and received is not matching on {count} iteration "

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
        wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)

        # # Close socket 1
        wifi_dut.interfaces.wifi.close_socket(sock)
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.leave()

    wifi_sniffer.interfaces.capture.stop_capture()

    # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

    cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, ["tls"], mode=1)
    if not (len(cipher_suite) > 0):
        logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                    "is "
                    "not captured")

    logger.info(f"{len(cipher_suite)} times tls client hello message captured on sniffer log")
    for cipher in cipher_suite:
        cipher_suite_tmp = cipher[1]
        if not (cipher_suite_tmp == expected_cipher):
            logger.info(f"******cipher suite mismatched on iteration {cipher[0]}******\nexpected "
                        f"is {expected_cipher}\nBut "
                        f"observed {cipher_suite_tmp} ")
    logger.info(f"******cipher suite advertised-> {cipher_suite_tmp}*******")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [[]])
def test_advertise_all_ciphers_ssl_tx_testcase1(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 0)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [[]])
def test_advertise_all_ciphers_ssl_rx_testcase2(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 1)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_tx_testcase3(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 0)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_rx_testcase4(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 1)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_advertise_ciphers_ssl_tx_testcase5(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 0)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_advertise_ciphers_ssl_rx_testcase6(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 1)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_tx_testcase7(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 0)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_rx_testcase8(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 1)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_advertise_ciphers_ssl_tx_testcase9(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 0)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_advertise_ciphers_ssl_rx_testcase10(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 1)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_tx_testcase11(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 0)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_rx_testcase12(
        wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cipher_list, logger
        ):
    capture_filename = os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
    ssl_connection_tx_rx(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, capture_filename, cipher_list,
                         logger, 1)

