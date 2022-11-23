# Test author: Vinod.G
# Test suite: Advertise CCM based more cipher suites for TLS_1.2
from typing import Dict
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
    SocketType,
    Cipher,
    DefaultCipher,
    DeviceConstants,
    )
from utf import UtfDatabaseProperties
from utf.utils.stopwatch import Stopwatch
import string
import random
from utf.utils.iperf.iperf_utils import ping
from random import randint
from datetime import datetime
import uuid

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


def get_cipher_list(wifi_sniffer, logger, decryption_key: str, mac_address, print_layers: list,
                    capture_filename,
                    mode=0) -> Dict[str, int]:
    cipher_suite = []
    count = 0
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {mac_address})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file
            ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "wlan":
                mac_layer = str(layer)
            if layer_name in print_layers:
                tls_layer = str(layer)
                if not "Client Hello" in tls_layer:
                    if mode == 0:
                        return cipher_suite
                else:
                    for mac_addr in mac_layer.split("\n"):
                        if "Transmitter address" in mac_addr:
                            ta_address = mac_addr.split(": ")[1].strip()
                    if ta_address == mac_address:
                        logger.info(f"Cleint hello pkt sent by DUT {mac_address}-> {tls_layer}")
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
        for cipher_mem in Cipher:
            if count in str(cipher_mem):
                cipher = cipher | cipher_mem.value
    return cipher


def ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                         cipher_list, logger, mode, server_cert=None, server_key=None, test_run_time=120):
    ping_count = 10
    if not len(cipher_list):
        expected_cipher = DefaultCipher.cipher_list
    else:
        expected_cipher = cipher_list
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
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
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    if len(cipher_list):
        cipher = select_cipher_list(cipher_list)
        wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)
    if mode == 3:  # if mode is set to 3, socket open, connect to server, send data, disconnect test is done in loop
        logger.info(f"********Running the test for {test_run_time} seconds*******")
        pkt_count = 100
        bytes_sent = (pkt_count * buffer_length)
        sw = Stopwatch()
        count = 0
        while sw.elapsed_sec < test_run_time:
            count = count + 1
            # Open ssl server socket in remote device(Raspberry pi or static device)
            if server_cert is None:
                ssl_server.interfaces.ssl.start_server()
            else:
                ssl_server.interfaces.ssl.start_server(server_cert=server_cert, server_key=server_key)
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
            result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
            logger.info(f"Number of bytes sent by dut {result}")
            bytes_sent = result

            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
            assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                                 f"not matched on socket {server_socket_no} "
            logger.info(
                f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
            # Close socket 1
            result = wifi_dut.interfaces.wifi.close_socket(sock)
            assert b"success" in result, "unable to close opened ssl socket in the dut"
            logger.info("Successfully closed opened socket in the DUT")
            ssl_server.interfaces.ssl.stop_server()
            time.sleep(2)

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")

        # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        # cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, ["tls"], mode=1)
        cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, mac_address, ["tls"], capture_filename,
                                       mode=1)
        if not (len(cipher_suite) > 0):
            logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                        "is "
                        "not captured")
        assert (len(cipher_suite) > 0), f"tls client hello packet is not captured or one of the wifi 4-way handshake " \
                                        f"pkt is not captured "

        logger.info(f"{len(cipher_suite)} times tls client hello message captured on sniffer log")
        for cipher in cipher_suite:
            cipher_suite_tmp = cipher[1]
            if not (cipher_suite_tmp == expected_cipher):
                logger.info(f"******cipher suite mismatched on iteration {cipher[0]}******\nexpected "
                            f"is {expected_cipher}\nBut "
                            f"observed {cipher_suite_tmp} ")
        logger.info(
            f"******As per sniffer capture cipher suite advertised by device {mac_address}-> {cipher_suite_tmp}*******")

    else:
        pkt_count = 10000
        bytes_sent = (pkt_count * buffer_length)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        if server_cert is None:
            ssl_server.interfaces.ssl.start_server()
        else:
            ssl_server.interfaces.ssl.start_server(server_cert=server_cert, server_key=server_key)
        # Open ssl client socket in the DUT
        if mode == 0:  # if mode is set to 0, socket open, tx over the socket test will be initiated
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, f"socket id received is wrong, expected is 0"
        elif mode == 1:
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                                   socket_flag=SocketType.ASYNCHRONOUS)
            assert sock == 0, f"socket id received is wrong, expected is 0"
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
        server_socket_no = 1
        if mode == 0:
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
            result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
            logger.info(f"Number of bytes sent by dut {result}")
            bytes_sent = result

            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
            assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                                 f"not matched on socket {server_socket_no} "
            logger.info(
                f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
        elif mode == 1:  # if mode is set to 1, socket open, rx over the socket test will be initiated
            pkt_count = 1000
            ssl_server.interfaces.ssl.send_data(server_socket_no, pkt_count, msg_length=buffer_length, duration=300)
            logger.info("Wait for 300 seconds to receive the data")
            time.sleep(320)
            bytes_sent = ssl_server.interfaces.ssl.data_send_stats(server_socket_no)
            result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
            bytes_received = int(result.split(b":")[1])
            logger.info(f"Bytes sent by remote peer {bytes_sent} on socket {server_socket_no}")
            logger.info(f"bytes received on socket {sock} -> {bytes_received}")
            assert bytes_received == bytes_sent, "Packet loss observed while receive test"

        # Close socket 1
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")

        # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        # cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, ["tls"], mode=0)
        cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, mac_address, ["tls"], capture_filename,
                                       mode=0)

        if not (len(cipher_suite) > 0):
            logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                        "is "
                        "not captured")
        assert (len(cipher_suite) > 0), f"tls client hello packet is not captured or one of the wifi 4-way handshake " \
                                        f"pkt is not captured "
        cipher_suite = cipher_suite[0][1]
        logger.info(
            f"******As per sniffer capture, cipher suite advertised by DUT {mac_address}-> {cipher_suite}*******")
        if not (cipher_suite == expected_cipher):
            logger.info(f"******cipher suite mismatched ******\nexpected "
                        f"is {expected_cipher}\nBut "
                        f"observed {cipher_suite} ")


def wlan_ssl_connect_disconnect(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                cipher_list, logger, server_cert=None, server_key=None, test_run_time=120):
    ping_count = 10
    logger.info(f"********Running the test for {test_run_time} seconds*******")
    if not len(cipher_list):
        expected_cipher = DefaultCipher.cipher_list
    else:
        expected_cipher = cipher_list
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']

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

    sw = Stopwatch()
    count = 0
    while sw.elapsed_sec < test_run_time:
        count = count + 1
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
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        if len(cipher_list):
            cipher = select_cipher_list(cipher_list)
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)

        pkt_count = 100

        bytes_sent = (pkt_count * buffer_length)

        # Open ssl server socket in remote device(Raspberry pi or static device)
        if server_cert is None:
            ssl_server.interfaces.ssl.start_server()
        else:
            ssl_server.interfaces.ssl.start_server(server_cert=server_cert, server_key=server_key)
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
        result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
        logger.info(f"Number of bytes sent by dut {result}")
        bytes_sent = result

        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
        assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                             f"not matched on socket {server_socket_no} "
        logger.info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
        # Close socket 1
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.leave()

    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")

    # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

    # cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, ["tls"], mode=1)
    cipher_suite = get_cipher_list(wifi_sniffer, logger, decryption_key, mac_address, ["tls"], capture_filename, mode=1)
    if not (len(cipher_suite) > 0):
        logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                    "is "
                    "not captured")
    assert (len(cipher_suite) > 0), f"tls client hello packet is not captured or one of the wifi 4-way handshake " \
                                    f"pkt is not captured "

    logger.info(f"{len(cipher_suite)} times tls client hello message captured on sniffer log")
    for cipher in cipher_suite:
        cipher_suite_tmp = cipher[1]
        if not (cipher_suite_tmp == expected_cipher):
            logger.info(f"******cipher suite mismatched on iteration {cipher[0]}******\nexpected "
                        f"is {expected_cipher}\nBut "
                        f"observed {cipher_suite_tmp} ")
    logger.info(
        f"******As per sniffer capture, cipher suite advertised by DUT {mac_address}-> {cipher_suite_tmp}*******")
    wifi_dut.interfaces.wifi.leave()


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


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_bgscan_5G_C19383',
                                                       test_case_id='C19383',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [[]])
def test_advertise_all_ciphers_ssl_tx_TC19604(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_all_ciphers_ssl_tx_TC19604"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 0)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_advertise_all_ciphers_ssl_rx_TC19605',
                                                       test_case_id='TC19605',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [[]])
def test_advertise_all_ciphers_ssl_rx_TC19605(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_all_ciphers_ssl_rx_TC19605"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 1)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_advertise_ciphers_ssl_tx_TC19606',
                                                       test_case_id='TC19606',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_tx_TC19606(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_tx_TC19606"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 0)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_advertise_ciphers_ssl_rx_TC19607',
                                                       test_case_id='TC19607',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                                          'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                                          'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                                          'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_rx_TC19607(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_rx_TC19607"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 1)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_advertise_ciphers_ssl_tx_TC19608',
                                                       test_case_id='TC19608',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_advertise_ciphers_ssl_tx_TC19608(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_tx_TC19608"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 0)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_advertise_ciphers_ssl_rx_TC19609',
                                                       test_case_id='TC19609',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_advertise_ciphers_ssl_rx_TC19609(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_rx_TC19609"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 1)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_advertise_ciphers_ssl_tx_TC19610',
                                                       test_case_id='TC19610',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_tx_TC19610(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_tx_TC19610"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 0)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_advertise_ciphers_ssl_rx_TC19611',
                                                       test_case_id='TC19611',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_advertise_ciphers_ssl_rx_TC19611(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_tx_TC19611"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 1)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384']])
# TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384' ciphers are not supported in python
# 3.9. Need to change the implementation for these test cases
@pytest.mark.skip()
def test_advertise_ciphers_ssl_tx_TC19612(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_tx_TC19612"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 0)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384']])
# TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384' ciphers are not supported in python
# 3.9. Need to change the implementation for these test cases
@pytest.mark.skip()
def test_advertise_ciphers_ssl_rx_TC19613(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_rx_TC19613"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 1)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256']])
# TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384' ciphers are not supported in python
# 3.9. Need to change the implementation for these test cases
@pytest.mark.skip()
def test_advertise_ciphers_ssl_tx_TC19614(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_tx_TC19614"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 0)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256']])
# TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384' ciphers are not supported in python
# 3.9. Need to change the implementation for these test cases
@pytest.mark.skip()
def test_advertise_ciphers_ssl_rx_TC19615(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list, logger
        ):
    capture_filename = "test_advertise_ciphers_ssl_rx_TC19615"
    ssl_connection_tx_rx(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, cipher_list,
                         logger, 1)
