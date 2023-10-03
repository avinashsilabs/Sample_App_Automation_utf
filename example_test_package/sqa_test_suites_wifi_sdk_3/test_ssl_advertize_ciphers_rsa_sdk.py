import random
import string
import time
import pytest
from random import randint
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xAwsQos,
    DefaultCipher,
    DeviceConstants,
    SocketOptions,
    Cipher,
    SocketType
)

"""The testcases added in this file run below test steps for DUT-Si91x
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
        1. DUT(Si91x)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. NUC Wifi Sniffer
"""


def logger():
    return get_logger(__name__)


class ssl_connection:
    """
    Class to configure SSL and Rejoin parameters in DUT along with WLAN and SSL Socket Connection.
    """

    def __init__(self, wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename, sl_collections,
                 cipher_list, logger, mode=0, server_cert=None, server_key=None, test_run_time=120):
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.wifi_dut = wifi_dut
        self.ssl_server = ssl_server
        self.capture_filename = capture_filename
        self.sl_collections = sl_collections
        self.cipher_list = cipher_list
        self.logger = logger
        self.mode = mode
        self.server_cert = server_cert
        self.server_key = server_key
        self.test_run_time = test_run_time

    def ssl_connection_tx_rx(self):
        if not len(self.cipher_list):
            expected_cipher = DefaultCipher.cipher_list
        else:
            expected_cipher = self.cipher_list
        pkt_count = self.ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = self.ssl_server.interfaces.ssl.config['buffer_length']
        port1 = self.ssl_server.interfaces.ssl.config['device_port1']

        # configure interface for the channel of the access point
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        scan_fail = self.sl_collections.scan(self.wifi_dut)
        assert not scan_fail, "Scanning for AP failed"

        mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.logger.info(f"DUT MAC_Address: {mac_address}")

        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.capture_filename}.pcap"
        )

        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                      beacon_missed_count=40, first_time_retry_enable=0,
                                                                      )
        status = self.sl_collections.connect(self.wifi_dut, self.wifi_access_point)
        assert not status, "Failed to Join to AP"

        status = self.sl_collections.configure_ip(self.wifi_dut)
        assert not status, "Failed to Join to AP"

        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        # The below api parses DUTs IP address
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        if len(self.cipher_list):
            cipher = self.select_cipher_list(self.cipher_list)
            self.wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)
        if self.mode == 3:  # if mode is set to 3, socket open, connect to server, send data, disconnect test is done in loop
            self.logger.info(f"********Running the test for {self.test_run_time} seconds*******")
            pkt_count = 100
            bytes_sent = (pkt_count * buffer_length)
            sw = Stopwatch()
            count = 0
            while sw.elapsed_sec < self.test_run_time:
                count = count + 1
                # Open ssl server socket in remote device(Raspberry pi or static device)
                if self.server_cert is None:
                    self.ssl_server.interfaces.ssl.start_server()
                else:
                    self.ssl_server.interfaces.ssl.start_server(server_cert=self.server_cert,
                                                                server_key=self.server_key)
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
                assert sock == 0, "Socket id received is wrong. expected is 0"
                self.logger.info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                self.logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
                                                              option_val=SocketOptions.SOL_SOCKET)
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                              option_val=SocketOptions.SO_SSL_ENABLE)
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
                                                              option_val=SocketOptions.SSL_ENABLE)

                local_port = randint(5001, 60000)
                # Socket binds at (device_ip, 5001) in DUT
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip,
                                                   server_port=local_port,
                                                   timeout=15)
                # ssl socket opened in DUT connects to the server
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                               server_port=port1)

                # The api returns 100 bytes of random data
                data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                data_length = len(data_sent)
                self.logger.info(f"Sending data {data_sent} over socket_no->{sock}")
                # DUT sends 100 bytes of data over ssl socket
                self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data_sent)
                server_socket_no = 1
                # SSL server receives the data over ssl socket
                data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                self.logger.info(f"Data received on remote socket opened is {data_receive}")
                assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                self.logger.info("Data sent by DUT and received on server is matching")

                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
                self.logger.info(f"Number of bytes sent by dut {result}")
                bytes_sent = result

                bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                                     f"not matched on socket {server_socket_no} "
                self.logger.info(
                    f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
                # Close socket 1
                result = self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                assert b"success" in result, "unable to close opened ssl socket in the dut"
                self.logger.info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
                time.sleep(2)

            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.logger.info("Stop Sniffer finally")

            # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets
            decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
            cipher_suite = \
                self.sl_collections.ssl_packet_decryption(self.wifi_sniffer, decryption_key, mac_address, ["tls"],
                                                          self.capture_filename, mode=1, get_cipher=True)['cipher']
            if not (len(cipher_suite) > 0):
                self.logger.info(
                    f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt is not captured")
            assert (
                    len(cipher_suite) > 0), f"tls client hello packet is not captured or one of the wifi 4-way handshake " \
                                            f"pkt is not captured "

            self.logger.info(f"{len(cipher_suite)} times tls client hello message captured on sniffer log")
            for cipher in cipher_suite:
                cipher_suite_tmp = cipher[1]
                if not (cipher_suite_tmp == expected_cipher):
                    self.logger.info(f"******cipher suite mismatched on iteration {cipher[0]}******\nexpected "
                                     f"is {expected_cipher}\nBut "
                                     f"observed {cipher_suite_tmp} ")
            self.logger.info(
                f"******As per sniffer capture cipher suite advertised by device {mac_address}-> {cipher_suite_tmp}*******")

        else:
            pkt_count = 10000
            bytes_sent = (pkt_count * buffer_length)
            # Open ssl server socket in remote device(Raspberry pi or static device)
            if self.server_cert is None:
                self.ssl_server.interfaces.ssl.start_server()
            else:
                self.ssl_server.interfaces.ssl.start_server(server_cert=self.server_cert, server_key=self.server_key)
            # Open ssl client socket in the DUT
            if self.mode == 0:  # if mode is set to 0, socket open, tx over the socket test will be initiated
                sock = self.wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
                assert sock == 0, f"socket id received is wrong, expected is 0"
            elif self.mode == 1:
                sock = self.wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SO_SSL_ENABLE)
                assert sock == 0, f"socket id received is wrong, expected is 0"
            self.logger.info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            self.logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
                                                          option_val=SocketOptions.SOL_SOCKET)
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                          option_val=SocketOptions.SO_SSL_ENABLE)
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
                                                          option_val=SocketOptions.SSL_ENABLE)

            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                               timeout=15)
            # ssl socket opened in DUT connects to the server
            server_ip = self.ssl_server.interfaces.ssl.server_ip
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                           server_port=port1)
            server_socket_no = 1
            if self.mode == 0:
                # The api returns 100 bytes of random data
                data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                data_length = len(data_sent)
                self.logger.info(f"Sending data {data_sent} over socket_no->{sock}")
                # DUT sends 100 bytes of data over ssl socket
                self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data_sent)
                server_socket_no = 1
                # SSL server receives the data over ssl socket
                data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                self.logger.info(f"Data received on remote socket opened is {data_receive}")
                assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
                self.logger.info("Data sent by DUT and received on server is matching")

                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
                self.logger.info(f"Number of bytes sent by dut {result}")
                bytes_sent = result

                bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                                     f"not matched on socket {server_socket_no} "
                self.logger.info(
                    f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
            elif self.mode == 1:  # if mode is set to 1, socket open, rx over the socket test will be initiated
                pkt_count = 1000
                self.ssl_server.interfaces.ssl.send_data(server_socket_no, pkt_count, msg_length=buffer_length,
                                                         duration=300)
                self.logger.info("Wait for 300 seconds to receive the data")
                time.sleep(320)
                bytes_sent = self.ssl_server.interfaces.ssl.data_send_stats(server_socket_no)
                result = self.wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
                bytes_received = int(result.split(b":")[1])
                self.logger.info(f"Bytes sent by remote peer {bytes_sent} on socket {server_socket_no}")
                self.logger.info(f"bytes received on socket {sock} -> {bytes_received}")
                assert bytes_received == bytes_sent, "Packet loss observed while receive test"

            # Close socket 1
            result = self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            assert b"success" in result, "unable to close opened ssl socket in the dut"
            self.logger.info("Successfully closed opened socket in the DUT")

            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.logger.info("Stop Sniffer finally")

            # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets
            decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"

            cipher_suite = \
                self.sl_collections.ssl_packet_decryption(self.wifi_sniffer, decryption_key, mac_address, ["tls"],
                                                          self.capture_filename, mode=0, get_cipher=True)['cipher']
            if not (len(cipher_suite) > 0):
                self.logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                                 "is not captured")

            assert (
                    len(cipher_suite) > 0), f"tls client hello packet is not captured or one of the wifi 4-way handshake " \
                                            f"pkt is not captured "
            cipher_suite = cipher_suite[0][1]
            self.logger.info(
                f"******As per sniffer capture, cipher suite advertised by DUT {mac_address}-> {cipher_suite}*******")
            if not (cipher_suite == expected_cipher):
                self.logger.info(f"******cipher suite mismatched ******\nexpected "
                                 f"is {expected_cipher}\nButobserved {cipher_suite} ")

    def wlan_ssl_connect_disconnect(self):
        self.logger.info(f"********Running the test for {self.test_run_time} seconds*******")
        if not len(self.cipher_list):
            expected_cipher = DefaultCipher.cipher_list
        else:
            expected_cipher = self.cipher_list
        pkt_count = self.ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = self.ssl_server.interfaces.ssl.config['buffer_length']
        port1 = self.ssl_server.interfaces.ssl.config['device_port1']

        # configure interface for the channel of the access point
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        scan_fail = self.sl_collections.scan(self.wifi_dut)
        assert not scan_fail, "Scanning for AP failed"

        mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        self.logger.info(f"DUT MAC_Address: {mac_address}")

        self.wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{self.capture_filename}.pcap"
        )

        sw = Stopwatch()
        count = 0
        while sw.elapsed_sec < self.test_run_time:
            count = count + 1
            scan_fail = self.sl_collections.scan(self.wifi_dut)
            assert not scan_fail, "Scanning for AP failed"

            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)
            status = self.sl_collections.connect(self.wifi_dut, self.wifi_access_point)
            assert not status, "Failed to Join to AP"

            status = self.sl_collections.configure_ip(self.wifi_dut)
            assert not status, "Failed to Join to AP"

            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
            device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
            self.logger.info(f"Initiating ping to DUT ip {device_ip} after power save")

            device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

            if len(self.cipher_list):
                cipher = self.select_cipher_list(self.cipher_list)
                self.wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)

            pkt_count = 100
            bytes_sent = (pkt_count * buffer_length)
            # Open ssl server socket in remote device(Raspberry pi or static device)
            if self.server_cert is None:
                self.ssl_server.interfaces.ssl.start_server()
            else:
                self.ssl_server.interfaces.ssl.start_server(server_cert=self.server_cert, server_key=self.server_key)
            # Open ssl client socket in the DUT
            sock = self.wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, "Socket id received is wrong. expected is 0"
            self.logger.info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            self.logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
                                                          option_val=SocketOptions.SOL_SOCKET)
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                          option_val=SocketOptions.SO_SSL_ENABLE)
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
                                                          option_val=SocketOptions.SSL_ENABLE)

            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                               timeout=15)
            # ssl socket opened in DUT connects to the server
            server_ip = self.ssl_server.interfaces.ssl.server_ip
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                           server_port=port1)

            # The api returns 100 bytes of random data
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            self.logger.info(f"Sending data {data_sent} over socket_no->{sock}")
            # DUT sends 100 bytes of data over ssl socket
            self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=bytes_sent)
            server_socket_no = 1
            # SSL server receives the data over ssl socket
            data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
            self.logger.info(f"Data received on remote socket opened is {data_receive}")
            assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
            self.logger.info("Data sent by DUT and received on server is matching")

            if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
            result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
            self.logger.info(f"Number of bytes sent by dut {result}")
            bytes_sent = result

            bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
            assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer are" \
                                                 f"not matched on socket {server_socket_no} "
            self.logger.info(
                f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
            # Close socket 1
            result = self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            assert b"success" in result, "unable to close opened ssl socket in the dut"
            self.logger.info("Successfully closed opened socket in the DUT")
            self.ssl_server.interfaces.ssl.stop_server()
            self.wifi_dut.interfaces.wifi.leave()

        self.wifi_sniffer.interfaces.capture.stop_capture()
        self.logger.info("Stop Sniffer finally")

        # decrypt with proper decryption key & verify that we can see the ICMP/DHCP packets
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"

        cipher_suite = \
            self.sl_collections.ssl_packet_decryption(self.wifi_sniffer, decryption_key, mac_address, ["tls"],
                                                      self.capture_filename, mode=1, get_cipher=True)['cipher']
        if not (len(cipher_suite) > 0):
            self.logger.info(f"tls client hello packet is not captured or one of the wifi 4-way handshake pkt "
                             "is "
                             "not captured")
        assert (len(cipher_suite) > 0), f"tls client hello packet is not captured or one of the wifi 4-way handshake " \
                                        f"pkt is not captured "

        self.logger.info(f"{len(cipher_suite)} times tls client hello message captured on sniffer log")
        for cipher in cipher_suite:
            cipher_suite_tmp = cipher[1]
            if not (cipher_suite_tmp == expected_cipher):
                self.logger.info(f"******cipher suite mismatched on iteration {cipher[0]}******\nexpected "
                                 f"is {expected_cipher}\nBut "
                                 f"observed {cipher_suite_tmp} ")
        self.logger.info(
            f"******As per sniffer capture, cipher suite advertised by DUT {mac_address}-> {cipher_suite_tmp}*******")
        self.wifi_dut.interfaces.wifi.leave()

    def socket_connect(self, wifi_dut, openssl, wifi_client, device_ip, port):
        openssl.interfaces.server.start(port=5001, tls_version="-tls1_2")
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")

        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)
        logger().info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_2_ENABLE} for the socket-id->{sock} using "
                      f"rsi_set sock opt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_V_1_2_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_V_1_2_ENABLE)
        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip,
                                      server_port=local_port,
                                      timeout=15)
        # ssl socket opened in DUT connects to the server
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=host_ip,
                                                  server_port=port)
        return sock

    def select_cipher_list(self, cipher_list):
        cipher = 0
        for count in cipher_list:
            for cipher_mem in Cipher:
                if count in str(cipher_mem):
                    cipher = cipher | cipher_mem.value
        return cipher


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
            "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.IEEE802_11W | Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "ca_cert": "ca-chain.cert.pem",
            "set_send_feature_frame": True,
        }
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [[]])
def test_wifi_sdk_advertise_all_ciphers_ssl_tx_TC19604(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                       cipher_list, logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_advertise_all_ciphers_ssl_tx_TC19604"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                 sl_collections, cipher_list, logger, mode=0)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list", [[]])
def test_wifi_sdk_advertise_all_ciphers_ssl_rx_TC19605(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                       cipher_list, logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_advertise_all_ciphers_ssl_rx_TC19605"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                 sl_collections, cipher_list, logger, mode=1)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
def test_wifi_sdk_advertise_ciphers_ssl_tx_TC19606(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list,
                                                   logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_tx_TC19606"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                 sl_collections, cipher_list, logger, mode=0)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


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
def test_wifi_sdk_advertise_ciphers_ssl_rx_TC19607(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list,
                                                   logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_rx_TC19607"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                 sl_collections, cipher_list, logger, mode=1)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_wifi_sdk_advertise_ciphers_ssl_tx_TC19608(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list,
                                                   logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_tx_TC19608"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                 sl_collections, cipher_list, logger, mode=0)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_wifi_sdk_advertise_ciphers_ssl_rx_TC19609(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list,
                                                   logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_rx_TC19609"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                 sl_collections, cipher_list, logger, mode=1)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_wifi_sdk_advertise_ciphers_ssl_tx_TC19610(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list,
                                                   logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_tx_TC19610"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                 sl_collections, cipher_list, logger, mode=0)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_wifi_sdk_advertise_ciphers_ssl_rx_TC19611(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, cipher_list,
                                                   logger, sl_collections):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_tx_TC19611"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, capture_filename,
                                 sl_collections, cipher_list, logger, mode=1)
        ssl_obj.ssl_connection_tx_rx()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_send_feature_frame": True,
        "rejoin_max_retry": 0,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_wifi_sdk_advertise_ciphers_ssl_tx_TC19612(wifi_sniffer, wifi_dut, wifi_access_point, openssl, wifi_client,
                                                   cipher_list, logger, sl_collections, sniffer_filter):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_tx_TC19612"
        expected_cipher = cipher_list
        port_connect = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, openssl, capture_filename,
                                 sl_collections, cipher_list, logger, mode=0)
        if len(cipher_list):
            cipher = ssl_obj.select_cipher_list(cipher_list)
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)

        sock = ssl_obj.socket_connect(wifi_dut, openssl, wifi_client, device_ip, port_connect)
        duration = 60
        buffer_length = 100
        t_end = time.time() + duration
        data_check = []
        while time.time() < t_end:
            data = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            data_check.append(data)
            data_final = "".join(data_check)
            wifi_dut.interfaces.wifi.bsdSocketSend(sock, data)

        logger.info(f"Total data sent from DUT {data_final}")
        result = openssl.interfaces.server.get_messages(timeout=100)[-1]
        logger.info(f"*************data received*************** {result}")
        assert data_final == result, "Data received doesn't match"

        openssl.interfaces.server.stop()
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        cipher_suite = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                            capture_filename, mode=0, get_cipher=True)['cipher']
        assert (len(cipher_suite) > 0), f"tls client hello packet is not captured"
        cipher_suite = cipher_suite[0][1]
        assert cipher_suite == expected_cipher, "expected cipher suite is not matching with actual"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_send_feature_frame": True,
        "rejoin_max_retry": 0,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384']])
def test_wifi_sdk_advertise_ciphers_ssl_rx_TC19613(wifi_sniffer, wifi_access_point, wifi_dut, openssl, wifi_client,
                                                   cipher_list, logger, sl_collections, sniffer_filter):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_rx_TC19613"
        expected_cipher = cipher_list
        port_connect = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, openssl, capture_filename,
                                 sl_collections, cipher_list, logger, mode=0)
        if len(cipher_list):
            cipher = ssl_obj.select_cipher_list(cipher_list)
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)

        sock = ssl_obj.socket_connect(wifi_dut, openssl, wifi_client, device_ip, port_connect)
        buffer_length = 200
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
        logger.info(f"DATA sent from remote PC to dut {data}")
        openssl.interfaces.server.send_message(data)
        buffer_length, buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(0)
        logger.info(f"Data received on dut {buffer}")
        assert data == buffer.decode(), "Date received on dut does not match the data sent from host"

        openssl.interfaces.server.stop()
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        cipher_suite = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                            capture_filename, mode=0, get_cipher=True)['cipher']
        assert (len(cipher_suite) > 0), f"tls client hello packet is not captured"
        cipher_suite = cipher_suite[0][1]
        assert cipher_suite == expected_cipher, "expected cipher suite is not matching with actual"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_send_feature_frame": True,
        "rejoin_max_retry": 0,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_wifi_sdk_advertise_ciphers_ssl_tx_TC19614(wifi_sniffer, wifi_dut, wifi_access_point, openssl, wifi_client,
                                                   cipher_list, logger, sl_collections, sniffer_filter):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_tx_TC19614"
        expected_cipher = cipher_list
        port_connect = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, openssl, capture_filename,
                                 sl_collections, cipher_list, logger, mode=0)
        if len(cipher_list):
            cipher = ssl_obj.select_cipher_list(cipher_list)
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)

        sock = ssl_obj.socket_connect(wifi_dut, openssl, wifi_client, device_ip, port_connect)
        duration = 60
        buffer_length = 100
        t_end = time.time() + duration
        data_check = []
        while time.time() < t_end:
            data = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            data_check.append(data)
            data_final = "".join(data_check)
            wifi_dut.interfaces.wifi.bsdSocketSend(sock, data)

        logger.info(f"Total data sent from DUT {data_final}")
        result = openssl.interfaces.server.get_messages(timeout=100)[-1]
        logger.info(f"*************data received*************** {result}")
        assert data_final == result, "Data received doesn't match"

        openssl.interfaces.server.stop()
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        cipher_suite = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                            capture_filename, mode=0, get_cipher=True)['cipher']
        assert (len(cipher_suite) > 0), f"tls client hello packet is not captured"
        cipher_suite = cipher_suite[0][1]
        assert cipher_suite == expected_cipher, "expected cipher suite is not matching with actual"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_send_feature_frame": True,
        "rejoin_max_retry": 0,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
@pytest.mark.parametrize("cipher_list",
                         [['TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256']])
def test_wifi_sdk_advertise_ciphers_ssl_rx_TC19615(wifi_sniffer, wifi_access_point, wifi_dut, openssl, wifi_client,
                                                   cipher_list, logger, sl_collections, sniffer_filter):
    try:
        capture_filename = "test_wifi_sdk_advertise_ciphers_ssl_rx_TC19615"
        expected_cipher = cipher_list
        port_connect = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, [0, 4, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, openssl, capture_filename,
                                 sl_collections, cipher_list, logger, mode=0)
        if len(cipher_list):
            cipher = ssl_obj.select_cipher_list(cipher_list)
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)

        sock = ssl_obj.socket_connect(wifi_dut, openssl, wifi_client, device_ip, port_connect)
        buffer_length = 200
        data = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
        logger.info(f"DATA sent from remote PC to dut {data}")
        openssl.interfaces.server.send_message(data)
        buffer_length, buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(0)
        logger.info(f"Data received on dut {buffer}")
        assert data == buffer.decode(), "Date received on dut does not match the data sent from host"

        openssl.interfaces.server.stop()
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        cipher_suite = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                            capture_filename, mode=0, get_cipher=True)['cipher']
        assert (len(cipher_suite) > 0), f"tls client hello packet is not captured"
        cipher_suite = cipher_suite[0][1]
        assert cipher_suite == expected_cipher, "expected cipher suite is not matching with actual"
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)



