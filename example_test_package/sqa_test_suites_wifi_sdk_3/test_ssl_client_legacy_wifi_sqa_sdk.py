import time
import pytest
import re
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
    RS9116JoinFeatureBitMap,
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
from datetime import datetime
from typing import Dict
import uuid
from threading import Thread
import threading
from utf.utils import get_tls_certificate_dir
from utf.utils.logger import get_logger

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


def logger():
    return get_logger(__name__)


class SSL_Connection:
    """
    Class to configure SSL and Rejoin parameters in DUT along with WLAN and SSL Socket Connection.
    """
    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger, sl_collections, cert1=None,
                 cert2=None, cert3=None, listen_interval_feature=False, listen_interval=1600, rejoin_params=None,
                 switch=None):
        self.cert1 = cert1
        self.cert2 = cert2
        self.cert3 = cert3
        self.logger = logger
        self.switch = switch
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.rejoin_params = rejoin_params
        self.sl_collections = sl_collections
        self.listen_interval = listen_interval
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.listen_interval_feature = listen_interval_feature

    def join_get_ip_ssl(self):
        # configure interface for the channel of the access point
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel
        )
        scan_fail = self.sl_collections.scan(self.wifi_dut)
        assert not scan_fail, "Scanning for AP failed"
        mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(thread=True)
        self.logger.info(f"DUT MAC_Address: {mac_address}")

        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.capture_filename)

        if not self.rejoin_params:
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=20,
                                                                          scan_interval=6,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0,
                                                                          thread=True)
        else:
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=self.rejoin_params[0],
                                                                          scan_interval=self.rejoin_params[1],
                                                                          beacon_missed_count=self.rejoin_params[2],
                                                                          first_time_retry_enable=self.rejoin_params[3],
                                                                          thread=True)
        if self.listen_interval_feature:
            # DUT connects to AP after join_ap API is executed
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point,
                                                  join_feature_bitmap=RS9116JoinFeatureBitMap.ListenIntervalFromPowerSave,
                                                  thread=True)
        else:
            status = self.sl_collections.connect(self.wifi_dut, self.wifi_access_point)
            assert not status, "Failed to Join to AP"
        if self.cert1:
            # The below API loads ca-cert into DUT at cert index 0
            self.wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                              str(get_tls_certificate_dir().joinpath(self.cert1[0])),
                                                              cert_index=0, thread=True)
        if self.cert2:
            # The below API loads ca-cert into DUT at cert index 1
            self.wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                              str(get_tls_certificate_dir().joinpath(self.cert2[0])),
                                                              cert_index=1, thread=True)
        if self.cert3:
            # The below API loads ca-cert into DUT at cert index 2
            self.wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                              str(get_tls_certificate_dir().joinpath(self.cert3[0])),
                                                              cert_index=2, thread=True)

        # DUT gets ipaddress through DHCP process after start_ip API is executed
        status = self.sl_collections.configure_ip(self.wifi_dut)
        assert not status, "Failed to Join to AP"
        if self.listen_interval_feature:
            # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
            # DUT to power save in Wifi+bluetooth mode
            self.wifi_dut.interfaces.wifi.power_save_listen_interval(RS9116PowerSaveModes.PowerSaveMode2,
                                                                     RS9116PowerSaveProcedureTypes.FastPowerSave,
                                                                     listen_interval=self.listen_interval, thread=True)

        else:
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', thread=True)
            # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
            #                                        RS9116PowerSaveProcedureTypes.FastPowerSave, thread=True)

        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        self.logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
        ping(device_ip, 10)
        return mac_address

    def join_get_ip(self):
        ping_count = 10
        # configure interface for the channel of the access point
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        scan_fail = self.sl_collections.scan(self.wifi_dut)
        assert not scan_fail, "Scanning for AP failed"

        mac_address = self.wifi_dut.interfaces.wifi.get_mac_address(thread=True)
        self.logger.info(f"DUT MAC_Address: {mac_address}")

        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")

        self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0,
                                                                      scan_interval=6, beacon_missed_count=40,
                                                                      first_time_retry_enable=0, thread=True)
        status = self.sl_collections.connect(self.wifi_dut, self.wifi_access_point)
        assert not status, "Failed to Join to AP"

        status = self.sl_collections.configure_ip(self.wifi_dut)
        assert not status, "Failed to Join to AP"

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', thread=True)
        # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                        RS9116PowerSaveProcedureTypes.FastPowerSave, thread=True)
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        self.logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
        ping(device_ip, ping_count)
        return mac_address

    def pdu_switch(self, switch, sleep_time, logger):
        self.logger.info("Turning off the AP")
        self.switch.interfaces.pdu_switch.turn_off()
        self.logger.info("Successfully powered off AP")
        time.sleep(sleep_time)
        self.logger.info("Again turning on the AP")
        self.switch.interfaces.pdu_switch.turn_on()


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
def test_wifi_sdk_ssl_client_testcase_c19109(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
                                                      sl_collections):
    """
    SSL Protocol handshakes and Verify exchanges between server and client sockets during TCP connection establishment
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_testcase_TC19109"
        pkt_count = 20000
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_obj = SSL_Connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
                                 sl_collections)
        dut_mac_address = ssl_obj.join_get_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1, thread=True)
        # The api returns 100 bytes of random data
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        logger.info(f"Sending data {data_sent} over socket_no->{sock}")
        # DUT sends 100 bytes of data over ssl socket
        wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data_sent, thread=True)
        server_socket_no = 1
        # SSL server receives the data over ssl socket
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        logger.info(f"Data received on remote socket opened is {data_receive}")
        assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
        logger.info("Data sent by DUT and received on server is matching")

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
        result = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=bytes_sent, thread=True)
        logger.info(f"Number of bytes sent by dut {result}")
        bytes_sent = result
        assert_packet_check = (0.95 * float(bytes_sent))
        logger.info(f"Number of bytes sent by dut {assert_packet_check}")
        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
        assert bytes_received >= int(
            assert_packet_check), f"Number of bytes sent by DUT and received on the remote peer are" \
                                  f"not matched on socket {server_socket_no} "
        logger.info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
        # Close socket 1
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock, thread=True)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info("Successfully closed opened socket in the DUT")
        wifi_dut.interfaces.wifi.leave(thread=True)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.parametrize("repeat", [100])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_client_connect_close_sequence_testcase_c19130(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                    ssl_server, logger, repeat, sl_collections):
    """
    ssl client socket connection, data send and socket close regression
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_connect_close_sequence_testcase_C19130"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        server_ip = ssl_server.interfaces.ssl.server_ip
        ssl_obj = SSL_Connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
                                 sl_collections)
        dut_mac_address = ssl_obj.join_get_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        fail_count = 0
        for iteration in range(0, repeat):
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server()
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
            assert sock == 0, f"iteration no->{iteration}:Socket id received is wrong. expected is 0"
            logger.info(
                f"iteration no->{iteration}: Successfully opened tcp client socket and socket id received is {sock} which "
                f"is expected")

            logger.info(
                f"iteration no->{iteration}: Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened

            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                     option_val=SocketOptions.SOL_SOCKET)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                     option_val=SocketOptions.SO_SSL_ENABLE)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                     option_val=SocketOptions.SSL_ENABLE)

            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                          timeout=15, thread=True)
            try:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                          server_port=port1, thread=True)
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
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data_sent, thread=True)
            server_socket_no = 1
            # SSL server receives the data over ssl socket
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
            logger.info(f"iteration no->{iteration}: Data received on remote socket opened is {data_receive}")
            assert data_sent == data_receive.decode(), f"iteration no->{iteration}:Data sent by DUT and received on " \
                                                       f"server is matching "
            logger.info(f"iteration no->{iteration}: Data sent by DUT and received on server is matching")
            # Close socket 1
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock, thread=True)
            assert b"success" in result, f"iteration no->{iteration}:unable to close opened ssl socket in the dut"
            logger.info(f"iteration no->{iteration}: Successfully closed opened socket in the DUT")

            if fail_count:
                logger.info(f"{fail_count} times failed to connect to the server out of {repeat} iterations")
            assert fail_count == 0, f"{fail_count} times failed to connect to the server out of {repeat} iterations"
            time.sleep(1)
            ssl_server.interfaces.ssl.stop_server()

        wifi_dut.interfaces.wifi.leave(thread=True)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_client_tx_rx_bidirectional_testcase_c19129(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                                 logger, sl_collections):
    """
    Data transfer over one ssl socket and rx over another socket
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_tx_rx_bidirectional_testcase_TC19129"
        pkt_count = 10000
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        bytes_sent = (pkt_count * buffer_length)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        server_ip = ssl_server.interfaces.ssl.server_ip

        ssl_obj = SSL_Connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
                                 sl_collections)
        dut_mac_address = ssl_obj.join_get_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        ssl_server.interfaces.ssl.start_server(port=port2)
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)

        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)
        logger.info(f"Setting TCP-RETRY limit to {SocketOptions.TCP_MAX_RETRY} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='TCP_RETRY',
                                                 option_val=SocketOptions.TCP_RETRY)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='TCP_MAX_RETRY',
                                                 option_val=SocketOptions.TCP_MAX_RETRY)
        local_port = randint(5001, 20000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1, thread=True)

        sock1 = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
        assert sock1 == 1, "Socket id received is wrong. expected is 1"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock1} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock1} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock1, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock1, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock1, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        local_port = randint(20001, 40000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock1, device_ip, local_port)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock1, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock1, server_ip=server_ip,
                                                  server_port=port2, thread=True)
        # pkt_count = 1000
        ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length, duration=300)
        ssl_server.interfaces.ssl.data_receive(2, pkt_count, buffer_length)
        logger.info("Start tx on the DUT on socket_id1")

        result = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock1, data=bytes_sent, thread=True)
        logger.info(f"Number of bytes sent by dut {result}")
        bytes_sent = result
        assert_packet_check = (0.95 * float(bytes_sent))
        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(2)
        assert bytes_received >= assert_packet_check, f"Number of bytes sent by DUT and received on the remote peer " \
                                                      f"not matched on socket {2} "
        logger.info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
        logger.info("Wait for 320 seconds to receive data on the socket_id->0")
        time.sleep(320)
        bytes_sent = ssl_server.interfaces.ssl.data_send_stats(1)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock, thread=True)
        bytes_received = int(result.split(b":")[1])
        logger.info(f"bytes received on socket {sock} -> {bytes_received}")
        logger.info(f"Bytes sent by remote peer {bytes_sent} on socket {1}")
        assert_packet_check = (0.95 * float(bytes_sent))
        # assert bytes_received == bytes_sent, "Packet loss observed while receive test"
        assert bytes_received >= assert_packet_check, "Packet loss observed while receive test"
        logger.info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock1, thread=True)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger.info(f"Successfully closed opened socket {sock1} in the DUT")
        wifi_dut.interfaces.wifi.leave(thread=True)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")

        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        raise error


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
def test_wifi_sdk_ssl_client_cipher_list_testcase_c19132(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
                                                         cipher_list, sl_collections):
    """
    SSL client functionality with the following cipher suites. Configure one of the following combination, provided in the test steps
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_cipher_list_testcase_TC19132"
        pkt_count = 20000
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        server_ip = ssl_server.interfaces.ssl.server_ip
        ssl_obj = SSL_Connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
                                 sl_collections)
        dut_mac_address = ssl_obj.join_get_ip()
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
            wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher, thread=True)
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server()
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
            assert sock == 0, f"Socket id received is wrong. expected is 0 when cipher suite selected is {cipher_str}"
            logger.info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected when "
                f"cipher suite selected is {cipher_str}")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API when cipher suite "
                        f"selected is {cipher_str}")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                     option_val=SocketOptions.SOL_SOCKET)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                     option_val=SocketOptions.SO_SSL_ENABLE)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                     option_val=SocketOptions.SSL_ENABLE)

            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                          timeout=15, thread=True)
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
                                                      thread=True)

            # The api returns 100 bytes of random data
            data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_length = len(data_sent)
            logger.info(f"Sending data {data_sent} over socket_no->{sock} when cipher suite selected is {cipher_str}")
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data_sent, thread=True)
            server_socket_no = 1
            # SSL server receives the data over ssl socket
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
            logger.info(
                f"Data received on remote socket opened is {data_receive} when cipher suite selected is {cipher_str}")
            assert data_sent == data_receive.decode(), f"Data sent by DUT and received on server is matching when cipher " \
                                                       f"suite selected is {cipher_str} "
            logger.info(
                f"Data sent by DUT and received on server is matching when cipher suite selected is {cipher_str}")

            if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
            result = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=bytes_sent, thread=True)
            logger.info(f"Number of bytes sent by dut {result}")
            bytes_sent = result
            assert_packet_check = (0.95 * float(bytes_sent))
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
            assert bytes_received >= assert_packet_check, f"Number of bytes sent by DUT and received on the remote peer are" \
                                                          f"not matched on socket {server_socket_no} when cipher suite selected is {cipher_str}"
            logger.info(
                f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received} when cipher suite selected is {cipher_str}")
            # Close socket 1
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock, thread=True)
            assert b"success" in result, "unable to close opened ssl socket in the dut when cipher suite selected is {" \
                                         "cipher_str} "
            logger.info("Successfully closed opened socket in the DUT when cipher suite selected is {cipher_str}")

            ssl_server.interfaces.ssl.stop_server()

        wifi_dut.interfaces.wifi.leave(thread=True)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "disable_cipher"])
def test_wifi_sdk_ssl_client_ciphersuite_mismatch_testcase_c19133(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                                  logger, sl_collections):
    """
    Verify SSL hand shake functionality in client and server mode when module cipher suite mismatches with the remote peer cipher suite
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_ciphersuite_mismatch_testcase_TC19133"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        server_ip = ssl_server.interfaces.ssl.server_ip

        ssl_obj = SSL_Connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
                                 sl_collections)
        dut_mac_address = ssl_obj.join_get_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        logger.info(
            f"Opening SSL server socket remotely with cipher suite->{Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA}")
        wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
                                                   thread=True)
        logger.info(f"Cipher suite selected in DUT is ECDHE-RSA-AES256-SHA384")
        ssl_server.interfaces.ssl.start_server(cipher_list="ECDHE-RSA-AES256-SHA384")
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)
        with pytest.raises(WlanError) as exc_info:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
                                                      thread=True)
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
        logger.info(f"DUT returned {exc_info.value.error_code} when cipher suite is mismatched")
        wifi_dut.interfaces.wifi.leave(thread=True)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_socket_limit_testcase_c19121(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
                                                   sl_collections):
    """
    Open SSL server socket in DUT with maximum client limit 3
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_socket_limit_testcase_TC19121"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        server_ip = ssl_server.interfaces.ssl.server_ip

        ssl_obj = SSL_Connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
                                 sl_collections)
        dut_mac_address = ssl_obj.join_get_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server()
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=5002)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=5003)

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=1, thread=True)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 20000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5001, thread=True)
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=1, thread=True)
        assert sock == 1, "Socket id received is wrong. expected is 1"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        local_port = randint(20001, 40000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5002, thread=True)

        sock = wifi_dut.interfaces.wifi.socket(protocol=1, thread=True)
        assert sock == 2, "Socket id received is wrong. expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)
        local_port = randint(40001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5003,
                                                      thread=True)
        assert exc_info.value.error_code == 0xD3, "Observed wrong error code, expected is 0xD3"
        logger.info(f"DUT sent error code->{exc_info.value.error_code} when trying to open third ssl socket which is "
                    f"expected")
        wifi_dut.interfaces.wifi.leave(thread=True)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")

        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_client_version_1_2_testcase_c19119(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
                                                         sl_collections):
    """
    Connect to ssl server socket which run with version 1.2 at remote side and connect to it from module with version 1.0
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_version_1_2_testcase_TC19119"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        server_ip = ssl_server.interfaces.ssl.server_ip

        ssl_obj = SSL_Connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
                                 sl_collections)
        dut_mac_address = ssl_obj.join_get_ip()
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(version="ssl_1.2")
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_V_1_0_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_V_1_0_ENABLE)

        local_port = randint(5001, 60000)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)
        with pytest.raises(WlanError) as exc_info:
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
                                                      thread=True)
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
        logger.info(f"DUT returned {exc_info.value.error_code} error when trying to connect to SSL server operating at "
                    f"version 1.2 and version selected in DUT is 1.0")
        wifi_dut.interfaces.wifi.leave(thread=True)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        raise error


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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "close_sockets"])
def test_wifi_sdk_ssl_max_sockets_testcase_c19128(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1,
                                                  cert2, sl_collections):
    """
    Opening Max number of SSL client sockets and data transfer
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_max_sockets_testcaseTC19128"
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        server_ip = ssl_server.interfaces.ssl.server_ip

        ssl_obj = SSL_Connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
                                 sl_collections)
        dut_mac_address = ssl_obj.join_get_ip()

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        pkt_count = 10000
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

        for sock_count in range(0, 2):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
            if sock_count == 0:
                assert sock == 0, f"socket id received is wrong, expected is 0"
            else:
                assert sock == 1, f"socket id received is wrong, expected is 1"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                     option_val=SocketOptions.SOL_SOCKET)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                     option_val=SocketOptions.SO_SSL_ENABLE)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                     option_val=SocketOptions.SSL_ENABLE)
            logger.info(
                f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='TCP_RETRY',
                                                     option_val=SocketOptions.TCP_RETRY)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='TCP_MAX_RETRY',
                                                     option_val=SocketOptions.TCP_MAX_RETRY)
            if sock_count == 0:
                cert_index = SocketOptions.CERT_INDEX0
            elif sock_count == 1:
                cert_index = SocketOptions.CERT_INDEX1

            logger.info(f"Mapping certificate index->{cert_index} for socket_id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_CERT_INDEX',
                                                     option_val=SocketOptions.SO_CERT_INDEX)
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='CERT_INDEX',
                                                     option_val=cert_index)

            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2

            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port,
                                          timeout=15, thread=True)
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                      server_port=socket_port, thread=True)

        socket_no = [1, 2]
        for socket in socket_no:
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout=10)
        result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length,
                                                                     time_interval=600, number_of_pkts=pkt_count,
                                                                     timeout=620, thread=True)
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
                assert bytes_sent_list[
                           socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                          f"remote peer " \
                                                          f"not matched on socket {socket} "
        for sock_count in range(0, 2):
            logger.info(f"Closing socket_id->{sock_count}")
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count, thread=True)
            assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
            logger.info(f"Successfully closed socket_id->{sock_count}")
        wifi_dut.interfaces.wifi.leave(thread=True)
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        raise error


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
        "rejoin_max_retry": 40,
        "scan_interval": 6,
        "beacon_missed_count": 40,
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "close_sockets"])
def test_wifi_sdk_ssl_client_tx_rejoin_length_1460_20_c19134(wifi_dut, wifi_access_point, wifi_sniffer, ssl_server,
                                                             switch, cert1, logger, sl_collections):
    """
    ssl tx while rejoining with different data sizes(1460,20)
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_tx_rejoin_length_1460_C19134"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length0 = ssl_server.interfaces.ssl.config['buffer_length']
        buffer_length1 = 20
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        pkt_count = 5000
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        server_ip = ssl_server.interfaces.ssl.server_ip

        # DUT connects to AP after join_ap API is executed
        rejoin_params = [40, 6, 40, 0]

        ssl_obj = SSL_Connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                 sl_collections, rejoin_params=rejoin_params)
        dut_mac_address = ssl_obj.join_get_ip_ssl()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(thread=True)
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)

        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        logger.info(f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='TCP_RETRY',
                                                 option_val=SocketOptions.TCP_RETRY)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='TCP_MAX_RETRY',
                                                 option_val=SocketOptions.TCP_MAX_RETRY)

        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_CERT_INDEX',
                                                 option_val=SocketOptions.SO_CERT_INDEX)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='CERT_INDEX',
                                                 option_val=SocketOptions.CERT_INDEX0)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port1, timeout=15, thread=True)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1, thread=True)

        for i in range(2):
            buffer_length = eval("buffer_length" + str(i))
            logger.info(f"************************{buffer_length}")
            bytes_sent = (pkt_count * buffer_length)
            socket_no = [1]
            pkt_rcv_timeout = 90
            sleep_time = 10

            for socket in socket_no:
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout)
            sleep_time = 0
            thread = Thread(target=ssl_obj.pdu_switch, args=(switch, sleep_time, logger), )
            thread.start()
            wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=1, data_len=buffer_length,
                                                                time_interval=550, number_of_pkts=pkt_count,
                                                                timeout=700, thread=True)
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
            assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                 f"not matched on socket {1} "

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock, thread=True)
        wifi_dut.interfaces.wifi.leave(thread=True)
        wifi_sniffer.interfaces.capture.stop_capture()

        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        raise error


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_tx_wait_time": True,
        "tx_wait_time": 160000,
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "wifi_powersave_disable", "close_sockets"])
def test_wifi_sdk_ssl_client_rx_while_rejoining_c19135(wifi_dut, wifi_access_point, wifi_sniffer, ssl_server, switch,
                                                       cert1, logger, sl_collections):
    """
    To check SSL rx functionality of DUT while rejoining
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_rx_while_rejoining_C19135"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length0 = ssl_server.interfaces.ssl.config['buffer_length']
        buffer_length1 = 20
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        server_ip = ssl_server.interfaces.ssl.server_ip

        # DUT connects to AP after join_ap API is executed
        rejoin_params = [20, 6, 40, 0]
        # rejoin_params = [40, 6, 40, 0]
        ssl_obj = SSL_Connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
                                 sl_collections, rejoin_params=rejoin_params)

        dut_mac_address = ssl_obj.join_get_ip_ssl()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(thread=True)
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)

        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        logger.info(f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='TCP_RETRY',
                                                 option_val=SocketOptions.TCP_RETRY)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='TCP_MAX_RETRY',
                                                 option_val=SocketOptions.TCP_MAX_RETRY)

        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_CERT_INDEX',
                                                 option_val=SocketOptions.SO_CERT_INDEX)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='CERT_INDEX',
                                                 option_val=SocketOptions.CERT_INDEX0)

        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port1, timeout=15, thread=True)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1, thread=True)

        for i in range(2):
            buffer_length = eval("buffer_length" + str(i))
            logger.info(f"************************buffer_length{buffer_length}")
            bytes_sent = (pkt_count * buffer_length)
            socket_no = [1]
            for socket in socket_no:
                ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length)
            sleep_time = 0
            thread = Thread(target=ssl_obj.pdu_switch, args=(switch, sleep_time, logger), )
            thread.start()
            buffer_length_rx, buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=20,
                                                                                        thread=True)
            logger.info(f"bytes received on socket {sock} -> {buffer_length_rx}")
            assert buffer_length == buffer_length_rx, "Packet loss observed while receive test"

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock, thread=True)
        wifi_dut.interfaces.wifi.leave(thread=True)

        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
    except Exception as error:
        raise error


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.MultipleSslVersionSupport,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_send_feature_frame": True,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "clear_certs"])
def test_wifi_sdk_ssl_client_1_2version_server_1_0_testcase_c19120(wifi_sniffer, wifi_dut, wifi_access_point, openssl,
                                                                   wifi_client, logger, sl_collections):
    """
    Connect to ssl server socket which run with version 1.0 at remote side and connect to it from module with version 1.2
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_server_1_0version_client_1_2_testcase_TC19120"
        ping_count = 10
        port_connect = 5001

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        # configure interface for the channel of the access point
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        scan_fail = sl_collections.scan(wifi_dut)
        assert not scan_fail, "Scanning for AP failed"

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(thread=True)
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 thread=True)
        status = sl_collections.connect(wifi_dut, wifi_access_point)
        assert not status, "Failed to Join to AP"

        status = sl_collections.configure_ip(wifi_dut)
        assert not status, "Failed to Join to AP"

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', thread=True)
        # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                        RS9116PowerSaveProcedureTypes.FastPowerSave, thread=True)

        openssl.interfaces.server.start(port=5001, tls_version="-tls1")

        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_2_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_V_1_2_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_V_1_2_ENABLE)

        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      thread=True)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()

        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=host_ip,
                                                      server_port=port_connect, thread=True)
        assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"

        openssl.interfaces.server.stop()
        result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock, thread=True)
        wifi_dut.interfaces.wifi.leave(thread=True)

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                       capture_filename, ap_bssid)

        if len(ssl_pkt) > 0:
            for i in ssl_pkt:
                if re.search(".*Client Hello", i):
                    version = re.search("Version:.*", i).group(0)
                    logger.info(f"TLS VERSION USED BY DUT is--->{version}")
                    assert "TLS 1.2" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
                    assert "Client Hello" in i, "Client Hello packet missed"
        else:
            logger.info(f"SSL packets are not found")
    except Exception as error:
        raise error


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.MultipleSslVersionSupport,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": ["ca-chain.cert.pem"],
        "set_send_feature_frame": True,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "clear_certs"])
def test_wifi_sdk_ssl_client_1_0version_server_1_0_testcase_c19117(wifi_sniffer, wifi_dut, wifi_access_point, openssl,
                                                                   wifi_client, logger, sl_collections):
    """
    Open ssl client socket with version 1.0 and do data transfer.
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_server_1_0version_client_1_0_testcase_TC19117"
        ping_count = 10
        port_connect = 5001

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        # configure interface for the channel of the access point
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        scan_fail = sl_collections.scan(wifi_dut)
        assert not scan_fail, "Scanning for AP failed"

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address(thread=True)
        logger.info(f"DUT MAC_Address: {dut_mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 thread=True)
        status = sl_collections.connect(wifi_dut, wifi_access_point)
        assert not status, "Failed to Join to AP"

        status = sl_collections.configure_ip(wifi_dut)
        assert not status, "Failed to Join to AP"

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
        # DUT to power save in Wifi+bluetooth mode
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', thread=True)
        # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                        RS9116PowerSaveProcedureTypes.FastPowerSave, thread=True)

        openssl.interfaces.server.start(port=5001, tls_version="-tls1")
        sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE, thread=True)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SOL_SOCKET',
                                                 option_val=SocketOptions.SOL_SOCKET)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_ENABLE)
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SSL_ENABLE',
                                                 option_val=SocketOptions.SSL_ENABLE)

        logger.info(f"Selecting SSL version {SocketOptions.SO_SSL_V_1_0_ENABLE} for the socket-id->{sock} using "
                    f"rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(thread=True, socket_fd=sock, option_name='SO_SSL_V_1_0_ENABLE',
                                                 option_val=SocketOptions.SO_SSL_V_1_0_ENABLE)

        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
                                      Thread=True)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=host_ip, server_port=port_connect,
                                                  thread=True)

        duration = 60
        buffer_length = 100
        t_end = time.time() + duration
        data_check = []
        while time.time() < t_end:
            data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
            )
            data_check.append(data)
            data_final = "".join(data_check)
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data, thread=True)

        out = openssl.interfaces.server.get_messages(timeout=100)
        result = out[-1]
        logger.info(f"Total data sent from DUT {data_final}")
        logger.info(f"*************data received*************** {result}")

        assert data_final == result, "Data received doesn't match"

        openssl.interfaces.server.stop()
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock, thread=True)
        wifi_dut.interfaces.wifi.leave()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        validation = True
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger.info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                       capture_filename, ap_bssid)['tls']
        if len(ssl_pkt) > 0:
            for i in ssl_pkt:
                if re.search(".*Client Hello", i):
                    version = re.search("Version:.*", i).group(0)
                    logger.info(f"TLS VERSION USED BY DUT is--->{version}")
                    assert "TLS 1.0" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
                    assert "Client Hello" in i, "Client Hello packet missed"
        else:
            logger.info(f"SSL packets are not found")
    except Exception as error:
        raise error


