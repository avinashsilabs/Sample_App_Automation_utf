import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCertificateType,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    SocketOptions,
    Si91xOperatingMode,
    DeviceConstants,
    Si91xJoinFeatureBitMap,
    Si91xAwsQos,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xModuleType,
    Si91xCertIdentifier
)
from utf.interfaces.wifi import WlanError
from utf.utils import get_tls_certificate_dir
import string
import random
import time
import re
from threading import Thread
from utf.utils.time_measurer import TimeMeasurer
import math
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping
from random import randint
from utf.interfaces.socket import SOCKET_TYPE_TCP
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from datetime import datetime
import uuid


def logger():
    return get_logger(__name__)


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def get_socket_id(sock_fd):
    return int(math.log2(sock_fd))


class ssl_connection:
    """
    Class to configure SSL and Rejoin parameters in DUT along with WLAN and SSL Socket Connection.
    """

    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections,
                 listen_interval=0, rejoin_params=None):
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.rejoin_params = rejoin_params
        self.sl_collections = sl_collections
        self.listen_interval = listen_interval
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point

    def join_get_ip(self, sniff_capture=True, power_save=True):
        if sniff_capture:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        if not self.rejoin_params:
            self.rejoin_params = [20, 6, 40, 0]
        result = self.sl_collections.join_to_wifi_network_with_rejoin(self.wifi_dut, self.wifi_access_point,
                                                                      self.rejoin_params, power_save=power_save,
                                                                      listen_interval=self.listen_interval)
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        return dut_ip, dut_mac_address

    def pdu_switch(self, switch=None, sleep_time=10):
        if not switch:
            logger().info("\n\nDisabling Wireless in AP")
            self.wifi_access_point.interfaces.wifi.stop_ap()
            time.sleep(sleep_time)
            logger().info("\n\nEnabling Wireless in AP")
            self.wifi_access_point.interfaces.wifi.start_ap()
            time.sleep(sleep_time)
            return
        logger().info("Turning off the AP")
        switch.interfaces.pdu_switch.turn_off()
        logger().info("Successfully powered off AP")
        time.sleep(sleep_time)
        logger().info("Again turning on the AP")
        switch.interfaces.pdu_switch.turn_on()


class SocketDataTransfer:
    """
    This class contains methods related to TCP and SSL Data transfer between remote server and DUT
    """

    def tcp_socket_rx(self, remote_socket_factory, index, no_of_pkts, data_size, logger):
        data_length = 0
        index = index - 1
        logger.info(f"TCP Receiving data over socket id {index}")
        for count in range(0, no_of_pkts):
            data = remote_socket_factory.interfaces.socket.sockets[index].recv_data_tcp(data_size)
            data_length = data_length + len(data)
        logger.info(f"Total bytes received on socket id {index} -> {data_length} TCP")

    def ssl_socket_rx(self, ssl_server, sock_id, pkt_count, buffer_length, logger):
        logger.info(f"SSL Receiving data over socket id {sock_id}")
        ssl_server.interfaces.ssl.data_receive(sock_id + 1, pkt_count, buffer_length, pkt_rcv_timeout=120)


class FilterPacket:
    """
    Class for parsing sniffer capture to get beacon interval and dtim period.
    """

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


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_three_sockets_receive_data_testcase_C19153(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                                 logger, sl_collections):
    """
    Connection to Three Openssl Servers and receive data over three SSL Sockets
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_ssl_three_sockets_receive_data_testcase_C19153"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False, power_save=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        logger.info(f"Applying performance profile mode")
        wifi_dut.interfaces.wifi.set_performance_profile("power_save_low_latency")

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']

        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"

            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        socket_no = [1, 2, 3]
        for socket in socket_no:
            for iteration in range(5):
                buffer_length = 100
                pkt_count = 1
                tx_buffer = "".join(
                    random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
                )

                ssl_server.interfaces.ssl.send_data(socket, pkt_count, buffer_length, message=tx_buffer)
                sock = (socket - 1)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)

                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(1)
        wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORD,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_three_openssl_sockets_set_16k_record_C19164(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                                  logger, sl_collections):
    """
    Connection to three SSL Sockets. Three Openssl Servers and receive data over three SSL Sockets when 16K record size is enabled
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_three_openssl_sockets_set_16k_record_C19164"

        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False, power_save=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        logger.info(f"Applying performance profile mode")
        wifi_dut.interfaces.wifi.set_performance_profile("power_save_low_latency")

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']

        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"

            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        socket_no = [1, 2, 3]
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            for socket in socket_no:
                for iteration in range(5):
                    buffer_length = 100
                    pkt_count = 1
                    tx_buffer = "".join(
                        random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
                    )

                    ssl_server.interfaces.ssl.send_data(socket, pkt_count, buffer_length, message=tx_buffer)
                    sock = (socket - 1)
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)

                    assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
        wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_three_sockets_tx_rx_data_testcase_C19201(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                               logger, sl_collections):
    """
    Connection to three SSL Sockets. Three Openssl Servers and transmit over Two SSL Sockets and receive data over One SSL Sockets
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_tx_rx_data_testcase_C19201"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_params=[0, 4, 40, 0],
                                                                 associated=False, power_save=False)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        logger.info(f"Applying performance profile mode")
        wifi_dut.interfaces.wifi.set_performance_profile("power_save_low_latency")

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']

        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port1)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port2)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=port3)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"

            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)

            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        socket_no = [1, 2, 3]
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            for socket in socket_no:
                buffer_length = 100
                pkt_count = 1
                tx_buffer = "".join(
                    random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
                )
                if socket < 3:
                    logger.info(f"DATA TRANSFER -----DUT SENDING DATA ON SOCKET ID{socket - 1}")
                    data_length = len(tx_buffer)
                    socket_number = socket - 1
                    # DUT sends 100 bytes of data over ssl socket
                    wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket_number, data=tx_buffer)
                    server_socket_no = socket
                    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
                    logger.info(f"Data received on remote socket opened is {data_receive}")
                    assert tx_buffer == data_receive.decode(), "Data sent by DUT and received on server is matching"
                else:
                    logger.info(f"DATA TRANSFER -----DUT RECEVING DATA ON SOCKET ID{socket - 1}")
                    ssl_server.interfaces.ssl.send_data(socket, pkt_count, buffer_length, message=tx_buffer)
                    sock = (socket - 1)
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)

                    assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        for sock_count in range(0, 3):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
        wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
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
def test_wifi_sdk_ssl_three_sockets_shut_down_testcase_c19157(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                              cert1, cert2, cert3, logger, sl_collections,
                                                              sniffer_filter):
    """
    Connection to three SSL Sockets and Transmit data over three SSL Sockets and Socket Shutdown when calling rsi_shutdown()
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_shut_down_testcase_C19157"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']

        for count in range(1, 11):
            logger.info(f"************** Initiating test for iteration '{count}' ***********************")
            ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
            ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
            ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
            server_ip = ssl_server.interfaces.ssl.server_ip

            for sock_count in range(0, 3):
                sock = wifi_dut.interfaces.wifi.socket()
                assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
                logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                if sock_count == 0:
                    socket_port = port1
                elif sock_count == 1:
                    socket_port = port2
                else:
                    socket_port = port3
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

            pkt_count = 100
            buffer_length = 1300
            for socket in range(1, 4):
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout=10)
            socket_list = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                                              number_of_pkts=pkt_count, )
            sock_count = 0
            bytes_sent_list = []
            for socket_stats in socket_list:
                logger.info(
                    f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
                bytes_sent_list.append(socket_stats[0])
                sock_count = sock_count + 1
            for socket in range(1, 4):
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent_list[
                           socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                          f"remote peer not matched on socket {socket}"
            for sock_id in range(3):
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
                logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
            ssl_server.interfaces.ssl.stop_server()
            logger.info(f"************** Iteration '{count}' Completed ***********************\n\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
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
def test_wifi_sdk_ssl_three_sockets_close_reopen_socket2_c19159(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                ssl_server, logger, cert1, cert2, cert3,
                                                                sl_collections, sniffer_filter):
    """
    Connection to three SSL Sockets and Check the Network parameters after socket connection.
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_close_reopen_socket2_c19159"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(0, 3):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                socket_port = port3
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        sock_id = 1
        logger.info(f"Closing socket_id '{sock_id}' in the DUT as per test step")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
        ssl_server.interfaces.ssl.close_socket(socket_no=2)
        time.sleep(10)

        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 1, f"socket id received is wrong, expected is 1"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5002, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=5002)

        for socket in range(1, 4):
            if socket != 2:
                server_sock = socket
            else:
                server_sock = 4
            ssl_server.interfaces.ssl.data_receive(server_sock, pkt_count, buffer_length, pkt_rcv_timeout=10)

        socket_list = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                                          number_of_pkts=pkt_count)

        sock_count = 0
        bytes_sent_list = []
        for socket_stats in socket_list:
            logger.info(
                f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
            bytes_sent_list.append(socket_stats[0])
            sock_count = sock_count + 1

        for socket in range(1, 4):
            if socket != 2:
                server_sock = socket
            else:
                server_sock = 4
            if ssl_server.interfaces.ssl.socket_connection_status(server_sock):
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_sock)
                assert bytes_sent_list[
                           socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                          f"remote peer not matched on socket {socket - 1}"
        for sock_id in range(3):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
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
def test_wifi_sdk_ssl_three_sockets_close_socket2_on_remote_c19160(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                   ssl_server, logger, cert1, cert2, cert3,
                                                                   sl_collections, sniffer_filter):
    """
    Verify the data transmit over 2nd socket after close the socket from the remote server and reopen the Second Socket
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_close_reopen_socket2_testcase_c19160"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(0, 3):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                socket_port = port3
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        logger.info(f"Closing 2nd socket in remote server as per test step")
        ssl_server.interfaces.ssl.close_socket(socket_no=2)
        time.sleep(10)
        logger.info(f"Successfully closed 2nd socket in the remote server")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=1)
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        logger.info("Again opening client socket in DUT")
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 1, f"socket id received is wrong, expected is 1"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=5002, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=5002)

        for socket in range(1, 4):
            if socket != 2:
                server_sock = socket
            else:
                server_sock = 4
            ssl_server.interfaces.ssl.data_receive(server_sock, pkt_count, buffer_length, pkt_rcv_timeout=10)

        socket_list = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                                          number_of_pkts=pkt_count)

        sock_count = 0
        bytes_sent_list = []
        for socket_stats in socket_list:
            logger.info(
                f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
            bytes_sent_list.append(socket_stats[0])
            sock_count = sock_count + 1

        for socket in range(1, 4):
            if socket != 2:
                server_sock = socket
            else:
                server_sock = 4
            if ssl_server.interfaces.ssl.socket_connection_status(server_sock):
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_sock)
                assert bytes_sent_list[
                           socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                          f"remote peer not matched on socket {socket - 1}"
        for sock_id in range(3):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_wifi_sdk_rtc_get_multiple_times_c19178(wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold,
                                                logger, sl_collections):
    """
    Verify whether the device is able to set the RTC Timer multiple times
    """
    try:
        capture_filename = "test_wifi_sdk_rtc_get_multiple_times_c19178"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        set_seconds = 30
        set_minutes = 6
        set_hour = 10
        set_month_day = 10
        set_month = 10
        set_year = 2023
        set_week_day = 3
        wait_time_after_scan = 10
        set_time_sec = ((set_minutes * 60) + set_seconds)

        logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
        wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hours=set_hour,
                                         day=set_month_day, month=set_month, year=set_year, weekday=set_week_day)
        time.sleep(10)
        wifi_dut.interfaces.wifi.get_rtc()

        logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
        wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hours=set_hour,
                                         day=set_month_day, month=set_month, year=set_year, weekday=set_week_day)
        with TimeMeasurer() as t:
            wifi_dut.interfaces.wifi.scan(ssid=None)
            mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger.info(f"DUT MAC_Address: {mac_address}")
        scan_time = t.duration
        with TimeMeasurer() as t:
            logger.info(f"Time taken for scan -> {scan_time} seconds")
            logger.info(f"wait for {wait_time_after_scan} seconds")
        scan_logger_time1 = t.duration
        time.sleep(wait_time_after_scan)

        result = wifi_dut.interfaces.wifi.get_rtc()
        get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = result.values()
        get_time_sec = ((get_minutes * 60) + get_seconds)
        assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
                set_year == get_year) and (set_week_day == get_week_day)

        idle_time = wait_time_after_scan + scan_time + scan_logger_time1
        time_dif = get_time_sec - set_time_sec - idle_time

        with TimeMeasurer() as t:
            logger.info(f"idle time after initiating set rtc after scan -> {idle_time}")
            assert (time_dif >= tolerance_threshold[0]) and (
                    time_dif <= tolerance_threshold[1]), f"get time updated is not in tolerance level. Time" \
                                                         f"difference observed is {time_dif} after scan"
            logger.info(f"Time difference observed between set time and get time is {time_dif} seconds,which is in "
                        "tolerance level")
            logger.info("get_rtc is working fine after scan")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("tolerance_threshold", [[-1, 2]])
def test_wifi_sdk_rtc_get_multiple_times_c19179(wifi_sniffer, wifi_access_point, wifi_dut, tolerance_threshold,
                                                logger, sl_collections, sniffer_filter):
    """
    Verify whether the device is able to update the RTC Timer
    """
    try:
        capture_filename = "test_wifi_sdk_rtc_get_multiple_times_c19179"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        ping_count = 10
        set_seconds = 30
        set_minutes = 6
        set_hour = 10
        set_month_day = 10
        set_month = 10
        set_year = 2023
        set_week_day = 3
        wait_time_after_scan = 10
        listen_interval = 700
        set_time_sec = ((set_minutes * 60) + set_seconds)

        logger.info(f"Time in seconds just before initiating set rtc ->  {set_time_sec}")
        wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hours=set_hour,
                                         day=set_month_day, month=set_month, year=set_year, weekday=set_week_day)

        with TimeMeasurer() as t:
            wifi_dut.interfaces.wifi.scan(ssid=None)
        scan_time = t.duration
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger.info(f"DUT MAC_Address: {dut_mac_address}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        with TimeMeasurer() as t:
            logger.info(f"Time taken for scan -> {scan_time} seconds")
            logger.info(f"wait for {wait_time_after_scan} seconds")
        scan_logger_time1 = t.duration
        time.sleep(wait_time_after_scan)

        # get_rtc API returns time parameters output at the instance
        result = wifi_dut.interfaces.wifi.get_rtc()
        get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = result.values()
        get_time_sec = ((get_minutes * 60) + get_seconds)
        assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
                set_year == get_year) and (set_week_day == get_week_day)

        idle_time = wait_time_after_scan + scan_time + scan_logger_time1
        time_dif = get_time_sec - set_time_sec - idle_time

        with TimeMeasurer() as t:
            logger.info(f"idle time after initiating set rtc after scan -> {idle_time}")
            assert (time_dif >= tolerance_threshold[0]) and (
                    time_dif <= tolerance_threshold[1]), f"get time updated is not in tolerance level." \
                                                         f"Time difference observed is {time_dif} after scan"
            logger.info(
                f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance "
                f"level ")

            logger.info("get_rtc is working fine after scan")
        scan_logger_time2 = t.duration

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromPowerSave)
        with TimeMeasurer() as t:
            logger.info("Joining the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            ip_status, ip_config = sl_collections.configure_ip(wifi_dut)
            assert ip_status, "Failed to get ip"
        join_time = t.duration

        with TimeMeasurer() as t:
            logger.info(f"Time taken for connecting to the AP, getting IP and ping for 10 sec  -> {join_time} seconds")
            logger.info(f"wait for 10 seconds")
        join_logger_time = t.duration
        wait_time_after_join = 10
        time.sleep(wait_time_after_join)
        idle_time = wait_time_after_scan + wait_time_after_join + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time

        # get_rtc API returns time parameters output at the instance
        result = wifi_dut.interfaces.wifi.get_rtc()
        get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = result.values()
        get_time_sec = ((get_minutes * 60) + get_seconds)
        assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
                set_year == get_year) and (set_week_day == get_week_day)
        time_dif = get_time_sec - set_time_sec - idle_time

        with TimeMeasurer() as t:
            logger.info(f"idle time after initiating set rtc after join, ip-> {idle_time}")
            assert (time_dif >= tolerance_threshold[0]) and (
                    time_dif <= tolerance_threshold[1]), f"get time updated is not in tolerance level." \
                                                         "Time difference observed is {time_dif} after join, ip"
            logger.info(
                f"Time difference observed between set time and get time is {time_dif} seconds,which is in tolerance "
                f"level")
            logger.info("get_rtc is working fine after ip command")
        join_logger_time2 = t.duration

        with TimeMeasurer() as t:
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
            wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
                                                             listen_interval=listen_interval)
            ping(device_ip, ping_count)
        power_save_time = t.duration
        with TimeMeasurer() as t:
            logger.info(
                f"Time taken for executing power save api, ping for {ping_count} packets -> {power_save_time} seconds")
            logger.info(f"wait for 10 seconds")
        powersave_logger_time = t.duration
        wait_time_after_powersave = 10
        time.sleep(wait_time_after_powersave)
        idle_time = wait_time_after_scan + wait_time_after_join + wait_time_after_powersave + scan_time + join_time + scan_logger_time1 + scan_logger_time2 + join_logger_time + join_logger_time2 + power_save_time + powersave_logger_time

        # get_rtc API returns time parameters output at the instance
        result = wifi_dut.interfaces.wifi.get_rtc()
        get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = result.values()

        get_time_sec = ((get_minutes * 60) + get_seconds)
        assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
                set_year == get_year) and (set_week_day == get_week_day)
        time_dif = get_time_sec - set_time_sec - idle_time
        logger.info(f"idle time after initiating set rtc after power save -> {idle_time}")
        assert (time_dif >= tolerance_threshold[0]) and (
                time_dif <= tolerance_threshold[1]), f"get time updated is not in tolerance level." \
                                                     f"Time difference observed is {time_dif} after power save"
        logger.info(f"Time difference observed between set time and get time is {time_dif} seconds, which is in "
                    f"tolerance level")
        logger.info("get_rtc is working fine after power save command is initiated")
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3) | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca_ecdsa.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca_ecdsa.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca_ecdsa.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
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
@pytest.mark.parametrize("domain_name", ["a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_three_sockets_connectivity_check_loading_wrong_certs_c19165(wifi_sniffer, wifi_dut, logger,
                                                                                  wifi_access_point, sniffer_filter,
                                                                                  ssl_server, cert1, cert2, domain_name,
                                                                                  cert3, sl_collections):
    """
    Verify the three SSL Socket Functionality by loading the wrong certificates
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_connectivity_check_loading_wrong_certs_c19165"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = 8883
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                server_ip = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000, timeout=30)
                server_ip = re.sub('b\'', '', str(server_ip))[:-3]
                logger.info(f"server_ip {server_ip}")
                socket_port = port3
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
            error_code = 0
            try:
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
            except Exception as err:
                error_match = re.search("status:(.*)", str(err))
                if error_match:
                    error_code = error_match.group()
                    logger.info(f"error_code: {error_code}")
            assert error_code, "DUT did not send error code when trying to connect to ssl server"
            logger.info(f"DUT sent error code when trying to connect to ssl server which is expected as per test step")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("domain_name", ["a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "close_sockets"])
def test_wifi_sdk_ssl_connection_when_the_date_rtc_timer_expired_c19199(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                        domain_name, logger, sl_collections,
                                                                        sniffer_filter):
    """
    Cloud/SSL Connection when the Date (RTC Timer) is expired
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_connection_when_the_date_rtc_timer_expired_c19199"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        port = 8883
        set_seconds = 30
        set_minutes = 6
        set_hour = 10
        set_month_day = 10
        set_month = 10
        set_year = 2000
        set_week_day = 3
        wait_time = 100
        set_time_sec = ((set_minutes * 60) + set_seconds)

        wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hours=set_hour, day=set_month_day,
                                         month=set_month, year=set_year, weekday=set_week_day)
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        result = wifi_dut.interfaces.wifi.get_rtc()
        get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = result.values()
        get_time_sec = ((get_minutes * 60) + get_seconds)
        assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
                set_year == get_year) and (set_week_day == get_week_day)
        time_dif = get_time_sec - set_time_sec - wait_time
        logger.info(f"time diff between set and get rtc'{time_dif}'")

        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "socket id received is wrong, expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        local_port = randint(40001, 50000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)

        server_ip = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000)
        server_ip = re.sub('b\'', '', str(server_ip))[:-3]
        logger.info(f"server_ip {server_ip}")
        error_code = 0
        try:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port)
        except Exception as err:
            error_match = re.search("status:(.*)", str(err))
            if error_match:
                error_code = error_match.group()
                logger.info(f"error_code: {error_code}")
        assert error_code, "DUT did not send error code when trying to connect to aws server"
        logger.info(f"DUT sent error code when trying to connect to aws server which is expected as per test step")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger.info(f"Successfully closed socket_id '{sock}' in the DUT")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 4, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_2SSL_1TCP_TX_testcase_C19185(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                               remote_socket_factory, logger, sl_collections):
    """
    Connection to Two Secured (SSL) Sockets, one Unsecured Socket and transmit data on three sockets
    """
    try:
        capture_filename = "test_wifi_sdk_2SSL_1TCP_TX_testcase_C19185"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        sock_obj = SocketDataTransfer()
        #
        port3 = 5007
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port3']
        list_sock = []
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, ping_count=10,
                                                     associated=False)

        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        # Open ssl server socket in remote device-Port1
        ssl_server.interfaces.ssl.start_server(port=port1)
        # Open ssl server socket in remote device-Port2
        ssl_server.interfaces.ssl.start_server(port=port2)
        # Open ssl server socket in remote device-Port3
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock_port = eval('port' + str(sock_count + 1))
            # Open ssl client socket in the DUT
            if sock_count < 2:
                local_port = randint(5001, 20000)
                sock = wifi_dut.interfaces.wifi.socket()
                assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"

                # Enable ssl option for socket opened
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)

                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
                retrial = 0
                for retry in range(3):
                    try:
                        logger.info(f"DUT with sock id {sock} connecting to server with port number:{sock_port}")
                        # ssl socket opened in DUT connects to the server
                        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                  server_port=sock_port, timeout=20)
                        retrial = 1
                        break
                    except:
                        if retry == 2:
                            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                            ssl_server.interfaces.ssl.stop_server()
                        logger.info(f"Retrying connection for {retry} times")
                        time.sleep(5)
                assert retrial == 1, "Connection to socket failed"
            else:
                local_port = randint(20001, 40000)
                server_socket = remote_socket_factory.interfaces.socket.create_socket()
                server_socket.time_limit = 3600
                server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)

                sock = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                       protocol="IPPROTO_TCP")
                assert sock == sock_count, f"socket id received is wrong, expected is 2"
                logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
                server_ipp = server_socket.hostname_or_ip_address(ip_version=4)
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ipp, server_port=sock_port)

            list_sock.append(sock)
        send_list = []
        pkt_count = 100
        buffer_length = 100
        data_size = 100
        for sock_id in list_sock:
            if sock_id == 2:
                th_start = Thread(target=sock_obj.tcp_socket_rx,
                                  args=(remote_socket_factory, 1, pkt_count, data_size, logger), )
            else:
                th_start = Thread(target=sock_obj.ssl_socket_rx,
                                  args=(ssl_server, sock_id, pkt_count, buffer_length, logger), )
            send_list.append(th_start)
            th_start.start()

        wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                            number_of_pkts=pkt_count)
        time.sleep(5)

        validation = True
        wifi_sniffer.interfaces.capture.stop_capture()
        for sock in range(3):
            logger.info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_2SSL_1TCP_RX_testcase_C19187(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                               remote_socket_factory, logger, sl_collections):
    """
    Connection to Two Secured (SSL) Sockets, one Unsecured Socket and receive data on three sockets
    """
    try:
        capture_filename = "test_wifi_sdk_2SSL_1TCP_RX_testcase_C19187"
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        port3 = 5007
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port3']
        list_sock = []
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True, ping_count=10,
                                                     associated=False, retry_count=2)

        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        # Open ssl server socket in remote device-Port1
        ssl_server.interfaces.ssl.start_server(port=port1)
        # Open ssl server socket in remote device-Port2
        ssl_server.interfaces.ssl.start_server(port=port2)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock_port = eval('port' + str(sock_count + 1))
            # Open ssl client socket in the DUT
            if sock_count < 2:
                local_port = randint(5001, 20000)
                sock = wifi_dut.interfaces.wifi.socket()
                assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"

                # Enable ssl option for socket opened
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)

                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
                retrial = 0
                for retry in range(3):
                    try:
                        logger.info(f"DUT with sock id {sock} connecting to server with port number:{sock_port}")
                        # ssl socket opened in DUT connects to the server
                        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                  server_port=sock_port, timeout=20)
                        retrial = 1
                        break
                    except:
                        if retry == 2:
                            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                            ssl_server.interfaces.ssl.stop_server()
                        logger.info(f"Retrying connection for {retry} times")
                        time.sleep(5)
                assert retrial == 1, "Connection to socket failed"
            else:
                local_port = randint(20001, 40000)
                server_socket = remote_socket_factory.interfaces.socket.create_socket()
                server_socket.time_limit = 3600
                server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)

                sock = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                       protocol="IPPROTO_TCP")
                assert sock == sock_count, f"socket id received is wrong, expected is 2"
                logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
                server_ipp = server_socket.hostname_or_ip_address(ip_version=4)
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ipp, server_port=sock_port)

            list_sock.append(sock)

        socket_no = [1, 2, 3]
        for i in range(10):
            for socket in socket_no:
                buffer_length = 100
                pkt_count = 10
                tx_buffer = "".join(
                    random.choices(string.ascii_uppercase + string.digits, k=buffer_length)
                )
                if socket < 3:
                    ssl_server.interfaces.ssl.send_data(socket, pkt_count, buffer_length, message=tx_buffer)
                    logger.info(f"DATA SENT :{tx_buffer}")
                else:
                    remote_socket_factory.interfaces.socket.sockets[0].send_data_tcp(tx_buffer, use_server_socket=True)
                    logger.info(f"DATA SENT :{tx_buffer}")

                socket_id = (socket - 1)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket_id)

        validation = True

        for sock in list_sock:
            logger.info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        ssl_server.interfaces.ssl.stop_server()
        remote_socket_factory.interfaces.socket.close_all()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 4, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_1ssl_2tcp_sockets_send_data_testcase_C19188(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                              remote_socket_factory, logger, sl_collections):
    """
    Connection to Two TCP Servers and One OpenSSL Server and transmit data over three sockets
    """
    try:
        capture_filename = "test_wifi_sdk_1ssl_2tcp_sockets_send_data_testcase_C19188"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        sock_obj = SocketDataTransfer()
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = 5002
        port3 = 5003
        list_sock = []
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, ping_count=10,
                                                     associated=False)

        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)

        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        # Open ssl server socket in remote device-Port1
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock_port = eval('port' + str(sock_count + 1))
            # Open ssl client socket in the DUT
            if sock_count == 0:
                local_port = randint(5001, 20000)
                sock = wifi_dut.interfaces.wifi.socket()
                assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"

                # Enable ssl option for socket opened
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)

                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
                retrial = 0
                for retry in range(3):
                    try:
                        logger.info(f"DUT with sock id {sock} connecting to server with port number:{sock_port}")
                        # ssl socket opened in DUT connects to the server
                        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                  server_port=sock_port, timeout=20)
                        retrial = 1
                        break
                    except:
                        if retry == 2:
                            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                            ssl_server.interfaces.ssl.stop_server()
                        logger.info(f"Retrying connection for {retry} times")
                        time.sleep(5)
                assert retrial == 1, "Connection to socket failed"
            if sock_count > 0:
                local_port = randint(20001, 40000)
                server_socket = remote_socket_factory.interfaces.socket.create_socket()
                server_socket.time_limit = 3600
                server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)

                sock = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                       protocol="IPPROTO_TCP")
                assert sock == sock_count, f"socket id received is wrong, expected is 2"
                logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
                server_ipp = server_socket.hostname_or_ip_address(ip_version=4)
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ipp, server_port=sock_port)

            list_sock.append(sock)
        logger.info(f"SOCKET LIST{list_sock}")

        pkt_count = 100
        buffer_length = 100
        data_size = 100
        send_list = []

        for sock_id in list_sock:
            if sock_id > 0:
                th_start = Thread(target=sock_obj.tcp_socket_rx,
                                  args=(remote_socket_factory, sock_id, pkt_count, data_size, logger), )
            if sock_id == 0:
                th_start = Thread(target=sock_obj.ssl_socket_rx,
                                  args=(ssl_server, sock_id, pkt_count, buffer_length, logger), )
            send_list.append(th_start)
            th_start.start()

        wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                            number_of_pkts=pkt_count)
        time.sleep(10)
        validation = True
        for sock in list_sock:
            logger.info(f"Closing socket_id->{sock}")
            result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()
        remote_socket_factory.interfaces.socket.close_all()
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        ssl_server.interfaces.ssl.stop_server()
        remote_socket_factory.interfaces.socket.close_all()
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 4, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_tcp_three_sockets_send_data_testcase_C19189(wifi_sniffer, wifi_dut, wifi_access_point,
                                                              remote_socket_factory, remote_socket, logger,
                                                              sl_collections):
    """
    Connection to Three Unsecured (TCP) Servers and transmit data over three sockets
    """
    try:
        capture_filename = "test_wifi_sdk_tcp_three_sockets_send_data_testcase_C19189"
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}.pcap"
        )
        sock_obj = SocketDataTransfer()
        port1 = 5001
        port2 = 5002
        port3 = 5003
        list_sock = []
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, ping_count=10,
                                                     associated=False)

        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)

        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        for sock_count in range(3):
            sock_port = eval('port' + str(sock_count + 1))
            local_port = randint(20001, 60000)
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)

            sock = wifi_dut.interfaces.wifi.socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                   protocol="IPPROTO_TCP")
            assert sock == sock_count, f"socket id received is wrong, expected is 2"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            server_ipp = server_socket.hostname_or_ip_address(ip_version=4)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ipp, server_port=sock_port)
            list_sock.append(sock)
        logger.info(f"SOCKET LIST{list_sock}")

        pkt_count = 100
        buffer_length = 100
        data_size = 100
        for sock_id in range(1, 4):
            th_start = Thread(target=sock_obj.tcp_socket_rx,
                              args=(remote_socket_factory, sock_id, pkt_count, data_size, logger), )
            th_start.start()

        wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                            time_interval=600,
                                                            number_of_pkts=pkt_count)
        time.sleep(5)

        validation = True

        for sock in list_sock:
            logger.info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
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
def test_wifi_sdk_2SSL_tcp_ack_feature_testcase_c19136(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cert1,
                                                       cert2, logger, sl_collections, sniffer_filter):
    """
    Open more than one ssl tcp sockets by enabling TCP ack feature in the socket create command.
    """
    try:
        capture_filename = "test_wifi_sdk_2SSL_tcp_ack_feature_testcase_c19136"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(2):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        pkt_count = 1000
        buffer_length = 100
        send_list = []
        for sock_id in range(1, 3):
            th_start = Thread(target=ssl_server.interfaces.ssl.data_receive,
                              args=(sock_id, pkt_count, buffer_length))
            send_list.append(th_start)
            th_start.start()
        wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length, time_interval=600,
                                                            number_of_pkts=pkt_count)
        for sock_id in range(2):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
        tcp_pkt_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tcp"],
                                                            capture_filename, ap_bssid)['tcp']
        for port in [port1, port2]:
            if re.search(f'.*Source Port: {port}', str(tcp_pkt_list)):
                logger.info(f"******************** Found tcp packet with Source Port:{port} ********************")
            if re.search(r".*Acknowledgment: Set", str(tcp_pkt_list)):
                logger.info("******************** Found tcp packet with Ack flag set to 1 ********************")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
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
def test_wifi_sdk_ssl_three_sockets_data_tx_while_rejoin_testcase_c19155(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                         ssl_server, logger, cert1, cert2, switch,
                                                                         cert3, sl_collections, sniffer_filter):
    """
    Connection to three SSL Sockets and transmit data over SSL Sockets. Turn OFF/ON the AP. DUT continuous to transmit the data once the Rejoin to the AP is completed
    """
    sock_opened = 0
    try:
        capture_filename = "test_wifi_sdk_ssl_ssl_three_sockets_data_tx_while_rejoin_testcase_c19155"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections,
                                 rejoin_params=[40, 6, 40, 0])
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            sock_opened += 1
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                socket_port = port3
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        for socket in range(1, 4):
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, 120)
        thread = Thread(target=ssl_obj.pdu_switch, args=(switch, 10))
        thread.start()
        socket_list = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=1300,
                                                                          number_of_pkts=pkt_count)

        bytes_sent = (pkt_count * buffer_length)
        sock_count = 0
        for socket_stats in socket_list:
            logger.info(
                f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
            assert bytes_sent == socket_stats[0], f"Number of bytes initiated by test and actually sent by DUT are not " \
                                                  f"matched. Initiated->{bytes_sent} bytes. But Sent by DUT->{socket_stats[0]} bytes "
            sock_count = sock_count + 1
        for socket in range(1, 4):
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                                     f"not matched on socket {socket} "
        for sock_id in range(3):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        ssl_server.interfaces.ssl.stop_server()
        for sock_id in range(sock_opened):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT |
                              Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
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
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "aws_disconnect"])
def test_wifi_sdk_ssl_aws_testcase_c19202(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, sniffer_filter,
                                          cert1, cert2, logger, sl_collections, remote_socket_factory):
    """
    Connection to Three Sockets (One AWS Server and One Unsecured (TCP) and One Secured Servers) and transmit data over three sockets
    """
    sock_opened = 0
    server_socket = remote_socket_factory.interfaces.socket.create_socket()
    server_socket.time_limit = 3600
    try:
        topic = "sdk/test/Python"
        messages = []
        for i in range(5):
            messages.append(text_generator(size=100))
        capture_filename = "test_wifi_sdk_ssl_aws_testcase_C19202"

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        server_socket.start_server(port=port2, socket_type=SOCKET_TYPE_TCP)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            sock_opened += 1

            if sock_count == 1:
                socket_port = port1
                logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                local_port = randint(5001, 20000)
            elif sock_count == 2:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                continue
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=0, cert_index=0)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.aws_iot_mqtt_init()
        time.sleep(3)
        wifi_dut.interfaces.wifi.aws_iot_mqtt_connect()
        qos = Si91xAwsQos.QOS0
        wifi_dut.interfaces.wifi.aws_iot_mqtt_subscribe(topic_name=topic, qos=qos)
        for count, msg in enumerate(messages):
            logger.info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{qos}'"
                        f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
            wifi_dut.interfaces.wifi.aws_iot_mqtt_publish(topic, qos, payload=msg)
            time.sleep(3)

        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger.info(f"Sending data {data} over SSL socket_no->{1}")
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=1, data=data)
            time.sleep(0.5)
            data_receive = ssl_server.interfaces.ssl.data_recv_content(1, buffer_size=len(data))
            logger.info(f"Total bytes received on remote SSL socket is -> {len(data)}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"

            logger.info(f"Sending data {data} over TCP socket_no->{2}")
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=2, data=data)
            time.sleep(0.5)
            data = remote_socket_factory.interfaces.socket.sockets[0].recv_data_tcp(len(data))
            logger.info(f"Total bytes received on remote TCP socket is -> {len(data)}")
            logger.info("Data sent by DUT and received on server is matching\n\n")

        for sock_id in range(3):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        server_socket.stop()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        ssl_server.interfaces.ssl.stop_server()
        server_socket.stop()
        for sock_id in range(sock_opened):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
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
def test_wifi_sdk_ssl_three_sockets_data_tx_after_rejoin_testcase_c19156(wifi_sniffer, wifi_dut, switch, ssl_server,
                                                                         wifi_access_point, logger, cert2, cert3,
                                                                         sniffer_filter, cert1, sl_collections):
    """
    Connection to three SSL Sockets and transmit data over SSL Sockets. Turn OFF/ON the AP. DUT needs to connect to Three OpenSSL sockets once DUT returns the rejoin fail error to host
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_data_tx_after_rejoin_testcase_c19156"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        for count in range(2):
            ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
            ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
            ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
            server_ip = ssl_server.interfaces.ssl.server_ip

            for sock_count in range(0, 3):
                sock = wifi_dut.interfaces.wifi.socket()
                assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
                logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                if sock_count == 0:
                    socket_port = port1
                elif sock_count == 1:
                    socket_port = port2
                else:
                    socket_port = port3
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

            for socket in range(1, 4):
                th_start = Thread(target=ssl_server.interfaces.ssl.data_receive,
                                  args=(socket, pkt_count, buffer_length))
                th_start.start()
            wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=1300, time_interval=550,
                                                                number_of_pkts=pkt_count, timeout=700)
            if count == 1:
                break
            for sock_id in range(3):
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
                logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
            ssl_server.interfaces.ssl.stop_server()

            logger.info("\n\nTurning off the AP")
            switch.interfaces.pdu_switch.turn_off(delay=5)
            logger.info("Successfully powered off AP")

            # logger.info("\n\nDisabling Wireless in AP")
            # wifi_access_point.interfaces.wifi.stop_ap()
            # time.sleep(5)
            # logger.info("Disabled Wireless in AP")

            logger.info("Checking for rejoin fail event from dut, this may take some time....")
            sw = Stopwatch()
            rejoin_msg = 0
            since_time = time.perf_counter_ns()
            while sw.elapsed_sec <= 500:
                events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                        rejoin_msg = 1
                if rejoin_msg:
                    break
            assert rejoin_msg == 1, f"Rejoin Error not found from DUT even after AP is switched off for 500 seconds"
            logger.info("Rejoin Error Received from DUT")

            logger.info("\n\nAgain turning on the AP")
            switch.interfaces.pdu_switch.turn_on(delay=60)
            logger.info("Successfully powered on AP")

            # logger.info("\n\nEnabling Wireless in AP")
            # wifi_access_point.interfaces.wifi.start_ap()
            # time.sleep(60)
            # logger.info("Enabled Wireless in AP")
            device_ip = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                            associated=False)['device_ip']
            wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        for sock_id in range(3):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
            logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3) | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
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
def test_wifi_sdk_2_ssl_tx_1_tcp_rx_c19161(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, sniffer_filter,
                                           logger, remote_socket_factory, cert1, cert2, sl_collections):
    """
    Verify the transmit and receive functionality when device transmits over two OpenSSL Sockets and receives over One TCP Socket
    """
    server_socket = remote_socket_factory.interfaces.socket.create_socket()
    server_socket.time_limit = 3600
    socket_opened = 0
    try:
        capture_filename = "test_wifi_sdk_2_ssl_tx_1_tcp_rx_c19161"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        pkt_count = 100
        buffer_length = 500
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])

        server_socket.start_server(port=port3, socket_type=SOCKET_TYPE_TCP)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            socket_opened += 1
            if sock_count < 2:
                logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                socket_port = port3
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        time.sleep(3)
        send_list = []
        for sock_id in range(1, 3):
            thread = Thread(target=ssl_server.interfaces.ssl.data_receive,
                            args=(sock_id, pkt_count, buffer_length, 120))
            send_list.append(thread)
            thread.start()
        wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length, time_interval=600,
                                                            number_of_pkts=pkt_count, timeout=520)
        [thread.join() for thread in send_list]

        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
            remote_socket_factory.interfaces.socket.sockets[0].send_data_tcp(tx_buffer, use_server_socket=True)
            time.sleep(1)
            rx_buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=2)
            assert tx_buffer == rx_buffer, f"buffer sent by remote peer and received on the socket id 2 opened in the DUT is not matched"
            logger.info("Data sent by remote peer and data received on DUT is matched")

        for sock in range(3):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger.info(f"Successfully closed socket_id '{sock}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        server_socket.stop()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        ssl_server.interfaces.ssl.stop_server()
        server_socket.stop()
        for sock in range(socket_opened):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger.info(f"Successfully closed socket_id '{sock}' in the DUT")
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3) | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
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
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "clear_certs"])
def test_wifi_sdk_2ssl_1aws_testcase_c19150(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, cert1, cert2,
                                            logger, sl_collections, sniffer_filter):
    """
    Connection with three SSL Sockets, two local OpenSSL Servers and One AWS Cloud Server
    """
    try:
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("client-certificate.crt")),
                                                     Si91xCertificateType.SL_NET_CERTIFICATE,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2)
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("private-key.key")),
                                                     Si91xCertificateType.SL_NET_PRIVATE_KEY,
                                                     Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START,
                                                     cert_index=2)

        domain_name = "a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"
        capture_filename = "test_wifi_sdk_2ssl_1aws_testcase_c19150"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = 8883
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
            if sock_count == 0:
                socket_port = port1
            elif sock_count == 1:
                socket_port = port2
            else:
                socket_port = port3
                result = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000, timeout=30)
                server_ip = result.strip().decode()
                logger.info(f"aws_server_ip {server_ip}")
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        for socket in range(1, 3):
            ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout=10)
        socket_list = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length,
                                                                          number_of_pkts=pkt_count, )
        sock_count = 0
        bytes_sent_list = []
        for socket_stats in socket_list:
            logger.info(
                f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
            bytes_sent_list.append(socket_stats[0])
            sock_count = sock_count + 1
        for socket in range(1, 3):
            if ssl_server.interfaces.ssl.socket_connection_status(socket):
                bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
                assert bytes_sent_list[socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the" \
                                                                      f"remote peer not matched on socket {socket}"
        for sock in range(3):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger.info(f"Successfully closed socket_id '{sock}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.wifi_access_points(["raspi_wifi", "asus_rt_ax3000_ap"])
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
            'ssid': 'TEST_C19183_AP1',
            'security': 'WPA2',
            'passphrase': '123123123',
            'channel': 6,
            'interface': 'wlan0'
        },
        1: {
            'ssid': 'TEST_C19183_AP2',
            'security': 'WPA2',
            'passphrase': '123123321',
            'channel': 6,
            'interface': 'wlan0'
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3) | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("domain_name", ["a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"])
@pytest.mark.end_state("wifi_access_points", wifi="ap_disabled")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated", "disable_store_config", "clear_certs"])
def test_wifi_sdk_dns_get_func_with_multiple_APs_c19183(wifi_sniffer, wifi_access_points, wifi_dut, domain_name,
                                                        logger, sl_collections, sniffer_filter):
    """
    DNS Functionality with Multiple APs.
    """
    try:
        capture_filename = "test_wifi_sdk_dns_get_func_with_multiple_APs_c19183"
        for i in range(0, len(wifi_access_points)):
            ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_points[i], capture_filename, sl_collections)
            device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
            wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
            ap_bssid = wifi_access_points[1].interfaces.wifi.bssid
            if not i:
                ap_bssid = wifi_access_points[i].interfaces.wifi.get_mac_address()
            logger.info(f'AP BSSID = {ap_bssid}')
            time.sleep(3)

            result = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000, timeout=30)
            server_ip = result.strip().decode()
            logger.info(f"aws_server_ip {server_ip}")

            wifi_dut.interfaces.wifi.leave()
            logger.info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sl_collections.join_sniffer_validation(wifi_access_points[i], wifi_sniffer, dut_mac_address, ap_bssid,
                                                   sniffer_filter, power_save=False)
            wifi_access_points[i].interfaces.wifi.stop_ap()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3) | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("aws_root_cert.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
        "client_cert": [("client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                        ("A0E1010000000411_cat.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
        "client_key": [("private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                       ("A0E1010000000411_device.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("domain_name", [("a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com",
                                          "a1ctxhjnkhtvqq.iot.us-east-2.amazonaws.com")])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "disassociated", "disable_store_config", "clear_certs"])
def test_wifi_sdk_aws_cloud_with_different_certificate_c19186(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                              remote_socket, domain_name, logger, sl_collections,
                                                              sniffer_filter):
    """
    Connectivity with Allegion AWS Cloud with Different Certificates
    """
    try:
        port = 8883
        capture_filename = "test_wifi_sdk_aws_cloud_with_different_certificate_c19186"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        for index in range(len(domain_name)):
            for _ in range(3):
                try:
                    result = wifi_dut.interfaces.wifi.dns_get(domain_name[index], query_timeout=120000, timeout=30)
                    server_ip = result.strip().decode()
                    logger.info(f"aws_server_ip {server_ip}")
                    break
                except:
                    time.sleep(5)

            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == 0, f"socket id received is wrong, expected is 0"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=index)

            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port)

            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger.info(f"Successfully closed socket_id '{sock}' in the DUT")
            ssl_server.interfaces.ssl.stop_server()
            logger.info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                                   sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
            3) | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("aws_root_cert.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
        "client_cert": [("client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                        ("A0E1010000000411_cat.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
        "client_key": [("private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                       ("A0E1010000000411_device.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
    }
)
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.parametrize("domain_name", [("a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com",
                                          "a1ctxhjnkhtvqq.iot.us-east-2.amazonaws.com")])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "close_sockets", "disassociated", "clear_certs"])
def test_wifi_sdk_three_socket_connection_with_1ssl_2aws_c19151(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server,
                                                                domain_name, cert1, logger, sl_collections,
                                                                sniffer_filter):
    """
    Connection to three SSL Sockets. One Openssl Servers and Two Cloud Server
    """
    try:
        socket_port = 8883
        capture_filename = "test_wifi_sdk_three_socket_connection_with_1ssl_2aws_c19151"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        for sock_count in range(3):
            if sock_count == 2:
                ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
                server_ip = ssl_server.interfaces.ssl.server_ip
                local_port = port1
                socket_port = port1
            else:
                local_port = randint(40001, 45000)
                server_ip = None
                for _ in range(3):
                    try:
                        server_ip = wifi_dut.interfaces.wifi.dns_get(domain_name[sock_count], query_timeout=120000,
                                                                     timeout=30).strip().decode()
                        logger.info(f"aws_server_ip {server_ip}")
                        break
                    except:
                        time.sleep(5)
                assert server_ip, "Failed to get aws_server ip from dns_get command"

            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is 0"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        for sock in range(3):
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger.info(f"Successfully closed socket_id '{sock}' in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3) |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [(["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                            "mosquitto-utf.silabs.com.key.pem"],
                           ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                            "mosquitto-utf.silabs.com.key.pem"],
                           ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                            "mosquitto-utf.silabs.com.key.pem"]
                           )]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "clear_certs"])
def test_wifi_sdk_ssl_three_sockets_socket_select_receive_data_c19162(wifi_sniffer, wifi_dut, logger, sl_collections,
                                                                      wifi_access_point, ssl_server, cert1, cert2,
                                                                      cert3, sniffer_filter):
    """
    Verify whether the device is able to receive data over three sockets by using select() API
    """
    sock_opened = 0
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_socket_select_receive_data_C19162"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock = wifi_dut.interfaces.wifi.Asyncsocket()
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"
            sock_opened += 1
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        time.sleep(3)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=3, time=30)
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            for socket in range(3):
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Remote peer sending data over socket {socket + 1} and data:{tx_buffer}")
                ssl_server.interfaces.ssl.send_data((socket + 1), 1, msg_length=100, message=tx_buffer)
                time.sleep(2)
                wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{socket} opened in the DUT is not matched"
                logger.info("Data sent by remote peer and received on DUT is matching")

        for sock_count in range(sock_opened):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_count)
        ssl_server.interfaces.ssl.stop_server()
        sock_opened = 0
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_count in range(sock_opened):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_count)
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3) |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
    }
)
@pytest.mark.parametrize("cert1, cert2, cert3",
                         [(["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                            "mosquitto-utf.silabs.com.key.pem"],
                           ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                            "mosquitto-utf.silabs.com.key.pem"],
                           ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                            "mosquitto-utf.silabs.com.key.pem"]
                           )]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "clear_certs"])
def test_wifi_sdk_ssl_three_sockets_socket_select_tx_rx_data_c19166(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                    ssl_server, logger, cert1, cert2, cert3,
                                                                    sl_collections, sniffer_filter):
    """
    Verify tx over one socket and rx over another two sockets using select() api.
    """
    sock_opened = 0
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_socket_select_tx_rx_data_c19166"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
        ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(3):
            sock = wifi_dut.interfaces.wifi.Asyncsocket()
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"
            sock_opened += 1
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")

            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        time.sleep(3)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=3, time=30)
        sw = Stopwatch()
        while sw.elapsed_sec <= 60:
            for socket in range(3):
                if socket < 2:
                    tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                    logger.info(f"Remote peer sending data over socket {socket + 1} and data:{tx_buffer}")
                    ssl_server.interfaces.ssl.send_data((socket + 1), 1, msg_length=100, message=tx_buffer)
                    time.sleep(2)
                    wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=socket)
                    assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                                   f"{socket} opened in the DUT is not matched"
                    logger.info("Data sent by remote peer and received on DUT is matching")
                else:
                    data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                    logger.info(f"Remote peer sending data over socket {socket + 1} and data:{data}")
                    wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=2, data=data)
                    time.sleep(0.5)
                    data_receive = ssl_server.interfaces.ssl.data_recv_content(socket + 1, buffer_size=len(data))
                    logger.info(f"Total bytes received on remote SSL socket is -> {len(data)}")
                    assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                    logger.info("Data sent by DUT and received on remote peer is matching")

        for sock_count in range(sock_opened):
            logger.info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_count)
        ssl_server.interfaces.ssl.stop_server()
        sock_opened = 0
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        for sock_count in range(sock_opened):
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_count)
        ssl_server.interfaces.ssl.stop_server()
        wifi_dut.interfaces.wifi.is_dut_bad_state = True
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3) |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.parametrize("cert1",
                         [("ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                           "mosquitto-utf.silabs.com.key.pem")])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_socket_select_ssl_asynchronous_c19192(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger,
                                                        sl_collections, sniffer_filter, cert1):
    """
    socket select functionality of DUT in asynchronous mode when ssl socket is opened in DUT
    """
    try:
        capture_filename = "test_wifi_sdk_socket_select_ssl_asynchronous_c19192"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        server_ip = ssl_server.interfaces.ssl.server_ip
        local_port = randint(20001, 40000)

        sock = wifi_dut.interfaces.wifi.Asyncsocket()
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
        time.sleep(3)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=60)
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger.info(f"Remote peer sending data over socket {sock + 1} and data:{tx_buffer}")
            ssl_server.interfaces.ssl.send_data((sock + 1), 1, msg_length=100, message=tx_buffer)
            time.sleep(2)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                           f"{sock} opened in the DUT is not matched"
            logger.info("Data sent by remote peer and received on DUT is matching")

        logger.info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3) |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_synchronous_socket_send_data_c19137(wifi_sniffer, wifi_dut, wifi_access_point,
                                                          sniffer_filter, ssl_server, logger, sl_collections):
    """
    Synchronous read feature over ssl server socket when more than one client is connected to it..
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_synchronous_socket_send_data_c19137"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        ssl_server.interfaces.ssl.start_server(port=port1)
        ssl_server.interfaces.ssl.start_server(port=port2)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(2):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            else:
                socket_port = port2
                local_port = randint(40001, 60000)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
            time.sleep(3)

        pkt_count = 1
        buffer_length = 100
        sw = Stopwatch()
        while sw.elapsed_sec <= 60:
            for sock_id in range(2):
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
                logger.info(f"Sending data from remote peer, data --> '{tx_buffer}'")
                ssl_server.interfaces.ssl.send_data(sock_id + 1, pkt_count, buffer_length, tx_buffer)
                wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=2, time=10)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_id} opened in the DUT is not matched "
                logger.info(f"Data sent by remote peer and received at DUT is matching at socket --> '{sock_id}'\n\n")

        for sock_id in range(2):
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3) |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_synchronous_select_timeout_c19198(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                        logger, sl_collections, sniffer_filter):
    """
    To check SSL Synchronous Select Timeout Functionality of DUT.
    """
    try:
        capture_filename = 'test_wifi_sdk_ssl_synchronous_select_timeout_c19198'
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port1 = randint(5001, 5010)
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        local_port = randint(5001, 20000)

        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
        time.sleep(3)
        try:
            with TimeMeasurer() as t:
                wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1, time=10)
        except AssertionError:
            select_response_timeout = round(t.duration, 1)
            logger.info("Socket select timeout occurred")
            logger.info(f"Socket select API returned after '{select_response_timeout}' seconds when there is "
                        f"no data received on the opened socket when timeout given in the API is '10' seconds")

        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3) |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_synchronous_select_timeout_c19200(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                        logger, sl_collections, sniffer_filter):
    """
    To check SSL Rx with Synchronous Select Timeout Functionality of DUT
    """
    try:
        capture_filename = 'test_wifi_sdk_ssl_synchronous_select_timeout_c19200'
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        local_port = randint(5001, 20000)

        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
        time.sleep(3)

        pkt_count = 1
        buffer_length = 100
        sw = Stopwatch()
        while sw.elapsed_sec <= 30:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            logger.info(f"Sending data from remote peer, data --> '{tx_buffer}'")
            ssl_server.interfaces.ssl.send_data(sock + 1, pkt_count, buffer_length, tx_buffer)
            wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1, time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
            logger.info("Data sent by remote peer and received at DUT is matching")
            time.sleep(1)

        logger.info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_ps_func_when_ps_li_greater_than_join_li_c19168(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                     logger, sl_collections, sniffer_filter):
    """
    Verify the Power Save functionality when the Power Save Listen Interval is greater than the Join Listen Interval.
    """
    try:
        capture_filename = 'test_wifi_sdk_ssl_ps_func_when_ps_li_greater_than_join_li_c19168'
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        wifi_dut.interfaces.wifi.set_listen_interval(listen_interval=1000)
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromPowerSave)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        error_code = 0
        try:
            wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=1200)
        except Exception as err:
            error_match = re.search("status:(.*)", str(err))
            if error_match:
                error_code = error_match.group()
                logger.info(f"error_code: {error_code}")
        assert error_code, ("DUT did not send error code when trying to set powersave listen interval greater than "
                            "join listen interval, which is not expected")
        logger.info("DUT sent error code when trying to set powersave listen interval greater than join listen "
                    "interval, which is expected")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3) |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_three_sockets_load_remove_certs_connection_c19163(wifi_sniffer, wifi_access_point, sl_collections,
                                                                        ssl_server, wifi_dut, logger, sniffer_filter):
    """
    Verify the three SSL Socket Functionality by with and without loading the certificates
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_three_sockets_load_remove_certs_connection_c19163"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        port1 = ssl_server.interfaces.ssl.config['device_port1']

        sniff = True
        for count in range(10):
            logger.info(f"****************** Initiating testcase for iteration: {count + 1} ******************")
            for cert_index in range(3):
                logger.info(f"Loading certificate at index --> '{cert_index}'")
                wifi_dut.interfaces.wifi.set_ssl_certificate(get_tls_certificate_dir().joinpath("ca-chain.cert.pem"),
                                                             "ca_cert", "tls_server", cert_index)
            for iteration in range(2):
                error_code = 0
                device_ip, dut_mac_address = ssl_obj.join_get_ip(sniff_capture=sniff, power_save=False)
                wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
                for sock_count in range(3):
                    socket_port = port1 + sock_count
                    ssl_server.interfaces.ssl.start_server(port=socket_port)
                    server_ip = ssl_server.interfaces.ssl.server_ip
                    sock = wifi_dut.interfaces.wifi.socket()
                    wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                    wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port,
                                                  timeout=15)
                    wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=sock_count)
                    if iteration == 0:
                        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                  server_port=socket_port)
                    else:
                        try:
                            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                      server_port=socket_port)
                        except Exception as err:
                            error_match = re.search("status:(.*)", str(err))
                            if error_match:
                                error_code = error_match.group()
                                logger.info(f"error_code: {error_code}")
                        assert error_code, (
                            "DUT did not send error code when trying to connect ssl server without loading "
                            "certificate, which is not expected")
                    logger.info("DUT sent error code when trying to connect ssl server without loading certificate, "
                                "which is expected")
                if iteration == 0:
                    sniff = False
                    logger.info("Disconnection DUT from 3rd party AP")
                    wifi_dut.interfaces.wifi.leave()
                    logger.info("De-Initializing the DUT")
                    wifi_dut.interfaces.wifi.deinit()
                    logger.info("Initializing the DUT")
                    wifi_dut.interfaces.wifi.init(load_certificate=False)
                    for cert_index in range(3):
                        logger.info(f"Clearing certificate at index --> '{cert_index}'")
                        wifi_dut.interfaces.wifi.clear_certificate(cert_index,
                                                                   Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                                   Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START)
                ssl_server.interfaces.ssl.stop_server()
            logger.info("Disconnection DUT from 3rd party AP")
            wifi_dut.interfaces.wifi.leave()
            logger.info(f"****************** Iteration '{count + 1}' Completed ******************\n\n")
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPSServer
                          | Si91xTCPIPFeatureBitMap.SingleSSLSocket,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]

    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_client_when_https_server_is_enabled_c19124(wifi_sniffer, wifi_access_point, sl_collections,
                                                                 ssl_server, wifi_dut, logger, sniffer_filter):
    """
    Open ssl client socket when https server is enabled.
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_when_https_server_is_enabled_c19124"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        error_code = 0
        socket_port = 443
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ssl_server.interfaces.ssl.start_server(port=socket_port)
        server_ip = ssl_server.interfaces.ssl.server_ip
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
        try:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        except Exception as err:
            error_match = re.search("status:(.*)", str(err))
            if error_match: error_code = error_match.group()
            logger.info(f"error_code: {error_code}")
        assert error_code, ("DUT did not send error code when trying to connect ssl server when https server is "
                            "enabled, which is not expected")
        logger.info("DUT sent error code when trying to connect ssl server when https server is enabled, "
                    "which is expected")

        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(3) |
                              Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "clear_certs"])
def test_wifi_sdk_ssl_tx_with_1aws_2tcp_sockets_c19193(wifi_sniffer, wifi_dut, wifi_access_point, remote_socket_factory,
                                                       logger, sl_collections, sniffer_filter):
    """
    Connection to Three Sockets (One AWS Server and Two Unsecured (TCP) Servers) and transmit data over three sockets.
    """
    try:
        domain_name = "a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"
        capture_filename = "test_wifi_sdk_ssl_tx_with_1aws_2tcp_sockets_c19193"

        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        start_port = 5001
        aws_port = 8883
        aws_server_ip = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000, timeout=30).strip().decode()
        logger.info(f"aws_server_ip {aws_server_ip}")
        for sock_count in range(3):
            sock = wifi_dut.interfaces.wifi.socket()
            socket_port = start_port + sock_count
            if sock_count == 0:
                server_ip = aws_server_ip
                socket_port = aws_port
            else:
                server_socket = remote_socket_factory.interfaces.socket.create_socket()
                server_socket.time_limit = 3600
                server_socket.start_server(port=socket_port, socket_type=SOCKET_TYPE_TCP)
                server_ip = server_socket.hostname_or_ip_address(ip_version=4)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        sw = Stopwatch()
        while sw.elapsed_sec <= 60:
            for sock_id in range(2):
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
                logger.info(f"DUT is sending data over socket {sock_id + 1} and data:{tx_buffer}")
                wifi_dut.interfaces.wifi.bsdSocketSend(sock_id + 1, tx_buffer, timeout=30)
                time.sleep(1)
                buffer_rx = remote_socket_factory.interfaces.socket.sockets[sock_id].recv_data_tcp(len(tx_buffer))
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_id + 1} opened in the DUT is not matched"
                logger.info("Data sent by DUT and received on remote peer is matching")

        for sock_id in range(3):
            logger.info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.skip("sntp test_agent support needed")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.Ping | Si91xTCPIPFeatureBitMap.SNTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_sntp_functionality_c19191(wifi_sniffer, wifi_dut, wifi_access_point, logger, sl_collections,
                                            sniffer_filter):
    """
    Device should get the Date and Time from the NTP Server and give the correct response type
    """
    try:
        capture_filename = "test_wifi_sdk_sntp_functionality_c19191"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip(power_save=False)
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', listen_interval=700)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        sntp_server_ip = wifi_dut.interfaces.wifi.sntp_get_server_info()[0]
        logger.info("**************** Creating SNTP Client Session in DUT ***************")
        wifi_dut.interfaces.wifi.sntp_client_start(server_ip=sntp_server_ip, sntp_timeout=120)
        time.sleep(30)
        logger.info("**************** Getting SNTP Time and DATE from DUT ***************")
        wifi_dut.interfaces.wifi.sntp_get_time_data()
        logger.info("**************** Getting SNTP Server Information from DUT ***************")
        sntp_server_address = wifi_dut.interfaces.wifi.sntp_get_server_info()
        logger.info("**************** Deleting SNTP Client Session in DUT ***************")
        wifi_dut.interfaces.wifi.sntp_client_stop()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION_KEY --> {decryption_key}")
        logger.info("SSL Packet Decryption is going to start, This may take some time")
        ntp_capture_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["ntp"],
                                                                capture_filename, ap_bssid)['ntp']
        assert len(ntp_capture_list), (f"NTP packets are not captured or one of the 4-way handshake packets are not "
                                       f"captured in the sniffer capture")
        for ntp_pkt in ntp_capture_list:
            logger.info(f"NTP_PACKET:{ntp_pkt}")
            if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == device_ip):
                logger.info(f"SNTP response body received in the sniffer {ntp_pkt}")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


"""Below testcases are not supported in Si917_Beta_Soc_WIFISDK"""
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": Si91xOperatingMode.AccessPoint,
#         "features": Si91xFeatureBitMap.PSKSecurity,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server,
#         "security": "WPA2", "ssid": "SILABS_AP_C19176", "passphrase": "12345678", "dtim_period": 5,
#         "beacon_interval": 100,
#     },
# )
# @pytest.mark.parametrize("channel", [11])
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
# def test_wifi_sdk_wireless_statistics_AP_TC19176(wifi_sniffer, wifi_client, wifi_dut, channel, logger, sl_collections):
#     """
#     Verify whether the device is able to get the Wireless Statistics in AP Mode
#     """
#     try:
#         wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
#         capture_filename = "test_wifi_sdk_ssl_wifi_wireless_statistics_AP_TC19176"
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
#         logger.info(f"Sniffer capture started")
#
#         sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip='192.168.100.76', static_subnet='255.255.255.0',
#                                                   static_gateway='192.168.100.76')
#         wifi_dut.interfaces.wifi.start_ap(channel=channel)
#         time.sleep(10)
#
#         operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_dut.interfaces.wifi.get_statistics(
#         )
#         dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
#         validation = True
#         beacon_interval_obj = FilterPacket()
#         dtim_period_obj = FilterPacket()
#         packet_filter3 = "Type/Subtype: Beacon frame (0x0008)"
#         logger.info("****************Beacon Filter******************")
#         packet_filter = f'(wlan.addr == {dut_mac_address} and (wlan.fc.type_subtype == 0x008))'
#         wifi_sniffer.interfaces.capture.stop_capture()
#         assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter, packet_filter3)[
#             'packet_count']
#
#         beacon_interval_dut_as_ap = beacon_interval_obj.get_beacon_interval()
#         if beacon_interval_dut_as_ap is None:
#             logger.info(f'Unable to find Beacon Interval={beacon_interval_dut_as_ap}')
#             assert False
#         else:
#             logger.info(f'\n\n *** Beacon Interval ={beacon_interval_dut_as_ap} *** \n')
#
#         packet_filter1 = f'(wlan.addr == {dut_mac_address}) and (wlan.fc.type_subtype == 0x008) and (wlan.fixed.beacon == {beacon_interval_dut_as_ap})'
#
#         dtim_period_dut_as_ap = dtim_period_obj.get_dtim_period()
#         if dtim_period_dut_as_ap is None:
#             logger.info(f'Unable to find DTIM Period={dtim_period_dut_as_ap}')
#             assert False
#         else:
#             logger.info(f'\n\n *** DTIM Period ={dtim_period_dut_as_ap} *** \n')
#
#         logger.info(
#             f"DUT as Access point Beacon interval -> {beacon_interval_dut_as_ap},  DTIM period-> {dtim_period_dut_as_ap}")
#         assert operating_mode == Si91xOperatingMode.AccessPoint, "Operating mode is not matching, expected is 0"
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)


#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.ULPGPIOHandshake,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
#         "custom_features": Si91xCustomFeatureBitMap.Default,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
#             3),
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "rejoin_max_retry": 10,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0,
#     }
# )
# @pytest.mark.parametrize("cert1, cert2, cert3",
#                          [
#                              (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
#                                "mosquitto-utf.silabs.com.key.pem"],
#                               ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
#                                "mosquitto-utf.silabs.com.key.pem"],
#                               ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
#                                "mosquitto-utf.silabs.com.key.pem"]
#
#                               )
#                          ]
#                          )
# @pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
# @pytest.mark.skip()
# def test_ssl_clear_cert2_TC19154(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2, cert3,
#                                  sl_collections):
#     """
#     Connection to three SSL Sockets, then reset the DUT and clear 2nd ca certificate and try to Connect to Three SSL client sockets again
#     """
#     try:
#         capture_filename = "test_ssl_clear_cert2_TC19154"
#         # configure interface for the channel of the access point
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#
#         scan_fail = sl_collections.scan(wifi_dut)
#         assert not scan_fail, "Scanning for AP failed"
#         mac_address = wifi_dut.interfaces.wifi.get_mac_address()
#         logger.info(f"DUT MAC_Address: {mac_address}")
#         capture_filter = "ether host " + mac_address
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap",
#                                                       capture_filter=capture_filter)
#         server_ip = ssl_server.interfaces.ssl.server_ip
#
#         pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
#         buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
#         port1 = ssl_server.interfaces.ssl.config['device_port1']
#         port2 = ssl_server.interfaces.ssl.config['device_port2']
#         port3 = ssl_server.interfaces.ssl.config['device_port3']
#         bytes_sent = (pkt_count * buffer_length)
#
#         for iteration in range(0, 2):
#             if iteration == 1:
#                 time.sleep(120)
#                 wifi_dut.interfaces.wifi.reset()
#                 wifi_dut.interfaces.wifi.init()
#             # DUT connects to AP after join_ap API is executed
#             status = sl_collections.connect(wifi_dut, wifi_access_point)
#
#             if iteration == 0:
#                 # The below API loads ca-cert into DUT at cert index
#                 wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
#                                                           str(get_tls_certificate_dir().joinpath(cert1[0])),
#                                                           cert_index=0)
#
#                 # The below API loads ca-cert into DUT at cert index 1
#                 wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
#                                                           str(get_tls_certificate_dir().joinpath(cert2[0])),
#                                                           cert_index=1)
#                 # The below API loads ca-cert into DUT at cert index 2
#                 wifi_dut.interfaces.wifi.load_certificate(Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
#                                                           str(get_tls_certificate_dir().joinpath(cert3[0])),
#                                                           cert_index=2)
#             if iteration == 1:
#                 wifi_dut.interfaces.wifi.clear_certificate(Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
#                                                            cert_index=2,
#                                                            )
#
#             # DUT gets ipaddress through DHCP process after start_ip API is executed
#             status = sl_collections.configure_ip(wifi_dut)
#             assert not status, "Failed to Join to AP"
#             # The below api put DUT to power save
#             wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
#             # The below api parses DUTs IP address
#             device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#             # Open ssl server socket in remote device(Raspberry pi or static device)
#             ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
#             # Open ssl server socket in remote device(Raspberry pi or static device)
#             ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
#             # Open ssl server socket in remote device(Raspberry pi or static device)
#             ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
#
#             # Open ssl client socket in the DUT
#             sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#             assert sock == 0, f"socket id received is wrong, expected is 0"
#             # Enable ssl option for socket opened
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                      option_val=SocketOptions.SOL_SOCKET)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                      option_val=SocketOptions.SO_SSL_ENABLE)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                      option_val=SocketOptions.SSL_ENABLE)
#
#             # Enable cert index 0 for socket opened
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                      option_val=SocketOptions.SO_CERT_INDEX)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                      option_val=SocketOptions.CERT_INDEX0)
#             # Socket binds at (device_ip, 5001) in DUT
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port1,
#                                           timeout=15)
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
#                                                       server_port=port1)
#
#             # Open ssl client socket in the DUT
#             sock1 = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#             assert sock1 == 1, f"socket id received is wrong, expected is 1"
#             # Enable ssl option for socket opened
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                      option_val=SocketOptions.SOL_SOCKET)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                      option_val=SocketOptions.SO_SSL_ENABLE)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                      option_val=SocketOptions.SSL_ENABLE)
#
#             # Enable cert index 1 for socket opened
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                      option_val=SocketOptions.SO_CERT_INDEX)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                      option_val=SocketOptions.CERT_INDEX1)
#
#             # Socket binds at (device_ip, 5001) in DUT
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock1, device_ip=device_ip, server_port=port2,
#                                           timeout=15)
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock1, server_ip=server_ip,
#                                                       server_port=port2)
#
#             # Open ssl client socket in the DUT
#             sock2 = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#             assert sock2 == 2, f"socket id received is wrong, expected is 2"
#
#             # Enable ssl option for socket opened
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                      option_val=SocketOptions.SOL_SOCKET)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                      option_val=SocketOptions.SO_SSL_ENABLE)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                      option_val=SocketOptions.SSL_ENABLE)
#
#             # Enable cert index 1 for socket opened
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                      option_val=SocketOptions.SO_CERT_INDEX)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                      option_val=SocketOptions.CERT_INDEX2)
#
#             # Socket binds at (device_ip, 5001) in DUT
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock2, device_ip=device_ip, server_port=port3,
#                                           timeout=15)
#             if iteration == 0:
#                 # ssl socket opened in DUT connects to the server
#                 wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock2, server_ip=server_ip,
#                                                           server_port=port3)
#             else:
#                 with pytest.raises(WlanError) as exc_info:
#                     # ssl socket opened in DUT connects to the server
#                     wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock2, server_ip=server_ip,
#                                                               server_port=port3)
#                 assert exc_info.value.error_code == 0xd2, "DUT sent wrong error code, expected is 0xD2"
#
#             if iteration == 0:
#                 socket_no = [1, 2, 3]
#             else:
#                 socket_no = [1, 2]
#             for socket in socket_no:
#                 ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
#
#             if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
#                 if iteration == 0:
#                     socket_no = [1, 2, 3]
#                 else:
#                     socket_no = [1, 2]
#                 for socket in socket_no:
#                     if ssl_server.interfaces.ssl.socket_connection_status(socket):
#                         # ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
#                         wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket, data=bytes_sent)
#                         time.sleep(10)
#                         bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
#                         assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
#                                                              f"not matched on socket {socket} "
#
#                     else:
#                         assert f"failed to connect on socket no {socket}"
#
#             # Close socket 1
#             result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#             # Close socket 2
#             result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock1)
#             if iteration == 0:
#                 # Close socket 3
#                 result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock2)
#                 ssl_server.interfaces.ssl.stop_server()
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.ULPGPIOHandshake,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
#         "custom_features": Si91xCustomFeatureBitMap.Default,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
#             3),
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": ["ca-chain.cert.pem", "ca-chain.cert.pem", "ca-chain.cert.pem"]
#     }
# )
# @pytest.mark.parametrize("cert1, cert2, cert3",
#                          [
#                              (["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
#                                "mosquitto-utf.silabs.com.key.pem"],
#                               ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
#                                "mosquitto-utf.silabs.com.key.pem"],
#                               ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
#                                "mosquitto-utf.silabs.com.key.pem"]
#
#                               )
#                          ]
#                          )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# def test_wifi_sdk_ssl_socket_check_TC19158(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1, cert2,
#                                            cert3, sl_collections):
#     """
#     Connection to three SSL Sockets and Check the Network parameters after socket connection.
#     """
#     try:
#         listen_interval = 700
#         capture_filename = "test_wifi_sdk_socket_check_TC19158"
#         server_ip = ssl_server.interfaces.ssl.server_ip
#
#         ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
#                                  sl_collections, listen_interval_feature=True, listen_interval=listen_interval)
#         dut_mac_address = ssl_obj.join_get_ip()
#
#         port1 = ssl_server.interfaces.ssl.config['device_port1']
#         port2 = ssl_server.interfaces.ssl.config['device_port2']
#         port3 = ssl_server.interfaces.ssl.config['device_port3']
#
#         # The below api parses DUTs IP address
#         device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#         # Open ssl server socket in remote device(Raspberry pi or static device)
#         ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
#         # Open ssl server socket in remote device(Raspberry pi or static device)
#         ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
#         # Open ssl server socket in remote device(Raspberry pi or static device)
#         ssl_server.interfaces.ssl.start_server(port=port3, server_cert=cert3[1], server_key=cert3[2])
#         server_ip = ssl_server.interfaces.ssl.hostname_or_ip_address()
#
#         # Open ssl client socket in the DUT
#         sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#         assert sock == 0, f"socket id received is wrong, expected is 0"
#         # Enable ssl option for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                  option_val=SocketOptions.SOL_SOCKET)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                  option_val=SocketOptions.SO_SSL_ENABLE)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                  option_val=SocketOptions.SSL_ENABLE)
#         # Enable cert index 0 for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                  option_val=SocketOptions.SO_CERT_INDEX)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                  option_val=SocketOptions.CERT_INDEX0)
#
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port1, timeout=15)
#         # ssl socket opened in DUT connects to the server
#         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
#
#         # Open ssl client socket in the DUT
#         sock1 = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#         assert sock1 == 1, f"socket id received is wrong, expected is 1"
#         # Enable ssl option for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                  option_val=SocketOptions.SOL_SOCKET)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                  option_val=SocketOptions.SO_SSL_ENABLE)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                  option_val=SocketOptions.SSL_ENABLE)
#         # Enable cert index 1 for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                  option_val=SocketOptions.SO_CERT_INDEX)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                  option_val=SocketOptions.CERT_INDEX1)
#
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock1, device_ip=device_ip, server_port=port2, timeout=15)
#         # ssl socket opened in DUT connects to the server
#         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock1, server_ip=server_ip, server_port=port2)
#
#         # Open ssl client socket in the DUT
#         sock2 = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#         assert sock2 == 2, f"socket id received is wrong, expected is 2"
#
#         # Enable ssl option for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                  option_val=SocketOptions.SOL_SOCKET)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                  option_val=SocketOptions.SO_SSL_ENABLE)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                  option_val=SocketOptions.SSL_ENABLE)
#         # Enable cert index 0 for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                  option_val=SocketOptions.SO_CERT_INDEX)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                  option_val=SocketOptions.CERT_INDEX2)
#
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock2, device_ip=device_ip, server_port=port3, timeout=15)
#         # ssl socket opened in DUT connects to the server
#         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock2, server_ip=server_ip, server_port=port3)
#
#         socket1 = tuple([(sock + 1), 0, port1, port1, server_ip])
#         socket2 = tuple([(sock1 + 1), 0, port2, port2, server_ip])
#         socket3 = tuple([(sock2 + 1), 0, port3, port3, server_ip])
#
#         sockets_opened, socket_info = wifi_dut.interfaces.wifi.wlan_get_socket_info()
#         assert sockets_opened == 3, f"Number of sockets opened in DUT is 3. But shown {sockets_opened} when query " \
#                                     f"through get_network_params api"
#         iter = 0
#         if sockets_opened:
#             for count in socket_info:
#                 iter = iter + 1
#                 if iter == 1:
#                     assert count[0] == socket1[
#                         0], f"socket id received in network query response is wrong for socket {iter} expected is {socket1[0]} "
#                     assert count[1] == socket1[
#                         1], f"socket type received in network query response is wrong for socket {iter} expected is {socket1[1]} "
#                     assert count[2] == socket1[
#                         2], f"source port received in network query response is wrong for socket {iter} expected is {socket1[2]}"
#                     assert count[3] == socket1[3], f"destination port received in network query response is wrong for " \
#                                                    f"socket {iter} expected is {socket1[3]} "
#                     assert count[4] == socket1[
#                         4], f"server ip received in network query response is wrong for socket {iter} expected is {socket1[4]}"
#
#                 elif iter == 2:
#                     assert count[0] == socket2[
#                         0], f"socket id received in network query response is wrong for socket {iter} expected is {socket2[0]}"
#                     assert count[1] == socket2[
#                         1], f"socket type received in network query response is wrong for socket {iter} expected is {socket2[1]}"
#                     assert count[2] == socket2[
#                         2], f"source port received in network query response is wrong for socket {iter} expected is {socket2[2]}"
#                     assert count[3] == socket2[3], f"destination port received in network query response is wrong for " \
#                                                    f"socket {iter} expected is {socket2[3]} "
#                     assert count[4] == socket2[
#                         4], f"server ip received in network query response is wrong for socket {iter} expected is {socket2[4]}"
#                 elif iter == 3:
#                     assert count[0] == socket3[
#                         0], f"socket id received in network query response is wrong for socket {iter} expected is {socket3[0]}"
#                     assert count[1] == socket3[
#                         1], f"socket type received in network query response is wrong for socket {iter} expected is {socket3[1]}"
#                     assert count[2] == socket3[
#                         2], f"source port received in network query response is wrong for socket {iter} expected is {socket3[2]}"
#                     assert count[3] == socket3[3], f"destination port received in network query response is wrong for " \
#                                                    f"socket {iter} expected is {socket3[3]} "
#                     assert count[4] == socket3[
#                         4], f"server ip received in network query response is wrong for socket {iter} expected is {socket3[4]} "
#
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#
#         for sock_count in range(0, 3):
#             logger.info(f"Closing socket_id->{sock_count}")
#             result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
#             assert b"success" in result, f"unable to close opened tcp socket in the dut for socket_id->{sock_count}"
#             logger.info(f"Successfully closed socket_id->{sock_count}")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.ULPGPIOHandshake,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
#         "custom_features": Si91xCustomFeatureBitMap.Default,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
#             3),
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "set_send_feature_frame": True
#     }
# )
# @pytest.mark.config('wifi_access_point',
#                     wifi={"dtim": 3, "beacon_interval": 100})
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# def test_wifi_sdk_query_wireless_stats_TC19175(wifi_sniffer, wifi_dut, wifi_access_point, logger, sl_collections):
#     """
#     Verify whether the device is able to get the Wireless Statistics in Station Mode
#     """
#     try:
#         listen_interval = 700
#         beacon_interval_obj = FilterPacket()
#         dtim_period_obj = FilterPacket()
#         validation = True
#         packet_filter3 = "    Type/Subtype: Beacon (0x0008)"
#         capture_filename = "test_wifi_sdk_query_wireless_stats_TC19175"
#
#         ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
#                                  sl_collections, listen_interval_feature=True, listen_interval=listen_interval)
#         dut_mac_address = ssl_obj.join_get_ip()
#
#         operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_dut.interfaces.wifi.get_statistics(
#         )
#         logger.info("****************Beacon Filter******************")
#         packet_filter = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008)'
#         wifi_sniffer.interfaces.capture.stop_capture()
#         assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter, packet_filter3)[
#             'packet_count']
#
#         beacon_interval_ap = beacon_interval_obj.get_beacon_interval()
#         if beacon_interval_ap is None:
#             logger.info(f'Unable to find Beacon Interval={beacon_interval_ap}')
#             assert False
#         else:
#             logger.info(f'\n\n *** Beacon Interval ={beacon_interval_ap} *** \n')
#
#         packet_filter4 = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008) and (wlan.fixed.beacon == {beacon_interval_ap})'
#
#         dtim_period_ap = dtim_period_obj.get_dtim_period()
#         if dtim_period_ap is None:
#             logger.info(f'Unable to find DTIM Period={dtim_period_ap}')
#             assert False
#         else:
#             logger.info(f'\n\n *** DTIM Period ={dtim_period_ap} *** \n')
#
#         packet_filter5 = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008) and (wlan.dtim.period == {dtim_period_ap})'
#
#         logger.info(f"Access point Beacon interval -> {beacon_interval_ap},  DTIM period-> {dtim_period_ap}")
#
#         logger.info(f"DUT Beacon interval -> {beacon_interval},  DTIM period-> {dtim_period}")
#
#         assert operating_mode == 0, "Operating mode is not matching, expected is 0"
#
#         assert beacon_interval == beacon_interval_ap, f"AP beacon interval received in wlan stats and actual beacon " \
#                                                       f"interval of connected AP is not matched, e" \
#                                                       f"xpected is {beacon_interval_ap}. But observed {beacon_interval} "
#         assert dtim_period == dtim_period_ap, f"DTIM period received in wlan stats and actual DTIM " \
#                                               f"interval of connected AP is not matched, e" \
#                                               f"expected is {dtim_period_ap}. But observed {dtim_period} "
#
#         connection = f'(wlan.addr == {dut_mac_address}) and (wlan.addr == {wifi_access_point.interfaces.wifi.bssid}) and (eapol)'
#         connection_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, connection)['packet_count']
#         assert connection_count, "Association Packets are not captured in the sniffer"
#         logger.info(f"Association Packets packets are captured in the sniffer")
#
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.ULPGPIOHandshake,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL,
#         "custom_features": Si91xCustomFeatureBitMap.Default,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
#             3),
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#     }
# )
# @pytest.mark.config('wifi_access_point',
#                     wifi={"dtim": 3, "beacon_interval": 100})
# @pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
# def test_wifi_sdk_query_wireless_stats_after_rejoin_TC19177(wifi_sniffer, wifi_dut, wifi_access_point, logger,
#                                                             sl_collections):
#     """
#     Verify whether the device is able to get the Wireless Statistics in Station Mode once the rejoin Process is completed
#     """
#     try:
#         listen_interval = 700
#         beacon_interval_obj = FilterPacket()
#         dtim_period_obj = FilterPacket()
#         validation = True
#         packet_filter3 = "    Type/Subtype: Beacon (0x0008)"
#         capture_filename = "test_wifi_sdk_query_wireless_stats_after_rejoin_TC19177"
#
#         ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
#                                  sl_collections, listen_interval_feature=True, listen_interval=listen_interval)
#         dut_mac_address = ssl_obj.join_get_ip()
#
#         wait_time = 5
#         obj = SocketDataTransfer()
#         obj.ApWirelessOff(wifi_access_point, wait_time, logger)
#
#         operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, beacon_interval = wifi_dut.interfaces.wifi.get_statistics(
#         )
#         logger.info("****************Beacon Filter******************")
#         packet_filter = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008)'
#         wifi_sniffer.interfaces.capture.stop_capture()
#         assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter, packet_filter3)[
#             'packet_count']
#
#         beacon_interval_ap = beacon_interval_obj.get_beacon_interval()
#         if beacon_interval_ap is None:
#             logger.info(f'Unable to find Beacon Interval={beacon_interval_ap}')
#             assert False
#         else:
#             logger.info(f'\n\n *** Beacon Interval ={beacon_interval_ap} *** \n')
#
#         packet_filter4 = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008) and (wlan.fixed.beacon == {beacon_interval_ap})'
#
#         dtim_period_ap = dtim_period_obj.get_dtim_period()
#         if dtim_period_ap is None:
#             logger.info(f'Unable to find DTIM Period={dtim_period_ap}')
#             assert False
#         else:
#             logger.info(f'\n\n *** DTIM Period ={dtim_period_ap} *** \n')
#
#         packet_filter5 = f'(wlan.ssid == {wifi_access_point.interfaces.wifi.ssid}) and (wlan.fc.type_subtype == 0x008) and (wlan.dtim.period == {dtim_period_ap})'
#
#         logger.info(f"Access point Beacon interval -> {beacon_interval_ap},  DTIM period-> {dtim_period_ap}")
#
#         logger.info(f"DUT Beacon interval -> {beacon_interval},  DTIM period-> {dtim_period}")
#         assert operating_mode == 0, "Operating mode is not matching, expected is 0"
#
#         assert beacon_interval == beacon_interval_ap, f"AP beacon interval received in wlan stats and actual beacon " \
#                                                       f"interval of connected AP is not matched, e" \
#                                                       f"xpected is {beacon_interval_ap}. But observed {beacon_interval} "
#         assert dtim_period == dtim_period_ap, f"DTIM period received in wlan stats and actual DTIM " \
#                                               f"interval of connected AP is not matched, e" \
#                                               f"expected is {dtim_period_ap}. But observed {dtim_period} "
#
#         wifi_sniffer.interfaces.capture.stop_capture()
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.config(
#     "wifi_access_points",
#     wifi={
#         0: {
#             'ssid': 'TESTAPONE',
#             'security': 'WPA2',
#             'passphrase': '123123123',
#             'channel': 6,
#             'interface': 'wlan0'
#         },
#         1: {
#             'ssid': 'TESTAPTWO',
#             'security': 'WPA2',
#             'passphrase': '1234567890',
#             'channel': 6,
#             'interface': 'wlan0'
#         }
#     }
# )
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "set_send_feature_frame": True,
#     }
# )
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
# @pytest.mark.store_config
# def test_wifi_sdk_autojoin_functionality_with_Two_APs_TC19181(wifi_sniffer, wifi_access_points, wifi_dut, logger,
#                                                               sl_collections):
#     """
#     Verify the auto join functionality with the Two APs.
#     """
#     try:
#         logger.info(" ====== configuring the sniffer with access point channel ====== ")
#
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
#
#         logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file='test_wifi_sdk_autojoin_functionality_with_Two_APs_TC19181_1')
#         listen_interval = 700
#
#         wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[0].interfaces.wifi.ssid, channel=6)
#         status = sl_collections.connect(wifi_dut, wifi_access_points[0])
#         assert not status, "Joining to AP is failed"
#         status = sl_collections.configure_ip(wifi_dut)
#         assert not status, "Failed to Join to AP"
#         device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#
#         logger.info(f"Initiating ping to DUT ip '{device_ip} '")
#         status = ping(device_ip, 10)
#         assert status == 1, "DUT not responding for ping request......"
#         dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
#         logger.info(f"DUT MAC_Address: {dut_mac_address}")
#
#         wifi_dut.interfaces.wifi.set_wifi_config()
#         wifi_dut.interfaces.wifi.config_enable(config=1)
#         for i in range(0, 2):
#             logger.info(f"RETRYING FOR {i} times")
#             wifi_dut.interfaces.wifi.deinit()
#             time.sleep(3)
#             try:
#                 wifi_dut.interfaces.wifi.init()
#             except WlanError as e:
#                 if e.error_code == 0x5a5a:
#                     assert e.error_code == 0x5a5a
#                     break
#
#         wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
#                                                          listen_interval=listen_interval)
#
#         wifi_dut.interfaces.wifi.config_enable(config=0)
#         wifi_dut.interfaces.wifi.deinit()
#         time.sleep(5)
#         wifi_dut.interfaces.wifi.init()
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#         eapol = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
#         assert eapol, "packets are not captured in the sniffer"
#
#         wifi_dut.interfaces.wifi.associated = False
#         logger.info("Stop Sniffer finally")
#         time.sleep(5)
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info(" ====== configuring the sniffer with access point channel ====== ")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
#
#         logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file='test_wifi_sdk_autojoin_functionality_with_Two_APs_TC19181_2')
#
#         ap_mac_two = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[1].interfaces.wifi.ssid, channel=6,
#                                                    )
#         status = sl_collections.connect(wifi_dut, wifi_access_points[1])
#         assert not status, "Joining to AP is failed"
#         logger.info("JOIN TO second AP IS SCUCCESSFUL")
#         status = sl_collections.configure_ip(wifi_dut)
#         assert not status, "Failed to Join to AP"
#         device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#         logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
#         ping(device_ip, 10)
#
#         wifi_dut.interfaces.wifi.leave()
#
#         logger.info("Stop Sniffer finally")
#         time.sleep(5)
#         wifi_sniffer.interfaces.capture.stop_capture()
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         packet_filter2 = f'(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         eapol = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
#         assert eapol, "packets are not captured in the sniffer"
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#     finally:
#         wifi_dut.interfaces.wifi.config_enable(config=0)
#
#
# @pytest.mark.skip()
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "set_send_feature_frame": True,
#         "ca_cert": ["start_field.pem"],
#         "client_cert": ["client-certificate.crt"],
#         "client_key": ["private-key.key"],
#     }
# )
# @pytest.mark.store_config
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "disable_store_config"])
# def test_wifi_sdk_feature_TC19138(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, remote_socket, domain_name,
#                                   logger, sl_collections):
#     """
#     Feature Test: Commissioning
#     """
#     try:
#         ping_count = 10
#         listen_interval = 700
#         capture_filename = "test_wifi_sdk_TC19138_feature_test"
#         rejoin_params = [40, 6, 40, 0]
#
#         ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
#                                  sl_collections, listen_interval_feature=True, listen_interval=listen_interval)
#         dut_mac_address = ssl_obj.join_get_ip()
#
#         port = 8883
#         bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {bssid}')
#
#         device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#         logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
#         status = ping(device_ip, 10)
#         assert status == 1, "DUT not responding for ping request......"
#
#         wifi_dut.interfaces.wifi.config_save()
#         wifi_dut.interfaces.wifi.config_enable(config=1)
#
#         for i in range(0, 10):
#             logger.info(f"Repeating Scenario for {i} time")
#             for i in range(0, 2):
#                 logger.info(f"RETRYING FOR {i} times")
#                 wifi_dut.interfaces.wifi.deinit()
#                 time.sleep(3)
#                 try:
#                     wifi_dut.interfaces.wifi.init()
#                     # time.sleep(5)
#                 except WlanError as e:
#                     if e.error_code == 0x5a5a:
#                         assert e.error_code == 0x5a5a
#                         break
#
#             logger.info(f"Initiating ping to DUT ip {device_ip} after auto join is successful")
#             ping(device_ip, ping_count)
#
#             wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
#             sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#             assert sock == 0, "Socket id received is wrong. expected is 0"
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                      option_val=SocketOptions.SOL_SOCKET)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                      option_val=SocketOptions.SO_SSL_ENABLE)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                      option_val=SocketOptions.SSL_ENABLE)
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_RETRY',
#                                                      option_val=SocketOptions.TCP_RETRY)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_MAX_RETRY',
#                                                      option_val=SocketOptions.TCP_MAX_RETRY)
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                      option_val=SocketOptions.SO_CERT_INDEX)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                      option_val=SocketOptions.CERT_INDEX0)
#
#             result = wifi_dut.interfaces.wifi.bsdGetHostByName(4, domain_name)
#             logger.info(f"dns response is {result}")
#             server_ip = result.split(b"\n")[1].split(b":")[1].decode()
#             logger.info(f"server_ip {server_ip}")
#
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port,
#                                           timeout=15)
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
#                                                       server_port=port)
#
#             result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#             assert b"success" in result, "unable to close opened tcp socket in the dut"
#
#         wifi_dut.interfaces.wifi.config_enable(config=0)
#         wifi_dut.interfaces.wifi.leave()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#
#         packet_filter2 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
#                          f'and wlan.sa == {dut_mac_address} and wlan.da == {bssid}'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#         pwr = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
#         assert pwr, "packets are not captured in the sniffer"
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.skip()
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": ["start_field.pem"],
#         "client_cert": ["client-certificate.crt"],
#         "client_key": ["private-key.key"],
#     }
# )
# @pytest.mark.store_config
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "disassociated", "disable_store_config"])
# def test_wifi_sdk_auto_connection_reconnection_after_reset_TC19140(wifi_sniffer, wifi_dut, wifi_access_point,
#                                                                    ssl_server,
#                                                                    remote_socket, domain_name, logger, sl_collections):
#     """
#     Feature Test: Auto Connection and Reconnection after reset
#     """
#     try:
#         listen_interval = 700
#         capture_filename = "test_wifi_sdk_TC19140_auto_connection_reconnection_after_reset"
#         rejoin_params = [40, 6, 40, 0]
#
#         power_save = 1
#         for count in range(3):
#             try:
#                 wifi_dut.interfaces.wifi.set_performance_profile(mode='standby_power_save')
#                 power_save = 0
#                 break
#             except:
#                 time.sleep(5)
#                 logger.info(f"Retry_count:{count}")
#         assert power_save == 0
#
#         ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger,
#                                  sl_collections, listen_interval_feature=True, listen_interval=listen_interval)
#         dut_mac_address = ssl_obj.join_get_ip()
#
#         port = 8883
#         bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {bssid}')
#         device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#         logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
#         status = ping(device_ip, 10)
#         assert status == 1, "DUT not responding for ping request......"
#
#         wifi_dut.interfaces.wifi.config_save()
#         wifi_dut.interfaces.wifi.config_enable(config=1)
#
#         for i in range(0, 10):
#             logger.info(f"Repeating Scenario for {i} time")
#             for i in range(0, 2):
#                 logger.info(f"RETRYING FOR {i} times")
#                 wifi_dut.interfaces.wifi.deinit()
#                 time.sleep(3)
#                 try:
#                     wifi_dut.interfaces.wifi.init()
#                     # time.sleep(5)
#                 except WlanError as e:
#                     if e.error_code == 0x5a5a:
#                         assert e.error_code == 0x5a5a
#                         break
#
#             logger.info(f"Initiating ping to DUT ip {device_ip} after auto join is successful")
#             status = ping(device_ip, 10)
#             assert status == 1, "DUT not responding for ping request......"
#
#             wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
#             sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#             assert sock == 0, "Socket id received is wrong. expected is 0"
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                      option_val=SocketOptions.SOL_SOCKET)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                      option_val=SocketOptions.SO_SSL_ENABLE)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                      option_val=SocketOptions.SSL_ENABLE)
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_RETRY',
#                                                      option_val=SocketOptions.TCP_RETRY)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_MAX_RETRY',
#                                                      option_val=SocketOptions.TCP_MAX_RETRY)
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                      option_val=SocketOptions.SO_CERT_INDEX)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                      option_val=SocketOptions.CERT_INDEX0)
#
#             result = wifi_dut.interfaces.wifi.bsdGetHostByName(4, domain_name)
#             logger.info(f"dns response is {result}")
#             server_ip = result.split(b"\n")[1].split(b":")[1].decode()
#             logger.info(f"server_ip {server_ip}")
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port,
#                                           timeout=15)
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
#                                                       server_port=port)
#             for i in range(0, 2):
#                 logger.info(f"RETRYING FOR {i} times")
#                 wifi_dut.interfaces.wifi.deinit()
#                 time.sleep(3)
#                 try:
#                     wifi_dut.interfaces.wifi.init()
#                     # time.sleep(5)
#                 except WlanError as e:
#                     if e.error_code == 0x5a5a:
#                         assert e.error_code == 0x5a5a
#                         break
#
#             wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
#             sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#             assert sock == 0, "Socket id received is wrong. expected is 0"
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                      option_val=SocketOptions.SOL_SOCKET)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                      option_val=SocketOptions.SO_SSL_ENABLE)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                      option_val=SocketOptions.SSL_ENABLE)
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_RETRY',
#                                                      option_val=SocketOptions.TCP_RETRY)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_MAX_RETRY',
#                                                      option_val=SocketOptions.TCP_MAX_RETRY)
#
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                      option_val=SocketOptions.SO_CERT_INDEX)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                      option_val=SocketOptions.CERT_INDEX0)
#
#             result = wifi_dut.interfaces.wifi.bsdGetHostByName(4, domain_name)
#
#             logger.info(f"dns response is {result}")
#             server_ip = result.split(b"\n")[1].split(b":")[1].decode()
#             logger.info(f"server_ip {server_ip}")
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port,
#                                           timeout=15)
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
#                                                       server_port=port)
#             result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#             assert b"success" in result, "unable to close opened tcp socket in the dut"
#
#         wifi_dut.interfaces.wifi.config_enable(config=0)
#         wifi_dut.interfaces.wifi.leave()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         packet_filter2 = f'wlan.fc.type_subtype == 0x0028 and wlan.fc.pwrmgt == 1 ' \
#                          f'and wlan.sa == {dut_mac_address} and wlan.da == {bssid}'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#
#         pwr = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count']
#         assert pwr, "packets are not captured in the sniffer"
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)

#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "ca_cert": ["start_field.pem"],
#         "client_cert": ["client-certificate.crt"],
#         "client_key": ["private-key.key"],
#         "set_tx_wait_time": True,
#         "tx_wait_time": 160000,
#     }
# )
# @pytest.mark.config('wifi_access_point',
#                     wifi={"ssid": "trialtrial", "passphrase": 'trialtrialp', "security": 'WPA2'})
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "close_sockets"])
# @pytest.mark.parametrize('execution_number', range(10))
# def test_wifi_sdk_invalid_Credentials_Flow_TC19139(wifi_sniffer, wifi_access_point, wifi_dut, logger, execution_number,
#                                                    sl_collections):
#     """
#     To check invalid credentials flow functionality of DUT
#     """
#     try:
#         capture_filename = "test_wifi_sdk_TC19139"
#         rejoin_params = [40, 6, 40, 0]
#         port1 = 8883
#
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel
#         )
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
#         power_save = 1
#
#         for count in range(3):
#             try:
#                 wifi_dut.interfaces.wifi.set_performance_profile(mode='standby_power_save')
#                 power_save = 0
#                 break
#             except:
#                 time.sleep(5)
#                 logger.info(f"Retry_count:{count}")
#         time.sleep(2)
#         assert power_save == 0
#         time.sleep(10)
#
#         scan_fail = sl_collections.scan(wifi_dut)
#         assert not scan_fail, "Scanning for AP failed"
#         join = 0
#         while True:
#             logger.info("connecting to Access point with wrong cred")
#             result = True
#             with pytest.raises(WlanError) as exc_info:
#                 wifi_dut.interfaces.wifi.join_ap(wifi_access_point, passphrase="1111111111111")
#             if exc_info.value.error_code == 0x0008 or exc_info.value.error_code == 0x0003:
#                 result = False
#             assert exc_info.value.error_code == 0x0008 or exc_info.value.error_code == 0x0003, "DUT SEND WRRONG ERROR CODE"
#             logger.info(f"Dut Tried to connect to ap with wrong password, observed error code 0x0008 which is expected")
#
#             if not result:
#                 logger.info("JOIN FAILED WITH INVALID CREDEDNTIALS")
#                 join = join + 1
#
#             if join == 10:
#                 result = sl_collections.connect(wifi_dut, wifi_access_point)
#                 if not result:
#                     logger.info("JOIN FAILED WITH VALID CREDENTIALS")
#                 else:
#                     logger.info("JOIN SUCCESS")
#                     wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=rejoin_params[0],
#                                                                              scan_interval=rejoin_params[1],
#                                                                              beacon_missed_count=rejoin_params[2],
#                                                                              first_time_retry_enable=rejoin_params[3],
#                                                                              )
#                     status = sl_collections.configure_ip(wifi_dut)
#                     assert not status, "Failed to Join to AP"
#
#                     device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#
#                     wifi_dut.interfaces.wifi.config_save()
#                     wifi_dut.interfaces.wifi.config_enable(config=1)
#
#                     for repeat_count in range(0, 2):
#                         logger.info(f"RETRYING FOR wireless_deinit and dut_init for {repeat_count} times")
#                         wifi_dut.interfaces.wifi.deinit()
#                         time.sleep(3)
#                         try:
#                             wifi_dut.interfaces.wifi.init()
#                         except WlanError as e:
#                             if e.error_code == 0x5a5a:
#                                 assert e.error_code == 0x5a5a
#                                 break
#                     time.sleep(10)
#
#                     wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
#
#                     sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#                     assert sock == 0, "Socket id received is wrong. expected is 0"
#
#                     wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                              option_val=SocketOptions.SOL_SOCKET)
#                     wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                              option_val=SocketOptions.SO_SSL_ENABLE)
#                     wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                              option_val=SocketOptions.SSL_ENABLE)
#
#                     wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_RETRY',
#                                                              option_val=SocketOptions.TCP_RETRY)
#                     wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_MAX_RETRY',
#                                                              option_val=SocketOptions.TCP_MAX_RETRY)
#
#                     wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                              option_val=SocketOptions.SO_CERT_INDEX)
#                     wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                              option_val=SocketOptions.CERT_INDEX0)
#                     socket_port = port1
#                     local_port = randint(5001, 20000)
#
#                     result = wifi_dut.interfaces.wifi.bsdGetHostByName(4,
#                                                                        "a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com",
#                                                                        )
#
#                     wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip,
#                                                   server_port=local_port,
#                                                   timeout=15)
#                     logger.info(f"dns response is {result}")
#                     server_ip = result.split(b"\n")[1].split(b":")[1].decode()
#                     for count in range(0, 3):
#                         try:
#                             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
#                                                                       server_port=socket_port)
#                             break
#                         except:
#                             logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
#                             time.sleep(1)
#                             if count == 2:
#                                 raise
#                     logger.info(f"Connection to AWS server on socket id->{sock} is successful")
#
#                     result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#                     assert b"success" in result, "unable to close opened tcp socket in the dut"
#                 break
#     except Exception as error:
#         logger.info(f"###########################{error}")
#         sl_collections.exception_handling(wifi_dut, error)
#     finally:
#         logger.info("Disable store configuration")
#         wifi_dut.interfaces.wifi.config_enable(config=0)
#         time.sleep(3)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.config(
#     "wifi_access_points",
#     wifi={
#         0: {
#             'ssid': 'TESTAPONE',
#             'security': 'WPA2',
#             'passphrase': '123123123',
#             'channel': 6,
#             'interface': 'wlan0'
#         },
#         1: {
#             'ssid': 'TESTAPONE',
#             'security': 'WPA2',
#             'passphrase': '987654321',
#             'channel': 6,
#             'interface': 'wlan0'
#         }
#     }
# )
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "set_send_feature_frame": True,
#     }
# )
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "bt_powersave_disable", "disable_store_config"])
# @pytest.mark.store_config
# def test_wifi_sdk_AutoJoin_Functionality_with_two_APs_with_different_PSK_TC19194(wifi_sniffer, wifi_access_points,
#                                                                                  wifi_dut, logger, sl_collections):
#     """
#     Verifies the Auto Join Functionality when the two APs are configured with same SSID but with different PSK
#     """
#     try:
#         logger.info(" ====== configuring the sniffer with access point channel ====== ")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
#
#         logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file='test_wifi_sdk_AutoJoin_Functionality_with_two_APs_with_different_PSK_TC19194')
#         listen_interval = 700
#
#         logger.info(" Enabling rejoin...")
#         wifi_dut.interfaces.wifi.rejoin()
#         wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[0].interfaces.wifi.ssid, channel=6)
#
#         join = 1
#         for count in range(3):
#             try:
#                 wifi_dut.interfaces.wifi.join_ap(wifi_access_points[0], timeout=20)
#                 time.sleep(3)
#                 join = 0
#                 break
#             except Exception as e:
#                 if ('0x8') in str(e):
#                     wifi_access_points[1].interfaces.wifi.stop_ap()
#                     time.sleep(5)
#             logger.info(f"Connection failure{count}")
#         assert join == 0, "Connection failure"
#         status = sl_collections.configure_ip(wifi_dut)
#         assert not status, "Failed to Join to AP"
#         wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
#                                                          listen_interval=listen_interval)
#         time.sleep(5)
#         wifi_dut.interfaces.wifi.config_save()
#         wifi_dut.interfaces.wifi.config_enable(config=1, )
#         error_code = 0
#         for i in range(3):
#             logger.info(f"RETRYING FOR {i} times")
#             wifi_dut.interfaces.wifi.wireless_deinit()
#             time.sleep(3)
#             try:
#                 wifi_dut.interfaces.wifi.dut_init(timeout=20, retries=0)
#             except WlanError as e:
#                 if e.error_code == 0x5a5a:
#                     assert e.error_code == 0x5a5a, "Expected error code is 0x5a5a, received wrong error code"
#                     error_code = 1
#                     break
#
#         time.sleep(10)
#         assert error_code == 1, "Expected error code is 0x5a5a, received wrong error code"
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#
#         logger.info(" ====== configuring the sniffer with access point channel ====== ")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
#
#         logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file='test_wifi_sdk_AutoJoin_Functionality_with_two_APs_with_different_PSK_TC19194')
#         wifi_access_points[1].interfaces.wifi.start_ap()
#         time.sleep(5)
#         wifi_access_points[0].interfaces.wifi.stop_ap()
#
#         wifi_dut.interfaces.wifi.wireless_deinit()
#         time.sleep(3)
#         with pytest.raises(WlanError) as e:
#             wifi_dut.interfaces.wifi.dut_init(timeout=50, retries=0)
#         # Deauthentication received from AP
#         assert e.value.error_code == 0x0008, "Observed wrong error code.expected is 0x0008"
#         logger.info("joining failed to 2nd AP which has different PSK")
#         logger.info("Stop Sniffer finally")
#         time.sleep(5)
#         wifi_sniffer.interfaces.capture.stop_capture()
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#     finally:
#         logger.info("Disable store configuration")
#         wifi_dut.interfaces.wifi.config_enable(config=0)
#         time.sleep(3)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.config(
#     "wifi_access_points",
#     wifi={
#         # Here, indexing (starts with 0) applies as per order defined in harness.
#         0: {
#             'ssid': 'TESTAPONE95',
#             'security': 'WPA2',
#             'passphrase': '123456789',
#             'channel': 7,
#             'interface': 'wlan0'
#         },
#         1: {
#             'ssid': 'TESTAPTWO95',
#             'security': 'WPA2',
#             'passphrase': '123456789',
#             'channel': 7,
#             'interface': 'wlan0'
#         }
#     }
# )
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "set_send_feature_frame": True,
#         "band": 0,
#     }
# )
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
# @pytest.mark.store_config
# def test_wifi_sdk_AutoJoin_Functionality_with_two_APs_with_different_SSID_TC19195(wifi_sniffer, wifi_dut, wifi_client,
#                                                                                   wifi_access_points, logger,
#                                                                                   sl_collections):
#     """
#     Auto Join Functionality when the two APs are configured with different SSID and same PSK
#     """
#     try:
#         logger.info(" ====== configuring the sniffer with access point channel ====== ")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
#
#         logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file='test_wifi_sdk_AutoJoin_Functionality_with_two_APs_with_different_SSID_TC19195')
#         listen_interval = 700
#         logger.info(" Enabling rejoin...")
#         wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=20,
#                                                                  scan_interval=6,
#                                                                  beacon_missed_count=40, first_time_retry_enable=0,
#                                                                  )
#         wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[0].interfaces.wifi.ssid, channel=7)
#         join = 1
#         status = sl_collections.connect(wifi_dut, wifi_access_points[0])
#         assert not status, "Joining to AP is failed"
#
#         status = sl_collections.configure_ip(wifi_dut)
#         assert not status, "Failed to Join to AP"
#
#         wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
#                                                          listen_interval=listen_interval)
#
#         wifi_dut.interfaces.wifi.config_save()
#         wifi_dut.interfaces.wifi.config_enable(config=1)
#         for i in range(0, 2):
#             logger.info(f"RETRYING FOR {i} times")
#             wifi_dut.interfaces.wifi.deinit()
#             time.sleep(3)
#             try:
#                 wifi_dut.interfaces.wifi.init()
#             except WlanError as e:
#                 if e.error_code == 0x5a5a:
#                     assert e.error_code == 0x5a5a, "Expected error code is 0x5a5a, received wrong error code"
#                     break
#         time.sleep(10)
#         wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
#                                                          listen_interval=listen_interval)
#
#         logger.info("Stop Sniffer finally")
#         time.sleep(5)
#         wifi_sniffer.interfaces.capture.stop_capture()
#
#         logger.info(" ====== configuring the sniffer with access point channel ====== ")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
#
#         logger.info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
#         wifi_sniffer.interfaces.capture.start_capture(
#             capture_file='test_wifi_sdk_AutoJoin_Functionality_with_two_APs_with_different_SSID_TC19195')
#         wifi_access_points[1].interfaces.wifi.start_ap()
#         time.sleep(5)
#         wifi_access_points[0].interfaces.wifi.stop_ap()
#
#         wifi_dut.interfaces.wifi.deinit()
#         time.sleep(3)
#         with pytest.raises(WlanError) as e:
#             wifi_dut.interfaces.wifi.init()
#         # access point not found/rejoin failure
#         assert e.value.error_code == 0x0003 or e.value.error_code == 0x0019, "Observed wrong error code"
#         logger.info("joining failed to 2nd AP which has different SSID")
#
#         time.sleep(10)
#         wifi_dut.interfaces.wifi.inited = True
#         wifi_dut.interfaces.wifi.associated = False
#         time.sleep(5)
#
#         ap_mac_two = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_points[1].interfaces.wifi.ssid, channel=7,
#                                                    )
#         status = sl_collections.connect(wifi_dut, wifi_access_points[1])
#         assert not status, "Joining to AP is failed"
#         logger.info("JOIN TO second AP IS SUCCESSFUL")
#         time.sleep(3)
#
#         status = sl_collections.configure_ip(wifi_dut)
#         assert not status, "Failed to Join to AP"
#
#         wifi_dut.interfaces.wifi.config_save(thrad=True)
#         wifi_dut.interfaces.wifi.config_enable(config=1)
#         for i in range(0, 2):
#             logger.info(f"RETRYING FOR {i} times")
#             wifi_dut.interfaces.wifi.deinit()
#             time.sleep(3)
#             try:
#                 wifi_dut.interfaces.wifi.init()
#             except WlanError as e:
#                 if e.error_code == 0x5a5a:
#                     assert e.error_code == 0x5a5a, "Expected error code is 0x5a5a, received wrong error code"
#                     break
#         time.sleep(10)
#
#         wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
#         time.sleep(2)
#         logger.info("Stop Sniffer finally")
#         wifi_sniffer.interfaces.capture.stop_capture()
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#     finally:
#         logger.info("Disable store configuration")
#         wifi_dut.interfaces.wifi.config_enable(config=0)
#         wifi_access_points[1].interfaces.wifi.stop_ap()
#         time.sleep(2)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "set_send_feature_frame": True,
#         "ca_cert": ["start_field.pem"],
#         "client_cert": ["client-certificate.crt"],
#         "client_key": ["private-key.key"],
#         "rejoin_max_retry": 0,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0
#     }
# )
# @pytest.mark.store_config
# @pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
#                              "clear_certs"])
# def test_wifi_sdk_Stored_AP_Powered_Off_After_Initial_Connection_C19146(wifi_sniffer, wifi_dut, wifi_access_point,
#                                                                         domain_name, switch, logger, sl_collections):
#     """
#     Stored AP Powered Off After Initial Connection (Power Loss)
#     """
#     try:
#         port = 8883
#         capture_filename = "test_wifi_sdk_Stored_AP_Powered_Off_After_Initial_Connection_C19146"
#         wifi_sniffer.interfaces.capture.configure_interface(
#             channel=wifi_access_point.interfaces.wifi.channel
#         )
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
#         exception_count = 0
#
#         for iter in range(10):
#             logger.info(f"Iteration of testcase for {iter}th time")
#             try:
#                 power_save = 1
#                 for count in range(3):
#                     try:
#                         wifi_dut.interfaces.wifi.set_performance_profile(mode='standby_power_save')
#                         power_save = 0
#                         break
#                     except:
#                         time.sleep(5)
#                         logger.info(f"Retry_count:{count}")
#                 assert power_save == 0
#
#                 time.sleep(5)
#
#                 scan_fail = sl_collections.scan(wifi_dut)
#                 assert not scan_fail, "Scanning for AP failed"
#
#                 rejoin_params = [0, 6, 40, 0]
#
#                 wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=rejoin_params[0],
#                                                                          scan_interval=rejoin_params[1],
#                                                                          beacon_missed_count=rejoin_params[2],
#                                                                          first_time_retry_enable=rejoin_params[3],
#                                                                          )
#
#                 status = sl_collections.connect(wifi_dut, wifi_access_point)
#                 assert not status, "Joining to AP is failed"
#
#                 status = sl_collections.configure_ip(wifi_dut)
#                 assert not status, "Failed to Join to AP"
#
#                 mac_address = wifi_dut.interfaces.wifi.get_mac_address()
#                 logger.info(f"DUT MAC_Address: {mac_address}")
#
#                 device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#                 #
#                 wifi_dut.interfaces.wifi.config_save()
#                 wifi_dut.interfaces.wifi.config_enable(config=1)
#
#                 for i in range(0, 2):
#                     logger.info(f"RETRYING FOR {i} times")
#                     wifi_dut.interfaces.wifi.deinit()
#                     time.sleep(3)
#                     try:
#                         wifi_dut.interfaces.wifi.init()
#                     except WlanError as e:
#                         if e.error_code == 0x5a5a:
#                             assert e.error_code == 0x5a5a
#                             break
#
#                 wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
#
#                 sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#                 assert sock == 0, "Socket id received is wrong. expected is 0"
#
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                          option_val=SocketOptions.SOL_SOCKET)
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                          option_val=SocketOptions.SO_SSL_ENABLE)
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                          option_val=SocketOptions.SSL_ENABLE)
#
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_RETRY',
#                                                          option_val=SocketOptions.TCP_RETRY)
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_MAX_RETRY',
#                                                          option_val=SocketOptions.TCP_MAX_RETRY)
#
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                          option_val=SocketOptions.SO_CERT_INDEX)
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                          option_val=SocketOptions.CERT_INDEX0)
#
#                 local_port = randint(40001, 50000)
#
#                 wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
#                                               timeout=15)
#                 result = wifi_dut.interfaces.wifi.bsdGetHostByName(4, domain_name)
#
#                 logger.info(f"dns response is {result}")
#                 server_ip = result.split(b"\n")[1].split(b":")[1].decode()
#                 logger.info(f"server_ip {server_ip}")
#
#                 check = 0
#                 for i in range(2):
#                     try:
#                         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
#                                                                   server_port=port)
#                         check = 1
#                         break
#                     except:
#                         logger.info(f"Connection failed")
#                 assert check == 1, "Connect failed"
#                 sleep_time = 3060
#                 obj = SocketDataTransfer()
#                 thread = Thread(target=obj.pdu_switch, args=(switch, sleep_time, logger), )
#                 thread.start()
#                 sw = Stopwatch()
#                 while sw.elapsed_sec < 4200:
#                     if (sw.elapsed_sec >= 2100) and (sw.elapsed_sec <= 2110):
#                         wifi_dut.interfaces.wifi.deinit()
#
#                         with pytest.raises(WlanError) as e:
#                             wifi_dut.interfaces.wifi.init()
#                         assert e.value.error_code == 0x0003, "Observed wrong error code"
#
#                     if sw.elapsed_sec >= 3140:
#                         wifi_dut.interfaces.wifi.deinit()
#                         time.sleep(3)
#                         try:
#                             wifi_dut.interfaces.wifi.init()
#                         except WlanError as e:
#                             if e.error_code == 0x5a5a:
#                                 assert e.error_code == 0x5a5a
#                                 break
#
#             except Exception as e:
#                 if ('0xfffffffd' in str(e)) or ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or (
#                         "0xFFFFFFD5" in str(e)):
#                     logger.info("Initiating reset for device cleanup")
#                     wifi_dut.interfaces.wifi.reset()
#                     time.sleep(10)
#                     wifi_dut.interfaces.wifi.associated = True
#                     logger.info("Initializing the DUT")
#                     wifi_dut.interfaces.wifi.init()
#                     time.sleep(5)
#                     exception_count += 1
#             finally:
#                 wifi_dut.interfaces.wifi.config_enable(config=0)
#                 get_state = switch.interfaces.pdu_switch.get_state()
#                 if get_state == False:
#                     switch.interfaces.pdu_switch.turn_on(delay=60)
#
#         assert exception_count <= 3, "Failed"
#
#         mac_address = wifi_dut.interfaces.wifi.get_mac_address()
#         logger.info(f"DUT MAC_Address: {mac_address}")
#
#         validation = True
#         packet_filter1 = f'(wlan.ta == {mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": Si91xCoexMode.WLANOnly,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD | Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "set_send_feature_frame": True,
#         "ca_cert": ["start_field.pem"],
#         "client_cert": ["client-certificate.crt"],
#         "client_key": ["private-key.key"],
#         "rejoin_max_retry": 0,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0
#     }
# )
# @pytest.mark.store_config
# @pytest.mark.parametrize("domain_name", ["a25jwtlmds8eip-ats.iot.us-east-2.amazonaws.com"])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
#                              "clear_certs"])
# def test_wifi_sdk_Stored_AP_Powered_OFF_during_boot_C19145(wifi_sniffer, wifi_dut, wifi_access_point, domain_name,
#                                                            switch, logger, sl_collections):
#     """
#     test store configuration of stored AP when powered OFF during boot
#     """
#     try:
#         port = 8883
#         capture_filename = "test_wifi_sdk_C19145"
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
#         exception_count = 0
#         error = ""
#         listen_interval = 700
#
#         for iter_count in range(1, 2):
#             logger.info(f"Iteration of testcase for {iter_count}th time")
#             try:
#                 power_save = 1
#                 for count in range(3):
#                     try:
#                         wifi_dut.interfaces.wifi.set_performance_profile(mode='standby_power_save')
#                         power_save = 0
#                         break
#                     except:
#                         time.sleep(5)
#                         logger.info(f"Retry_count:{count}")
#                 assert power_save == 0
#
#                 time.sleep(5)
#
#                 scan_fail = sl_collections.scan(wifi_dut)
#                 assert not scan_fail, "Scanning for AP failed"
#                 rejoin_params = [0, 6, 40, 0]
#                 wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=rejoin_params[0],
#                                                                          scan_interval=rejoin_params[1],
#                                                                          beacon_missed_count=rejoin_params[2],
#                                                                          first_time_retry_enable=rejoin_params[3],
#                                                                          )
#
#                 status = sl_collections.connect(wifi_dut, wifi_access_point)
#                 assert not status, "Joining to AP is failed "
#                 time.sleep(2)
#
#                 status = sl_collections.configure_ip(wifi_dut)
#                 assert not status, "Failed to Join to AP"
#
#                 device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#                 #
#                 wifi_dut.interfaces.wifi.config_save()
#                 wifi_dut.interfaces.wifi.config_enable(config=1)
#
#                 for i in range(0, 2):
#                     logger.info(f"RETRYING FOR {i} times")
#                     wifi_dut.interfaces.wifi.deinit()
#                     time.sleep(3)
#                     try:
#                         wifi_dut.interfaces.wifi.init()
#                     except WlanError as e:
#                         if e.error_code == 0x5a5a:
#                             assert e.error_code == 0x5a5a
#                             break
#
#                 wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency',
#                                                                  listen_interval=listen_interval)
#
#                 sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#                 assert sock == 0, "Socket id received is wrong. expected is 0"
#
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                          option_val=SocketOptions.SOL_SOCKET)
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                          option_val=SocketOptions.SO_SSL_ENABLE)
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                          option_val=SocketOptions.SSL_ENABLE)
#
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_RETRY',
#                                                          option_val=SocketOptions.TCP_RETRY)
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='TCP_MAX_RETRY',
#                                                          option_val=SocketOptions.TCP_MAX_RETRY)
#
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_CERT_INDEX',
#                                                          option_val=SocketOptions.SO_CERT_INDEX)
#                 wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='CERT_INDEX',
#                                                          option_val=SocketOptions.CERT_INDEX0)
#
#                 local_port = randint(40001, 50000)
#                 wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
#                                               timeout=15)
#
#                 result = wifi_dut.interfaces.wifi.bsdGetHostByName(4, domain_name)
#
#                 logger.info(f"dns response is {result}")
#                 server_ip = result.split(b"\n")[1].split(b":")[1].decode()
#                 logger.info(f"server_ip {server_ip}")
#
#                 check = 0
#                 for i in range(2):
#                     try:
#                         wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
#                                                                   server_port=port)
#                         check = 1
#                         break
#                     except:
#                         logger.info(f"Connection failed")
#
#                 assert check == 1, "Connect failed"
#
#                 sleep_time = 3060
#                 obj = SocketDataTransfer()
#                 thread = Thread(target=obj.pdu_switch, args=(switch, sleep_time, logger), )
#                 thread.start()
#                 sw = Stopwatch()
#                 while sw.elapsed_sec < 4200:
#                     if (sw.elapsed_sec >= 2100) and (sw.elapsed_sec <= 2110):
#                         wifi_dut.interfaces.wifi.deinit()
#                         with pytest.raises(WlanError) as e:
#                             wifi_dut.interfaces.wifi.init()
#                         assert e.value.error_code == 0x0003, "Observed wrong error code"
#
#                 logger.info("ENDED THE TESTCASE")
#
#             except Exception as e:
#                 if ('0xfffffffd' in str(e)) or ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or (
#                         "0xFFFFFFD5" in str(e)):
#                     logger.info("Initiating reset for device cleanup")
#                     wifi_dut.interfaces.wifi.reset()
#                     time.sleep(10)
#                     wifi_dut.interfaces.wifi.associated = True
#                     logger.info("Initializing the DUT")
#                     wifi_dut.interfaces.wifi.init()
#                     time.sleep(5)
#                 logger.info(f"In Exception block error: {e}")
#                 exception_count += 1
#                 logger.info(f"exception_count: {exception_count}")
#                 error = e
#
#             finally:
#                 wifi_dut.interfaces.wifi.config_enable(config=0)
#                 get_state = switch.interfaces.pdu_switch.get_state()
#                 if not get_state:
#                     switch.interfaces.pdu_switch.turn_on(delay=60)
#         logger.info(f"exception_count: {exception_count}")
#         assert exception_count == 0, error
#
#         mac_address = wifi_dut.interfaces.wifi.get_mac_address()
#         logger.info(f"DUT MAC_Address: {mac_address}")
#
#         validation = True
#         packet_filter1 = f'(wlan.ta == {mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count']
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"As per sniffer validation DUT went to power save and sending PS-POLLS for retrieving data")
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
