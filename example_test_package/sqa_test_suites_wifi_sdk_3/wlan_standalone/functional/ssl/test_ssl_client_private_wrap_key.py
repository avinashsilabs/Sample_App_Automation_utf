import time
import pytest
import re
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xAwsQos,
    Si91xCertificateType,
    Si91xModuleType,
    Si91xCertIdentifier,
    Si91xBTFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Cipher,
    Si91xCryptoWrapMode
)
import string
import random
from utf.utf_config import UtfConfig

from random import randint
from utf.utils.thread_base import ThreadBase
from threading import Thread
from utf.utils import get_tls_certificate_dir
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch

"""The testcases added in this file run below test steps for DUT-Si91x
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates in the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Create a new TCP/IP socket over ssl 
        6. Bind the socket with DUT ip address
        7. Connect the client with server socket as specified port number.
        8. Send and receive the data over the socket. Verify the data integrity and packet loss checks.
    setup requirement:
        1. DUT(Si91x)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)


def wifi_dut_marker(oper_mode=0,coex_mode=0,ca_cert=None, client_cert=None, client_key=None, eap_cert=None, tcpip_feat=0, ext_custom_feat=0, ext_tcpip_feat=0):
    """
    Common method to generate wifi_dut marker for pytest.mark.config decorator.
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient | oper_mode,
        "coex_mode": Si91xCoexMode.WLANOnly | coex_mode,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | tcpip_feat,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | ext_tcpip_feat,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | ext_custom_feat,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert

    if client_key:
        config["client_key"] = client_key
    if eap_cert:
        config["eap_cert"] = eap_cert
    return pytest.mark.config("wifi_dut", wifi=config)


class WLanJoinThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 sl_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None,
                 capture_filename=None, client_key=None, wifi_client=None, switch=None, ssl_server=None, eap_type=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None
        self.power_save = power_save
        self.ap_mac_address = ap_mac_address
        self.capture_filename = capture_filename
        self.wifi_client = wifi_client
        self.switch = switch
        self.client_key = client_key
        self.ssl_server = ssl_server
        self.eap_type = eap_type

    def run(self):
        try:
            logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            if self.client_key:
                if self.test_case == '1163608' or self.test_case == '1163614' or self.test_case == '1163624':
                    index = 0
                    for cert in self.client_key:
                        logger().info(f"Clearing client key at index {index}")
                        self.wifi_dut.interfaces.wifi.clear_certificate(
                            cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP,
                            cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START, cert_index=index)
                        logger().info(f"loading client key at index {index}")
                        self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=cert, cert_index=index)
                        index = index+1
                elif self.test_case == '1163607' or self.test_case == '1163615' or self.test_case == '1163621':
                    index = 0
                    for cert in self.client_key:
                        logger().info(f"Clearing client key at index {index}")
                        self.wifi_dut.interfaces.wifi.clear_certificate(
                            cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                            cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START, cert_index=index)
                        logger().info(f"loading client key at index {index}")
                        self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=cert,
                                                                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                                        wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                        iv=None,
                                                                        cert_index=index)
                        index = index + 1
                elif self.test_case == '1163604' or self.test_case == '1163606':
                    self.wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_CBC_WRAP, cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)
                    self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=self.client_key)

                elif self.test_case == '1163603' or self.test_case == '1163605' or self.test_case == '1163613' or self.test_case == '1163612':
                    self.wifi_dut.interfaces.wifi.clear_certificate(
                        cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                        cert_identifier=Si91xCertIdentifier.SL_NET_TLS_CLIENT_CREDENTIAL_START)

                    self.sl_collections.load_tls_client_private_key(self.wifi_dut, cert_file=self.client_key,
                                                                    cert_type=Si91xCertificateType.SL_NET_TLS_PRIVATE_KEY_ECB_WRAP,
                                                                    wrap_iv_mode=Si91xCryptoWrapMode.SL_SI91X_WRAP_IV_ECB_MODE,
                                                                    iv=None)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.capture_filename)
            if self.test_case == '1163612' or self.test_case == '1163615':
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.eap_type,
                                                                        retry_count=3,
                                                                        ping_after_power_save=True)
            else:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                         retry_count=3)
            if self.test_case == '1163608' or self.test_case == '1163607' or self.test_case == '1163614' or self.test_case == '1163615' or self.test_case == '1163624' or self.test_case == '1163621':
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                port2 = self.ssl_server.interfaces.ssl.config['device_port2']
                port3 = self.ssl_server.interfaces.ssl.config['device_port3']
                pkt_count = 100
                buffer_length = 1300
                if self.test_case == '1163621':
                    self.ssl_server.interfaces.ssl.start_server(port=port1,
                                                                server_cert='server_ecdsa_cert_test1.pem',
                                                                server_key='server_ecdsa_key_test1.pem',
                                                                tls_client_enable=True,
                                                                client_cert='ca_ecdsa_test1.pem')
                    self.ssl_server.interfaces.ssl.start_server(port=port2,
                                                                server_cert='server_ecdsa_cert_test2.pem',
                                                                server_key='server_ecdsa_key_test2.pem',
                                                                tls_client_enable=True,
                                                                client_cert='ca_ecdsa_test2.pem')
                    self.ssl_server.interfaces.ssl.start_server(port=port3,
                                                                server_cert='server_ecdsa_cert_test3.pem',
                                                                server_key='server_ecdsa_key_test3.pem',
                                                                tls_client_enable=True,
                                                                client_cert='ca_ecdsa_test3.pem')
                else:
                    self.ssl_server.interfaces.ssl.start_server(port= port1,
                                                                server_cert='server_test1.crt',
                                                                server_key='server_test1.key',
                                                                tls_client_enable=True,
                                                                client_cert='ca_test1.crt')
                    self.ssl_server.interfaces.ssl.start_server(port = port2,
                                                                server_cert='server_test2.crt',
                                                                server_key='server_test2.key',
                                                                tls_client_enable=True,
                                                                client_cert='ca_test2.crt')
                    self.ssl_server.interfaces.ssl.start_server(port = port3,
                                                                server_cert='server_test3.crt',
                                                                server_key='server_test3.key',
                                                                tls_client_enable=True,
                                                                client_cert='ca_test3.crt')

                server_ip = self.ssl_server.interfaces.ssl.server_ip
                device_ip = self.dut_addr['device_ip']

                for count in range(0, 3):
                    # Open ssl client socket in the DUT
                    sock = self.wifi_dut.interfaces.wifi.socket()
                    if count == 0:
                        assert sock == 0, "Socket id received is wrong. expected is 0"
                    elif count == 1:
                        assert sock == 1, "Socket id received is wrong. expected is 1"
                    else:
                        assert sock == 2, "Socket id received is wrong. expected is 2"
                    logger().info(
                        f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                    logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                    # Enable ssl option for socket opened
                    self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                    # self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="SOL_TCP", option_val="SO_MAX_RETRANSMISSION_TIMEOUT_VALUE")
                    if count == 0:
                        local_port = randint(5001, 6000)
                    elif count == 1:
                        local_port = randint(6001, 7000)
                    else:
                        local_port = randint(7001, 8000)
                    # Socket binds at (device_ip, 5001) in DUT
                    self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                                       timeout=15)
                    time.sleep(3)
                    try:
                        # ssl socket opened in DUT connects to the server
                        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                       server_port=port1+count)
                    except:
                        logger().info(f"Failed to connect to server socket")
                        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                        self.ssl_server.interfaces.ssl.stop_server()
                        time.sleep(1)
                        raise
                for socket in range(1, 4):
                    server_sock = socket
                    self.ssl_server.interfaces.ssl.data_receive(server_sock, pkt_count, buffer_length, pkt_rcv_timeout=10)

                socket_list = self.wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=7, data_len=buffer_length,
                                                                                  number_of_pkts=pkt_count)
                sock_count = 0
                bytes_sent_list = []
                for socket_stats in socket_list:
                    logger.info(
                        f"Number of bytes sent by DUT on socket_id:{sock_count}->{socket_stats[0]} and time taken->{(socket_stats[1] / 1000)} seconds")
                    bytes_sent_list.append(socket_stats[0])
                    sock_count = sock_count + 1
                for socket in range(1, 4):
                    server_sock = socket
                    if self.ssl_server.interfaces.ssl.socket_connection_status(server_sock):
                        bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_sock)
                        assert bytes_sent_list[
                                   socket - 1] == bytes_received, f"Number of bytes sent by DUT and received on the " \
                                                                  f"remote peer not matched on socket {socket - 1}"
                for sock_id in range(3):
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
                    logger.info(f"Successfully closed socket_id '{sock_id}' in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()

            elif self.test_case == '1163603' or self.test_case == '1163604' or self.test_case == '1163605' or self.test_case == '1163606' or self.test_case == '1163613' or self.test_case == '1163612':
                pkt_count = 10000
                buffer_length = 1300
                self.ssl_server.interfaces.ssl.start_server(server_cert='server_test1.crt',
                                                            server_key='server_test1.key',
                                                            tls_client_enable=True, client_cert='ca_test1.crt')
                server_ip = self.ssl_server.interfaces.ssl.server_ip
                device_ip = self.dut_addr['device_ip']
                port1 = self.ssl_server.interfaces.ssl.config['device_port1']
                # Open ssl client socket in the DUT
                sock = self.wifi_dut.interfaces.wifi.socket()
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(
                    f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                # Enable ssl option for socket opened
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                # self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="SOL_TCP", option_val="SO_MAX_RETRANSMISSION_TIMEOUT_VALUE")
                local_port = randint(5001, 60000)
                # Socket binds at (device_ip, 5001) in DUT
                self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                                   timeout=15)
                time.sleep(3)
                try:
                    # ssl socket opened in DUT connects to the server
                    self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                                   server_port=port1)
                except:
                    logger().info(f"Failed to connect to server socket")
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    self.ssl_server.interfaces.ssl.stop_server()
                    time.sleep(1)
                    raise
                # The api returns 100 bytes of random data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger().info(f"Sending data {data} over socket_no->{sock}")
                try:
                    self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                except:
                    self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                    self.ssl_server.interfaces.ssl.stop_server()
                    raise
                # SSL server receives the data over ssl socket
                time.sleep(1)
                server_socket_no = 1
                data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
                logger().info(f"Data received on remote socket opened is {data_receive}")
                assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                logger().info("Data sent by DUT and received on server is matching\n\n")

                if self.ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                    self.ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
                result = self.wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count, server_ip)
                logger().info(f"Number of bytes sent by dut {result}")
                bytes_sent = result

                bytes_received = self.ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)

                logger().info(
                    f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")

                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()
            self.wifi_dut.interfaces.wifi.leave()
            logger().info("Stopping sniffer capture")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                filter_name="power_mgmt_bit")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=self.power_save_filter)['packet_count'] > 0, \
                "Unable to find NULL-Data frame packets with power save bit = 1"
            return

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode = Si91xCoexMode.WLAN |Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_c1163604(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163604',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode = Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_c1163603(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163603',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode = Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_in_ram_c1163606(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163606',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode = Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_in_ram_c1163605(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163605',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 coex_mode = Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'WPA3',
                                               "protected_management_frame": "Capable", })
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_wpa3_c1163613(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163613',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)




@wifi_dut_marker(ca_cert=["ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 client_cert=["client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
                 eap_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
                 oper_mode=Si91xOperatingMode.EAPWiFiClient,
                 coex_mode = Si91xCoexMode.WLAN|Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.parametrize("client_key", ['client_test1.key'])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_eap_c1163612(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, radius_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163612',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server, eap_type="tls")

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)

@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode = Si91xCoexMode.WLAN |Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_three_certs_c1163608(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163608',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode = Si91xCoexMode.WLAN|Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_three_certs_c1163607(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163607',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode = Si91xCoexMode.WLAN|Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.LoadSSLCertificatesToRAM,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_three_certs_in_ram_c1163614(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163614',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 eap_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
                 oper_mode=Si91xOperatingMode.EAPWiFiClient,
                 coex_mode = Si91xCoexMode.WLAN|Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_three_certs_eap_sec_c1163615(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163615',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server, eap_type="tls")

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_test1.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test2.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_test3.crt", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_test1.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test2.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_test3.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode = Si91xCoexMode.WLANOnly,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_test1.key', 'client_test2.key', 'client_test3.key']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_cbc_mode_three_certs_SL_SI91X_EXT_FEAT_352K_M4SS_320K_sta_alone_c1163624(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163624',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=[("ca_ecdsa_test1.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_ecdsa_test2.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                          ("ca_ecdsa_test3.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")],
                 client_cert=[("client_ecdsa_cert_test1.pem", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_ecdsa_cert_test2.pem", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"),
                              ("client_ecdsa_cert_test3.pem", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START")],
                 coex_mode = Si91xCoexMode.WLAN|Si91xCoexMode.BLE,
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
@pytest.mark.parametrize("client_key", [['client_ecdsa_key_test1.pem', 'client_ecdsa_key_test2.pem', 'client_ecdsa_key_test3.pem']])
def test_wifi_sdk_ssl_load_private_wrap_key_iv_ecb_mode_three_certs_ecdsa_c1163621(wifi_access_point, sniffer_filter, sl_collections,
                                                                 wifi_dut, ssl_server, utf_constants,
                                                                 wifi_sniffer, client_key, request):
    """
    ssl client connection and data transfer
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='1163621',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  capture_filename=capture_filename, client_key=client_key, ssl_server=ssl_server)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


