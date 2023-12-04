import time
import pytest
import re
from utf_wiseconnect_3.tests.devices.si91x import (
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
    Si91xBLECustomFeatureBitMap
)
import string
import random
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import ping
from random import randint
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


class ssl_connection:
    """
    Class to configure SSL and Rejoin parameters in DUT along with WLAN and SSL Socket Connection.
    """

    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections,
                 listen_interval_feature=False, listen_interval=1600, rejoin_params=None):
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.rejoin_params = rejoin_params
        self.sl_collections = sl_collections
        self.listen_interval = listen_interval
        self.capture_filename = capture_filename
        self.wifi_access_point = wifi_access_point
        self.listen_interval_feature = listen_interval_feature

    def join_get_ip(self, sniff_capture=True):
        if sniff_capture:
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        self.wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        if not self.rejoin_params:
            self.rejoin_params = [0, 6, 40, 0]
        result = self.sl_collections.join_to_wifi_network_with_rejoin(self.wifi_dut, self.wifi_access_point,
                                                                      self.rejoin_params)
        dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        return dut_ip, dut_mac_address

    def pdu_switch(self, sleep_time=10, switch=None):
        time.sleep(3)
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

    @staticmethod
    def socket_data_rx(wifi_dut, ssl_server, sock_no, pkt_count, buffer_length, duration=30):
        sw = Stopwatch()
        while sw.elapsed_sec < duration:
            time.sleep(1)
            logger().info(f"Receiving data from DUT over socket_no ---> {sock_no - 1}")
            ssl_server.interfaces.ssl.send_data(sock_no, pkt_count, msg_length=buffer_length)
            rx_buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_no - 1, timeout=20)
            assert rx_buffer, "Packet loss observed at receiver side"
            logger().info("Data sent by remote peer is received from DUT\n\n")


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.Ping,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode
                                   | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xModuleType.EXT_TCP_IP_TOTAL_SELECTS(
                1),
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.BLE_MAX_NUM_OF_PHERIPHERALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC |
                            Si91xBLEFeatureBitMap.BLE_MAX_NBR_CENTRALS | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV |
                            Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
                            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES
                                       | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
            "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                               | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
            "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
        }
    )
]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_client_connect_close_sequence_testcase_c19130(wifi_access_point, sniffer_filter, sl_collections,
                                                                    wifi_dut, ssl_server, logger, utf_constants,
                                                                    wifi_sniffer):
    """
    ssl client socket connection, data send and socket close regression
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_connect_close_sequence_testcase_C19130"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        test_run_time = utf_constants.get('time_duration')

        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip()

        fail_count = 0
        sw = Stopwatch()
        while sw.elapsed_sec < test_run_time:
            logger.info(
                f"\n\nRemaining time to complete this testcase is '{round(((test_run_time - sw.elapsed_sec) / 60), 2)}' minutes")
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server()
            server_ip = ssl_server.interfaces.ssl.server_ip
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == 0, "Socket id received is wrong. expected is 0"
            logger.info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            local_port = randint(5001, 60000)
            # Socket binds at (device_ip, 5001) in DUT
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                          timeout=15)
            time.sleep(3)
            try:
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                          server_port=port1)
            except:
                fail_count = fail_count + 1
                logger.info(f"Failed to connect to server socket")
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
                ssl_server.interfaces.ssl.stop_server()
                time.sleep(5)
                continue

            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger.info(f"Sending data {data} over socket_no->{sock}")

            sw1 = Stopwatch()
            while sw1.elapsed_sec <= 30:
                # DUT sends 100 bytes of data over ssl socket
                wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                # SSL server receives the data over ssl socket
                time.sleep(1)
                server_socket_no = 1
                data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
                logger.info(f"Data received on remote socket opened is {data_receive}")
                assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                logger.info("Data sent by DUT and received on server is matching\n\n")

            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger.info("Successfully closed opened socket in the DUT")
            ssl_server.interfaces.ssl.stop_server()
            time.sleep(5)

        if fail_count:
            logger.info(f"{fail_count} times failed to connect to the server in '{test_run_time}' seconds of testrun")
        assert fail_count == 0, f"{fail_count} times failed to connect to the server in '{test_run_time}' seconds of testrun"

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_socket_limit_testcase_c19121(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
                                                   sl_collections, sniffer_filter):
    """
    Open SSL server socket in DUT with maximum client limit 3
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_socket_limit_testcase_TC19121"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=5001)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=5002)
        # Open ssl server socket in remote device(Raspberry pi or static device)
        ssl_server.interfaces.ssl.start_server(port=5003)
        server_ip = ssl_server.interfaces.ssl.server_ip

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 20000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5001)

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 1, "Socket id received is wrong. expected is 1"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(20001, 40000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5002)

        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 2, "Socket id received is wrong. expected is 2"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(40001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        error_code = 0
        try:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5003)
        except Exception as err:
            error_match = re.search("status:(.*)", str(err))
            if error_match:
                error_code = error_match.group()
                logger.info(f"error_code: {error_code}")
        assert error_code, "DUT sent error code when trying to connect to third ssl socket which is expected"
        logger.info(f"DUT sent error code when trying to connect to third ssl socket which is expected")

        for sock_id in range(3):
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
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_client_1_2_version_server_1_0_testcase_c19120(wifi_sniffer, wifi_dut, wifi_access_point, openssl,
                                                                    wifi_client, logger, sl_collections,
                                                                    sniffer_filter):
    """
    Connect to ssl server socket which run with version 1.0 at remote side and connect to it from module with version 1.2
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_server_1_0version_client_1_2_testcase_TC19120"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        openssl.interfaces.server.start(port=5001, tls_version="-tls1")
        server_ip = wifi_client.interfaces.wifi.get_ip_address()

        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)

        error_code = 0
        try:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5001)
        except Exception as err:
            error_match = re.search("status:(.*)", str(err))
            if error_match:
                error_code = error_match.group()
                logger.info(f"error_code: {error_code}")
        assert error_code, "DUT sent error code when trying to connect to ssl socket with open_ssl_v1_0 which is expected"
        logger.info(f"DUT sent error code when trying to connect to ssl socket with open_ssl_v1_0 which is expected")

        openssl.interfaces.server.stop()
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                       capture_filename, ap_bssid)['tls']
        if len(ssl_pkt) > 0:
            for i in ssl_pkt:
                if re.search(".*Client Hello", i):
                    version = re.search("Version:.*", i).group(0)
                    logger.info(f"TLS VERSION USED BY DUT is--->{version}")
                    assert "TLS 1.2" in version, "TLS version mismatch, expected TLS VERSION 1.2 to be sent by DUT"
                    assert "Client Hello" in i, "Client Hello packet missed"
        else:
            logger.info("SSL packets are not found")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_client_testcase_c19109(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
                                             sl_collections, sniffer_filter, utf_constants):
    """
    SSL Protocol handshakes and Verify exchanges between server and client sockets during TCP connection establishment
    """
    try:
        capture = True
        capture_filename = "test_wifi_sdk_ssl_client_testcase_TC19109"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        repeat = utf_constants.get("iter_count")
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)

        for repeat_count in range(1, repeat + 1):
            logger.info(f"******** Iteration {repeat_count} Starts ********")
            device_ip, dut_mac_address = ssl_obj.join_get_ip(sniff_capture=capture)
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server()
            server_ip = ssl_server.interfaces.ssl.server_ip
            logger.info(f"SSL server started with server ip:{server_ip}")

            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == 0, "Socket id received is wrong. expected is 0"
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            # Socket binds at (device_ip, port) in DUT
            local_port = randint(5001, 60000)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            # ssl socket opened in DUT connects to the server
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                      server_port=port1)

            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                # The api returns 100 bytes of random data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger.info(f"Sending data {data} over socket_no->{sock}")
                # DUT sends 100 bytes of data over ssl socket
                wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
                time.sleep(1)
                # SSL server receives the data over ssl socket
                server_socket_no = 1
                data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
                logger.info(f"Data received on remote socket opened is {data_receive}")
                assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                logger.info("Data sent by DUT and received on server is matching\n\n")

            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            logger.info("Successfully closed opened socket in the DUT")
            ssl_server.interfaces.ssl.stop_server()

            logger.info("Initiating wlan disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()
            capture = False
            logger.info(f"******** Iteration {repeat_count} Ends ********\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger.info("Stop Sniffer finally")
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.parametrize("cert1, cert2",
                         [(["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                            "mosquitto-utf.silabs.com.key.pem"],
                           ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                            "mosquitto-utf.silabs.com.key.pem"])
                          ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_max_sockets_testcase_c19128(wifi_sniffer, wifi_dut, wifi_access_point, ssl_server, logger, cert1,
                                                  cert2, sl_collections, sniffer_filter, utf_constants):
    """
    Opening Max number of SSL client sockets and data transfer
    """
    try:
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        capture = True
        capture_filename = "test_wifi_sdk_ssl_max_sockets_testcaseTC19128"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        repeat = utf_constants.get("iter_count")

        logger.info("Loading certificates at index 1 and 2")
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE, cert_index=1)
        wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath("ca-chain.cert.pem")),
                                                     Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE, cert_index=2)
        logger.info("Loading certificates done\n\n")

        for repeat_count in range(1, repeat + 1):
            logger.info(f"******** Iteration {repeat_count} Starts ********")

            ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
            device_ip, dut_mac_address = ssl_obj.join_get_ip(sniff_capture=capture)

            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server(server_cert=cert1[1], server_key=cert1[2])
            # Open ssl server socket in remote device(Raspberry pi or static device)
            ssl_server.interfaces.ssl.start_server(port=port2, server_cert=cert2[1], server_key=cert2[2])
            server_ip = ssl_server.interfaces.ssl.server_ip

            for sock_count in range(0, 2):
                # Open ssl client socket in the DUT
                sock = wifi_dut.interfaces.wifi.socket()
                if sock_count == 0:
                    assert sock == 0, f"socket id received is wrong, expected is 0"
                else:
                    assert sock == 1, f"socket id received is wrong, expected is 1"
                logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                # Enable ssl option for socket opened
                wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
                if sock_count == 0:
                    socket_port = port1
                elif sock_count == 1:
                    socket_port = port2

                # Socket binds at (device_ip, 5001) in DUT
                wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port,
                                              timeout=15)
                # ssl socket opened in DUT connects to the server
                wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

            time.sleep(5)
            socket_no = [1, 2]
            for socket in socket_no:
                ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length, pkt_rcv_timeout=120)
            result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=3, data_len=buffer_length,
                                                                         number_of_pkts=pkt_count)
            socket_list = result
            logger.info(f"*** socket_list *** {socket_list} ")
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
                                                              f"remote peer not matched on socket {socket}"
            for sock_count in range(0, 2):
                logger.info(f"Closing socket_id->{sock_count}")
                wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
                logger.info(f"Successfully closed socket_id->{sock_count}")
            ssl_server.interfaces.ssl.stop_server()
            logger.info("Initiating wlan disconnect from DUT")
            wifi_dut.interfaces.wifi.leave()
            capture = False
            logger.info(f"******** Iteration {repeat_count} Ends ********\n\n")

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
                                             ap_bssid)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated", "close_sockets"])
def test_wifi_sdk_ssl_client_tx_while_rejoining_c19134(wifi_dut, wifi_access_point, wifi_sniffer, ssl_server,
                                                       cert1, logger, sl_collections, sniffer_filter, switch):
    """
    ssl tx while rejoining with different data sizes.
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_tx_while_rejoining_c19134"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections,
                                 rejoin_params=[20, 6, 40, 0])
        device_ip, dut_mac_address = ssl_obj.join_get_ip()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        server_ip = ssl_server.interfaces.ssl.server_ip
        local_port = randint(5001, 60000)

        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)

        thread = Thread(target=ssl_obj.pdu_switch, args=(5, switch))
        for tx_buffer in [20, buffer_length]:
            ssl_server.interfaces.ssl.data_receive(1, pkt_count, tx_buffer, 10)
            if tx_buffer == 20:
                thread.start()
            wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=1, data_len=tx_buffer,
                                                                number_of_pkts=pkt_count)
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
            assert bytes_received, "Failed receive data on the remote peer"
            thread.join()

        ssl_server.interfaces.ssl.stop_server()
        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_client_tx_rx_bidirectional_c19129(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
                                                        logger, sl_collections, sniffer_filter):
    """
    Data transfer over one ssl socket and rx over another socket
    """
    sock_opened = 0
    try:
        capture_filename = "test_wifi_sdk_ssl_client_tx_rx_bidirectional_c19129"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']

        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_server.interfaces.ssl.start_server(port=port1)
        ssl_server.interfaces.ssl.start_server(port=port2)
        server_ip = ssl_server.interfaces.ssl.server_ip

        for sock_count in range(2):
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"
            logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            sock_opened += 1
            logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
            else:
                socket_port = port2
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=socket_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)

        rx_thread = Thread(target=ssl_obj.socket_data_rx, args=(wifi_dut, ssl_server, 2, pkt_count, buffer_length))
        sw = Stopwatch()
        rx_thread.start()
        while sw.elapsed_sec < 30:
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger.info(f"Sending data from DUT over socket_no ---> 0")
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=0, data=data)
            data_receive = ssl_server.interfaces.ssl.data_recv_content(1, buffer_size=len(data))
            logger.info(f"Data received on remote socket opened is {data_receive}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger.info("Data sent by DUT and received on server is matching in socket id --> 0\n\n")
            time.sleep(1)
        rx_thread.join()

        for sock_id in range(2):
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


@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "wifi_powersave_disable", "close_sockets"])
def test_wifi_sdk_ssl_client_rx_while_rejoining_c19135(wifi_dut, wifi_access_point, wifi_sniffer, ssl_server,
                                                       cert1, logger, sl_collections, sniffer_filter, switch):
    """
    To check SSL rx functionality of DUT while rejoining
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_client_rx_while_rejoining_c19135"
        pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
        tx_buffer_len = ssl_server.interfaces.ssl.config['buffer_length']
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections,
                                 rejoin_params=[20, 6, 40, 0])
        device_ip, dut_mac_address = ssl_obj.join_get_ip()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1], server_key=cert1[2])
        server_ip = ssl_server.interfaces.ssl.server_ip

        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        wifi_dut.interfaces.wifi.bsdSsetCustomSyncSockopt(socket_fd=sock, cert_index=0)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port1, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)

        thread = Thread(target=ssl_obj.pdu_switch, args=(5, switch))
        for tx_buffer in [tx_buffer_len, 20]:
            ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=tx_buffer)
            if tx_buffer != 20:
                thread.start()
            rx_buffer = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=20)
            assert rx_buffer, "Packet loss observed at receiver side"
            thread.join()
            time.sleep(30)

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=0)
        logger.info("Successfully closed socket_id 0 in the DUT")
        ssl_server.interfaces.ssl.stop_server()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.check
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated",
                             "clear_certs"])
def test_wifi_sdk_ssl_server_v1_0_and_client_v1_0_c19117(sl_collections, openssl, logger, wifi_access_point,
                                                         wifi_client, wifi_sniffer, wifi_dut, sniffer_filter):
    """
    Open ssl client socket with version 1.0 and do data transfer.
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_server_v1_0_and_client_v1_0_c19117"
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        openssl.interfaces.server.start(port=5001, tls_version="-tls1")
        server_ip = wifi_client.interfaces.wifi.get_ip_address()
        local_port = randint(5001, 60000)

        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_0")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=5001)

        data_sent = []
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            data = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
            data_sent.append(data)
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)

        tx_data = "".join(data_sent)
        rx_data = openssl.interfaces.server.get_messages(timeout=100)[-1]
        logger.info(f"\n\n*************** Total data sent from DUT ***************\n{tx_data}")
        logger.info(f"\n\n*************** data received *************** \n{rx_data}")
        assert tx_data == rx_data, "Data received doesn't match"

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        openssl.interfaces.server.stop()

        logger.info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter)
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger.info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"],
                                                       capture_filename, ap_bssid)["tls"]
        if len(ssl_pkt) > 0:
            for i in ssl_pkt:
                if re.search(".*Client Hello", i):
                    version = re.search("Version:.*", i).group(0)
                    logger.info(f"TLS VERSION USED BY DUT is--->{version}")
                    assert "TLS 1.0" in version, "TLS version mismatch, expected TLS VERSION 1.0 to be sent by DUT"
                    assert "Client Hello" in i, "Client Hello packet missed"
        else:
            logger.info(f"SSL packets are not found")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@pytest.mark.check
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ssl_server_v1_2_and_client_v1_0_c19119(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
                                                         sl_collections):
    """
    Connect to ssl server socket which run with version 1.2 at remote side and connect to it from module with version 1.0
    """
    try:
        capture_filename = "test_wifi_sdk_ssl_server_v1_2_and_client_v1_0_c19119"
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_obj = ssl_connection(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, sl_collections)
        device_ip, dut_mac_address = ssl_obj.join_get_ip()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(f'AP BSSID = {ap_bssid}')

        ssl_server.interfaces.ssl.start_server(version="ssl_1.2")
        server_ip = ssl_server.interfaces.ssl.server_ip

        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")

        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_0")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=port1, timeout=15)
        error_code = None
        try:
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1)
        except Exception as err:
            error_match = re.search("status:(.*)", str(err))
            if error_match:
                error_code = error_match.group()
                logger.info(f"error_code: {error_code}")
        assert error_code, "DUT did not send error when trying to connect to SSL server with version 1.2 which is not expected"
        logger.info("DUT sent error when trying to connect to SSL server with version 1.2 which is expected")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


""" Below testcases are commented, rework needed for these testcases for upcoming announcements."""
# # BIT_TLS_RSA_WITH_AES_256_CBC_SHA256 -> Supported with current python version
# # BIT_TLS_RSA_WITH_AES_128_CBC_SHA256 -> Supported with current python version
# # BIT_TLS_RSA_WITH_AES_256_CBC_SHA -> Supported with current python version
# # BIT_TLS_DHE_RSA_WITH_AES_128_CBC_SHA -> Supported with current python version
# # BIT_TLS_RSA_WITH_AES_128_CCM_8 -> Not supported with current python version
# # BIT_TLS_RSA_WITH_AES_256_CCM_8 -> Not supported with current python version
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "disassociated",
#                              "disable_cipher"])
# @pytest.mark.parametrize("cipher_list", [
#     [Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256,
#      Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA, Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA]])
# def test_wifi_sdk_ssl_client_cipher_list_testcase_c19132(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,
#                                                          cipher_list, sl_collections):
#     """
#     SSL client functionality with the following cipher suites. Configure one of the following combination, provided in the test steps
#     """
#     try:
#         capture_filename = "test_wifi_sdk_ssl_client_cipher_list_testcase_TC19132"
#         pkt_count = 20000
#         buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
#         port1 = ssl_server.interfaces.ssl.config['device_port1']
#         bytes_sent = (pkt_count * buffer_length)
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         server_ip = ssl_server.interfaces.ssl.server_ip
#         ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
#                                  sl_collections)
#         dut_mac_address = ssl_obj.join_get_ip()
#         # The below api parses DUTs IP address
#         device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#
#         for cipher in cipher_list:
#             if cipher == Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA256:
#                 cipher_str = 'TLS_RSA_WITH_AES_256_CBC_SHA256'
#             elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA256:
#                 cipher_str = 'TLS_RSA_WITH_AES_128_CBC_SHA256'
#             elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_256_CBC_SHA:
#                 cipher_str = 'TLS_RSA_WITH_AES_256_CBC_SHA'
#             elif cipher == Cipher.BIT_TLS_RSA_WITH_AES_128_CBC_SHA:
#                 cipher_str = 'TLS_RSA_WITH_AES_128_CBC_SHA'
#             logger.info(f"Running SSL test when cipher suite selected is {cipher_str}")
#             wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=cipher)
#             # Open ssl server socket in remote device(Raspberry pi or static device)
#             ssl_server.interfaces.ssl.start_server()
#             # Open ssl client socket in the DUT
#             sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
#             assert sock == 0, f"Socket id received is wrong. expected is 0 when cipher suite selected is {cipher_str}"
#             logger.info(
#                 f"Successfully opened tcp client socket and socket id received is {sock} which is expected when "
#                 f"cipher suite selected is {cipher_str}")
#             logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API when cipher suite "
#                         f"selected is {cipher_str}")
#             # Enable ssl option for socket opened
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                      option_val=SocketOptions.SOL_SOCKET)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                      option_val=SocketOptions.SO_SSL_ENABLE)
#             wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                      option_val=SocketOptions.SSL_ENABLE)
#
#             local_port = randint(5001, 60000)
#             # Socket binds at (device_ip, 5001) in DUT
#             wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
#                                           timeout=15)
#             # ssl socket opened in DUT connects to the server
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
#                                                       )
#
#             # The api returns 100 bytes of random data
#             data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#             data_length = len(data_sent)
#             logger.info(f"Sending data {data_sent} over socket_no->{sock} when cipher suite selected is {cipher_str}")
#             # DUT sends 100 bytes of data over ssl socket
#             wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data_sent)
#             server_socket_no = 1
#             # SSL server receives the data over ssl socket
#             data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
#             logger.info(
#                 f"Data received on remote socket opened is {data_receive} when cipher suite selected is {cipher_str}")
#             assert data_sent == data_receive.decode(), f"Data sent by DUT and received on server is matching when cipher " \
#                                                        f"suite selected is {cipher_str} "
#             logger.info(
#                 f"Data sent by DUT and received on server is matching when cipher suite selected is {cipher_str}")
#
#             if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
#                 ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
#             result = wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=bytes_sent)
#             logger.info(f"Number of bytes sent by dut {result}")
#             bytes_sent = result
#             assert_packet_check = (0.95 * float(bytes_sent))
#             bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
#             assert bytes_received >= assert_packet_check, f"Number of bytes sent by DUT and received on the remote peer are" \
#                                                           f"not matched on socket {server_socket_no} when cipher suite selected is {cipher_str}"
#             logger.info(
#                 f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received} when cipher suite selected is {cipher_str}")
#             # Close socket 1
#             result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
#             assert b"success" in result, "unable to close opened ssl socket in the dut when cipher suite selected is {" \
#                                          "cipher_str} "
#             logger.info("Successfully closed opened socket in the DUT when cipher suite selected is {cipher_str}")
#
#             ssl_server.interfaces.ssl.stop_server()
#
#         wifi_dut.interfaces.wifi.leave()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         logger.info(f"DECRYPTION KEY-->{decryption_key}")
#         sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
#                                              ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#
#
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["close_sockets", "wifi_powersave_disable", "disassociated",
#                              "disable_cipher"])
# def test_wifi_sdk_ssl_client_ciphersuite_mismatch_testcase_c19133(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server,
#                                                                   logger, sl_collections):
#     """
#     Verify SSL hand shake functionality in client and server mode when module cipher suite mismatches with the remote peer cipher suite
#     """
#     try:
#         capture_filename = "test_wifi_sdk_ssl_client_ciphersuite_mismatch_testcase_TC19133"
#         port1 = ssl_server.interfaces.ssl.config['device_port1']
#         ap_bssid = wifi_access_point.interfaces.wifi.bssid
#         logger.info(f'AP BSSID = {ap_bssid}')
#         server_ip = ssl_server.interfaces.ssl.server_ip
#
#         ssl_obj = ssl_connection(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger,
#                                  sl_collections)
#         dut_mac_address = ssl_obj.join_get_ip()
#         # The below api parses DUTs IP address
#         device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
#         # Open ssl server socket in remote device(Raspberry pi or static device)
#         logger.info(
#             f"Opening SSL server socket remotely with cipher suite->{Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA}")
#         wifi_dut.interfaces.wifi.select_ssl_cipher(cipher_list=Cipher.BIT_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
#                                                    )
#         logger.info(f"Cipher suite selected in DUT is ECDHE-RSA-AES256-SHA384")
#         ssl_server.interfaces.ssl.start_server(cipher_list="ECDHE-RSA-AES256-SHA384")
#         # Open ssl client socket in the DUT
#         sock = wifi_dut.interfaces.socket(protocol=SocketOptions.SSL_ENABLE)
#         assert sock == 0, "Socket id received is wrong. expected is 0"
#         logger.info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
#         logger.info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
#         # Enable ssl option for socket opened
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SOL_SOCKET',
#                                                  option_val=SocketOptions.SOL_SOCKET)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SO_SSL_ENABLE',
#                                                  option_val=SocketOptions.SO_SSL_ENABLE)
#         wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=sock, option_name='SSL_ENABLE',
#                                                  option_val=SocketOptions.SSL_ENABLE)
#
#         local_port = randint(5001, 60000)
#         # Socket binds at (device_ip, 5001) in DUT
#         wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15,
#                                       )
#         with pytest.raises(WlanError) as exc_info:
#             # ssl socket opened in DUT connects to the server
#             wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=port1,
#                                                       )
#         assert exc_info.value.error_code == 0xD2, f"DUT sent wrong error code expected is 0xD2"
#         logger.info(f"DUT returned {exc_info.value.error_code} when cipher suite is mismatched")
#         wifi_dut.interfaces.wifi.leave()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger.info("Stop Sniffer finally")
#         validation = True
#         packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
#         snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
#         assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
#         logger.info(f"PS-POLL packets are captured in the sniffer")
#
#         decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
#         logger.info(f"DECRYPTION KEY-->{decryption_key}")
#         sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["tls"], capture_filename,
#                                              ap_bssid)
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
